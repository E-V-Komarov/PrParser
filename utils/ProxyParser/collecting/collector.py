"""Пул потоков поверх источников: скачивание и дедупликация.

На источник — свой поток со своим event loop и своей aiohttp-сессией:
aiohttp-объекты привязаны к loop, одна сессия на все потоки небезопасна.
Состояние общее, но защищено обычным ``threading.Lock``.
"""

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple

import aiohttp

from utils.ProxyParser import config
from utils.ProxyParser.collecting.http import Fetcher
from utils.ProxyParser.collecting.sources import Deadline, scan_page
from utils.ProxyParser.parsing import Proxy


class Collector:
    """Качает источники в потоках и копит уникальные прокси."""

    def __init__(self, concurrency: int = config.CONCURRENCY,
                 use_anonymizers: bool = True, log=None):
        self.concurrency = max(1, concurrency)
        self.use_anonymizers = use_anonymizers
        self.log = log or (lambda msg: None)

        self.seen: Dict[str, Proxy] = {}
        self.found_total = 0
        self.dupes = 0
        self.done = 0
        self.total = 0
        self.bytes = 0
        self.sources_ok: Dict[str, str] = {}   # источник -> сработавший URL
        self.sources_empty: List[str] = []      # прокси не нашлось
        self.sources_no_new: List[str] = []     # нашлись, но все уже были

        self._lock = threading.Lock()
        self._local = threading.local()          # loop+session на поток
        # (loop, session) по одному на поток: loop'и созданы в чужих потоках,
        # закрыть их из главного можно только через сохранённые ссылки.
        self._sessions: List[Tuple[asyncio.AbstractEventLoop,
                                   aiohttp.ClientSession]] = []
        self._fetchers: List[Fetcher] = []

    @property
    def unique(self) -> int:
        return len(self.seen)

    def _thread_ctx(self):
        """Ленивая сессия текущего потока (создаётся один раз).

        Сессия и коннектор создаются *внутри* цикла потока: aiohttp цепляется
        к текущему loop при инициализации, и вне ``run_until_complete`` поднимает
        ``RuntimeError: no running event loop``.
        """
        ctx = getattr(self._local, "ctx", None)
        if ctx is not None:
            return ctx

        async def make():
            connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300,
                                             ssl=False)
            return aiohttp.ClientSession(
                connector=connector,
                headers={"User-Agent": config.USER_AGENT,
                         "Accept": config.ACCEPT})

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        session = loop.run_until_complete(make())
        self._sessions.append((loop, session))
        fetcher = Fetcher(session, self.use_anonymizers, self.log)
        self._fetchers.append(fetcher)
        ctx = self._local.ctx = (loop, session, fetcher)
        return ctx

    def _close_sessions(self) -> None:
        """Закрывает сессию и event loop каждого потока.

        Сессия асинхронная, поэтому close() гоняем через её же loop. Порядок
        важен: сначала сессия, потом loop — иначе остаются незакрытые сокеты
        и aiohttp ругается в лог.
        """
        for loop, session in self._sessions:
            if loop.is_closed():
                continue
            try:
                loop.run_until_complete(session.close())
            except Exception:
                pass
            # На Windows транспорты закрываются асинхронно: session.close()
            # лишь ставит отмену, а сокет освобождается позже. Без этого
            # loop.close() оставляет висящие сокеты и ResourceWarning.
            for _ in range(3):
                try:
                    loop.run_until_complete(asyncio.sleep(0))
                except Exception:
                    break
            try:
                loop.run_until_complete(asyncio.sleep(0.1))
            except Exception:
                pass
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            try:
                loop.close()
            except Exception:
                pass
        self._sessions.clear()
        self._fetchers.clear()
        self._local = threading.local()

    def _fetch(self, url: str) -> Tuple[List[Proxy], str, str]:
        loop, _session, fetcher = self._thread_ctx()
        return loop.run_until_complete(scan_page(fetcher, url, Deadline()))

    def _absorb(self, url: str, found: List[Proxy]) -> int:
        """Кладёт прокси в seen под замком, возвращает число новых."""
        new = 0
        for p in found:
            key = p.dedup_key()
            if key in self.seen:
                self.dupes += 1
                continue
            self.seen[key] = p
            new += 1
        return new

    def _bytes_total(self) -> int:
        return sum(getattr(f, "bytes", 0) for f in self._fetchers)

    def run(self, pages: List[str],
            on_done: Optional[Callable[[int, int], None]] = None) -> None:
        """Скачивает все источники. ``on_done(done, found_total)`` — прогресс."""
        self.total = len(pages)

        def worker(url: str) -> None:
            try:
                found, via, err = self._fetch(url)
            except Exception as exc:
                found, via, err = [], url, f"error: {type(exc).__name__}: {exc}"
            with self._lock:
                self.done += 1
                self.found_total += len(found)
                new = self._absorb(url, found)
                if found:
                    self.sources_ok[url] = via
                    if not new:
                        self.sources_no_new.append(url)
                    self.log(f"+ {_short(url)}: {len(found)} найдено, "
                             f"{new} новых ({_short(via)})")
                else:
                    self.sources_empty.append(url)
                    self.log(f"- {_short(url)}: {err}")
            if on_done:
                on_done(self.done, self.found_total)

        try:
            with ThreadPoolExecutor(max_workers=self.concurrency,
                                    thread_name_prefix="src") as ex:
                for fut in as_completed([ex.submit(worker, u) for u in pages]):
                    try:
                        fut.result()
                    except Exception as exc:      # не роняем этап из-за одного
                        self.log(f"worker failed: {type(exc).__name__}: {exc}")
        finally:
            # bytes считаем до закрытия сессий: у каждого потока свой Fetcher.
            self.bytes = self._bytes_total()
            self._close_sessions()


def _short(url: str) -> str:
    return url.split("://", 1)[-1][:72]


def collect(pages: List[str], concurrency: int = config.CONCURRENCY,
            use_anonymizers: bool = True, log=None,
            on_done: Optional[Callable[[int, int], None]] = None) -> Collector:
    """Прогоняет источники и возвращает собранный :class:`Collector`."""
    coll = Collector(concurrency, use_anonymizers, log)
    coll.run(pages, on_done)
    return coll