"""HTTP-слой: один запрос с ретраями, цепочка анонимайзеров, обход Wayback.

Стратегия ровно как в оригинале (PageScanner.FETCH_PROXIES, Mirrors):
  1. прямая загрузка;
  2. при неудаче — цепочка анонимайзеров (codetabs, allorigins, jina, …);
  3. маршрут запоминается, чтобы пагинацию вести тем же путём.
"""

import asyncio
from typing import List, Optional, Tuple
from urllib.parse import quote

import aiohttp

from utils.ProxyParser import config

WAYBACK_PREFIX = "https://web.archive.org/web/"


class Fetcher:
    """Скачивает URL прямым запросом, при неудаче — через анонимайзеры.

    Помнит, каким маршрутом удалось взять страницу (:meth:`route_of`), чтобы
    пагинацию (?before=, &st=) вести по тому же маршруту, а не упираться в
    блок��ровку снова.
    """

    def __init__(self, session: aiohttp.ClientSession,
                 use_anonymizers: bool = True, log=None):
        self.session = session
        self.use_anonymizers = use_anonymizers
        self.log = log or (lambda msg: None)
        self.bytes = 0

    async def _get(self, url: str) -> Optional[str]:
        """Один запрос с ретраями на транзиентные ошибки.

        429/5xx и таймауты почти всегда означают троттлинг, а не «нет
        доступа»: повтор через паузу почти всегда проходит. 4xx вроде
        403/404/410/451 повторять бессмысленно — их не лечит время.
        """
        delay = config.RETRY_SLEEP
        for attempt in range(config.HTTP_RETRIES):
            retry = False
            try:
                async with self.session.get(
                        url, timeout=aiohttp.ClientTimeout(
                            total=config.TIMEOUT_TOTAL,
                            connect=config.TIMEOUT_CONNECT,
                            sock_read=config.TIMEOUT_READ)) as resp:
                    if resp.status in config.RETRY_STATUSES:
                        retry = True
                    elif resp.status < 200 or resp.status >= 300:
                        return None
                    else:
                        # Важно: content.read(n) отдаёт только то, что уже лежит
                        # в буфере, — на больших/медленных ответах это обрывок
                        # тела (проверено на llimonix.dev: 503 байт вместо 9117).
                        # Читаем поток до EOF, сами ограничивая размер.
                        raw = await self._read_capped(resp)
                        if raw is None:
                            return None      # тело больше MAX_BODY — не берём
                        self.bytes += len(raw)
                        # Пустая строка — тоже успех: хост жив, содержимого
                        # просто нет. Раньше "" считался неудачей, и пустой
                        # список уходил в перебор всех зеркал и анонимайзеров.
                        return raw.decode("utf-8", errors="replace")
            except Exception:
                retry = True
            if not retry or attempt == config.HTTP_RETRIES - 1:
                return None
            await asyncio.sleep(delay)
            delay *= config.RETRY_BACKOFF
        return None

    @staticmethod
    async def _read_capped(resp, cap: int = None) -> Optional[bytes]:
        """Тело ответа целиком, но не больше cap байт.

        None — тело слишком велико; ``b""`` — пустой ответ (валидный успех).
        """
        cap = config.MAX_BODY if cap is None else cap
        chunks = []
        total = 0
        async for chunk in resp.content.iter_chunked(64 * 1024):
            total += len(chunk)
            if total > cap:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def route_of(page_url: str, used_url: str) -> Optional[tuple]:
        """Маршрут, которым реально скачали страницу (None — напрямую)."""
        if used_url == page_url:
            return None
        if used_url.startswith(WAYBACK_PREFIX):
            return ("wayback",)
        for label, prefix, encode in config.FETCH_PROXIES:
            if used_url.startswith(prefix):
                return ("anon", label, prefix, encode)
        return None

    @staticmethod
    def _wrap(route: tuple, target: str) -> str:
        kind = route[0]
        if kind == "wayback":
            return WAYBACK_PREFIX + target
        _kind, _label, prefix, encode = route
        return prefix + (quote(target, safe="") if encode else target)

    async def get(self, url: str, route=None) -> Optional[str]:
        """route=None — сначала напрямую, затем по всей цепочке анонимайзеров;
        иначе — только по указанному маршруту."""
        if route is not None:
            return await self._get(self._wrap(route, url))
        body = await self._get(url)
        if body is not None:
            return body
        if not self.use_anonymizers:
            return None
        for label, prefix, encode in config.FETCH_PROXIES:
            body = await self._get(self._wrap(("anon", label, prefix, encode),
                                             url))
            if body is not None:
                self.log(f"прямой доступ закрыт — через {label}")
                return body
        return None

    async def get_many(self, urls: List[str]) -> List[Tuple[str, Optional[str]]]:
        """Скачивает список URL конкурентно, возвращает (url, body|None)."""
        tasks = [asyncio.ensure_future(self.get(u)) for u in urls]
        bodies = await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for url, body in zip(urls, bodies):
            out.append((url, None if isinstance(body, BaseException) else body))
        return out