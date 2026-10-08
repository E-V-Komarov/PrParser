"""Потоковая проверка прокси средствами самого TDLib.

В отличие от TcpChecker, который бьёт по сокетам из пятидесяти потоков, здесь
проверку делает Telegram-клиент: ``pingProxy`` поднимает настоящее соединение
с прокси и отдаёт задержку в секундах. Это честнее TCP-connect — видно, что
прокси действительно говорит по протоколу, а не просто держит порт открытым.

Главное свойство — поток. ``stream()`` возвращает генератор: запись уходит в
проверку только тогда, когда освободился слот, а результат выдаётся сразу, как
пришёл ответ. Список прокси целиком в памяти не собирается, поэтому на вход
можно подавать генератор на миллион строк и получать вердикты на лету.

Формат результата совпадает с TcpChecker (те же ключи), но вердикты TDLib
пишутся через ``ProxyDatabase.apply_tdlib_results()``: они хранят протокольный
пинг рядом с пингом TCP, взятым из ``get_tcp_checked()``.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from utils.TdLibChecker.client import TdLibClient, build_proxy
from utils.TdLibChecker.records import Record, records_from

__all__ = ["TdLibChecker", "OK", "NO_PING", "PING_SO_BIG"]

OK = "ok"
NO_PING = "NoPing"
PING_SO_BIG = "PingSoBig"


class _Pending:
    """Один запрос ``pingProxy`` в работе."""

    __slots__ = ("entry_id", "record", "attempt", "deadline")

    def __init__(self, record: Record, attempt: int, deadline: float) -> None:
        self.record = record
        self.entry_id = record[0]
        self.attempt = attempt
        self.deadline = deadline


class TdLibChecker:
    """Проверка прокси через TDLib.

    Параметры:
        clients     — сколько клиентов TDLib работает одновременно;
        max_inflight — сколько ``pingProxy`` может висеть в работе суммарно;
        timeout     — свой таймаут на запрос. TDLib сам сдаётся на 10 с, но без
                      ``setTdlibParameters`` он не отвечает вообще, поэтому
                      таймаут здесь обязателен;
        attempts    — повторы; по умолчанию один, ведь ``pingProxy`` и так
                      отвечает отказом за ~2 с на мёртвом порту;
        pause_ms    — пауза перед повтором, как в TcpChecker;
        ping_max_ms — выше этого пинга вердикт PingSoBig, а не ok.
    """

    @classmethod
    def stream(cls, source: Any, *, clients: int = 4, max_inflight: int = 8,
               timeout: float = 15.0, attempts: int = 1, pause_ms: int = 200,
               ping_max_ms: float = 1700.0, on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
               client_factory: Optional[Callable[[], TdLibClient]] = None,
               recycle_after: int = 16,
               **client_kwargs: Any) -> Iterator[Dict[str, Any]]:
        """Генератор вердиктов: ``{'id', 'server', 'ping_ms', 'status', 'message'}``."""
        factory = client_factory or TdLibClient
        pool: List[TdLibClient] = [factory(**client_kwargs) for _ in range(max(1, int(clients)))]
        slots = max(1, int(max_inflight))
        attempts = max(1, int(attempts))
        pause = max(0.0, float(pause_ms) / 1000.0)

        inflight: Dict[str, Tuple[int, _Pending]] = {}
        by_client: List[set] = [set() for _ in pool]
        retries: List[Tuple[float, _Pending]] = []
        abandoned = [0] * len(pool)
        source_it = records_from(source)
        source_done = False
        cursor = 0

        def dispatch(pending: _Pending) -> None:
            nonlocal cursor
            best = min(range(len(pool)),
                       key=lambda i: (len(by_client[i]), abandoned[i], (i - cursor) % len(pool)))
            cursor = (best + 1) % len(pool)
            entry_id, kind, host, port, secret = pending.record
            extra = pool[best].ping(build_proxy(kind, host, port, secret))
            pending.deadline = time.monotonic() + timeout
            inflight[extra] = (best, pending)
            by_client[best].add(extra)

        def verdict(pending: _Pending, ping_ms: Optional[float], status: Optional[str],
                    message: Optional[str]) -> Optional[Dict[str, Any]]:
            """Готовый результат; ``None`` означает «ещё раз попробовать»."""
            if status is None and ping_ms is None and pending.attempt < attempts:
                retries.append((time.monotonic() + pause, pending))
                return None
            if status is None:
                status = NO_PING
            _entry_id, _kind, host, port, _secret = pending.record
            return {"id": pending.entry_id, "server": "%s:%d" % (host, port),
                    "ping_ms": ping_ms, "status": status, "message": message}

        def resolve(extra: str, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            index, pending = inflight.pop(extra)
            by_client[index].discard(extra)
            abandoned[index] = max(0, abandoned[index] - 1)
            if event.get("@type") == "seconds":
                ping = round(float(event["seconds"]) * 1000.0, 1)
                if ping > ping_max_ms:
                    return verdict(pending, ping, PING_SO_BIG,
                                   "ping %.0f ms > %.0f ms" % (ping, ping_max_ms))
                return verdict(pending, ping, OK, None)
            return verdict(pending, None, None,
                           str(event.get("message") or event.get("@type") or "TDLib error"))

        try:
            while True:
                now = time.monotonic()

                if retries:
                    ready = [item for item in retries if item[0] <= now]
                    retries = [item for item in retries if item[0] > now]
                    for _ready_at, pending in ready:
                        pending.attempt += 1
                        dispatch(pending)

                while not source_done and len(inflight) + len(retries) < slots:
                    try:
                        record = next(source_it)
                    except StopIteration:
                        source_done = True
                        break
                    dispatch(_Pending(record, 1, 0.0))

                if not inflight and not retries and source_done:
                    break

                out: List[Dict[str, Any]] = []

                wait = 1.0
                if inflight:
                    wait = min(1.0, max(0.01, min(p.deadline for _i, p in inflight.values()) - now))
                for offset in range(len(pool)):
                    index = (cursor + offset) % len(pool)
                    if by_client[index]:
                        break
                else:
                    index = cursor % len(pool)

                event = pool[index].receive(wait)
                if event is not None:
                    extra = event.get("@extra")
                    if extra in inflight:
                        result = resolve(extra, event)
                        if result is not None:
                            out.append(result)

                now = time.monotonic()
                for extra in [e for e, (_i, p) in inflight.items() if p.deadline <= now]:
                    client_index, pending = inflight.pop(extra)
                    by_client[client_index].discard(extra)
                    abandoned[client_index] += 1
                    result = verdict(pending, None, None,
                                     "таймаут %.0f с" % timeout)
                    if result is not None:
                        out.append(result)

                for client_index in range(len(pool)):
                    if abandoned[client_index] > recycle_after:
                        for extra in list(by_client[client_index]):
                            _i, pending = inflight.pop(extra)
                            result = verdict(pending, None, None, "клиент перезапущен")
                            if result is not None:
                                out.append(result)
                        by_client[client_index].clear()
                        abandoned[client_index] = 0
                        pool[client_index].close()
                        pool[client_index] = factory(**client_kwargs)

                for result in out:
                    if on_result is not None:
                        on_result(result)
                    yield result
        finally:
            for client in pool:
                try:
                    client.close()
                except Exception:
                    pass

    @classmethod
    def check(cls, source: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        """Собирает поток в список — для коротких списков и тестов."""
        return list(cls.stream(source, **kwargs))