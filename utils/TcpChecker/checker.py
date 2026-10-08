"""TCP-connect проверка прокси в потоках.

Алгоритм по умолчанию (меняется аргументами :func:`check`):

* до 3 попыток соединения, у каждой таймаут 2000 мс;
* перед повторной попыткой — пауза 200 мс;
* 50 потоков;
* попытка, которая ответила, считается успехом и дальше не повторяется —
  повторять есть смысл только после неудачи;
* не ответил ни разу → ``NoPing``;
* ответил, но дольше 1700 мс → ``PingSoBig``;
* иначе результат содержит пинг в миллисекундах.

Никакой базы данных: на вход прокси, на выходе список вердиктов по id.
Поэтому один и тот же модуль работает и из main, и как библиотека.

    import TcpChecker
    for r in TcpChecker.check({"12": "1.2.3.4:443"}):
        print(r["id"], r["ping_ms"], r["status"])
"""

import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

__all__ = ["check", "ping_once", "normalize", "TRIES", "TIMEOUT_MS",
           "PAUSE_MS", "WORKERS", "SO_BIG_MS", "STATUS_OK", "STATUS_NO_PING",
           "STATUS_SO_BIG"]

TRIES = 3              # попыток соединения на прокси
TIMEOUT_MS = 2000      # таймаут одной попытки, мс
PAUSE_MS = 200         # пауза перед повторной попыткой, мс
WORKERS = 50           # потоков проверки
SO_BIG_MS = 1700       # пин�� дольше → PingSoBig

STATUS_OK = "ok"
STATUS_NO_PING = "NoPing"
STATUS_SO_BIG = "PingSoBig"

Result = Dict[str, Any]


def _split_hostport(server: str) -> Tuple[str, int]:
    """'1.2.3.4:443' → ('1.2.3.4', 443); [::1]:443 тоже понимает."""
    host, _, port = server.rpartition(":")
    if not host:
        raise ValueError(f"не host:port: {server!r}")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.strip(), int(port)


def _entry_to_hostport(value: Any) -> Tuple[str, int]:
    """Принимает dict прокси, кортеж или строку 'host:port'."""
    if isinstance(value, Mapping):
        if "server" in value and value["server"]:
            return _split_hostport(str(value["server"]))
        host = value.get("host") or value.get("ip") or value.get("address")
        port = value.get("port")
        if host and port:
            return str(host).strip(), int(port)
        if value.get("link"):
            return _link_hostport(str(value["link"]))
        raise ValueError(f"в записи нет адреса: {dict(value)!r}")
    if isinstance(value, (list, tuple)):
        host, port = value[0], value[1]
        return str(host).strip(), int(port)
    return _split_hostport(str(value))


def _link_hostport(link: str) -> Tuple[str, int]:
    """'tg://proxy?server=h&port=443&secret=…' → ('h', 443)."""
    from urllib.parse import parse_qs, urlparse
    query = parse_qs(urlparse(link).query)
    host = (query.get("server") or query.get("host") or [""])[0]
    port = (query.get("port") or [""])[0]
    if not host or not port:
        raise ValueError(f"ссылка без server/port: {link!r}")
    return host.strip(), int(port)


def normalize(source: Any) -> List[Tuple[Any, str, int]]:
    """Приводит вход к списку ``(id, host, port)``.

    Понимает:
      * str — путь к файлу (если файл есть) либо текст со ссылками/строками;
      * dict ``{id: прокси}`` — то, что отдаёт ``ProxyDatabase.get_parsed``;
      * список/генератор прокси: dict, кортеж ``(host, port)`` или ``'host:port'``;
      * JSON-объекты по одной на строку — такой вывод даёт
        ``python -m ProxyDatabase --list``, его же можно скормить сюда.

    У записей без своего id проставляется порядковый номер с 1 — такой же,
    как ``AUTOINCREMENT`` в базе, поэтому его можно не выдумывать на стороне
    вызова.
    """
    if hasattr(source, "read"):                      # файловый объект
        source = source.read()

    if isinstance(source, (str, bytes)):
        text = source.decode("utf-8", "replace") if isinstance(source, bytes) else source
        try:
            if os.path.isfile(text.strip()) and "\n" not in text.strip():
                with open(text.strip(), encoding="utf-8") as fh:
                    text = fh.read()
        except (OSError, ValueError):
            pass
        out = []
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("{"):
                # Строка от ProxyDatabase --list: {"id": 1, "server": "h:p"}
                try:
                    entry = json.loads(line)
                    host, port = _entry_to_hostport(entry)
                except (ValueError, TypeError, IndexError):
                    continue
                out.append((entry.get("id", n), host, port))
                continue
            try:
                host, port = _link_hostport(line) if "://" in line \
                    else _split_hostport(line)
            except (ValueError, IndexError):
                continue
            out.append((n, host, port))
        return out

    out = []
    if isinstance(source, Mapping):
        items = source.items()
        for n, (key, value) in enumerate(items, 1):
            try:
                host, port = _entry_to_hostport(value)
            except (ValueError, TypeError, IndexError):
                continue
            out.append((key if key is not None else n, host, port))
        return out

    for n, value in enumerate(source or (), 1):
        raw_id = value.get("id") if isinstance(value, Mapping) else None
        try:
            host, port = _entry_to_hostport(value)
        except (ValueError, TypeError, IndexError):
            continue
        out.append((raw_id if raw_id is not None else n, host, port))
    return out


def ping_once(host: str, port: int, timeout_ms: int = TIMEOUT_MS) -> Optional[int]:
    """Одно TCP-соединение. Возвращает время в мс либо None.

    Оговорка: таймаут покрывает connect, но не резолвинг имени — DNS живёт
    по своим правилам и на медленном DNS может занять больше. На результат
    это почти не влияет: getaddrinfo отпускает GIL, поэтому потоки
    продолжают работать, а прокси без успешной попытки получают NoPing.
    """
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_ms / 1000.0):
            pass
    except OSError:
        return None
    return max(1, int(round((time.perf_counter() - start) * 1000.0)))


def _check_one(item: Tuple[Any, str, int], tries: int, timeout_ms: int,
               pause_ms: int, so_big_ms: int) -> Result:
    _id, host, port = item
    result: Result = {"id": _id, "server": f"{host}:{port}",
                      "ping_ms": None, "status": STATUS_NO_PING}
    ping = None
    for attempt in range(tries):
        if attempt:
            # Пауза перед повторной попыткой, а не порог результата: сеть
            # успевает «остыть», и один зависший ответ не портит замер.
            time.sleep(pause_ms / 1000.0)
        ping = ping_once(host, port, timeout_ms)
        if ping is not None:
            break
    if ping is None:
        return result
    result["ping_ms"] = ping
    result["status"] = STATUS_SO_BIG if ping > so_big_ms else STATUS_OK
    return result


def check(source: Any,
          tries: int = TRIES,
          timeout_ms: int = TIMEOUT_MS,
          pause_ms: int = PAUSE_MS,
          workers: int = WORKERS,
          so_big_ms: int = SO_BIG_MS,
          on_progress=None) -> List[Result]:
    """Проверяет прокси и возвращает вердикты в порядке завершения.

    :param source: путь к файлу, текст, dict ``{id: прокси}`` или список
        прокси — любой формат из :func:`normalize`.
    :param on_progress: ``(готово, всего, последний результат)``.

    Возвращает список словарей ``{"id", "server", "ping_ms", "status"}``,
    где status — ``ok``, ``NoPing`` или ``PingSoBig``.
    """
    items = normalize(source)
    total = len(items)
    if not total:
        return []
    results: List[Result] = []
    # max_workers не может быть нулевым, а 50 потоков на 3 прокси — лишнее.
    pool_size = max(1, min(workers, total))
    with ThreadPoolExecutor(max_workers=pool_size,
                            thread_name_prefix="tcp") as ex:
        futures = [ex.submit(_check_one, item, tries, timeout_ms,
                             pause_ms, so_big_ms) for item in items]
        for n, fut in enumerate(futures, 1):
            # Идём по списку futures, а не as_completed: порядок результатов
            # тогда совпадает с порядком входа, и вызывающий может сопоставить
            # их по позиции.
            try:
                result = fut.result()
            except Exception as exc:                # прокси не должен ронять всё
                item = items[n - 1]
                result = {"id": item[0], "server": f"{item[1]}:{item[2]}",
                          "ping_ms": None, "status": STATUS_NO_PING,
                          "error": f"{type(exc).__name__}: {exc}"}
            results.append(result)
            if on_progress:
                on_progress(n, total, result)
    return results