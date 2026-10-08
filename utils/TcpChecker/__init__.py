"""TcpChecker — проверка прокси по TCP-connect.

Библиотека:

    from utils import TcpChecker
    results = TcpChecker.check(proxies)      # файл, текст, dict или список
    for r in results:
        print(r["id"], r["ping_ms"] or r["status"])

Программа:

    python -m utils.TcpChecker proxy.md --workers 50
"""

from utils.TcpChecker.checker import (PAUSE_MS, SO_BIG_MS, STATUS_NO_PING,
                                STATUS_OK, STATUS_SO_BIG, TIMEOUT_MS, TRIES,
                                WORKERS, Result, check, normalize, ping_once)

__all__ = ["check", "normalize", "ping_once", "Result", "TRIES", "TIMEOUT_MS",
           "PAUSE_MS", "WORKERS", "SO_BIG_MS", "STATUS_OK", "STATUS_NO_PING",
           "STATUS_SO_BIG"]