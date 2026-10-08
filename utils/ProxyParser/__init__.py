"""Пакет ProxyParser — самостоятельная программа сбора прокси Telegram.

Запуск как программа (пишет ``proxy.md``, одна ссылка ``tg://`` на строку)::

    python app.py
    python app.py -o out.md --no-anonymizers
    python app.py --json          # вместо файла — JSON в stdout

Запуск как библиотека (возвращает dict, готовый для ``json.dumps``)::

    from utils import ProxyParser
    data = ProxyParser.collect()
    print(data["count"], data["proxies"][0])

    # список прокси отдельно, без статистики
    ProxyParser.links(ProxyParser.collect_proxies())

Пакет самодостаточен: внутри лежат собственные ``config``, ``parsing``,
``collecting`` и ``utils``. Проверки TCP и SQLite здесь нет — только сбор
и дедупликация.
"""

import json
import os
import time
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional

from utils.ProxyParser import config
from utils.ProxyParser.collecting.collector import Collector
from utils.ProxyParser.parsing import Proxy
from utils.ProxyParser.utils.report import write_lines

__all__ = ["collect", "collect_proxies", "links", "to_json", "write_lines",
           "DEFAULT_OUT", "TG_PREFIX"]

DEFAULT_OUT = config.OUTPUT_FILE
TG_PREFIX = "tg://"


def links(proxies: Iterable[Proxy], only_tg: bool = True) -> List[str]:
    """Ссылки для импорта: отсортированные и без повторов.

    ``Proxy.link()`` для WEB-прокси даёт ``http://…``; такой ссылкой Telegram
    не импортирует, поэтому по умолчанию (``only_tg``) они отбрасываются.
    Сортировка по типу и адресу — повторный прогон даёт тот же файл.
    """
    ordered = sorted(proxies, key=lambda p: (p.ptype, p.host.lower(),
                                            p.port, p.secret or ""))
    out: List[str] = []
    seen = set()
    for p in ordered:
        link = p.link()
        if only_tg and not link.startswith(TG_PREFIX):
            continue
        if link in seen:
            continue
        seen.add(link)
        out.append(link)
    return out


def _scan(urls: Optional[Iterable[str]],
          concurrency: Optional[int],
          deadline: Optional[int],
          timeout: Optional[int],
          use_anonymizers: bool,
          log: Optional[Callable[[str], None]],
          on_progress: Optional[Callable[[int, int], None]],
          ) -> Collector:
    """Общий прогон сети. Возвращает наполненный :class:`Collector`."""
    pages = list(dict.fromkeys(urls if urls is not None
                               else config.DEFAULT_PAGES))

    # Сеть читает эти значения из config в момент запроса, поэтому правим
    # их на время прогона и возвращаем как было.
    saved = (config.TIMEOUT_TOTAL, config.SOURCE_DEADLINE)
    if timeout is not None:
        config.TIMEOUT_TOTAL = timeout
    if deadline is not None:
        config.SOURCE_DEADLINE = deadline

    coll = Collector(concurrency or config.CONCURRENCY,
                     use_anonymizers, log or (lambda msg: None))
    try:
        coll.run(pages, on_progress)
    finally:
        config.TIMEOUT_TOTAL, config.SOURCE_DEADLINE = saved
    return coll


def collect_proxies(urls: Optional[Iterable[str]] = None,
                    concurrency: Optional[int] = None,
                    deadline: Optional[int] = None,
                    timeout: Optional[int] = None,
                    use_anonymizers: bool = True,
                    only_tg: bool = True,
                    log: Optional[Callable[[str], None]] = None,
                    on_progress: Optional[Callable[[int, int], None]] = None,
                    ) -> List[str]:
    """Собирает прокси и возвращает готовые ссылки.

    Не трогает файлы и базу — только сеть.
    """
    coll = _scan(urls, concurrency, deadline, timeout, use_anonymizers,
                 log, on_progress)
    return links(coll.seen.values(), only_tg=only_tg)


def collect(urls: Optional[Iterable[str]] = None,
            concurrency: Optional[int] = None,
            deadline: Optional[int] = None,
            timeout: Optional[int] = None,
            use_anonymizers: bool = True,
            only_tg: bool = True,
            log: Optional[Callable[[str], None]] = None,
            on_progress: Optional[Callable[[int, int], None]] = None,
            ) -> Dict[str, Any]:
    """Собирает прокси и возвращает статистику со списком ссылок.

    Результат сериализуется в JSON без преобразований::

        {
          "count": 5956,
          "proxies": ["tg://proxy?server=…&port=…&secret=…", …],
          "types": {"MTPROTO": 5000, "SOCKS5": 956},
          "dropped_non_tg": 0,        # отброшенные http://-прокси
          "duplicates": 27000,
          "sources": {"total": 61, "ok": 40, "empty": 21, "no_new": 3},
          "elapsed_sec": 95.4,
          "generated_at": "2026-10-02T12:00:00+03:00"
        }

    :param urls: источники; по умолчанию ``config.DEFAULT_PAGES``.
    :param deadline: бюджет секунд на источник (по умолчанию из config).
    :param only_tg: оставить только ``tg://``-ссылки (WEB отбрасываются).
    :param on_progress: ``(источников готово, найдено прокси)``.
    """
    started = time.monotonic()
    coll = _scan(urls, concurrency, deadline, timeout, use_anonymizers,
                 log, on_progress)
    found = list(coll.seen.values())
    out = links(found, only_tg=only_tg)

    types: Dict[str, int] = {}
    for p in found:
        types[p.ptype] = types.get(p.ptype, 0) + 1

    return {
        "count": len(out),
        "proxies": out,
        "types": types,
        "dropped_non_tg": len(found) - len(out),
        "duplicates": coll.dupes,
        "sources": {
            "total": coll.total,
            "ok": len(coll.sources_ok),
            "empty": len(coll.sources_empty),
            "no_new": len(coll.sources_no_new),
        },
        "elapsed_sec": round(time.monotonic() - started, 1),
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def to_json(data: Dict[str, Any], indent: Optional[int] = None) -> str:
    """Тот же результат строкой JSON."""
    return json.dumps(data, indent=indent, ensure_ascii=False)