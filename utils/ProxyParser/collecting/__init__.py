"""Скачивание страниц-источников и разбор их содержимого.

Пакет состоит из трёх слоёв:

* :mod:`collecting.http` — низкий уровень: запрос по прямому маршруту,
  ретраи, обходные анонимайзеры. Ничего не знает про прокси.
* :mod:`collecting.sources` — один источник целиком: зеркала GitHub,
  Wayback, прокрутка канала t.me, пагинация 4pda, inline-JS, AES-GCM.
* :mod:`collecting.collector` — пул потоков поверх обоих слоёв.
"""

from utils.ProxyParser.collecting.collector import Collector
from utils.ProxyParser.collecting.sources import scan_page

__all__ = ["Collector", "scan_page"]