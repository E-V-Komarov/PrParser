"""Запись результата: список ссылок tg:// в proxy.md.

Формат файла намеренно минимальный — одна ссылка на строку, без заголовков и
разметки: такой файл одинаково читается и клиентом Telegram, и скриптом,
который потом берёт строки по одному на прокси.
"""

import os
from typing import Iterable

__all__ = ["write_lines"]


def write_lines(path: str, proxies: Iterable[str]) -> str:
    """Пишет список ссылок в файл: одна строка — одна ссылка.

    Ссылок может быть много, поэтому файл перезаписывается целиком, а не
    дописывается в конец: повторный запуск не оставляет старые строки.
    """
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    # newline="\n" — иначе Windows напишет CRLF, а такие файлы часто
    # склеивают скрипты, читающие список построчно.
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for link in proxies:
            fh.write(link + "\n")
    return path