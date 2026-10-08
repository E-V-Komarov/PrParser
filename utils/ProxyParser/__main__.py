"""Позволяет запускать пакет как ``python -m utils.ProxyParser``.

Логика целиком в :mod:`utils.ProxyParser.app`, здесь только запуск.
"""

import sys

from utils.ProxyParser.app import main

if __name__ == "__main__":
    sys.exit(main())