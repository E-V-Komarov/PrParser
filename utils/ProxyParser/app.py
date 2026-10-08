"""ProxyParser — точка входа.

Как программа: ``python app.py`` пишет ``proxy.md`` — по одной ссылке
``tg://`` на строку. Как библиотека: ``import utils.ProxyParser`` отдаёт JSON.

    python app.py                                  # -> ProxyParser/proxy.md
    python app.py -o list.txt -c 16
    python app.py -u https://t.me/s/mtp4tg         # свой источник
    python app.py --no-anonymizers                 # быстрее, меньше результата
    python app.py --json --indent 2                # JSON в stdout вместо файла
    python app.py -q                               # без полосы прогресса

    python -m utils.ProxyParser --json             # то же из корня проекта

Требуется: pip install aiohttp tqdm
"""

import argparse
import os
import sys

# Запуск файла напрямую кладёт в sys.path только папку ProxyParser, а пакет
# живёт по пути utils.ProxyParser. Поэтому поднимаемся до корня проекта и
# импортируем пакет как обычно — одинаково для `python app.py`,
# `python -m utils.ProxyParser` и `import utils.ProxyParser`.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from utils.ProxyParser import DEFAULT_OUT, collect, to_json, write_lines  # noqa: E402
from utils.ProxyParser import config                                       # noqa: E402
from utils.ProxyParser.utils.stages import stage                           # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ProxyParser",
        description="Собирает уникальные прокси Telegram в список tg://, "
                    "по одному на строку.",
        epilog="Запущенный файл пишет proxy.md; импорт как библиотека "
               "возвращает JSON.",
    )
    ap.add_argument("-o", "--out", default=DEFAULT_OUT, metavar="FILE",
                    help=f"файл со списком (по умолчанию {DEFAULT_OUT})")
    ap.add_argument("-u", "--url", action="append", dest="urls", metavar="URL",
                    help="свой источник; можно указать несколько раз "
                         "(по умолчанию весь список из config)")
    ap.add_argument("-c", "--concurrency", type=int, metavar="N",
                    help="одновременных загрузок")
    ap.add_argument("-d", "--deadline", type=int, metavar="SEC",
                    help="бюджет секунд на один источник")
    ap.add_argument("-t", "--timeout", type=int, metavar="SEC",
                    help="таймаут одного запроса, сек")
    ap.add_argument("--no-anonymizers", action="store_true",
                    help="не ходить через обходные маршруты (быстрее, "
                         "меньше результат)")
    ap.add_argument("--keep-web", action="store_true",
                    help="оставить и http:// прокси (по умолчанию только "
                         "tg:// — Telegram импортирует только их)")
    ap.add_argument("--json", action="store_true",
                    help="напечатать JSON в stdout вместо записи файла")
    ap.add_argument("--indent", type=int, default=None, metavar="N",
                    help="отступ в JSON для читаемости")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="без полосы прогресса; логи остаются в logs/")
    return ap


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = build_parser().parse_args(argv)

    # Полосу прогресса и заголовок ведёт utils.stages — тот же, что и в
    # большом коллекторе. В --json режиме молчим: stdout должен содержать
    # только JSON, иначе его не разобрать.
    # Список собираем здесь же и с дедупликацией — ровно как это делает
    # collect(). Иначе на полосе стояло бы "61/?": число источников известно
    # только после того, как список сформирован.
    pages = list(dict.fromkeys(args.urls if args.urls
                               else config.DEFAULT_PAGES))

    def on_progress(done: int, found: int) -> None:
        st.bar.update(1)
        st.set_postfix(f"proxy: {found}",
                       refresh=st.bar.n % 5 == 0)

    with stage(1, "Сбор прокси", total=len(pages), unit="src",
               log_name="collect.log", quiet=args.quiet or args.json) as st:
        st.log(f"источников: {len(pages)}")
        data = collect(urls=pages,
                       concurrency=args.concurrency,
                       deadline=args.deadline,
                       timeout=args.timeout,
                       use_anonymizers=not args.no_anonymizers,
                       only_tg=not args.keep_web,
                       log=st.log,
                       on_progress=on_progress)
        st.close(f"уникальных {data['count']} | дублей "
                 f"{data['duplicates']} | источников с прокси "
                 f"{data['sources']['ok']} из {data['sources']['total']}")

    if args.json:
        print(to_json(data, indent=args.indent))
        return 0 if data["count"] else 1

    path = write_lines(args.out, data["proxies"])
    print(f"Записано прокси: {data['count']} -> {os.path.abspath(path)}")
    if data["dropped_non_tg"]:
        print(f"Отброшено не-tg (http): {data['dropped_non_tg']}")
    print(f"Время: {data['elapsed_sec']} с")
    return 0 if data["count"] else 1


if __name__ == "__main__":
    sys.exit(main())