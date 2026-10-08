"""Конвейер: собрать → в базу → TCP → TDLib → выгрузить.

    python main.py                        # полный прогон из сети
    python main.py -f proxy.md            # взять готовый файл
    python main.py -f proxy.md -l 200     # проверить первые 200
    python main.py --no-tdlib             # только TCP, без TDLib
    python main.py -b FakeTLS,padded      # только эти варианты
    python main.py --export               # собрать proxy.md из базы

Программы не знают друг о друге: ProxyParser отдаёт список ссылок,
ProxyDatabase — словари очередей, TcpChecker и TdLibChecker — вердикты по id.
Связывает их точка входа, поэтому любой кусок можно заменить или запустить
отдельно.

Проверка двухслойная: TCP-connect дёшев и отсекает мёртвые адреса, а
``pingProxy`` TDLib меряет настоящую задержку до Telegram по протоколу. Поэтому
в базе и два вердикта подряд: ``ProxyTcpChecked`` и ``ProxyTdLibChecked``, у
обоих в ``ProxyTdLib*`` лежит пинг TCP.

Проверяются все варианты прокси: классический MTProto, FakeTLS (секрет на
``ee``), padded (``dd``) и SOCKS5. Вид хранится в колонке ``variant`` во всех
таблицах, поэтому по вердикту видно, что именно дошло до проверки.

``--export`` собирает из накопленного новый ``proxy.md``: строки
``[host:port пинг](tg://…)``, отсортированные по пингу, — от быстрых к
медленным. Работает и без проверки: базу можно пересобирать в выгрузку, не
гоняя сеть заново.
"""

import argparse
import os
import sys
import time
from typing import Dict, List

from utils import ProxyParser, TcpChecker, TdLibChecker
from utils.ProxyDatabase import (BUCKETS, CHECKED_TABLE, DEFAULT_PATH,
                             TDLIB_BANNED_TABLE, TDLIB_CHECKED_TABLE, Database,
                             md_line)
from utils.ProxyParser import config as parser_config
from utils.ProxyParser.utils.stages import stage

# Что проверяем по умолчанию: все варианты, SOCKS5 включительно. Раньше здесь
# стоял MtProtoClassic, и прогон либо упирался в пустую очередь, либо молча
# игнорировал ee/dd и SOCKS5, ради которых проект и писался.
BUCKET = "all"
EXPORT_FILE = "proxy.md"

# Сколько вердиктов TDLib копим перед записью в базу. Пачками, а не по одному:
# apply_tdlib_results открывает транзакцию на вызов, и на сотне тысяч строк это
# заметная часть времени. Слишком большой нельзя — теряется выгода от потока.
TDLIB_BATCH = 100

# Параметры проверки TDLib по умолчанию: клиентов, одновременных pingProxy и
# таймаут одного запроса. Значения те же, что у `python -m utils.TdLibChecker`.
TDLIB_CLIENTS = 4
TDLIB_INFLIGHT = 8
TDLIB_TIMEOUT = 15.0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Собрать прокси, записать в базу, проверить TCP и TDLib, "
                    "выгрузить proxy.md.")
    ap.add_argument("-f", "--file", metavar="FILE",
                    help="взять прокси из файла вместо сбора из сети")
    ap.add_argument("--db", default=DEFAULT_PATH, metavar="PATH",
                    help="файл базы (по умолчанию %s)" % DEFAULT_PATH)
    ap.add_argument("-l", "--limit", type=int, metavar="N",
                    help="проверить только первые N из очереди")
    ap.add_argument("-b", "--bucket", default=BUCKET, metavar="NAMES",
                    help="корзины на проверку через запятую: %s; "
                         "all — все варианты вместе с SOCKS5, "
                         "* — всё, кроме SOCKS5 (по умолчанию %s)"
                         % (", ".join(BUCKETS), BUCKET))
    ap.add_argument("-w", "--workers", type=int, default=TcpChecker.WORKERS,
                    help="потоков проверки (по умолчанию %d)" % TcpChecker.WORKERS)
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="без полос прогресса; логи остаются в logs/")
    ap.add_argument("--no-tdlib", action="store_true",
                    help="не проверять через TDLib, только TCP")
    ap.add_argument("--tdlib", metavar="PATH",
                    help="путь к tdjson.dll или к папке с ней "
                         "(иначе берётся TDLIB_PATH)")
    ap.add_argument("--tdlib-clients", type=int, default=TDLIB_CLIENTS,
                    metavar="N",
                    help="одновременных клиентов TDLib "
                         "(по умолчанию %d)" % TDLIB_CLIENTS)
    ap.add_argument("--tdlib-inflight", type=int, default=TDLIB_INFLIGHT,
                    metavar="N",
                    help="одновременных pingProxy "
                         "(по умолчанию %d)" % TDLIB_INFLIGHT)
    ap.add_argument("--tdlib-timeout", type=float, default=TDLIB_TIMEOUT,
                    metavar="SEC",
                    help="таймаут одного pingProxy, с "
                         "(по умолчанию %g)" % TDLIB_TIMEOUT)
    ap.add_argument("--tdlib-limit", type=int, metavar="N",
                    help="проверить через TDLib только первые N "
                         "из ProxyTcpChecked")
    ap.add_argument("--export", action="store_true",
                    help="выгрузить проверенные прокси в markdown, "
                         "отсортировав по пингу")
    ap.add_argument("--export-out", default=EXPORT_FILE, metavar="FILE",
                    help="куда выгружать (по умолчанию %s)" % EXPORT_FILE)
    ap.add_argument("--export-source", default="tdlib", choices=("tdlib", "tcp"),
                    help="откуда брать и по какому пингу сортировать: "
                         "tdlib — протокольный пинг (по умолчанию), "
                         "tcp — только TCP-connect")
    ap.add_argument("--export-bucket", metavar="NAMES",
                    help="выгрузить только эти варианты, через запятую "
                         "(по умолчанию все)")
    ap.add_argument("--export-limit", type=int, metavar="N",
                    help="оставить только N самых быстрых прокси")
    ap.add_argument("--only-export", action="store_true",
                    help="только выгрузить из базы, ничего не проверяя: "
                         "пересобрать proxy.md без похода в сеть")
    return ap


def export_md(db, args) -> int:
    """Шаг 6: выгрузка проверенных прокси в markdown, отсортированных по пингу.

    Строка выглядит как ``[1.2.3.4:443 120ms](tg://proxy?server=…)``: адрес и
    пинг видны в самом тексте, поэтому в выгрузке сразу понятно, что быстрее,
    а открывать ссылку для этого не нужно.

    :returns: код возврата для ``main`` либо ``None``, если всё в порядке.
    """
    try:
        rows = db.export_rows(args.export_source, buckets=args.export_bucket,
                              limit=args.export_limit)
    except ValueError as exc:
        print("Выгрузка не удалась: %s" % exc, file=sys.stderr)
        return 2
    if not rows:
        table = ("ProxyTdLibChecked" if args.export_source == "tdlib"
                 else CHECKED_TABLE)
        print("Выгружать нечего: в таблице %s нет подходящих записей" % table)
        return None

    lines = [md_line(row["type"], row["host"], row["port"], row["secret"],
                     row["ping_ms"]) for row in rows]
    path = args.export_out
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    pings = [row["ping_ms"] for row in rows if row["ping_ms"] is not None]
    by_variant: Dict[str, int] = {}
    for row in rows:
        by_variant[row["variant"]] = by_variant.get(row["variant"], 0) + 1
    print("Выгружено: %d прокси в %s (пинг %g..%g мс)"
          % (len(rows), os.path.abspath(path),
             min(pings) if pings else 0, max(pings) if pings else 0))
    print("По вариантам: %s" % ", ".join(
        "%s %d" % (name, count) for name, count in sorted(by_variant.items())))
    return None


def collect_proxies(args) -> str:
    """Шаг 1: получить прокси. Файл — или сбор из сети.

    Возвращает текст со ссылками: одинаково выглядит и proxy.md, и то, что
    отдаёт ``ProxyParser.collect()["proxies"]``.
    """
    if args.file:
        # utf-8-sig, а не utf-8: файл, сохранённый блокнотом, начинается с
        # BOM, и без него первая строка не распарсилась бы в прокси.
        with open(args.file, encoding="utf-8-sig") as fh:
            text = fh.read()
        print("Читаю %s: %d строк" % (args.file, text.count("\n")), flush=True)
        return text
    print("Собираю прокси из источников…", flush=True)
    pages = list(dict.fromkeys(parser_config.DEFAULT_PAGES))
    with stage(1, "Сбор прокси", total=len(pages), unit="src",
               log_name="collect.log", quiet=args.quiet) as st:
        st.log(f"источников: {len(pages)}")

        def on_progress(done: int, found: int) -> None:
            st.bar.update(1)
            st.set_postfix(f"прокси: {found}", refresh=done % 5 == 0)

        data = ProxyParser.collect(urls=pages, log=st.log,
                                   on_progress=on_progress)
        st.close("уникальных %d | дублей %d | источников с прокси %d из %d"
                 % (data["count"], data["duplicates"],
                    data["sources"]["ok"], data["sources"]["total"]))
    print("Собрано прокси: %d" % data["count"], flush=True)
    return "\n".join(data["proxies"])


def check_tdlib(db, args) -> int:
    """Шаг 5: проверка отвечавших по TCP средствами TDLib.

    Логика попыток та же, что у TcpChecker: TcpChecker.TRIES попыток с паузой
    PAUSE_MS и порогом SO_BIG_MS. Параллелизм задаётся клиентами TDLib, а не
    потоками Python: у каждого клиента своя очередь pingProxy.

    Вердикты идут в ProxyTdLibChecked / ProxyTdLibBanned вместе с пингом TCP,
    который лежит в ProxyTcpChecked.

    :returns: код возврата для ``main`` либо ``None``, если всё в порядке.
    """
    pending = db.get_tcp_checked(limit=args.tdlib_limit)
    if not pending:
        print("Нет непроверенных по TDLib — этап пропущен")
        return None

    try:
        library = TdLibChecker.find_tdjson(args.tdlib)
    except FileNotFoundError as exc:
        print("TDLib пропущен: %s" % exc, file=sys.stderr)
        print("Подсказка: скачайте tdjson.dll и укажите путь через "
              "--tdlib или переменную TDLIB_PATH.", file=sys.stderr)
        return 2

    print("Проверяю TDLib: %d прокси | клиентов %d | в работе %d | "
          "попыток %d"
          % (len(pending), args.tdlib_clients, args.tdlib_inflight,
             TcpChecker.TRIES), flush=True)

    # Поток вердиктов выдаётся по мере ответов, поэтому кладём их в базу пачками
    # и не держим весь результат в памяти: на большой базе это сотни тысяч строк.
    tally: Dict[str, int] = {}
    buffer: List[dict] = []

    def flush() -> None:
        if not buffer:
            return
        db.apply_tdlib_results(buffer)
        buffer.clear()

    with stage(3, "Проверка TDLib", total=len(pending), unit="proxy",
               log_name="tdlib.log", quiet=args.quiet) as st:
        st.log(f"TDLib: {library}")
        st.log(f"клиентов {args.tdlib_clients}, в работе "
               f"{args.tdlib_inflight}, попыток {TcpChecker.TRIES}")

        stream = TdLibChecker.stream(
            pending,
            clients=args.tdlib_clients,
            max_inflight=args.tdlib_inflight,
            timeout=args.tdlib_timeout,
            attempts=TcpChecker.TRIES,
            pause_ms=TcpChecker.PAUSE_MS,
            ping_max_ms=TcpChecker.SO_BIG_MS,
            library_path=library,
            on_result=None)

        for done, result in enumerate(stream, 1):
            st.bar.update(1)
            tally[result["status"]] = tally.get(result["status"], 0) + 1
            st.log("[%d/%d] %s -> %s" % (done, len(pending), result["server"],
                                         result["ping_ms"] or result["status"]))
            st.set_postfix("%s %s" % (result["server"],
                                      result["ping_ms"] or result["status"]),
                           refresh=done % 5 == 0)
            buffer.append(result)
            # Транзакция на каждый результат дорога, а на пачку — нет.
            if len(buffer) >= TDLIB_BATCH:
                flush()
        flush()
        st.close("ok %d | NoPing %d | PingSoBig %d"
                 % (tally.get(TdLibChecker.OK, 0),
                    tally.get(TdLibChecker.NO_PING, 0),
                    tally.get(TdLibChecker.PING_SO_BIG, 0)))

    counts = db.counts()
    print("TDLib: ok %d | забанено %d"
          % (counts[TDLIB_CHECKED_TABLE], counts[TDLIB_BANNED_TABLE]))
    print("Пинги: %s" % db.tdlib_ping_stats())
    if counts[TDLIB_BANNED_TABLE]:
        print("Забанено TDLib: %s" % db.tdlib_reasons())
    return None


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = build_parser().parse_args(argv)
    started = time.monotonic()

    # Шаг 1. Собрать прокси: файл proxy.md или результат ProxyParser.
    source = collect_proxies(args)

    # Шаг 2. Вписать в ParsedProxy. Уже известные (в очереди или в вердиктах)
    # отбрасываются — повторно их не проверяем.
    with Database(args.db) as db:
        report = db.insert_parsed(source)
        print("В очередь: +%d | уже было %d | дублей %d | битых строк %d"
              % (report["parsed"], report["known"], report["duplicates"],
                 report["invalid"]), flush=True)
        print("В базе: %s" % db.counts(), flush=True)

        # Шаг 3. Забрать из очереди то, что положим проверять, и прогнать TCP.
        # SOCKS5 остаются в очереди: по TCP они не проверяются.
        queue = db.get_parsed(args.bucket, limit=args.limit)
        if args.only_export:
            # Пересобрать выгрузку из накопленного: очередь не трогаем и в сеть
            # не идём, иначе пересборка proxy.md стоила бы полного прогона.
            print("Проверки пропущены (--only-export)")
        elif queue:
            print("Проверяю %d прокси (%s), потоков %d"
                  % (len(queue), args.bucket, args.workers), flush=True)

            # Полосу ведёт тот же stage: TcpChecker.check отдаёт on_progress
            # на каждый вердикт, поэтому полоса идёт по прокси, а postfix
            # показывает последний ответ — так видно, что проверка идёт,
            # а не висит.
            with stage(2, "Проверка TCP", total=len(queue), unit="proxy",
                       log_name="tcp.log", quiet=args.quiet) as st:
                st.log(f"корзина {args.bucket}, потоков {args.workers}")

                def progress(done: int, total: int, last: dict) -> None:
                    st.bar.update(1)
                    st.log("[%d/%d] %s -> %s"
                           % (done, total, last["server"],
                              last["ping_ms"] or last["status"]))
                    st.set_postfix("%s %s" % (last["server"],
                                              last["ping_ms"] or last["status"]),
                                   refresh=done % 5 == 0)

                results = TcpChecker.check(queue,
                                           workers=args.workers,
                                           so_big_ms=TcpChecker.SO_BIG_MS,
                                           on_progress=progress)
                by_status: Dict[str, int] = {}
                for r in results:
                    by_status[r["status"]] = by_status.get(r["status"], 0) + 1
                st.close("ok %d | NoPing %d | PingSoBig %d"
                         % (by_status.get(TcpChecker.STATUS_OK, 0),
                            by_status.get(TcpChecker.STATUS_NO_PING, 0),
                            by_status.get(TcpChecker.STATUS_SO_BIG, 0)))

            # Шаг 4. Разложить вердикты: ping -> ProxyTcpChecked,
            # NoPing/PingSoBig -> ProxyBanned. Очередь уменьшается на эти строки.
            tally = db.apply_tcp_results(results)
            print("Проверено: ok %d | забанено %d | неизвестных id %d"
                  % (tally["checked"], tally["banned"], tally["unknown_id"]))
            print("В базе: %s" % db.counts())
            print("Пинг: %s" % db.ping_stats())
            if args.limit:
                print("Осталось в очереди не проверенного: %d (--limit %d)"
                      % (db.counts()["ParsedProxy"], args.limit))
        else:
            # Корзина пуста — это не ошибка. Обычно значит, что ParsedProxy
            # уже разобран прошлым прогоном, а весь TCP лежит в
            # ProxyTcpChecked. Раньше тут стоял `return 1`, и повторный запуск
            # без новых ссылок до шага 5 не доходил — TDLib-проверку нельзя
            # было отложить на отдельный запуск.
            print("В корзине %s пусто — проверка TCP пропущена" % args.bucket)

        # Шаг 5. То, что ответило по TCP, проверяем по протоколу через TDLib.
        # Отдельно от шага 3: TDLib дороже и медленнее, а TCP-connect уже
        # отсёк мёртвые адреса.
        if not args.only_export and not args.no_tdlib:
            rc = check_tdlib(db, args)
            if rc is not None:
                return rc

        # Шаг 6. Выгрузка проверенного в markdown. Отдельный шаг и отдельный
        # флаг: выгрузка имеет смысл и без проверки — пересобрать proxy.md
        # из уже накопленной базы, не гоняя сеть заново.
        if args.export:
            rc = export_md(db, args)
            if rc is not None:
                return rc

    print("Готово за %.1f с | база: %s"
          % (time.monotonic() - started, os.path.abspath(args.db)))
    return 0


if __name__ == "__main__":
    sys.exit(main())