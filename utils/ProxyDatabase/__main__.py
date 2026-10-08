"""``python -m utils.ProxyDatabase`` — загрузить список прокси в базу и
посмотреть сводку."""

import argparse
import json
import os
import sys

from utils.ProxyDatabase import BUCKETS, DEFAULT_PATH, Database
from utils.ProxyDatabase.parse import parse_any


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ProxyDatabase",
        description="Кладёт прокси из proxy.md (или строки) в ParsedProxy, "
                    "отбрасывая уже известные.",
    )
    ap.add_argument("source", nargs="?", metavar="FILE",
                    help="файл proxy.md или путь; без него читает stdin")
    ap.add_argument("--db", default=DEFAULT_PATH, metavar="PATH",
                    help="файл базы (по умолчанию %s)" % DEFAULT_PATH)
    ap.add_argument("--list", metavar="BUCKET",
                    help="показать очередь корзины: %s или * (всё кроме SOCKS)"
                         % ", ".join(BUCKETS))
    ap.add_argument("--limit", type=int, metavar="N",
                    help="ограничить количество строк в --list")
    ap.add_argument("--json", action="store_true",
                    help="сводка в JSON")
    return ap


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = build_parser().parse_args(argv)

    with Database(args.db) as db:
        if args.list:
            queue = db.get_parsed(args.list, limit=args.limit)
            for _id, item in queue.items():
                print(json.dumps({"id": _id, **item}, ensure_ascii=False))
            print("в очереди (%s): %d" % (args.list, len(queue)),
                  file=sys.stderr)
            return 0

        if args.source:
            report = db.insert_parsed(args.source)   # insert_parsed сам читает файл
        else:
            records, invalid = parse_any(sys.stdin.read())
            report = db.insert_parsed(records)
            report["invalid"] = invalid

        summary = {"insert": report, "counts": db.counts(),
                   "buckets": db.bucket_counts(), "reasons": db.reasons(),
                   "tdlib_reasons": db.tdlib_reasons(),
                   "ping": db.ping_stats(),
                   "tdlib_ping": db.tdlib_ping_stats()}
        if args.json:
            print(json.dumps(summary, indent=2, ensure_ascii=False))
        else:
            print("Добавлено: %(parsed)d | уже было: %(known)d | "
                  "дублей: %(duplicates)d | битых строк: %(invalid)d"
                  % report)
            print("В базе: ParsedProxy %(ParsedProxy)d | ProxyTcpChecked "
                  "%(ProxyTcpChecked)d | ProxyBanned %(ProxyBanned)d\n"
                  "TDLib: ProxyTdLibChecked %(ProxyTdLibChecked)d | "
                  "ProxyTdLibBanned %(ProxyTdLibBanned)d"
                  % summary["counts"])
            if summary["buckets"]:
                print("Очередь: " + ", ".join(
                    "%s %d" % (k, v) for k, v in summary["buckets"].items()))
            if summary["reasons"]:
                print("Забанировано: " + ", ".join(
                    "%s %d" % (k, v) for k, v in summary["reasons"].items()))
            if summary["tdlib_reasons"]:
                print("Забанировано TDLib: " + ", ".join(
                    "%s %d" % (k, v)
                    for k, v in summary["tdlib_reasons"].items()))
        print("Файл базы: " + os.path.abspath(args.db), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())