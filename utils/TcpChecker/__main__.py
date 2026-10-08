"""``python -m utils.TcpChecker`` — проверка списка прокси из файла или текста."""

import argparse
import sys
import time

from utils.TcpChecker import (PAUSE_MS, SO_BIG_MS, TIMEOUT_MS, TRIES, WORKERS,
                              check)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="TcpChecker",
        description="Проверяет прокси TCP-connect: %d попытки по %d мс, "
                    "пауза %d мс, %d потоков, порог PingSoBig %d мс."
                    % (TRIES, TIMEOUT_MS, PAUSE_MS, WORKERS, SO_BIG_MS),
    )
    ap.add_argument("source", nargs="?", default="-",
                    help="файл со списком прокси или - для stdin")
    ap.add_argument("-w", "--workers", type=int, default=WORKERS,
                    help="потоков (по умолчанию %d)" % WORKERS)
    ap.add_argument("--tries", type=int, default=TRIES,
                    help="попыток соединения (по умолчанию %d)" % TRIES)
    ap.add_argument("--timeout", type=int, default=TIMEOUT_MS,
                    help="таймаут попытки, мс (по умолчанию %d)" % TIMEOUT_MS)
    ap.add_argument("--pause", type=int, default=PAUSE_MS,
                    help="пауза перед повторной попыткой, мс "
                         "(по умолчанию %d)" % PAUSE_MS)
    ap.add_argument("--so-big", type=int, default=SO_BIG_MS,
                    help="порог PingSoBig, мс (по умолчанию %d)" % SO_BIG_MS)
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="только итог, без прогресса и строк по прокси")
    return ap


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = build_parser().parse_args(argv)

    source = sys.stdin.read() if args.source == "-" else args.source
    started = time.monotonic()

    def progress(done: int, total: int, last: dict) -> None:
        if args.quiet or done % 25 and done != total:
            return
        # Строки идут в stderr: так вывод можно перенаправить в файл,
        # оставив stdout чистым.
        print("[%d/%d] %s -> %s" % (done, total, last["server"],
                                     last["ping_ms"] or last["status"]),
              file=sys.stderr, flush=True)

    results = check(source,
                    tries=args.tries,
                    timeout_ms=args.timeout,
                    pause_ms=args.pause,
                    workers=args.workers,
                    so_big_ms=args.so_big,
                    on_progress=progress)

    tally = {}
    for r in results:
        tally[r["status"]] = tally.get(r["status"], 0) + 1
    if not args.quiet:
        for r in results:
            print("%s\t%s\t%s" % (r["id"], r["ping_ms"] or "-", r["status"]))
    print("Итого: %d | ok %d | NoPing %d | PingSoBig %d | %.1f с"
          % (len(results), tally.get("ok", 0), tally.get("NoPing", 0),
             tally.get("PingSoBig", 0), time.monotonic() - started),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())