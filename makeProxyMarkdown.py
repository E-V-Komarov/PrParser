"""Выгрузка проверенных прокси в Markdown и HTML."""

import argparse
import html
import os
import re
import sys

from utils.ProxyDatabase import (
    BUCKETS,
    DEFAULT_PATH,
    TDLIB_CHECKED_TABLE,
    Database,
    md_line,
)

DEFAULT_OUT = "proxy.md"

# Формат строки, создаваемой md_line:
# [подпись](tg://proxy?...)
MARKDOWN_LINK_RE = re.compile(r"^\[(.*)\]\((tg://.*)\)$")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="makeProxyMarkdown",
        description="Собрать Markdown- и HTML-файлы с прокси, прошедшими TDLib.",
    )
    ap.add_argument(
        "--db",
        default=DEFAULT_PATH,
        metavar="PATH",
        help="файл базы (по умолчанию %s)" % DEFAULT_PATH,
    )
    ap.add_argument(
        "--out",
        default=DEFAULT_OUT,
        metavar="FILE",
        help="имя Markdown-файла (по умолчанию %s; HTML получит такое же имя с расширением .html)"
        % DEFAULT_OUT,
    )
    ap.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="оставить только N самых быстрых прокси",
    )
    ap.add_argument(
        "--bucket",
        metavar="NAMES",
        help="только эти варианты, через запятую: %s (по умолчанию все)"
        % ", ".join(BUCKETS),
    )
    return ap


def make_markdown_line(row) -> str:
    return md_line(
        row["type"],
        row["host"],
        row["port"],
        row["secret"],
        row["ping_ms"],
    )


def markdown_line_to_html_item(line: str) -> str:
    match = MARKDOWN_LINK_RE.match(line)
    if not match:
        raise ValueError(
            "md_line вернул строку неожиданного формата: %s" % line
        )

    label, url = match.groups()
    return '<li><a href="%s">%s</a></li>' % (
        html.escape(url, quote=True),
        html.escape(label),
    )


def write_html(path: str, markdown_lines) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("<!doctype html>\n")
        fh.write('<html lang="ru">\n')
        fh.write("<head>\n")
        fh.write('  <meta charset="utf-8">\n')
        fh.write("  <title>Проверенные прокси</title>\n")
        fh.write("</head>\n")
        fh.write("<body>\n")
        fh.write("<ul>\n")

        for line in markdown_lines:
            fh.write(markdown_line_to_html_item(line))
            fh.write("\n")

        fh.write("</ul>\n")
        fh.write("</body>\n")
        fh.write("</html>\n")


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    args = build_parser().parse_args(argv)

    with Database(args.db) as db:
        try:
            rows = db.export_rows(
                "tdlib",
                buckets=args.bucket,
                limit=args.limit,
            )
        except ValueError as exc:
            print("Не удалось выбрать прокси: %s" % exc, file=sys.stderr)
            return 2

        total = db.conn.execute(
            "SELECT COUNT(*) FROM %s" % TDLIB_CHECKED_TABLE
        ).fetchone()[0]

    if not rows:
        print(
            "В %s нет прокси, прошедших TDLib — файлы не изменены"
            % TDLIB_CHECKED_TABLE
        )
        return 0

    markdown_lines = [make_markdown_line(row) for row in rows]

    # HTML-файл получает то же имя, что и Markdown, но расширение .html.
    html_out = os.path.splitext(args.out)[0] + ".html"

    directory = os.path.dirname(os.path.abspath(args.out))
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(markdown_lines) + "\n")

    write_html(html_out, markdown_lines)

    pings = [
        row["ping_ms"]
        for row in rows
        if row["ping_ms"] is not None
    ]

    by_variant = {}
    for row in rows:
        variant = row["variant"]
        by_variant[variant] = by_variant.get(variant, 0) + 1

    print("Готово: %d из %d прокси" % (len(rows), total))
    print("Markdown: %s" % os.path.abspath(args.out))
    print("HTML: %s" % os.path.abspath(html_out))

    if pings:
        print(
            "Пинг: %g..%g мс (средний %g)"
            % (min(pings), max(pings), sum(pings) / len(pings))
        )
    else:
        print("Пинг: нет данных")

    print(
        "По вариантам: %s"
        % ", ".join(
            "%s %d" % (name, count)
            for name, count in sorted(by_variant.items())
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
