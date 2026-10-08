"""ProxyDatabase — хранилище прокси в SQLite.

Таблицы:
    ``ParsedProxy``       очередь: тип, адрес, порт, секрет, корзина ``variant``.
                         Здесь остаются SOCKS5 — их по TCP не проверяют.
    ``ProxyTcpChecked``   ответившие: тип, адрес, порт, секрет, ``variant``,
                         ``ping_ms``. Сюда в основном попадают MTProto ee/dd.
    ``ProxyBanned``       не ответившие по TCP: ``variant``, ``reason`` =
                         ``NoPing`` / ``PingSoBig``.
    ``ProxyTdLibChecked`` ответившие по протоколу: оба пинга —
                         ``tcp_ping_ms`` и ``tdlib_ping_ms``, ``variant``,
                         плюс ``checked_at``.
    ``ProxyTdLibBanned``  не ответившие по протоколу: ``variant``,
                         ``tcp_ping_ms``, ``reason`` и ``message`` от TDLib.

Корзина ``variant`` — вид прокси: ``MtProtoClassic``, ``FakeTLS`` (секрет на
``ee``), ``padded`` (на ``dd``), ``Socks5``, ``Web``. Выводится из типа и
секрета, поэтому хранится во всех таблицах: по нему видно, какой вид дошёл до
проверки, не возвращаясь к очереди.

Принимает на вход файл ``proxy.md`` или строку с теми же ссылками и
отбрасывает всё, что уже есть в базе:

    from utils.ProxyDatabase import Database

    with Database() as db:
        db.insert_parsed("proxy.md")
        queue = db.get_parsed("all")         # {id: {...}} — все варианты
        db.apply_tcp_results(results)        # -> ProxyTcpChecked/Banned

Второй этап — проверка средствами TDLib по тому, что ответило по TCP:

        pending = db.get_tcp_checked()       # {id: {... tcp_ping_ms}}
        db.apply_tdlib_results(results)      # -> ProxyTdLibChecked/Banned

Готовое выгружается в markdown, отсортированным по пингу:

        rows = db.export_rows("tdlib")       # [{'type', 'host', ..., 'ping_ms'}]
        with open("proxy.md", "w", encoding="utf-8") as fh:
            fh.write("\\n".join(md_line(r["type"], r["host"], r["port"],
                                        r["secret"], r["ping_ms"])
                               for r in rows))
"""

from utils.ProxyDatabase.db import (ALL_TABLES, BANNED_TABLE, CHECKED_TABLE,
                              DEFAULT_PATH, EXPORT_SOURCES, PARSED_TABLE,
                              REASON_NO_PING, REASON_SO_BIG, TDLIB_BANNED_TABLE,
                              TDLIB_CHECKED_TABLE, VERDICT_TABLES, Database)
from utils.ProxyDatabase.parse import (BUCKET_CLASSIC, BUCKET_FAKETLS,
                                 BUCKET_PADDED, BUCKET_SOCKS, BUCKET_WEB,
                                 BUCKETS, MTPROTO, SOCKS5, WEB, dedup_key,
                                 md_line, parse_any, parse_line, parse_text,
                                 tg_link, variant)

__all__ = ["Database", "insert", "PARSED_TABLE", "CHECKED_TABLE",
           "BANNED_TABLE", "TDLIB_CHECKED_TABLE", "TDLIB_BANNED_TABLE",
           "VERDICT_TABLES", "ALL_TABLES", "EXPORT_SOURCES",
           "DEFAULT_PATH", "REASON_NO_PING", "REASON_SO_BIG",
           "BUCKETS", "BUCKET_CLASSIC", "BUCKET_FAKETLS", "BUCKET_PADDED",
           "BUCKET_SOCKS", "BUCKET_WEB", "MTPROTO", "SOCKS5", "WEB",
           "parse_any", "parse_text", "parse_line", "variant", "dedup_key",
           "tg_link", "md_line"]


def insert(source, path: str = DEFAULT_PATH) -> dict:
    """Разовая вставка файла/строки в базу. Для разовых задач и проверок.

    Основной сценарий — объект :class:`Database`: он держит соединение и
    позволяет вставить, прочитать очередь и записать вердикты подряд.
    """
    with Database(path) as db:
        return db.insert_parsed(source)