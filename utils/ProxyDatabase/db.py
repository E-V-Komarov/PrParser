"""Хранилище прокси: SQLite с пятью таблицами.

``ParsedProxy``
    Очередь: всё, что разобрано, но ещё не проверено. Здесь же по умолчанию
    остаются SOCKS5 — их TCP-не проверяют.

``ProxyTcpChecked``
    Ответившие по TCP: тип, адрес, порт, секрет и пинг в мс. Сюда попадают
    в основном MTProto ee/dd (FakeTLS и padded).

``ProxyBanned``
    Не ответившие по TCP: ``reason`` — ``NoPing`` или ``PingSoBig``.

``ProxyTdLibChecked``
    Ответившие по протоколу: те же поля плюс оба пинга — ``tcp_ping_ms`` из
    предыдущего этапа и ``tdlib_ping_ms`` из ``pingProxy``.

``ProxyTdLibBanned``
    Не ответившие по протоколу: ``tcp_ping_ms``, ``reason`` и ``message``.

Связка между этапами идёт по ``id``: TcpChecker и TdLibChecker возвращают
вердикты с теми же id, что были выданы в :meth:`Database.get_parsed` и
:meth:`Database.get_tcp_checked`.
"""

import os
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from utils.ProxyDatabase.parse import (BUCKET_SOCKS, BUCKETS, MTPROTO, SOCKS5, WEB,
                                 Record, dedup_key, parse_any, sort_key)
from utils.ProxyDatabase.parse import variant as variant_of

__all__ = ["Database", "PARSED_TABLE", "CHECKED_TABLE", "BANNED_TABLE",
           "TDLIB_CHECKED_TABLE", "TDLIB_BANNED_TABLE", "REASON_NO_PING",
           "REASON_SO_BIG", "DEFAULT_PATH", "VERDICT_TABLES", "ALL_TABLES"]

PARSED_TABLE = "ParsedProxy"
CHECKED_TABLE = "ProxyTcpChecked"
BANNED_TABLE = "ProxyBanned"
TDLIB_CHECKED_TABLE = "ProxyTdLibChecked"
TDLIB_BANNED_TABLE = "ProxyTdLibBanned"

# Таблицы с вердиктами: из них прокси уже не возвращается в очередь, поэтому
# повторная вставка такого прокси должна его игнорировать.
VERDICT_TABLES = (CHECKED_TABLE, BANNED_TABLE, TDLIB_CHECKED_TABLE,
                  TDLIB_BANNED_TABLE)
ALL_TABLES = (PARSED_TABLE,) + VERDICT_TABLES

REASON_NO_PING = "NoPing"
REASON_SO_BIG = "PingSoBig"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH = os.path.join(BASE_DIR, "proxy.sqlite3")

# UNIQUE по (тип, хост, порт, секрет). COLLATE NOCASE — регистр в ссылках
# гуляет, а прокси от этого не меняется.
SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {PARSED_TABLE} (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    type     TEXT NOT NULL,
    host     TEXT NOT NULL,
    port     INTEGER NOT NULL,
    secret   TEXT,
    variant  TEXT NOT NULL,
    added_at REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_parsed_proxy
    ON {PARSED_TABLE} (type, host COLLATE NOCASE, port,
                       IFNULL(secret, '') COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_parsed_variant ON {PARSED_TABLE} (variant);

CREATE TABLE IF NOT EXISTS {CHECKED_TABLE} (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    secret     TEXT,
    variant    TEXT,
    ping_ms    INTEGER NOT NULL,
    checked_at REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_tcp_checked
    ON {CHECKED_TABLE} (type, host COLLATE NOCASE, port,
                        IFNULL(secret, '') COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_tcp_checked_ping ON {CHECKED_TABLE} (ping_ms);

CREATE TABLE IF NOT EXISTS {BANNED_TABLE} (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    secret     TEXT,
    variant    TEXT,
    reason     TEXT NOT NULL,
    checked_at REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_banned
    ON {BANNED_TABLE} (type, host COLLATE NOCASE, port,
                       IFNULL(secret, '') COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_banned_reason ON {BANNED_TABLE} (reason);

CREATE TABLE IF NOT EXISTS {TDLIB_CHECKED_TABLE} (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    type          TEXT NOT NULL,
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    secret        TEXT,
    variant       TEXT,
    tcp_ping_ms   INTEGER NOT NULL,
    tdlib_ping_ms REAL NOT NULL,
    checked_at    REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_tdlib_checked
    ON {TDLIB_CHECKED_TABLE} (type, host COLLATE NOCASE, port,
                              IFNULL(secret, '') COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_tdlib_checked_ping
    ON {TDLIB_CHECKED_TABLE} (tdlib_ping_ms);

CREATE TABLE IF NOT EXISTS {TDLIB_BANNED_TABLE} (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    secret      TEXT,
    variant     TEXT,
    tcp_ping_ms INTEGER,
    reason      TEXT NOT NULL,
    message     TEXT,
    checked_at  REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_tdlib_banned
    ON {TDLIB_BANNED_TABLE} (type, host COLLATE NOCASE, port,
                             IFNULL(secret, '') COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_tdlib_banned_reason ON {TDLIB_BANNED_TABLE} (reason);
"""

# Индексы по variant создаются отдельно от SCHEMA: у базы, созданной до
# появления колонки, их нет, а CREATE INDEX по несуществующей колонке валит
# executescript. Поэтому сначала ALTER TABLE, потом индексы.
VARIANT_INDEXES = {
    PARSED_TABLE: "ix_parsed_variant",
    CHECKED_TABLE: "ix_tcp_checked_variant",
    TDLIB_CHECKED_TABLE: "ix_tdlib_checked_variant",
}

# Откуда выгружаем и по какому пингу сортируем.
EXPORT_SOURCES = {
    "tdlib": (TDLIB_CHECKED_TABLE, "tdlib_ping_ms"),
    "tcp": (CHECKED_TABLE, "ping_ms"),
}

# Хост и секрет храним в нижнем регистре: иначе один и тот же прокси,
# написанный в разном регистре, прошёл бы по UNIQUE дважды.
FIELDS = ("type", "host", "port", "secret")


def _row_key(row: sqlite3.Row) -> Tuple[str, str, int, str]:
    return (row["type"], (row["host"] or "").lower(), int(row["port"]),
            (row["secret"] or "").lower())


class Database:
    """Хранилище прокси. Одна таблица-очередь на входе, вердикты — на выходе.

        with Database() as db:
            db.insert_parsed("proxy.md")
            results = db.get_parsed("MtProtoClassic")
            db.apply_tcp_results(results)

    Соединение живёт вместе с объектом: держать его в модуле плохо —
    тогда библиотеку нельзя закрыть, а два прогона мешают друг другу.
    """

    def __init__(self, path: str = DEFAULT_PATH, timeout: float = 30.0):
        self.path = os.path.abspath(path)
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=timeout)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate_variant()

    # ---------- миграции ----------

    def _migrate_variant(self) -> None:
        """Добавляет колонку ``variant`` в таблицы вердиктов и заполняет её.

        ``SCHEMA`` идёт через ``CREATE TABLE IF NOT EXISTS``, поэтому на базе,
        созданной раньше, новых колонок в ней не будет. Вариант выводится из
        типа и секрета (префикс ``ee`` — FakeTLS, ``dd`` — padded), так что
        старые строки достраиваются, а не остаются пустыми.
        """
        for table in VERDICT_TABLES:
            columns = {row[1] for row in self.conn.execute(
                f"PRAGMA table_info({table})")}
            if "variant" not in columns:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN variant TEXT")
        self.conn.commit()

        for table in VERDICT_TABLES:
            missing = self.conn.execute(
                f"SELECT id, type, secret FROM {table} WHERE variant IS NULL"
            ).fetchall()
            if missing:
                self.conn.executemany(
                    f"UPDATE {table} SET variant=? WHERE id=?",
                    [(variant_of(row["type"], row["secret"]), row["id"])
                     for row in missing])
        self.conn.commit()

        for table, index in VARIANT_INDEXES.items():
            self.conn.execute(
                f"CREATE INDEX IF NOT EXISTS {index} ON {table} (variant)")
        self.conn.commit()

    # ---------- жизненный цикл ----------

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------- вход ----------

    def _known_keys(self) -> set:
        """Ключи всех прокси во всех таблицах.

        Загружаем один раз перед вставкой: проверка «а не было ли такого
        раньше» дешевле одним проходом, чем запросом на каждую строку.
        """
        keys = set()
        for table in ALL_TABLES:
            for row in self.conn.execute(
                    f"SELECT type, host, port, secret FROM {table}"):
                keys.add(_row_key(row))
        return keys

    def insert_parsed(self, source: Any) -> Dict[str, int]:
        """Кладёт прокси из файла/текста/списка в ``ParsedProxy``.

        Уже известные прокси (в очереди или в одном из вердиктов) и повторы
        внутри входа отбрасываются — «старые или существующие» не возвращаются.

        :returns: ``{"parsed", "known", "duplicates", "invalid"}``.
        """
        records, invalid = parse_any(source)
        seen = set()
        fresh: List[Record] = []
        for record in records:
            key = dedup_key(record)
            if key in seen:
                continue
            seen.add(key)
            fresh.append(record)

        known = self._known_keys()
        fresh = [r for r in fresh if dedup_key(r) not in known]
        skipped_known = len(seen) - len(fresh)

        now = time.time()
        before = self.conn.total_changes
        self.conn.executemany(
            f"INSERT OR IGNORE INTO {PARSED_TABLE} "
            "(type, host, port, secret, variant, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(r["type"], r["host"].lower(), int(r["port"]),
              (r["secret"] or "").lower() or None, r["variant"], now)
             for r in sorted(fresh, key=sort_key)])
        self.conn.commit()
        return {"parsed": self.conn.total_changes - before,
                "known": skipped_known,
                "duplicates": len(records) - len(seen),
                "invalid": invalid}

    # ---------- очередь на проверку ----------

    def get_parsed(self, bucket: Any = None,
                    limit: Optional[int] = None) -> Dict[Any, Dict[str, Any]]:
        """Отдаёт очередь проверки: ``{id: {...}}``.

        :param bucket: корзина из ``parse.BUCKETS`` (например ``"FakeTLS"``),
            список корзин через запятую (``"FakeTLS,padded"``) либо готовый
            список. Специальные значения: ``None`` — вся очередь, ``"*"`` —
            всё, кроме SOCKS5, ``"all"`` — все варианты, включая SOCKS5.
        """
        sql = (f"SELECT id, type, host, port, secret, variant "
               f"FROM {PARSED_TABLE}")
        where = ""
        params: List[Any] = []
        buckets = self._bucket_list(bucket)
        if buckets and "*" in buckets:
            # «*» — историческое «всё, кроме SOCKS5». Явная корзина Socks5
            # выбирает именно SOCKS5, поэтому ветка проверяет только «*».
            where = " WHERE type<>?"
            params.append(SOCKS5)
        elif buckets:
            unknown = [b for b in buckets if b not in BUCKETS]
            if unknown:
                raise ValueError(
                    f"неизвестные корзины: {', '.join(unknown)}; "
                    f"доступны: {', '.join(BUCKETS)}, *, all")
            where = " WHERE variant IN (%s)" % ",".join("?" * len(buckets))
            params.extend(buckets)
        sql += where
        sql += " ORDER BY id"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))

        out: Dict[Any, Dict[str, Any]] = {}
        for row in self.conn.execute(sql, params):
            item = {k: row[k] for k in ("type", "host", "port", "secret",
                                        "variant")}
            # server — готовая пара host:port, её понимает TcpChecker.
            item["server"] = f"{row['host']}:{row['port']}"
            out[row["id"]] = item
        return out

    @staticmethod
    def _bucket_list(bucket: Any) -> List[str]:
        """Приводит выбор корзин к списку имён; пустой список — вся очередь."""
        if bucket is None:
            return []
        if isinstance(bucket, str):
            items = [part.strip() for part in bucket.split(",")]
        elif isinstance(bucket, (list, tuple, set)):
            items = [str(part).strip() for part in bucket]
        else:
            items = [str(bucket).strip()]
        names = [item for item in items if item]
        if names and all(name.lower() == "all" for name in names):
            return []
        return names

    def get_tcp_checked(self, limit: Optional[int] = None,
                        skip_done: bool = True) -> Dict[Any, Dict[str, Any]]:
        """Очередь на проверку TDLib: ``{id: {...}}`` из ``ProxyTcpChecked``.

        Формат записи тот же, что у :meth:`get_parsed`, плюс ``tcp_ping_ms`` —
        его потом кладём в обе новые таблицы, чтобы по строке было видно, сколько
        стоил прокси по TCP и сколько стоит по протоколу.

        :param skip_done: не отдавать прокси, у которых уже есть вердикт
            TDLib. Без этого повторный прогон проверял бы одно и то же снова;
            вердикты лежат в отдельных таблицах, поэтому ``ProxyTcpChecked``
            остаётся полным журналом TCP-проверок.
        """
        params: List[Any] = []
        if skip_done:
            # Совпадение по тому же ключу, что и UNIQUE-индексы: тип, хост,
            # порт, секрет. Сравнение по id здесь не годится — id в таблицах
            # вердиктов свои.
            skip = " AND ".join(
                f"NOT EXISTS (SELECT 1 FROM {table} t "
                f"WHERE t.type=c.type AND t.host=c.host COLLATE NOCASE "
                "AND t.port=c.port "
                "AND IFNULL(t.secret,'')=IFNULL(c.secret,''))"
                for table in (TDLIB_CHECKED_TABLE, TDLIB_BANNED_TABLE))
            sql = (f"SELECT c.id, c.type, c.host, c.port, c.secret, c.variant, "
                   f"c.ping_ms FROM {CHECKED_TABLE} c WHERE {skip} ORDER BY c.id")
        else:
            sql = (f"SELECT id, type, host, port, secret, variant, ping_ms "
                   f"FROM {CHECKED_TABLE} ORDER BY id")
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))

        out: Dict[Any, Dict[str, Any]] = {}
        for row in self.conn.execute(sql, params):
            item = {k: row[k] for k in ("type", "host", "port", "secret",
                                        "variant")}
            item["server"] = f"{row['host']}:{row['port']}"
            item["tcp_ping_ms"] = row["ping_ms"]
            out[row["id"]] = item
        return out

    # ---------- вердикты ----------

    def _tcp_row(self, cur: sqlite3.Cursor, entry_id: Any) -> Optional[sqlite3.Row]:
        return cur.execute(
            f"SELECT type, host, port, secret, variant, ping_ms "
            f"FROM {CHECKED_TABLE} WHERE id=?", (entry_id,)).fetchone()

    def apply_tcp_results(self, results: Iterable[Mapping[str, Any]],
                          status_ok: str = "ok") -> Dict[str, int]:
        """Раскладывает результаты проверки и чистит очередь.

        ``ok`` → ``ProxyTcpChecked`` с пингом; ``NoPing``/``PingSoBig`` →
        ``ProxyBanned`` с этой же причиной. Строка убирается из
        ``ParsedProxy`` только вместе с записью вердикта, обе операции — в
        одной транзакции: сбой посередине не оставил бы прокси без ответа.

        :returns: ``{"checked", "banned", "unknown_id"}``.
        """
        tally = {"checked": 0, "banned": 0, "unknown_id": 0}
        now = time.time()
        cur = self.conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE")
            for item in results:
                _id = item.get("id")
                row = cur.execute(
                    f"SELECT type, host, port, secret, variant FROM {PARSED_TABLE} "
                    "WHERE id=?", (_id,)).fetchone()
                if row is None:
                    # Пришёл id, которого в очереди нет: уже обработан или
                    # база другая. Молча пропускать опасно — считаем явно.
                    tally["unknown_id"] += 1
                    continue
                status = item.get("status")
                ping = item.get("ping_ms")
                if status == status_ok and ping is not None:
                    cur.execute(
                        f"INSERT OR IGNORE INTO {CHECKED_TABLE} "
                        "(type, host, port, secret, variant, ping_ms, "
                        "checked_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (row["type"], row["host"], int(row["port"]),
                         row["secret"], row["variant"], int(ping), now))
                    tally["checked"] += 1
                else:
                    cur.execute(
                        f"INSERT OR IGNORE INTO {BANNED_TABLE} "
                        "(type, host, port, secret, variant, reason, "
                        "checked_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (row["type"], row["host"], int(row["port"]),
                         row["secret"], row["variant"],
                         status or REASON_NO_PING, now))
                    tally["banned"] += 1
                cur.execute(f"DELETE FROM {PARSED_TABLE} WHERE id=?", (_id,))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            cur.close()
        return tally

    def apply_tdlib_results(self, results: Iterable[Mapping[str, Any]],
                            status_ok: str = "ok") -> Dict[str, int]:
        """Раскладывает результаты TDLib по новым таблицам.

        ``ok`` → :data:`TDLIB_CHECKED_TABLE` с обоими пингами; всё остальное →
        :data:`TDLIB_BANNED_TABLE` с причиной и текстом ответа TDLib.

        Отличие от :meth:`apply_tcp_results`: ``ProxyTcpChecked`` не чистится.
        Это журнал TCP-проверок, а не очередь, — из него берётся ``tcp_ping_ms``,
        и он же остаётся историей. Повторные прогоны отсекает
        ``skip_done`` в :meth:`get_tcp_checked`.

        :returns: ``{"checked", "banned", "unknown_id"}``.
        """
        tally = {"checked": 0, "banned": 0, "unknown_id": 0}
        now = time.time()
        cur = self.conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE")
            for item in results:
                _id = item.get("id")
                row = self._tcp_row(cur, _id)
                if row is None:
                    tally["unknown_id"] += 1
                    continue
                status = item.get("status")
                ping = item.get("ping_ms")
                tcp_ping = row["ping_ms"]
                if status == status_ok and ping is not None:
                    cur.execute(
                        f"INSERT OR IGNORE INTO {TDLIB_CHECKED_TABLE} "
                        "(type, host, port, secret, variant, tcp_ping_ms, "
                        "tdlib_ping_ms, checked_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (row["type"], row["host"], int(row["port"]),
                         row["secret"], row["variant"],
                         int(tcp_ping) if tcp_ping is not None else None,
                         round(float(ping), 1), now))
                    tally["checked"] += 1
                else:
                    message = item.get("message")
                    cur.execute(
                        f"INSERT OR IGNORE INTO {TDLIB_BANNED_TABLE} "
                        "(type, host, port, secret, variant, tcp_ping_ms, "
                        "reason, message, checked_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (row["type"], row["host"], int(row["port"]),
                         row["secret"], row["variant"],
                         int(tcp_ping) if tcp_ping is not None else None,
                         status or REASON_NO_PING,
                         str(message) if message else None, now))
                    tally["banned"] += 1
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            cur.close()
        return tally

    # ---------- выгрузка ----------

    def export_rows(self, source: str = "tdlib",
                    buckets: Any = None,
                    limit: Optional[int] = None) -> List[Record]:
        """Проверенные прокси, отсортированные по пингу — для proxy.md.

        :param source: ``"tdlib"`` — ``ProxyTdLibChecked`` по протокольному
            пингу, ``"tcp"`` — ``ProxyTcpChecked`` по TCP. Первое честнее:
            протокольный пинг отличается от TCP-connect заметно.
        :param buckets: оставить только эти варианты (``None`` — все).
        """
        if source not in EXPORT_SOURCES:
            raise ValueError(f"неизвестный источник {source!r}; "
                             f"доступны: {', '.join(sorted(EXPORT_SOURCES))}")
        table, ping_column = EXPORT_SOURCES[source]
        sql = (f"SELECT type, host, port, secret, variant, "
               f"{ping_column} AS ping_ms FROM {table}")
        names = self._bucket_list(buckets)
        params: List[Any] = []
        if names:
            unknown = [name for name in names if name not in BUCKETS]
            if unknown:
                raise ValueError(
                    f"неизвестные корзины: {', '.join(unknown)}; "
                    f"доступны: {', '.join(BUCKETS)}")
            sql += " WHERE variant IN (%s)" % ",".join("?" * len(names))
            params.extend(names)
        # NULL-пинг в конец: сортировка по пингу должна оставлять «не измерили»
        # в хвосте, а не перемешивать их с самыми быстрыми.
        sql += " ORDER BY ping_ms IS NULL, ping_ms, host, port"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        return [dict(row) for row in self.conn.execute(sql, params)]

    # ---------- сводка ----------

    def counts(self) -> Dict[str, int]:
        """Сколько прокси в каждой таблице."""
        out = {}
        for table in ALL_TABLES:
            out[table] = self.conn.execute(
                f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return out

    def bucket_counts(self) -> Dict[str, int]:
        """Разбивка очереди по корзинам."""
        return {row[0]: row[1] for row in self.conn.execute(
            f"SELECT variant, COUNT(*) FROM {PARSED_TABLE} "
            "GROUP BY variant ORDER BY variant")}

    def reasons(self) -> Dict[str, int]:
        """Сколько забанено по каждой причине."""
        return {row[0]: row[1] for row in self.conn.execute(
            f"SELECT reason, COUNT(*) FROM {BANNED_TABLE} "
            "GROUP BY reason ORDER BY reason")}

    def variant_counts(self, table: str) -> Dict[str, int]:
        """Сколько записей каждого варианта в таблице вердиктов."""
        if table not in ALL_TABLES:
            raise ValueError(f"неизвестная таблица {table!r}; "
                             f"доступны: {', '.join(ALL_TABLES)}")
        return {row[0]: row[1] for row in self.conn.execute(
            f"SELECT variant, COUNT(*) FROM {table} "
            "GROUP BY variant ORDER BY variant")}

    def tdlib_reasons(self) -> Dict[str, int]:
        """Сколько не прошло проверку TDLib по каждой причине."""
        return {row[0]: row[1] for row in self.conn.execute(
            f"SELECT reason, COUNT(*) FROM {TDLIB_BANNED_TABLE} "
            "GROUP BY reason ORDER BY reason")}

    def ping_stats(self) -> Dict[str, Any]:
        """Сводка по пингам проверенных: минимум, медиана, максимум."""
        row = self.conn.execute(
            f"SELECT COUNT(*) AS n, MIN(ping_ms) AS lo, MAX(ping_ms) AS hi, "
            f"AVG(ping_ms) AS avg FROM {CHECKED_TABLE}").fetchone()
        if not row["n"]:
            return {"count": 0}
        return {"count": row["n"], "min_ms": row["lo"], "max_ms": row["hi"],
                "avg_ms": round(row["avg"], 1)}

    def tdlib_ping_stats(self) -> Dict[str, Any]:
        """Сводка по TDLib-вердиктам: оба пинга и их разница.

        ``overhead_ms`` — насколько протокольная проверка дороже TCP-connect.
        Это и есть смысл двух этапов: TCP отсекает мёртвые адреса дёшево,
        TDLib показывает настоящую задержку до Telegram.
        """
        row = self.conn.execute(
            f"SELECT COUNT(*) AS n, "
            f"MIN(tdlib_ping_ms) AS lo, MAX(tdlib_ping_ms) AS hi, "
            f"AVG(tdlib_ping_ms) AS avg, AVG(tcp_ping_ms) AS tcp_avg, "
            f"AVG(tdlib_ping_ms - tcp_ping_ms) AS diff "
            f"FROM {TDLIB_CHECKED_TABLE}").fetchone()
        if not row["n"]:
            return {"count": 0}
        return {"count": row["n"],
                "min_ms": round(row["lo"], 1) if row["lo"] is not None else None,
                "max_ms": round(row["hi"], 1) if row["hi"] is not None else None,
                "avg_ms": round(row["avg"], 1) if row["avg"] is not None else None,
                "tcp_avg_ms": round(row["tcp_avg"], 1) if row["tcp_avg"] is not None else None,
                "overhead_ms": round(row["diff"], 1) if row["diff"] is not None else None}