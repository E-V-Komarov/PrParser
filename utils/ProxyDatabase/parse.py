"""Разбор входа базы: файл proxy.md, текст или готовые записи.

Пакет самодостаточен, поэтому разбор ссылок tg:// живёт здесь, а не
импортируется из ProxyParser: иначе «независимая» программа завязалась бы на
соседний пакет.

Понимаются те же формы, что и в выдаче ProxyParser:
  tg://proxy?server=..&port=..&secret=..
  tg://socks?server=..&port=..
  host:port:secret   (MTProto, hex-секрет)
  host:port          (SOCKS5)
  http(s)://[user:pass@]host:port   (WEB)
"""

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote

MTPROTO = "MTPROTO"
SOCKS5 = "SOCKS5"
WEB = "WEB"

# Корзины: во что складываются прокси одного вида. FakeTLS и padded
# отличаются от классического MTProto только префиксом секрета (ee/dd).
BUCKET_CLASSIC = "MtProtoClassic"
BUCKET_FAKETLS = "FakeTLS"
BUCKET_PADDED = "padded"
BUCKET_SOCKS = "Socks5"
BUCKET_WEB = "Web"
BUCKETS = (BUCKET_CLASSIC, BUCKET_FAKETLS, BUCKET_PADDED, BUCKET_SOCKS,
           BUCKET_WEB)

MIN_SECRET_LEN = 16
MAX_PORT = 65535

_HOST_LEAD = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?")
_SECRET_LEAD = re.compile(r"^[A-Za-z0-9+/=_\-]+")
_LINK = re.compile(
    # Без якоря на конце: после ссылки часто идёт мусор на той же строке
    # («secret=…, см. список»), и жёсткий конец строки терял бы прокси.
    r"^(?:tg://|https?://t\.me/)(proxy|socks)\?([^\s\"'<>)\]]+)", re.I)
_WEB = re.compile(r"^(https?)://(?:([^@/\s:]+)(?::([^@/\s]*))?@)?"
                  r"([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:]+\]):(\d{1,5})/?$")
# Выгрузка проекта — markdown-ссылки вида ``[host:port 120ms](tg://proxy?…)``,
# поэтому такую строку тоже надо понимать: иначе собственный proxy.md не
# читается обратно, а файл обмена должен работать в обе стороны.
_MD_LINK = re.compile(r"^\[[^\]]*\]\(\s*([^)\s]+)\s*\)[\s]*$")
_BARE_MT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9.\-]*):(\d{1,5}):"
                      r"([0-9a-zA-Z+/=_\-]{16,})$")
_BARE_HP = re.compile(r"^(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9][A-Za-z0-9.\-]*)"
                      r":(\d{1,5})$")

Record = Dict[str, Any]


def norm_host(host: Optional[str]) -> Optional[str]:
    """Хост без мусора после него; None — не похож на адрес."""
    if not host:
        return None
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or host.startswith(".") or ".." in host:
        return None
    host = host.rstrip(".")
    m = _HOST_LEAD.match(host)
    return m.group(0) if m else None


def norm_secret(secret: Optional[str]) -> Optional[str]:
    """Секрет без мусора; hex приводим к нижнему регистру."""
    if not secret:
        return None
    m = _SECRET_LEAD.match(secret.strip())
    if not m:
        return None
    value = m.group(0)
    if len(value) < MIN_SECRET_LEN:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return value.lower()
    return value


def norm_port(port: Any) -> Optional[int]:
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= MAX_PORT else None


def variant(ptype: str, secret: Optional[str]) -> str:
    """Корзина прокси: по типу и префиксу секрета."""
    if ptype == SOCKS5:
        return BUCKET_SOCKS
    if ptype == WEB:
        return BUCKET_WEB
    secret = (secret or "").lower()
    if secret.startswith("ee"):
        return BUCKET_FAKETLS
    if secret.startswith("dd"):
        return BUCKET_PADDED
    return BUCKET_CLASSIC


def tg_link(ptype: str, host: str, port: int,
            secret: Optional[str] = None) -> str:
    """Ссылка tg:// для записи — то, что понимает клиент Telegram.

    Секрет кладём как есть: допустимые символы (``0-9a-fA-Z+/_=-``) в URL
    ничего не ломают, а ``quote`` превратил бы ``+`` в ``%2B`` — во многих
    клиентах такая ссылка не открывается. Экранируем только то, что действительно
    разорвало бы параметр.
    """
    def clean(value: str) -> str:
        return (value.replace("&", "%26").replace("#", "%23")
                    .replace("?", "%3F").replace(" ", "%20")
                    .replace('"', "%22"))

    parts = ["server=%s" % clean(host), "port=%d" % int(port)]
    if ptype == SOCKS5:
        return "tg://socks?" + "&".join(parts)
    parts.append("secret=%s" % clean(secret or ""))
    return "tg://proxy?" + "&".join(parts)


def md_line(ptype: str, host: str, port: int, secret: Optional[str],
            ping_ms: Any) -> str:
    """Строка proxy.md: ``[server ping](tg://…)``.

    Текст ссылки — адрес и пинг в миллисекундах, чтобы в выгрузке было видно,
    какой прокси быстрее, ещё до того как его откроют.
    """
    server = "%s:%d" % (host, int(port))
    ping = "-" if ping_ms is None else "%.0f" % float(ping_ms)
    return "[%s %sms](%s)" % (server, ping, tg_link(ptype, host, port, secret))


def qparam(query: str, key: str) -> Optional[str]:
    """Достаёт параметр из query-строки ссылки.

    Свой разбор вместо ``parse_qs`` ради одной вещи: ``parse_qs`` считает
    ``+`` пробелом, а в ссылках Telegram секрет лежит base64 без
    экранирования, где ``+`` и ``/`` — обычные символы. Через parse_qs
    половина таких прокси молча выпадала.
    """
    query = query.replace("&amp;", "&")      # ссылки из HTML-страниц
    for pair in query.split("&"):
        eq = pair.find("=")
        if eq <= 0:
            continue
        if pair[:eq].lower() == key.lower():
            return unquote(pair[eq + 1:], errors="replace")
    return None


def make_record(ptype: str, host: str, port: int,
                secret: Optional[str] = None) -> Optional[Record]:
    """Единая точка нормализации: нечего принять — None."""
    host = norm_host(host)
    port = norm_port(port)
    if not host or not port:
        return None
    if ptype in (MTPROTO, SOCKS5):
        secret = norm_secret(secret)
        if ptype == MTPROTO and not secret:
            return None
    return {
        "type": ptype,
        "host": host,
        "port": port,
        "secret": secret or None,
        "variant": variant(ptype, secret),
    }


def parse_line(line: str) -> Optional[Record]:
    """Одна строка файла/текста → запись прокси либо None."""
    line = line.strip()
    if not line or line.startswith(("#", "//")):
        return None

    # Markdown-ссылка из нашей же выгрузки: разворачиваем до самой ссылки.
    wrapped = _MD_LINK.match(line)
    if wrapped:
        line = wrapped.group(1)

    m = _LINK.match(line)
    if m:
        kind = m.group(1).lower()
        query = m.group(2)
        host = qparam(query, "server") or qparam(query, "host") or ""
        port = norm_port(qparam(query, "port"))
        secret = qparam(query, "secret")
        if kind == "socks":
            return make_record(SOCKS5, host, port)
        return make_record(MTPROTO, host, port, secret)

    m = _WEB.match(line)
    if m:
        _scheme, user, password, host, port = m.groups()
        auth = None
        if user:
            auth = f"{user}:{password}" if password else user
        record = make_record(WEB, host, norm_port(port), auth)
        if record:                       # у WEB секрет хранится как user:pass
            record["secret"] = auth or None
            record["variant"] = variant(WEB, auth)
        return record

    m = _BARE_MT.match(line)
    if m:
        return make_record(MTPROTO, m.group(1), m.group(2), m.group(3))

    m = _BARE_HP.match(line)
    if m:
        return make_record(SOCKS5, m.group(1), m.group(2))

    return None


def parse_text(text: str) -> List[Record]:
    """Текст со ссылками или строками → список записей."""
    return [r for r in (parse_line(line) for line in text.splitlines()) if r]


def parse_any(source: Any) -> Tuple[List[Record], int]:
    """Файл (путь), текст, список строк или готовые dict-записи.

    Возвращает ``(записи, отброшено)``: молчать о битых строках нельзя —
    иначе пустой результат выглядит как «источник отдал пусто».
    """
    if isinstance(source, (str, bytes)):
        if isinstance(source, bytes):
            source = source.decode("utf-8", "replace")
        try:
            if "\n" not in source.strip() and source.strip():
                # utf-8-sig: с BOM от блокнота первая строка иначе не разбиралась.
                with open(source.strip(), encoding="utf-8-sig") as fh:
                    source = fh.read()
        except (OSError, ValueError):
            pass
        records: List[Record] = []
        bad = 0
        for line in source.splitlines():
            if not line.strip() or line.strip().startswith(("#", "//")):
                continue
            record = parse_line(line)
            if record:
                records.append(record)
            else:
                bad += 1
        return records, bad

    out: List[Record] = []
    bad = 0
    for item in source or ():
        if isinstance(item, str):
            record = parse_line(item)
        elif isinstance(item, dict):
            record = make_record(item.get("type") or MTPROTO,
                                 item.get("host") or item.get("server") or "",
                                 item.get("port"), item.get("secret"))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            record = make_record(item[3] if len(item) > 3 else MTPROTO,
                                 item[0], item[1], item[2] if len(item) > 2 else None)
        else:
            record = None
        if record:
            out.append(record)
        else:
            bad += 1
    return out, bad


def dedup_key(record: Record) -> Tuple[str, str, int, str]:
    """Ключ, по которому прокси считается тем же самым в базе."""
    return (record["type"], record["host"].lower(), int(record["port"]),
            (record["secret"] or "").lower())


def sort_key(record: Record) -> Tuple:
    return (record["type"], record["host"].lower(), record["port"],
            record["secret"] or "")