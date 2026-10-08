"""Разбор текста источников в объекты ``Proxy``.

Модуль ничего не знает про сеть и про базу: на входе текст страницы, на
выходе — список прокси. Порт io.autoconnector.engine.scan.ProxyParser.

Распознаёт формы, которые встречаются в публичных списках:
  * tg://proxy?server=..&port=..&secret=..   и https://t.me/proxy?…
  * tg://socks?server=..&port=..            и https://t.me/socks?…
  * свободная строка server=..&port=..&secret=..
  * голый host:port:secret  (MTProto, hex-секрет)
  * голый host:port        (SOCKS5)
  * JSON-объекты {"host":..,"port":..,"secret":..} в любом порядке полей
  * целой строкой http(s)://[user:pass@]host:port — web/HTTP-прокси
  * atob('…') и целиком base64-тело (V2Ray-подписки), с рекурсией до 3 уровней
"""

import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import unquote

URL_PROXY = re.compile(
    r"(?:tg://|https?://t\.me/|t\.me/)(proxy|socks)\?([^\s\"'<>)\]]+)", re.I)
PARAMS_MT = re.compile(
    r"server=([a-zA-Z0-9._\-]+)&(?:amp;)?port=(\d{1,5})"
    r"&(?:amp;)?secret=([A-Za-z0-9+/=_\-]+)", re.I)
BARE_MT = re.compile(
    r"(?<![\w.])([a-zA-Z0-9][a-zA-Z0-9.\-]{1,253}):(\d{1,5}):([0-9a-fA-F]{32,})(?![\w])")
BARE_HP = re.compile(
    r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"
    r":(\d{1,5})(?![\w:.])")
# Целой строкой http(s)://[user:pass@]host:port. Якорь по краям строки —
# намеренно: иначе из текста вроде «см. https://site.tld:8080/…» или
# markdown-ссылок рождаются ложные web-прокси.
WEB_LINE = re.compile(
    r"(?i)^(https?)://"
    r"(?:([A-Za-z0-9._~%+\-]{1,64})(?::([^@/\s]{0,64}))?@)?"
    r"((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})"
    r":(\d{1,5})/?$")
JSON_OBJ = re.compile(r"\{[^{}]{0,600}\}")
J_HOST = re.compile(
    r"\"(?:host|ip|server|address|addr)\"\s*:\s*\"([^\"]+)\"", re.I)
J_PORT = re.compile(r"\"port\"\s*:\s*\"?(\d{1,5})\"?", re.I)
J_SECRET = re.compile(r"\"secret\"\s*:\s*\"([^\"]*)\"", re.I)
ATOB = re.compile(r"atob\(\s*['\"]([A-Za-z0-9+/=_\-]{32,})['\"]\s*\)")
WHOLE_B64 = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")

MAX_DEPTH = 3
MAX_B64_BODY = 4 * 1024 * 1024

# Признаки страниц, по которым решает ``collecting.sources``:
# нужна ли прокрутка канала, пагинация форума или разбор inline-JS.
TME_CHANNEL = re.compile(r"(?i)https?://t\.me/s/[^/?#]+")
POST_ID = re.compile(r"data-post=\"[^/\"]+/(\d+)\"")
TOPIC_4PDA = re.compile(r"(?i)4pda\.to/forum/index\.php\?[^\s\"']*showtopic=\d+")
ST_OFFSET = re.compile(r"(?:&amp;|&|\?)st=(\d+)")
SCRIPT_SRC = re.compile(r"(?i)<script[^>]+\bsrc\s*=\s*[\"']([^\"']+)[\"']")


@dataclass
class Proxy:
    ptype: str            # "MTPROTO" | "SOCKS5" | "WEB"
    host: str
    port: int
    secret: Optional[str]  # None у SOCKS5; у WEB — "user:password"
    source: str            # URL источника — для происхождения

    def dedup_key(self) -> str:
        """Ключ дедупликации: тип|host:port|secret (регистр host и hex-secret не важен)."""
        s = self.secret.lower() if self.secret else ""
        return f"{self.ptype}|{self.host.lower()}:{self.port}|{s}"

    def link(self) -> str:
        """Ссылка для импорта: у WEB — сам http(s)://URL, у остальных tg://."""
        if self.ptype == "WEB":
            auth = f"{self.secret}@" if self.secret else ""
            return f"http://{auth}{self.host}:{self.port}"
        if self.ptype == "SOCKS5":
            return f"tg://socks?server={self.host}&port={self.port}"
        return f"tg://proxy?server={self.host}&port={self.port}&secret={self.secret}"

    def variant(self) -> str:
        """Вариант прокси: MTProto — по префиксу секрета (ee/dd), WEB — по авторизации."""
        if self.ptype == "WEB":
            return "http-auth" if self.secret else "http"
        if self.ptype == "MTPROTO" and self.secret:
            s = self.secret.lower()
            if s.startswith("ee"):
                return "FakeTLS"
            if s.startswith("dd"):
                return "padded"
        return "classic"

    def to_md_line(self) -> str:
        link = f"- `{self.link()}`"
        ident = f"**{self.ptype}** `{self.host}:{self.port}`"
        if self.ptype == "WEB":
            sec = (f"auth `{self.secret}` ({self.variant()})" if self.secret
                   else "без авторизации")
        elif self.secret:
            sec = f"secret `{self.secret}` ({self.variant()})"
        else:
            sec = "без секрета (socks)"
        return f"{link}  |  {ident}  |  {sec}  |  _источник: {self.source}_"


_SECRET_LEAD = re.compile(r"^[A-Za-z0-9+/=_\-]+")
_HOST_LEAD = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?")
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")
_TLD = re.compile(r"^(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9\-]{2,59})$")
MIN_SECRET_LEN = 16

_B64_INV = [-1] * 128
for _i, _c in enumerate(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"):
    _B64_INV[ord(_c)] = _i
_B64_INV[ord("-")] = 62
_B64_INV[ord("_")] = 63


def b64decode(text: str) -> Optional[str]:
    """base64 без зависимостей: стандартный и URL-safe алфавит, padding не нужен."""
    if not text:
        return None
    buf = bytearray(len(text) * 3 // 4 + 3)
    out = 0
    accum = 0
    bits = 0
    for c in text:
        if c in "=\n\r \t":
            continue
        o = ord(c)
        if o >= 128:
            continue
        v = _B64_INV[o]
        if v < 0:
            continue
        accum = (accum << 6) | v
        bits += 6
        if bits >= 8:
            bits -= 8
            buf[out] = (accum >> bits) & 0xFF
            out += 1
    try:
        return bytes(buf[:out]).decode("utf-8", errors="replace")
    except Exception:
        return None


def is_ipv4(h: str) -> bool:
    m = _IPV4.match(h)
    return bool(m) and all(int(g) <= 255 for g in m.groups())


def is_hostname(h: str) -> bool:
    """Настоящее DNS-имя: есть точка, все лейблы валидны, TLD буквенный."""
    if not h or len(h) > 253 or "." not in h:
        return False
    labels = h.split(".")
    if not all(_LABEL.match(lb) for lb in labels):
        return False
    return bool(_TLD.match(labels[-1]))


def norm_secret(s: Optional[str]) -> Optional[str]:
    """Чистит секрет и приводит hex к нижнему регистру.

    В некоторых списках за полем secret тянется мусор (разделители, текст
    приписки) — он делает ссылку tg:// нерабочей, поэтому берём только
    ведущую последовательность допустимых символов. Секреты короче
    MIN_SECRET_LEN невозможны, значит это точно мусор — отбрасываем.
    """
    if not s:
        return None
    m = _SECRET_LEAD.match(s.strip())
    if not m:
        return None
    v = m.group(0)
    if len(v) < MIN_SECRET_LEN:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", v):
        return v.lower()
    return v


def norm_host(s: Optional[str]) -> Optional[str]:
    """Нормализует хост и отсекает мусор после него.

    В списках встречаются артефакты сбора: ``1.2.3.4|[текст``, хосты с
    завершающей точкой (``example.com.``), пустые лейблы (``a..b``) и
    целые строки-обрывки вроде ``In_Config_Tavasot_...Please.my.to.my.to``.
    Первые срезаются, последние отбрасываются: валидный прокси-хост — это
    либо IPv4, либо корректное DNS-имя.
    """
    if not s:
        return None
    s = s.strip()
    if not s or s.startswith(".") or ".." in s:
        return None
    s = s.rstrip(".")
    if not s:
        return None
    m = _HOST_LEAD.match(s)
    h = m.group(0) if m else None
    if not h or ".." in h:
        return None
    if is_ipv4(h) or is_hostname(h):
        return h
    return None


def qparam(query: str, key: str) -> Optional[str]:
    """Достаёт параметр из query-строки, понимая HTML-экранирование &amp;."""
    q = query.replace("&amp;", "&")
    for pair in q.split("&"):
        eq = pair.find("=")
        if eq <= 0:
            continue
        if pair[:eq].lower() == key.lower():
            return unquote(pair[eq + 1:], errors="replace")
    return None


def _port_ok(p: int) -> bool:
    return 0 < p <= 65535


def parse(text: str, source: str, bare_default: str = "SOCKS5",
          depth: int = 0) -> List[Proxy]:
    """Извлекает все прокси из произвольного текста."""
    out: List[Proxy] = []
    if not text or depth > MAX_DEPTH:
        return out

    # Исходник сохраняем: в inline-JS лежат atob('…') с полезной нагрузкой,
    # которые нельзя потерять вместе с блоком <script>.
    raw_text = text

    # Для HTML-страниц убираем inline <script>/<style> — там лежит код
    # приложений, а не данные. Это избавляет от ложных совпадений из
    # JS-кода (например, mtproto.cloud отдавал сервер/порт/секрет из
    # объявления переменной). Внешние скрипты (src=…) не трогаем — их
    # follow_scripts возьмёт отдельно.
    if depth == 0 and "<" in text and ("<script" in text.lower()
                                       or "<style" in text.lower()):
        text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1\s*>", " ", text)

    # 1) ссылки tg:// и t.me/
    for m in URL_PROXY.finditer(text):
        kind = m.group(1).lower()
        query = m.group(2)
        host = norm_host(qparam(query, "server") or qparam(query, "host"))
        port_s = qparam(query, "port")
        if not host or not port_s:
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        if not _port_ok(port):
            continue
        if kind == "socks":
            out.append(Proxy("SOCKS5", host, port, None, source))
            continue
        secret = norm_secret(qparam(query, "secret"))
        if not secret:
            # tg://proxy? с логином/паролем и без секрета — это SOCKS5
            if qparam(query, "user") or qparam(query, "pass"):
                out.append(Proxy("SOCKS5", host, port, None, source))
            continue
        out.append(Proxy("MTPROTO", host, port, secret, source))

    # 2) свободные строки server=&port=&secret=
    for m in PARAMS_MT.finditer(text):
        host = norm_host(m.group(1))
        if not host:
            continue
        try:
            port = int(m.group(2))
        except ValueError:
            continue
        if _port_ok(port):
            out.append(Proxy("MTPROTO", host, port,
                             norm_secret(m.group(3)), source))

    # 3) построчные голые формы
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "proxy?" in line or "socks?" in line:
            continue  # уже обработано выше
        m = WEB_LINE.match(line)
        if m:
            _scheme, user, password, raw_host, port_s = m.groups()
            host = norm_host(raw_host)
            if not host:
                continue
            try:
                port = int(port_s)
            except ValueError:
                continue
            if not _port_ok(port):
                continue
            # Логин/пароль у HTTP-прокси храним в secret — отдельных полей
            # для них в схеме БД нет.
            if user is None:
                auth = None
            elif password:
                auth = f"{user}:{password}"
            else:
                auth = user
            out.append(Proxy("WEB", host, port, auth, source))
            continue
        m = BARE_MT.search(line)
        if m:
            host = norm_host(m.group(1))
            if not host:
                continue
            try:
                port = int(m.group(2))
            except ValueError:
                continue
            if _port_ok(port):
                out.append(Proxy("MTPROTO", host, port,
                                 norm_secret(m.group(3)), source))
            continue
        m = BARE_HP.search(line)
        if m:
            host = norm_host(m.group(1))
            if not host:
                continue
            try:
                port = int(m.group(2))
            except ValueError:
                continue
            if _port_ok(port):
                out.append(Proxy(bare_default, host, port, None, source))

    # 4) JSON-объекты в любом порядке полей
    for m in JSON_OBJ.finditer(text):
        obj = m.group(0)
        mh = J_HOST.search(obj)
        mp = J_PORT.search(obj)
        if not mh or not mp:
            continue
        host = norm_host(mh.group(1))
        if not host:
            continue
        try:
            port = int(mp.group(1))
        except ValueError:
            continue
        if not _port_ok(port):
            continue
        ms = J_SECRET.search(obj)
        secret = norm_secret(ms.group(1)) if ms else None
        ptype = "MTPROTO" if secret else bare_default
        out.append(Proxy(ptype, host, port, secret, source))

    # 5) atob('…') — список спрятан в eval(atob(..)); ищем в исходнике,
    #    чтобы не потерять полезную нагрузку из inline-<script>
    for m in ATOB.finditer(raw_text):
        decoded = b64decode(m.group(1))
        if decoded:
            out.extend(parse(decoded, source, bare_default, depth + 1))

    # 6) тело целиком base64 — только если иначе ничего не нашли
    if not out and depth == 0:
        trimmed = text.strip()
        if 40 <= len(trimmed) <= MAX_B64_BODY and WHOLE_B64.fullmatch(trimmed):
            decoded = b64decode(trimmed)
            if decoded and decoded != trimmed:
                out.extend(parse(decoded, source, bare_default, depth + 1))

    return out