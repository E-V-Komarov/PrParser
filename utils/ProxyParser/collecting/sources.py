"""Обработка одного источника: зеркала, Wayback, пагинация, inline-JS, AES-GCM.

Ключевое отличие от простой цепочки попыток — бюджет времени на источник
(:class:`Deadline`). Без него «пустой» список в��одит в полный перебор
зеркал × анонимайзеров × ретраев, и один источник тянет минуты, пока все
остальные давно отработали.
"""

import asyncio
import re
import time
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from utils.ProxyParser import config
from utils.ProxyParser.collecting.http import WAYBACK_PREFIX, Fetcher
from utils.ProxyParser.parsing import (POST_ID, SCRIPT_SRC, ST_OFFSET, TME_CHANNEL, TOPIC_4PDA,
                     Proxy, parse)
from utils.ProxyParser.parsing.crypto import DecryptError, decrypt_text

GH_RAW_REFS = re.compile(
    r"https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.+)")
GH_RAW = re.compile(
    r"https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)")
GH_BLOB = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/(?:raw|blob)/([^/]+)/(.+)")


class Deadline:
    """Бюджет времени на один источник.

    Проверяется и перед каждой попыткой, и как таймаут самого запроса:
    ``deadline.guard()`` обрезает ожидание по остатку бюджета, поэтому
    недоступный хост не может съесть минуты. По умолчанию —
    ``config.SOURCE_DEADLINE``.
    """

    def __init__(self, seconds: Optional[float] = None):
        self.total = config.SOURCE_DEADLINE if seconds is None else seconds
        self.started = time.monotonic()
        self.cut_off = False

    @property
    def left(self) -> float:
        return self.total - (time.monotonic() - self.started)

    def expired(self) -> bool:
        return self.left <= 0

    async def guard(self, coro):
        """Ждёт корутину, но не дольше остатка бюджета.

        None — бюджет кончился либо запрос не успел. Корутина при обрыве
        отменяется, соединение закрывается насильно.
        """
        left = self.left
        if left <= 0:
            coro.close()
            self.cut_off = True
            return None
        try:
            return await asyncio.wait_for(coro, timeout=left)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            self.cut_off = True
            return None


def alternatives(url: str) -> List[str]:
    """URL + зеркала, которые стоит попробовать по порядку."""
    out = [url]
    m = GH_RAW_REFS.match(url) or GH_RAW.match(url) or GH_BLOB.match(url)
    if m and config.USE_GITHUB_MIRRORS:
        user, repo, branch, path = m.groups()
        out.append(f"https://cdn.jsdelivr.net/gh/{user}/{repo}@{branch}/{path}")
        out.append(f"https://cdn.statically.io/gh/{user}/{repo}/{branch}/{path}")
        out.append(f"https://raw.kkgithub.com/{user}/{repo}/{branch}/{path}")
        out.append("https://ghproxy.com/https://raw.githubusercontent.com/"
                   f"{user}/{repo}/{branch}/{path}")
    if config.USE_WAYBACK:
        out.append(WAYBACK_PREFIX + url)
    return out


def _same_host(a: str, b: str) -> bool:
    a, b = (a or "").lower(), (b or "").lower()
    return a == b or a.endswith("." + b) or b.endswith("." + a)


async def fetch_many(fetcher: Fetcher, urls: List[str],
                     deadline: Deadline) -> List[Tuple[str, Optional[str]]]:
    """Конкурентная загрузка URL с обрезкой по бюджету. Пустой список — не успели."""
    if not urls:
        return []
    got = await deadline.guard(fetcher.get_many(urls))
    return got or []


async def scroll_tme(fetcher: Fetcher, page_url: str, body: str, route,
                     deadline: Deadline) -> str:
    """t.me/s/<канал> отдаёт ~20 последних постов; подгружаем более старые."""
    base = page_url.split("?")[0]
    cur = body
    parts = [body]
    seen_ids = set(POST_ID.findall(body))
    for _ in range(config.TME_SCROLL_PAGES):
        if deadline.expired():
            break
        ids = [int(m.group(1)) for m in POST_ID.finditer(cur)]
        if not ids:
            break
        min_id = min(ids)
        if min_id <= 1:
            break
        await asyncio.sleep(config.TME_SCROLL_DELAY)
        nxt = await deadline.guard(fetcher.get(f"{base}?before={min_id}", route))
        if not nxt:
            break
        # У Wayback нет снапшотов страниц ?before= — он отдаёт ту же выдачу.
        # Если новых постов нет, дальше идти бессмысленно.
        new_ids = set(POST_ID.findall(nxt)) - seen_ids
        if not new_ids:
            break
        seen_ids |= new_ids
        parts.append(nxt)
        cur = nxt
    return "\n".join(parts)


async def scroll_4pda(fetcher: Fetcher, page_url: str, body: str, route,
                      deadline: Deadline) -> str:
    """Исходный URL с st=9999999 открывает последнюю страницу; идём назад по степу."""
    offsets = sorted({int(m.group(1)) for m in ST_OFFSET.finditer(body)
                      if 0 <= int(m.group(1)) < 9_000_000})
    if not offsets:
        return body
    last = offsets[-1]
    gaps = [offsets[i + 1] - offsets[i] for i in range(len(offsets) - 1)
            if offsets[i + 1] > offsets[i]]
    step = min(gaps) if gaps else 20
    base = re.sub(r"(?i)(&amp;|&)st=\d+", "", page_url)
    sep = "&" if "?" in base else "?"
    parts = [body]
    for k in range(1, config.FORUM_LAST_PAGES):
        st = last - step * k
        if st < 0 or deadline.expired():
            break
        await asyncio.sleep(config.FORUM_PAGE_DELAY)
        nxt = await deadline.guard(fetcher.get(f"{base}{sep}st={st}", route))
        if not nxt:
            break
        parts.append(nxt)
    return "\n".join(parts)


async def follow_scripts(fetcher: Fetcher, html: str, page_url: str,
                         deadline: Deadline) -> List[Proxy]:
    """Список на JS-странице лежит в same-origin бандле — тянем и разбираем его."""
    try:
        host = urlparse(page_url).host or ""
    except Exception:
        return []
    urls: List[str] = []
    for m in SCRIPT_SRC.finditer(html):
        if len(urls) >= config.MAX_SCRIPT_URLS:
            break
        ref = m.group(1).replace("&amp;", "&")
        try:
            absolute = urljoin(page_url, ref)
            if _same_host(urlparse(absolute).host or "", host):
                urls.append(absolute)
        except Exception:
            continue
    found: List[Proxy] = []
    if not urls:
        return found
    # Бандлы независимы, тянем их пачкой: последовательно это ×N таймаутов.
    wanted = urls[:config.MAX_FOLLOW_SCRIPTS]
    for (url, js) in await fetch_many(fetcher, wanted, deadline):
        if js:
            found.extend(parse(js, url))
    return found


async def enrich(fetcher: Fetcher, page_url: str, body: str, route,
                 deadline: Deadline) -> str:
    """Дотягивает страницу: прокрутка канала или пагинация форума."""
    if TME_CHANNEL.fullmatch(page_url):
        return await scroll_tme(fetcher, page_url, body, route, deadline)
    if TOPIC_4PDA.search(page_url):
        return await scroll_4pda(fetcher, page_url, body, route, deadline)
    return body


async def extract(fetcher: Fetcher, body: str, page_url: str, via: str,
                  deadline: Deadline) -> List[Proxy]:
    """parse() основного тела; если пусто — same-origin <script src>."""
    found = parse(body, page_url)
    if not found and not deadline.expired():
        found = await follow_scripts(fetcher, body, via, deadline)
    return found


async def scan_encrypted(fetcher: Fetcher, page_url: str,
                         deadline: Deadline) -> Tuple[List[Proxy], str, str]:
    """Источник отдаёт AES-GCM конверт — сначала расшифровка, потом parse().

    Обходные маршруты тут бесполезны: анонимайзеры отдают ту же строку
    конверта, а зеркала GitHub к такому хосту неприменимы.
    """
    body = await deadline.guard(fetcher._get(page_url))
    if body is None:
        return [], page_url, "download failed"
    try:
        plain = decrypt_text(body)
    except DecryptError as exc:
        return [], page_url, f"decrypt failed: {exc}"
    found = parse(plain, page_url)
    if not found:
        return [], page_url, "no proxies parsed"
    return found, page_url, ""


async def scan_page(fetcher: Fetcher, page_url: str,
                    deadline: Optional[Deadline] = None) \
        -> Tuple[List[Proxy], str, str]:
    """Возвращает (прокси, реально сработавший URL, сообщение об ошибке).

    Зеркала GitHub проверяются конкурентно, а не по очереди: раньше цепочка
    «direct → jsDelivr → statically → kkgithub → ghproxy → Wayback» шла
    последовательно, и один недоступный хост стоил полный таймаут.
    """
    deadline = deadline or Deadline()
    if page_url in config.ENCRYPTED_SOURCES:
        return await scan_encrypted(fetcher, page_url, deadline)

    # Прямая загрузка первой: если хост жив, но отдал пустое тело, зеркала
    # того же репозитория тоже пустые и обход не нужен.
    used = page_url
    first = await deadline.guard(fetcher.get(page_url))
    if first == "":
        return [], page_url, "empty body"
    if first is None:
        # Прямой путь закрыт — зеркала и Wayback пробуем конкурентно.
        used, first = None, None
        for url, body in await fetch_many(fetcher, alternatives(page_url)[1:],
                                          deadline):
            if body and first is None:
                used, first = url, body
        if first is None:
            return [], page_url, ("budget exhausted" if deadline.cut_off
                                  else "download failed")

    route = fetcher.route_of(page_url, used)
    body = await enrich(fetcher, page_url, first, route, deadline)
    found = await extract(fetcher, body, page_url, used, deadline)
    if found:
        return found, used, ""

    # Часть сайтов отдаёт небраузерному клиенту JS-оболочку вместо страницы.
    # Зеркало / анонимайзер / снапшот часто возвращает полную разметку.
    seen_bodies = {first}
    rest = [a for a in alternatives(page_url) if a != used]
    for url, body in await fetch_many(fetcher, rest, deadline):
        if not body or body in seen_bodies or deadline.expired():
            continue
        seen_bodies.add(body)
        alt_route = fetcher.route_of(page_url, url)
        enriched = await enrich(fetcher, page_url, body, alt_route, deadline)
        found = await extract(fetcher, enriched, page_url, url, deadline)
        if found:
            return found, url, ""

    return [], page_url, "no proxies parsed"