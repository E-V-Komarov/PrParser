"""Конфигурация ProxyParser — самостоятельной программы сбора прокси.

Источники и обходные маршруты портированы из проекта
AutoConnector_for_Telegram (PageScanner.DEFAULT_PAGES, Mirrors.alternatives,
PageScanner.FETCH_PROXIES).

Отличие от конфига большого коллектора: здесь нет SQLite и этапа проверки
TCP, поэтому секций «проверка TCP» и путей к базе тоже нет. Пути считаются
от папки ProxyParser, то есть файл proxy.md появляется рядом с app.py.
"""

import os

# --- файлы ---

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "proxy.md")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# --- сеть ---

CONCURRENCY = 8          # одновременных загрузок (потоков)
TIMEOUT_TOTAL = 4        # полный таймаут запроса на один элемент, сек
TIMEOUT_CONNECT = 4
TIMEOUT_READ = 4
MAX_BODY = 8 * 1024 * 1024

# Бюджет времени на один источник. Нужен, потому что цепочка
# «зеркала × анонимайзеры × ретраи» упирается в десятки секунд: раньше
# источник без прокси мог держать пул пять минут, пока остальные отработали.
SOURCE_DEADLINE = 60     # сек на источник целиком, включая пагинацию

# --- ретраи ---
# Проверено 2026-09-28: web.archive.org — единственный живой обходной маршрут,
# но он троттлит (429) и периодически отдаёт 5xx, поэтому без ретраев он
# «мигает» между прогонами. Тот же карандаш у каталогов: 200 при ручном
# запросе, 403/503 после серии запросов к одному хосту.
HTTP_RETRIES = 4              # попыток на транзиентную ошибку
RETRY_BACKOFF = 1.6           # множитель паузы между попытками
RETRY_SLEEP = 2.0             # первая пауза, сек
RETRY_STATUSES = (408, 425, 429, 500, 502, 503, 504)

USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
)
ACCEPT = "*/*"

# --- пагинация ---

TME_SCROLL_PAGES = 8     # сколько раз подгрузить ?before=<id> у t.me/s/<channel>
TME_SCROLL_DELAY = 0.4   # пауза между запросами, сек
FORUM_LAST_PAGES = 5     # сколько последних страниц 4pda обойти
FORUM_PAGE_DELAY = 0.4
MAX_FOLLOW_SCRIPTS = 6   # сколько same-origin JS-бандлов скачать с HTML-страницы
MAX_SCRIPT_URLS = 40     # кандидатов <script src> до проверки на same-origin

# --- источники: HTML-каталоги ---

CATALOG_PAGES = [
    "https://free-telegram.link/",
    "https://tgstat.com/channel/@TURKMEN_VPNLAR",
]

# --- источники: каналы Telegram (превращаются в https://t.me/s/<канал>) ---
# "proxy_tm_unlimited" удалён 2026-09-28: канал жив, но веб-превью
# отдаёт 0 постов, скрапить нечего.

CHANNELS = [
    "ProXyMTproto",
    "TelMTProto",
    "MTProtoProxies",
    "proxymtproto",
    "mtp4tg",
    "TURKMEN_VPNLAR",
    "TProxyRU",
    "ProxyFreeMTProto",
    "mtprotoF",
    "mtproto6",
    "mtprotoproxy_telegaram",
    "MTProxy4free",
    "proxytgtestperiod1",
    "MTPROTO_MTPROXY_Telegram",
    "telega_proxies",
    "proxy_telegramo",
    "proxy_telegramt",
    "proxy_Telegram6",
    "tgmtproxylol",
    "ProxyMTProto",
    "mtpro_xyz",
]

# --- источники: веб-витрины каналов, отличные от t.me/s ---

TELEGRAM_MIRROR_PAGES = [
    "https://tgstat.com/channel/@TURKMEN_VPNLAR",
]

# --- источники прокси на GitHub ---
# Замены удалённых репозиториев (2026-09-28): Flowseala/Telegram-Proxy,
# Yagami200/free-mtproto-proxies, klondike0x/mtp4tg-proxies и
# MahsaNetConfigTopic/proxy больше не существуют — GitHub API и raw отдают
# 404. Прежние версии тянулись из web.archive.org, то есть из замороженных
# снапшотов — там лежат мёртвые прокси.

GITHUB_SOURCES = [
    "https://raw.githubusercontent.com/tgmtproxy/mtproxy/main/proxies.txt",
    "https://raw.githubusercontent.com/dubblebyte/free-mtproto-proxies/main/all_proxies.txt",
    "https://raw.githubusercontent.com/kubiknubika/my-tg-proxies/main/data/proxies.json",
    "https://raw.githubusercontent.com/Iliya3ProX/good_proxies/main/proxies.txt",
    "https://raw.githubusercontent.com/leshchenko1979/tgproxy/main/docs/proxies.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies-tested.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_us.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/refs/heads/main/proxy_all.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
    "https://raw.githubusercontent.com/Argh94/telegram-proxy-scraper/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/all.txt",
    "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no1.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no2.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no3.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no4.txt",
    "https://raw.githubusercontent.com/onlymeoneme/mtproto/refs/heads/main/all_proxies_list.txt",
    "https://raw.githubusercontent.com/iwh3n/tg-proxy/refs/heads/main/proxys/All_Proxys.txt",
    "https://raw.githubusercontent.com/weltimistar777-crypto/MTProxy/refs/heads/main/archives.txt",
    "https://raw.githubusercontent.com/weltimistar777-crypto/MTProxy/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/protocols/mtproto.txt",
    "https://raw.githubusercontent.com/darkvibez456/mtproto-proxy-auto/refs/heads/main/proxies.txt",
    "https://raw.githubusercontent.com/shablin/mtproto-proxy/refs/heads/main/data/valid_proxy.txt",
    "https://zakky8.github.io/mtproto-proxy-pro/all_proxies.txt",
    "https://zakky8.github.io/mtproto-proxy-pro/censorship_resistant.txt",
    "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_verified.txt",
    "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_tme_verified.txt",
    "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_eu_verified.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies.txt",
    "https://raw.githubusercontent.com/Telegram-FZ-LLC/Telegram-Proxy/refs/heads/main/proxies.txt",
]

# --- источники: форумы ---

FORUM_PAGES = [
    "https://4pda.to/forum/index.php?showtopic=1119405&st=9999999",
]

# --- источники: зашифрованные API (AES-GCM, см. parsing/crypto.py) ---
# Отдают {"v":1,"alg":"AES-GCM","iv":…,"ct":…}; ключ собирается на клиенте,
# так что список читается только тем же кодом, что и сайт (index.html).

ENCRYPTED_SOURCES = [
    "https://proxy-public.llimonix.dev/v1/public-proxies",
    "https://proxy-sponsor.llimonix.dev/v1/site-proxies",
]

# Порядок сохраняем, повторы убираем: один URL, попавший в две категории
# (например tgstat в CATALOG_PAGES и TELEGRAM_MIRROR_PAGES), не должен
# качаться дважды.
DEFAULT_PAGES = list(dict.fromkeys(
    CATALOG_PAGES
    + [f"https://t.me/s/{c}" for c in CHANNELS]
    + TELEGRAM_MIRROR_PAGES
    + GITHUB_SOURCES
    + FORUM_PAGES
    + ENCRYPTED_SOURCES))

# --- анонимайзеры: серверная загрузка целевого URL (label, prefix, urlencode) ---
# Порядок = приоритет. Проверено 2026-09-28: публичные CORS-сервисы массово
# отвечают 401/403/429/503, поэтому allorigins и Wayback — единственные
# реально живые маршруты. Остальные оставлены на случай, если сеть другая.

FETCH_PROXIES = [
    ("allorigins", "https://api.allorigins.win/raw?url=", True),
    ("codetabs", "https://api.codetabs.com/v1/proxy/?quest=", True),
    ("jina", "https://r.jina.ai/", False),
    ("corsproxy", "https://corsproxy.io/?url=", True),
    ("isomorphic", "https://cors.isomorphic-git.org/", False),
]

# --- зеркала для GitHub-ссылок (Mirrors.alternatives) ---

USE_GITHUB_MIRRORS = True     # jsDelivr, statically, kkgithub, ghproxy
USE_WAYBACK = True            # web.archive.org — последний рубеж