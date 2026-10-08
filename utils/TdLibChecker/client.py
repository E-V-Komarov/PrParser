"""Низкоуровневая работа с tdjson.dll: поиск библиотеки, клиент, pingProxy.

Самая ценная находка при разборе tdlib_project: TDLib умеет проверять прокси
самостоятельно методом ``pingProxy`` — он возвращает ``Seconds``, то есть
время отклика в секундах. Это и есть «tdlib-ping»: замер до прокси с
настоящим MTProto/SOCKS5-рукопожатием, а не просто TCP-connect.

Клиенту обязателен ``setTdlibParameters``, иначе TDLib на ``pingProxy``
не отвечает вовсе (проверено на 1.8.67: тишина, а не ошибка).
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import tempfile
import time
from ctypes import CDLL, c_char_p, c_double, c_int, c_void_p
from typing import Any, Dict, List, Optional

__all__ = [
    "TdLibClient",
    "build_proxy",
    "find_tdjson",
    "load_library",
    "missing_dependencies",
    "MTPROTO",
    "SOCKS5",
    "HTTP",
    "HTTPS",
]


def _pe_imports(path: str) -> List[str]:
    """Имена DLL из таблицы импортов PE-файла.

    Нужен, чтобы перечислить зависимости tdjson.dll: у сборок TDLib для
    Windows они лежат рядом с библиотекой, а не в System32, и без них
    ``CDLL`` падает с невнятным «Could not find module ... or one of its
    dependencies».
    """
    with open(path, "rb") as fh:
        data = fh.read()

    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return []
    coff = pe + 4
    n_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    # 0x20B — PE32+ (x64), 0x10B — PE32. Смещение каталогов различается.
    data_dirs = opt + (112 if struct.unpack_from("<H", data, opt)[0] == 0x20B
                       else 96)
    import_rva = struct.unpack_from("<I", data, data_dirs + 8)[0]
    if not import_rva:
        return []

    sections = []
    base = opt + opt_size
    for i in range(n_sections):
        head = base + i * 40
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, head + 8)
        sections.append((vaddr, max(vsize, rsize), raddr))

    def to_offset(rva: int) -> int:
        for vaddr, span, raddr in sections:
            if vaddr <= rva < vaddr + span:
                return raddr + (rva - vaddr)
        raise ValueError("rva вне секций: %#x" % rva)

    names: List[str] = []
    cursor = to_offset(import_rva)
    while True:
        entry = data[cursor:cursor + 20]
        if len(entry) < 20 or entry == b"\0" * 20:
            break
        name_rva = struct.unpack_from("<I", entry, 12)[0]
        if not name_rva:
            break
        start = to_offset(name_rva)
        names.append(data[start:data.index(b"\0", start)].decode("ascii", "replace"))
        cursor += 20
    return names

MTPROTO = "mtproto"
SOCKS5 = "socks5"
HTTP = "http"
HTTPS = "https"

# Кредены из tdlib_project/check_proxies_tdlib.py: для pingProxy авторизация
# не нужна, но TDLib требует непустые параметры.
DEFAULT_API_ID = 38961944
DEFAULT_API_HASH = "3ac4712d7e02d3f15aca1eb24ce92a42"

_PROXY_TYPES = {
    MTPROTO: "proxyTypeMtproto",
    SOCKS5: "proxyTypeSocks5",
    HTTP: "proxyTypeHttp",
    HTTPS: "proxyTypeHttps",
}


def find_tdjson(library_path: Optional[str] = None) -> str:
    """Ищет tdjson.dll.

    Порядок: явный аргумент -> переменная окружения TDLIB_PATH -> папка lib
    внутри пакета -> папка рядом с пакетом -> tdlib_project/ проекта ->
    текущий каталог. Если библиотека не найдена, в тексте ошибки перечислены
    все проверенные места.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    if library_path:
        candidates.append(library_path)
    env = os.environ.get("TDLIB_PATH")
    if env:
        candidates.append(env)
        candidates.append(os.path.join(env, "tdjson.dll"))
    candidates += [
        os.path.join(here, "lib", "tdjson.dll"),
        os.path.join(here, "tdjson.dll"),
        os.path.join(os.path.dirname(here), "tdlib_project", "tdjson.dll"),
        os.path.join(os.getcwd(), "tdlib_project", "tdjson.dll"),
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            return os.path.abspath(cand)
    raise FileNotFoundError(
        "Не найден tdjson.dll. Проверенные места: "
        + ", ".join(c for c in candidates if c)
        + ". Укажите путь через TDLIB_PATH или аргумент --tdlib."
    )


def build_proxy(kind: str, host: str, port: int,
                secret: Optional[str] = None) -> Dict[str, Any]:
    """Собирает объект proxy для TDLib из записи нашей базы.

    Секрет передаётся как есть: TDLib сам разбирает и hex-, и base64-варианты
    (в том числе fake-TLS на ``ee`` и padded на ``dd``).
    """
    type_name = _PROXY_TYPES.get(kind, _PROXY_TYPES[MTPROTO])
    ptype: Dict[str, Any] = {"@type": type_name}
    if type_name == "proxyTypeMtproto":
        ptype["secret"] = secret or ""
    else:
        # У socks5/http/https в схеме TDLib username и password — обязательные
        # поля, и пустой объект без них не проходит проверку: pingProxy отвечает
        # ошибкой на каждом таком прокси. Пустые строки означают анонимный доступ,
        # авторизация для pingProxy и не нужна.
        ptype["username"] = ""
        ptype["password"] = ""
    return {
        "@type": "proxy",
        "server": host,
        "port": int(port),
        "type": ptype,
    }


def missing_dependencies(library_path: str) -> List[str]:
    """DLL, которых не хватает для загрузки ``library_path``.

    Windows ищет их только в системных папках и в папке самой библиотеки, а
    ctypes на нехватке сообщает дословно «or one of its dependencies» — не
    сказав, каких именно. Сборки TDLib для Windows обычно идут из MinGW и
    тянут за собой OpenSSL, zlib и libstdc++, которых в System32 нет.
    """
    try:
        needed = _pe_imports(library_path)
    except Exception:
        return []
    lib_dir = os.path.dirname(os.path.abspath(library_path))
    system = {d.lower() for d in os.listdir(os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32"))}
    absent = []
    for dll in needed:
        low = dll.lower()
        if low in system or os.path.isfile(os.path.join(lib_dir, dll)):
            continue
        absent.append(dll)
    return absent


def load_library(library_path: str):
    """Загружает tdjson.dll и объясняет нехватку зависимостей."""
    try:
        return CDLL(library_path)
    except OSError as exc:
        absent = missing_dependencies(library_path)
        if absent:
            raise OSError(
                "Не удалось загрузить %s: не хватает библиотек (%s). Положите их "
                "в ту же папку, что и tdjson.dll — %s"
                % (os.path.basename(library_path), ", ".join(absent),
                   os.path.dirname(os.path.abspath(library_path)))
            ) from exc
        raise


class TdLibClient:
    """Один клиент TDLib: создаётся, инициализируется, проверяет прокси, закрывается.

    Один клиент обрабатывает несколько одновременных ``pingProxy`` — ответы
    различаются по ``@extra``, поэтому события можно разводить по запросам.
    """

    def __init__(self, library_path: Optional[str] = None,
                 api_id: int = DEFAULT_API_ID, api_hash: str = DEFAULT_API_HASH,
                 use_test_dc: bool = False, log_verbosity: int = 0,
                 init_timeout: float = 20.0) -> None:
        self.library_path = find_tdjson(library_path)
        self._lib = load_library(self.library_path)
        self._lib.td_create_client_id.restype = c_int
        self._lib.td_create_client_id.argtypes = []
        self._lib.td_receive.restype = c_char_p
        self._lib.td_receive.argtypes = [c_double]
        self._lib.td_send.restype = None
        self._lib.td_send.argtypes = [c_int, c_char_p]
        self._lib.td_execute.restype = c_char_p
        self._lib.td_execute.argtypes = [c_char_p]
        # tdjson выделяет память под каждый ответ и отдаёт её нам во владение.
        # Без освобождения длинный прогон течёт, поэтому free есть везде.
        if hasattr(self._lib, "td_free"):
            self._lib.td_free.restype = None
            self._lib.td_free.argtypes = [c_void_p]
            self._has_free = True
        else:
            self._has_free = False

        self._counter = 0
        self._tempdirs: List[str] = []
        self.closed = False
        self._execute({"@type": "setLogVerbosityLevel", "new_verbosity_level": log_verbosity})
        self._client_id = self._lib.td_create_client_id()
        self._init(api_id, api_hash, use_test_dc, init_timeout)

    # --- внутреннее -----------------------------------------------------

    def _execute(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raw = self._lib.td_execute(json.dumps(query).encode("utf-8"))
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        finally:
            if self._has_free:
                self._lib.td_free(c_void_p(raw))

    def _init(self, api_id: int, api_hash: str, use_test_dc: bool,
              timeout: float) -> None:
        workdir = tempfile.mkdtemp(prefix="tdlib_checker_")
        self._tempdirs.append(workdir)
        params = {
            "@type": "setTdlibParameters",
            "use_test_dc": use_test_dc,
            "api_id": api_id,
            "api_hash": api_hash,
            "system_language_code": "ru",
            "device_model": "Desktop",
            "system_version": "Windows",
            "application_version": "1.0",
            "enable_storage_optimizer": True,
            "use_file_database": False,
            "use_message_database": False,
            "use_secret_chats": False,
            "database_directory": workdir,
            "files_directory": workdir,
        }
        response = self.request(params, timeout)
        if response is None or response.get("@type") != "ok":
            message = "нет ответа" if response is None else json.dumps(response, ensure_ascii=False)
            raise RuntimeError("Не удалось инициализировать клиент TDLib: " + message)

    def _drain(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.receive(max(0.0, deadline - time.monotonic())) is None:
                break

    # --- публичное ------------------------------------------------------

    def send(self, query: Dict[str, Any]) -> str:
        """Отправляет запрос и возвращает его ``@extra`` для сопоставления."""
        if self.closed:
            raise RuntimeError("Клиент TDLib уже закрыт")
        self._counter += 1
        extra = "tdc-%d-%d" % (self._client_id, self._counter)
        payload = dict(query)
        payload["@extra"] = extra
        self._lib.td_send(self._client_id, json.dumps(payload).encode("utf-8"))
        return extra

    def receive(self, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Забирает одно событие; ``None`` означает «пока тишина»."""
        raw = self._lib.td_receive(max(0.0, timeout))
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        finally:
            if self._has_free:
                self._lib.td_free(c_void_p(raw))

    def request(self, query: Dict[str, Any],
                timeout: float = 20.0) -> Optional[Dict[str, Any]]:
        """Отправляет запрос и ждёт именно его ответа, не теряя чужие события."""
        extra = self.send(query)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            event = self.receive(min(remaining, 1.0))
            if event is not None and event.get("@extra") == extra:
                return event

    def ping(self, proxy: Dict[str, Any]) -> str:
        """Стартует проверку прокси и возвращает ``@extra`` для ожидания ответа."""
        return self.send({"@type": "pingProxy", "proxy": proxy})

    def close(self) -> None:
        """Закрывает клиент и удаляет его временную базу."""
        if self.closed:
            return
        self.closed = True
        try:
            self.send({"@type": "close"})
            self._drain(0.5)
        except Exception:
            pass
        for path in self._tempdirs:
            shutil.rmtree(path, ignore_errors=True)
        self._tempdirs = []

    def __enter__(self) -> "TdLibClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()