"""Дешифратор зашифрованных списков прокси (источники llimonix.dev).

Отдача — JSON-конверт, а не открытый список::

    {"v":1,"alg":"AES-GCM","iv":"<base64,12 байт>","ct":"<base64>"}

Ключ собирается на клиенте (в index.html, функции ``_0x4d``/``_0x7b``):

    пароль    = bytes([0x6d,0x74,0x39,0x31,0x7a,0x78,0x71])          # "mt91zxq"
    заготовка = base64(массив SEED: разворот, каждый байт минус 0x11)
    ключ      = заготовка XOR SHA-256(пароль)                          # 32 байта
    plaintext = AES-GCM.decrypt(iv, ct) без AAD

AAD не используется, поэтому ``decrypt`` вызывается с ``associated_data=None``.
"""

import base64
import binascii
import functools
import hashlib
import json
from typing import Any, Dict, List, Optional

PASSWORD = bytes([0x6d, 0x74, 0x39, 0x31, 0x7a, 0x78, 0x71])
SEED = [78, 116, 96, 107, 87, 98, 106, 70, 128, 93, 70, 119, 60, 101, 122, 67,
        139, 119, 123, 85, 125, 67, 100, 137, 121, 72, 114, 69, 117, 87, 84,
        115, 86, 120, 129, 116, 86, 117, 65, 136, 88, 117, 87, 85]
SEED_SHIFT = 0x11
# Сервер подписывает конверт как "A256GCM", хотя сам код сайта поле alg вообще
# не читает и всегда зовёт AES-GCM. Поэтому принимаем любую из этих меток.
ALG_ALIASES = {"AES-GCM", "A256GCM", "AES256GCM", "AESGCM", "AES_256_GCM"}
IV_LEN = 12


class DecryptError(Exception):
    """Конверт не похож на наш формат или ключ/IV не подошли."""


def _aesgcm(key: bytes):
    """AES-GCM из cryptography; при отсутствии — из pycryptodome."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key)
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise DecryptError("нет AES-GCM: установи cryptography или pycryptodome") from exc

    class _PyCryptoGCM:
        def __init__(self, k: bytes):
            self._key = k

        def decrypt(self, iv: bytes, ct: bytes, aad: Optional[bytes]) -> bytes:
            # pycryptodome требует AAD всегда, даже пустой.
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=iv,
                             mac_len=16)
            return cipher.decrypt_and_verify(ct, cipher.digest(aad or b""))

    return _PyCryptoGCM(key)


@functools.lru_cache(maxsize=1)
def derive_key() -> bytes:
    """32-байтный AES-ключ: заготовка из SEED XOR SHA-256(пароля)."""
    draft = base64.b64decode(
        "".join(chr((c - SEED_SHIFT) & 0xFF) for c in reversed(SEED)))
    digest = hashlib.sha256(PASSWORD).digest()
    if len(draft) != len(digest):
        raise DecryptError(f"заготовка ключа {len(draft)} байт, "
                           f"ожидалось {len(digest)}")
    return bytes(a ^ b for a, b in zip(draft, digest))


def _b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise DecryptError(f"поле не строка: {type(value).__name__}")
    try:
        raw = base64.b64decode(value, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise DecryptError(f"битый base64: {exc}") from exc
    if not raw:
        raise DecryptError("пустой base64")
    return raw


def decrypt_envelope(envelope: Dict[str, Any]) -> str:
    """Расшифровывает конверт в JSON-текст со списком прокси."""
    if not isinstance(envelope, dict):
        raise DecryptError("конверт не объект")
    alg = envelope.get("alg")
    if alg and str(alg).upper().replace("_", "-") not in ALG_ALIASES:
        raise DecryptError(f"неизвестный алгоритм: {alg}")
    iv = _b64(envelope.get("iv"))
    if len(iv) != IV_LEN:
        raise DecryptError(f"IV {len(iv)} байт, ожидалось {IV_LEN}")
    ct = _b64(envelope.get("ct"))
    try:
        plain = _aesgcm(derive_key()).decrypt(iv, ct, None)
    except DecryptError:
        raise
    except Exception as exc:
        raise DecryptError(f"AES-GCM не сошёлся: {exc}") from exc
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptError(f"не UTF-8 после расшифровки: {exc}") from exc


def decrypt_text(body: str) -> str:
    """Принимает тело ответа (строку или уже разобранный dict) и возвращает JSON."""
    envelope: Any = body
    if isinstance(body, (str, bytes, bytearray)):
        text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else body
        try:
            envelope = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DecryptError(f"ответ не JSON: {exc}") from exc
    plain = decrypt_envelope(envelope)
    json.loads(plain)  # проверяем, что внутри действительно список
    return plain


def decrypt_items(body: str) -> List[Dict[str, Any]]:
    """Конверт -> список словарей с прокси."""
    data = json.loads(decrypt_text(body))
    if isinstance(data, dict):
        for key in ("proxies", "data", "items", "list"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    return [d for d in data if isinstance(d, dict)]