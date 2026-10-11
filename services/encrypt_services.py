from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
from core.exceptions import DecryptionFailedError, InvalidCiphertextError, InvalidKeyError, InvalidNonceError

KEY_SIZES = (16, 24, 32)  # Dozwolone długości klucza AES w bajtach (128, 192, 256 bitów)
NONCE_SIZE = 12  # Zalecana długość nonce dla AES-GCM w bajtach
TAG_SIZE = 16  # Długość znacznika, który AES-GCM dokleja do szyfrogramu


def decode_key(key: str) -> bytes:
    try:
        key_bytes = base64.b64decode(key, validate=True)
    except ValueError as exc:
        raise InvalidKeyError() from exc

    if len(key_bytes) not in KEY_SIZES:
        raise InvalidKeyError()

    return key_bytes


def decode_nonce(nonce: str) -> bytes:
    try:
        nonce_bytes = base64.b64decode(nonce, validate=True)
    except ValueError as exc:
        raise InvalidNonceError() from exc

    if len(nonce_bytes) != NONCE_SIZE:
        raise InvalidNonceError()

    return nonce_bytes


def decode_ciphertext(ciphertext: str) -> bytes:
    try:
        ciphertext_bytes = base64.b64decode(ciphertext, validate=True)
    except ValueError as exc:
        raise InvalidCiphertextError() from exc

    if len(ciphertext_bytes) < TAG_SIZE:
        raise InvalidCiphertextError()

    return ciphertext_bytes


def generate_key() -> str:
    key = AESGCM.generate_key(bit_length=128) # <bytes> w postaci bezpiecznej b'1\x8cI\x1e\xddI...'

    key_base64 = base64.b64encode(key) # Kodujemy do <bytes> base64 czyli do ASCII b'MYxJHt1J9Fc+wILCe38I0Q=='

    key_string = key_base64.decode("utf-8") # Dekodujemy do <str> 'MYxJHt1J9Fc+wILCe38I0Q=='

    return key_string


def encrypt(password: str, key: str | None = None) -> dict[str, str]:

    if key is None:
        key_bytes = AESGCM.generate_key(bit_length=128)
    else:
        key_bytes = decode_key(key) # Zamieniamy <str> od użytkownika na surowe <bytes>

    aesgcm = AESGCM(key_bytes)

    nonce = os.urandom(NONCE_SIZE)  # Zwraca <bytes>

    ciphertext = aesgcm.encrypt(nonce, password.encode("utf-8"), None)

    return {
        "encrypted_password": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "key": base64.b64encode(key_bytes).decode("utf-8")
    }


def decrypt(ciphertext: str, nonce: str, key: str) -> dict[str, str]:

    key_bytes = decode_key(key)
    nonce_bytes = decode_nonce(nonce)
    ciphertext_bytes = decode_ciphertext(ciphertext)

    aesgcm = AESGCM(key_bytes)

    try:
        password = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, None)

        return {"decrypted_password": password.decode("utf-8")}

    except (InvalidTag, UnicodeDecodeError) as exc:
        # Zły klucz, zły nonce albo zmodyfikowany szyfrogram. Celowo nie zdradzamy, który z nich.
        raise DecryptionFailedError() from exc