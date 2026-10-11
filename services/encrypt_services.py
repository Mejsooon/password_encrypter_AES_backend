from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
import os
import base64

KEY_SIZES = (16, 24, 32)  # Dozwolone długości klucza AES w bajtach (128, 192, 256 bitów)
NONCE_SIZE = 12  # Zalecana długość nonce dla AES-GCM w bajtach
TAG_SIZE = 16  # Długość znacznika uwierzytelniającego, który AES-GCM dokleja do szyfrogramu


class InvalidEncryptionData(ValueError):
    pass


def decode_base64(value: str, field: str) -> bytes:
    # <validate=True> odrzuca znaki spoza alfabetu base64 zamiast po cichu je pomijać
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidEncryptionData(f"{field} is not valid base64") from exc


def decode_key(key: str) -> bytes:
    key_bytes = decode_base64(key, "key")

    if len(key_bytes) not in KEY_SIZES:
        raise InvalidEncryptionData("key must be 16, 24 or 32 bytes long")

    return key_bytes


def decode_nonce(nonce: str) -> bytes:
    nonce_bytes = decode_base64(nonce, "nonce")

    if len(nonce_bytes) != NONCE_SIZE:
        raise InvalidEncryptionData(f"nonce must be {NONCE_SIZE} bytes long")

    return nonce_bytes


def decode_ciphertext(ciphertext: str) -> bytes:
    ciphertext_bytes = decode_base64(ciphertext, "ciphertext")

    if len(ciphertext_bytes) < TAG_SIZE:
        raise InvalidEncryptionData("ciphertext is too short")

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
    except InvalidTag as exc:
        # Zły klucz, zły nonce albo zmodyfikowany szyfrogram. Celowo nie zdradzamy, który z nich.
        raise InvalidEncryptionData("Invalid encryption data") from exc

    try:
        return {"decrypted_password": password.decode("utf-8")}
    except UnicodeDecodeError as exc:
        raise InvalidEncryptionData("Invalid encryption data") from exc