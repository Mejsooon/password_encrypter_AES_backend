from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import binascii
import os
from core.exceptions import InvalidNonceError, InvalidKeyError, InvalidCiphertextError, DecryptionFailedError

KEY_SIZES = (16, 24, 32)
TAG_SIZE = 16
NONCE_SIZE = 12

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
    key = AESGCM.generate_key(bit_length=128)

    key_string = base64.b64encode(key).decode("utf-8")

    return key_string


def encrypt(password: str, key: str | None = None) -> dict[str, str]:
    if key is None:
        key_bytes = AESGCM.generate_key(bit_length=128)
    else:
        key_bytes = decode_key(key)

    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, password.encode("utf-8"), None)

    return {
        "encrypted_password": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "key": base64.b64encode(key_bytes).decode("utf-8")
    }


def decrypt(ciphertext: str, nonce: str, key: str) -> dict[str, str]:

    ciphertext_bytes = decode_ciphertext(ciphertext)
    nonce_bytes = decode_nonce(nonce)
    key_bytes = decode_key(key)

    aesgcm = AESGCM(key_bytes)

    try:
        password = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, None)
        return {"decrypted_password": password.decode("utf-8")}
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise DecryptionFailedError() from exc