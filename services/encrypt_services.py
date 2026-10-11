from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import binascii
import os
from core.exceptions import InvalidEncryptionData

KEY_SIZES = (16, 24, 32)
TAG_SIZE = 16
NONCE_SIZE = 12


def generate_key() -> str:
    key = AESGCM.generate_key(bit_length=128)

    key_string = base64.b64encode(key).decode("utf-8")

    return key_string


def encrypt(password: str, key: str | None = None) -> dict[str, str]:
    if key is None:
        key_bytes = AESGCM.generate_key(bit_length=128)
    else:
        try:
            key_bytes = base64.b64decode(key, validate=True)
        except binascii.Error as exc:
            raise InvalidEncryptionData("key is not valid base64") from exc

    if len(key_bytes) not in KEY_SIZES:
        raise InvalidEncryptionData("key must be 16, 24 or 32 bytes long")

    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, password.encode("utf-8"), None)

    return {
        "encrypted_password": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "key": base64.b64encode(key_bytes).decode("utf-8")
    }


def decrypt(ciphertext: str, nonce: str, key: str) -> dict[str, str]:
    # ciphertext
    try:
        ciphertext_bytes = base64.b64decode(ciphertext, validate=True)
    except ValueError as exc:
        raise InvalidEncryptionData("ciphertext is not valid base64") from exc

    if len(ciphertext_bytes) < TAG_SIZE:
        raise InvalidEncryptionData("ciphertext is too short")

    # nonce
    try:
        nonce_bytes = base64.b64decode(nonce, validate=True)
    except ValueError as exc:
        raise InvalidEncryptionData("nonce is not valid base64") from exc

    if len(nonce_bytes) != NONCE_SIZE:
        raise InvalidEncryptionData(f"nonce must be {NONCE_SIZE} bytes long")

    # key
    try:
        key_bytes = base64.b64decode(key, validate=True)
    except ValueError as exc:
        raise InvalidEncryptionData("key is not valid base64") from exc

    if len(key_bytes) not in KEY_SIZES:
        raise InvalidEncryptionData("key must be 16, 24 or 32 bytes long")

    aesgcm = AESGCM(key_bytes)

    try:
        password = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, None)

        return {"decrypted_password": password.decode("utf-8")}
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise InvalidEncryptionData("Invalid Encryption Data") from exc