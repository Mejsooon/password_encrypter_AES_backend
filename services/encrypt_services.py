from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64


def generate_key():
    key = AESGCM.generate_key(bit_length=128) # <bytes>

    key_base64 = base64.b64encode(key) # Kodujemy do <bytes> base64

    key_string = key_base64.decode("utf-8") # Dekodujemy do <str>

    return key_string


def encrypt(password: str, key: str):

    if key is None:
        key_bytes = AESGCM.generate_key(bit_length=128)
    else:
        key_bytes = base64.b64decode(key)

    aesgcm = AESGCM(key_bytes)

    nonce = os.urandom(12)  # Zwraca <bytes>
    ciphertext = aesgcm.encrypt(nonce, password.encode("utf-8"), None)

    return {
        "encrypted_password": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "key": base64.b64encode(key_bytes).decode("utf-8")
    }


def decrypt(ciphertext, nonce, key):
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)

    return decrypted.decode("utf-8")