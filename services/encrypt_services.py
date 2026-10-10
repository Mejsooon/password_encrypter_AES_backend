from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64


def generate_key():
    key = AESGCM.generate_key(bit_length=128) # <bytes> w postaci bezpiecznej b'1\x8cI\x1e\xddI...'

    key_base64 = base64.b64encode(key) # Kodujemy do <bytes> base64 czyli do ASCII b'MYxJHt1J9Fc+wILCe38I0Q=='

    key_string = key_base64.decode("utf-8") # Dekodujemy do <str> 'MYxJHt1J9Fc+wILCe38I0Q=='

    return key_string


def encrypt(password: str, key: str):

    if key is None:
        key_bytes = AESGCM.generate_key(bit_length=128)
    else:
        key_bytes = base64.b64decode(key) # Zamieniamy <str> od użytkownika na surowe <bytes>

    aesgcm = AESGCM(key_bytes)

    nonce = os.urandom(12)  # Zwraca <bytes>

    ciphertext = aesgcm.encrypt(nonce, password.encode("utf-8"), None)

    return {
        "encrypted_password": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "key": base64.b64encode(key_bytes).decode("utf-8")
    }


def decrypt(ciphertext, nonce, key):

    if key is None or ciphertext is None or nonce is None:
        return "Missing parameters"

    try:
        key_bytes = base64.b64decode(key)
        nonce_bytes = base64.b64decode(nonce)
        ciphertext_bytes = base64.b64decode(ciphertext)

        aesgcm = AESGCM(key_bytes)

        password = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, None)

        return {"decrypted_password": password.decode("utf-8")}

    except (ValueError) as exc:
        raise ValueError("Invalid encryption data") from exc