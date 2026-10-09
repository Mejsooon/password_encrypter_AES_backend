from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def encrypt(password: str, key: str):

    if key is None:
        key = AESGCM.generate_key(bit_length=128)

    try:
        aesgcm = AESGCM(key)
    except ValueError:
        print("Invalid key")

    nonce = os.urandom(12)  # Zwraca <bytes>
    ciphertext = aesgcm.encrypt(nonce, password.encode("utf-8"), None)

    return ciphertext, nonce, key


def decrypt(ciphertext, nonce, key):
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)

    return decrypted.decode("utf-8")
