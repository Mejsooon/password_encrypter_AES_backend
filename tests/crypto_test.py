import base64

import pytest
from fastapi.testclient import TestClient

from core.exceptions import DecryptionFailedError, InvalidCiphertextError, InvalidKeyError, InvalidNonceError
from main import app
from services.encrypt_services import decrypt, encrypt, generate_key

client = TestClient(app)

TOO_SHORT = base64.b64encode(b"za krotki").decode("utf-8")  # Poprawny base64, ale tylko 9 bajtów


# --- Warstwa serwisu ---

def test_encryption_and_decryption():
    encrypted = encrypt("Test123", None)

    decrypted = decrypt(encrypted["encrypted_password"], encrypted["nonce"], encrypted["key"])

    assert decrypted == {"decrypted_password": "Test123"}


def test_encryption_with_own_key():
    key = generate_key()

    encrypted = encrypt("Test123", key)

    assert encrypted["key"] == key


def test_decryption_with_wrong_key_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(DecryptionFailedError):
        decrypt(encrypted["encrypted_password"], encrypted["nonce"], generate_key())


@pytest.mark.parametrize("key", ["to nie jest base64!", "MYxJ Ht1J9Fc+wILCe38I0Q==", TOO_SHORT])
def test_encryption_with_invalid_key_fails(key):
    with pytest.raises(InvalidKeyError):
        encrypt("Test123", key)


def test_decryption_with_invalid_key_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidKeyError):
        decrypt(encrypted["encrypted_password"], encrypted["nonce"], TOO_SHORT)


def test_decryption_with_invalid_nonce_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidNonceError):
        decrypt(encrypted["encrypted_password"], TOO_SHORT, encrypted["key"])


def test_decryption_with_invalid_ciphertext_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidCiphertextError):
        decrypt(TOO_SHORT, encrypted["nonce"], encrypted["key"])


# --- Warstwa API ---

def test_api_encrypt_and_decrypt():
    body = client.post("/encrypt", json={"password": "Test123"}).json()

    response = client.post(
        "/decrypt",
        json={"ciphertext": body["encrypted_password"], "nonce": body["nonce"], "key": body["key"]},
    )

    assert response.status_code == 200
    assert response.json() == {"decrypted_password": "Test123"}


def test_api_decrypt_with_wrong_key_returns_400():
    body = client.post("/encrypt", json={"password": "Test123"}).json()

    response = client.post(
        "/decrypt",
        json={"ciphertext": body["encrypted_password"], "nonce": body["nonce"], "key": generate_key()},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid encryption data"}


def test_api_encrypt_with_invalid_key_returns_400():
    response = client.post("/encrypt", json={"password": "Test123", "key": TOO_SHORT})

    assert response.status_code == 400
    assert response.json() == {"detail": "Key must be valid base64 and 16, 24 or 32 bytes long"}


def test_api_encrypt_with_empty_password_returns_422():
    response = client.post("/encrypt", json={"password": ""})

    assert response.status_code == 422