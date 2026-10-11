import base64

import pytest
from fastapi.testclient import TestClient

from core.exceptions import InvalidEncryptionData
from main import app
from services.encrypt_services import decrypt, encrypt, generate_key

client = TestClient(app)

NOT_BASE64 = "to nie jest base64!"
TOO_SHORT = base64.b64encode(b"za krotki").decode("utf-8")  # Poprawny base64, ale tylko 9 bajtów


# --- Warstwa serwisu: poprawne dane ---

def test_encryption_and_decryption():
    encrypted = encrypt("Test123", None)

    decrypted = decrypt(encrypted["encrypted_password"], encrypted["nonce"], encrypted["key"])

    assert decrypted == {"decrypted_password": "Test123"}


def test_encryption_with_own_key():
    key = generate_key()

    encrypted = encrypt("Test123", key)

    assert encrypted["key"] == key
    assert decrypt(encrypted["encrypted_password"], encrypted["nonce"], key) == {"decrypted_password": "Test123"}


def test_each_encryption_uses_new_nonce():
    key = generate_key()

    first = encrypt("Test123", key)
    second = encrypt("Test123", key)

    assert first["nonce"] != second["nonce"]
    assert first["encrypted_password"] != second["encrypted_password"]


# --- Warstwa serwisu: błędy w encrypt ---

@pytest.mark.parametrize("key", [NOT_BASE64, "MYxJ Ht1J9Fc+wILCe38I0Q==", "zażółć=="])
def test_encryption_with_key_not_in_base64_fails(key):
    with pytest.raises(InvalidEncryptionData, match="key is not valid base64"):
        encrypt("Test123", key)


def test_encryption_with_key_of_wrong_length_fails():
    with pytest.raises(InvalidEncryptionData, match="key must be 16, 24 or 32 bytes long"):
        encrypt("Test123", TOO_SHORT)


# --- Warstwa serwisu: błędy w decrypt ---

def test_decryption_with_wrong_key_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidEncryptionData, match="Invalid Encryption Data"):
        decrypt(encrypted["encrypted_password"], encrypted["nonce"], generate_key())


def test_decryption_with_key_not_in_base64_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidEncryptionData, match="key is not valid base64"):
        decrypt(encrypted["encrypted_password"], encrypted["nonce"], NOT_BASE64)


def test_decryption_with_key_of_wrong_length_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidEncryptionData, match="key must be 16, 24 or 32 bytes long"):
        decrypt(encrypted["encrypted_password"], encrypted["nonce"], TOO_SHORT)


def test_decryption_with_nonce_not_in_base64_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidEncryptionData, match="nonce is not valid base64"):
        decrypt(encrypted["encrypted_password"], NOT_BASE64, encrypted["key"])


def test_decryption_with_nonce_of_wrong_length_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidEncryptionData, match="nonce must be 12 bytes long"):
        decrypt(encrypted["encrypted_password"], TOO_SHORT, encrypted["key"])


def test_decryption_with_ciphertext_not_in_base64_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidEncryptionData, match="ciphertext is not valid base64"):
        decrypt(NOT_BASE64, encrypted["nonce"], encrypted["key"])


def test_decryption_with_too_short_ciphertext_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidEncryptionData, match="ciphertext is too short"):
        decrypt(TOO_SHORT, encrypted["nonce"], encrypted["key"])


# --- Warstwa API ---

def test_api_encrypt_and_decrypt():
    body = client.post("/encrypt", json={"password": "Test123"}).json()

    response = client.post(
        "/decrypt",
        json={"ciphertext": body["encrypted_password"], "nonce": body["nonce"], "key": body["key"]},
    )

    assert response.status_code == 200, response.json()
    assert response.json() == {"decrypted_password": "Test123"}


def test_api_key_can_be_used_for_encryption():
    key = client.get("/key").json()

    response = client.post("/encrypt", json={"password": "Test123", "key": key})

    assert response.status_code == 200, response.json()
    assert response.json()["key"] == key


def test_api_encrypt_with_invalid_key_returns_400():
    response = client.post("/encrypt", json={"password": "Test123", "key": TOO_SHORT})

    assert response.status_code == 400, response.json()
    assert response.json() == {"detail": "key must be 16, 24 or 32 bytes long"}


def test_api_decrypt_with_wrong_key_returns_400():
    body = client.post("/encrypt", json={"password": "Test123"}).json()

    response = client.post(
        "/decrypt",
        json={"ciphertext": body["encrypted_password"], "nonce": body["nonce"], "key": generate_key()},
    )

    assert response.status_code == 400, response.json()
    assert response.json() == {"detail": "Invalid Encryption Data"}


@pytest.mark.parametrize("password", ["", "a" * 1025])
def test_api_encrypt_with_invalid_password_returns_422(password):
    response = client.post("/encrypt", json={"password": password})

    assert response.status_code == 422


def test_api_decrypt_without_required_field_returns_422():
    response = client.post("/decrypt", json={"ciphertext": "abc", "nonce": "abc"})

    assert response.status_code == 422