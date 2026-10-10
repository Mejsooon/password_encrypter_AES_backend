from services.encrypt_services import decrypt, encrypt, generate_key, InvalidEncryptionData
import pytest


def test_encryption_and_decryption():
    encrypted = encrypt("Test123", None)

    # Do funkcji przekazujemy "wartości" ze słownika a nie klucze.
    decrypted = decrypt(encrypted["encrypted_password"], encrypted["nonce"], encrypted["key"])

    assert decrypted == {"decrypted_password": "Test123"}


def test_decryption_with_wrong_key_fails():
    encrypted = encrypt("Test123", None)

    with pytest.raises(InvalidEncryptionData):
        decrypt(encrypted["encrypted_password"], encrypted["nonce"], generate_key())