from services.encrypt_services import decrypt, encrypt


def test():
    ciphertext, nonce, key = encrypt("Test123", None)
    decrypted = decrypt(ciphertext, nonce, key)

    assert decrypted == "Test123", "Błąd"
    print("Success")