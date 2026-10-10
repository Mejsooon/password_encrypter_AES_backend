from pydantic import BaseModel

class EncryptRequest(BaseModel):
    password: str
    key: str | None = None # <None = None> oznacza, że w requescie można całkowicie pominąć <key>

class EncryptResponse(BaseModel):
    encrypted_password: str
    key: str
    nonce: str

class DecryptResponse(BaseModel):
    decrypted_password: str

class DecryptRequest(BaseModel):
    ciphertext: str
    nonce: str
    key: str