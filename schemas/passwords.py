from pydantic import BaseModel, Field

MAX_PASSWORD_LENGTH = 1024


class EncryptRequest(BaseModel):
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
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