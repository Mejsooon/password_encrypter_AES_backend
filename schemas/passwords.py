from pydantic import BaseModel, Field

MAX_LENGTH = 1024

class EncryptRequest(BaseModel):
    password: str = Field(min_length=1, max_length=MAX_LENGTH)
    key: str | None = None


class EncryptResponse(BaseModel):
    encrypted_password: str
    nonce: str
    key: str


class DecryptRequest(BaseModel):
    ciphertext: str
    nonce: str
    key: str

class DecryptResponse(BaseModel):
    decrypted_password: str