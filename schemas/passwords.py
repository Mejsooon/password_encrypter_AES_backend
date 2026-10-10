from pydantic import BaseModel

class EncryptRequest(BaseModel):
    password: str
    key: str | None = None

class EncryptResponse(BaseModel):
    encrypted_password: str
    key: str
    nonce: str