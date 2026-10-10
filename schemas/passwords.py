from pydantic import BaseModel

class PasswordHash(BaseModel):
    password: str
    key: str | None

class PasswordResponse(BaseModel):
    hashed_password: str
    key: str
    nonce: str