from fastapi import FastAPI

from schemas.passwords import PasswordResponse, PasswordHash
from services import encrypt_services

app = FastAPI()

@app.get("/")
def root():
    return {"Hello": "World"}

@app.get("/hashed_password", response_model=PasswordResponse)
def hashed_password(data: PasswordHash):
    password = encrypt_services.encrypt(data.password, None)

    return password