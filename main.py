from fastapi import FastAPI

from schemas.passwords import  EncryptResponse, EncryptRequest
from services import encrypt_services

app = FastAPI()

@app.get("/")
def root():
    return {"Hello": "World"}

@app.post("/encrypt", response_model=EncryptResponse)
def encrypt_password(data: EncryptRequest):
    encrypted_password = encrypt_services.encrypt(data.password, data.key)

    return encrypted_password