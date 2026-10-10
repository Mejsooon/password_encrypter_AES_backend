from fastapi import FastAPI

from schemas.passwords import EncryptResponse, EncryptRequest, DecryptResponse, DecryptRequest
from services import encrypt_services

app = FastAPI()

@app.get("/")
def root():
    return {"Hello": "World"}

@app.post("/encrypt", response_model=EncryptResponse)
def encrypt_password(data: EncryptRequest):
    encrypted_password = encrypt_services.encrypt(data.password, data.key)

    return encrypted_password

@app.get("/key")
def generate_key():
    return encrypt_services.generate_key()

@app.post("/decrypt", response_model=DecryptResponse)
def decrypt_password(data: DecryptRequest):
    decrypted_password = encrypt_services.decrypt(ciphertext=data.ciphertext, key=data.key, nonce=data.nonce)

    return decrypted_password