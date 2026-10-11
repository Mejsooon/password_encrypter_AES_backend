from fastapi import FastAPI, HTTPException

from schemas.passwords import EncryptResponse, EncryptRequest, DecryptResponse, DecryptRequest
from services import encrypt_services
from services.encrypt_services import InvalidEncryptionData

app = FastAPI()

@app.get("/")
def root():
    return {"Hello": "World"}

@app.post("/encrypt", response_model=EncryptResponse)
def encrypt_password(data: EncryptRequest):
    try:
        encrypted_password = encrypt_services.encrypt(data.password, data.key)
    except InvalidEncryptionData as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return encrypted_password

@app.post("/decrypt", response_model=DecryptResponse)
def decrypt_password(data: DecryptRequest):
    try:
        decrypted_password = encrypt_services.decrypt(ciphertext=data.ciphertext, key=data.key, nonce=data.nonce)
    except InvalidEncryptionData as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return decrypted_password

@app.get("/key")
def generate_key():
    return encrypt_services.generate_key()