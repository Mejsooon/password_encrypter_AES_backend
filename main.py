from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from core.exceptions import AppException
from schemas.passwords import EncryptResponse, EncryptRequest, DecryptResponse, DecryptRequest
from services import encrypt_services

app = FastAPI()


@app.exception_handler(AppException)
def handle_app_exception(request: Request, exc: AppException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/")
def root():
    return {"Hello": "World"}

@app.post("/encrypt", response_model=EncryptResponse)
def encrypt_password(data: EncryptRequest):
    return encrypt_services.encrypt(data.password, data.key)

@app.post("/decrypt", response_model=DecryptResponse)
def decrypt_password(data: DecryptRequest):
    return encrypt_services.decrypt(ciphertext=data.ciphertext, key=data.key, nonce=data.nonce)

@app.get("/key")
def generate_key():
    return encrypt_services.generate_key()