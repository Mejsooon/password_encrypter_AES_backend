from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from schemas.passwords import EncryptResponse, EncryptRequest, DecryptResponse, DecryptRequest
from services import encrypt_services
from core.exceptions import AppException

app = FastAPI()

# Wszystkie endpointy API są pod /api — nginx przekieruje /api/* do backendu,
# a resztę adresów (/, /app.js, /style.css) obsłuży jako pliki frontendu.
api_router = APIRouter(prefix="/api")


@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )


@api_router.get("/health")
def health():
    return {"status": "ok"}


@api_router.post("/encrypt", response_model=EncryptResponse)
def encrypt_password(data: EncryptRequest):
    return encrypt_services.encrypt(data.password, data.key)


@api_router.post("/decrypt", response_model=DecryptResponse)
def decrypt_password(data: DecryptRequest):
    return encrypt_services.decrypt(ciphertext=data.ciphertext, nonce=data.nonce, key=data.key)


@api_router.get("/key")
def generate_key():
    return encrypt_services.generate_key()


# Router trzeba dołączyć po zdefiniowaniu endpointów
app.include_router(api_router)