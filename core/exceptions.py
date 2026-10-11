class AppException(Exception):
    status_code = 500
    detail = "Internal server error"

    def __init__(self, detail: str | None = None):
        message = detail or self.detail
        super().__init__(message)
        self.detail = message


class InvalidKeyError(AppException):
    status_code = 400
    detail = "Key must be valid base64 and 16, 24 or 32 bytes long"


class InvalidNonceError(AppException):
    status_code = 400
    detail = "Nonce must be valid base64 and 12 bytes long"


class InvalidCiphertextError(AppException):
    status_code = 400
    detail = "Ciphertext must be valid base64 and at least 16 bytes long"


class DecryptionFailedError(AppException):
    status_code = 400
    detail = "Invalid encryption data"