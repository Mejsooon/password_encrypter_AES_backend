# dev.py — uruchamia backend + frontend lokalnie (tylko do testów, NIE na produkcję)

import uvicorn
from fastapi.staticfiles import StaticFiles

from main import app

# Wszystko, co nie zaczyna się od /api, będzie szukane w folderze frontend/
# html=True oznacza, że adres "/" pokaże frontend/index.html
app.mount("/", StaticFiles(directory="frontend", html=True))

uvicorn.run(app, host="127.0.0.1", port=8000)