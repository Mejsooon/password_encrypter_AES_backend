# Obraz bazowy: lekki Linux z Pythonem 3.13
FROM python:3.13-slim

# Python nie tworzy plików .pyc i od razu wypisuje logi (bez buforowania)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Folder roboczy w kontenerze
WORKDIR /app

# Najpierw tylko requirements.txt, żeby Docker mógł zapamiętać (cache)
# zainstalowane biblioteki i nie instalować ich od nowa przy każdej zmianie kodu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy kod aplikacji (bez testów i frontendu, nie są tu potrzebne)
COPY main.py .
COPY core/ core/
COPY schemas/ schemas/
COPY services/ services/

# Uruchamiamy aplikację jako zwykły użytkownik, a nie root (bezpieczniej)
RUN useradd --create-home appuser
USER appuser

# Port, na którym nasłuchuje uvicorn wewnątrz kontenera
EXPOSE 8000

# Docker co 30 s sprawdza, czy /api/health odpowiada
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"

# Polecenie startowe: uvicorn z naszą aplikacją FastAPI
# --proxy-headers: ufaj nagłówkom od nginx (prawdziwe IP użytkownika)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]