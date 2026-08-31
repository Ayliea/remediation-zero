# Console image. Read-only by construction: it ships no write path and runs
# under a service account with viewer access only.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements-ui.txt .
RUN pip install --no-cache-dir -r requirements-ui.txt

# Ship only the application. Development probes and local verification helpers
# do not belong in the public, read-only console image.
COPY ui/app.py ./ui/app.py

# Cloud Run supplies PORT. Single worker: the console is read-mostly and
# scaling out costs more than it saves at this traffic.
ENV PORT=8080
CMD exec uvicorn ui.app:app --host 0.0.0.0 --port ${PORT} --workers 1
