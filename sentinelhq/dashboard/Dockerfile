FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Force rebuild of app code on every build
ARG CACHEBUST=1
COPY . .
# Production WSGI server (the Flask dev server drops connections behind a proxy →
# intermittent 502). gthread workers: blocking IO (DB, OTX, Wazuh API) → threads.
CMD ["gunicorn", "-w", "2", "--threads", "4", "-b", "0.0.0.0:8080", \
     "--timeout", "120", "--graceful-timeout", "30", \
     "--access-logfile", "-", "--error-logfile", "-", "app:app"]
