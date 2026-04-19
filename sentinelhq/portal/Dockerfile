FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Force rebuild of app code on every build
ARG CACHEBUST=1
COPY . .
CMD ["python", "app.py"]
