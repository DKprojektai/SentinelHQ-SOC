FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ARG CACHEBUST=1
COPY . .
CMD ["python", "collector.py"]
