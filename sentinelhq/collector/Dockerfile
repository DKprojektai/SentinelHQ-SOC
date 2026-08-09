FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY collector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ARG CACHEBUST=1
COPY shared/ ./shared/
COPY collector/ .
CMD ["python", "collector.py"]
