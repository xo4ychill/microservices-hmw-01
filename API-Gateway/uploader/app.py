"""
Сервис загрузки файлов (uploader).

Единственный эндпоинт:
  POST /v1/upload — принимает бинарные данные в теле запроса, пытается
                     распознать их как изображение и пережать в JPEG
                     (уменьшая размер), после чего сохраняет результат
                     в MinIO под случайным UUID-именем.

Токен здесь НЕ проверяется повторно: проверка уже выполнена шлюзом через
auth_request до того, как запрос вообще попал в этот сервис. Это стандартная
практика для API Gateway — единая точка проверки аутентификации, чтобы не
дублировать эту логику в каждом внутреннем сервисе.
"""

import io
import os
import uuid

import boto3
from botocore.client import Config
from flask import Flask, request, jsonify
from PIL import Image

app = Flask(__name__)

# Параметры подключения к MinIO берём из окружения (задаются в
# docker-compose.yml), чтобы не хардкодить их в коде.
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
BUCKET = os.environ.get("MINIO_BUCKET", "images")

# Качество JPEG при пережатии (0-100). 80 — разумный баланс между
# размером файла и визуальным качеством для большинства фото.
JPEG_QUALITY = int(os.environ.get("JPEG_QUALITY", "80"))

# boto3 умеет работать с любым S3-совместимым хранилищем, не только с AWS —
# достаточно указать свой endpoint_url. MinIO реализует тот же протокол.
s3 = boto3.client(
    "s3",
    endpoint_url=MINIO_ENDPOINT,
    aws_access_key_id=MINIO_ACCESS_KEY,
    aws_secret_access_key=MINIO_SECRET_KEY,
    # signature_version="s3v4" — современная схема подписи запросов,
    # без неё MinIO по умолчанию тоже работает, но v4 — стандарт де-факто.
    config=Config(signature_version="s3v4"),
    region_name="us-east-1",  # MinIO region игнорирует, но boto3 требует значение
)


def _ensure_bucket():
    """Подстраховка на случай, если сервис стартовал раньше, чем
    отработал init-контейнер minio-init: создаём бакет, если его ещё нет.
    Идемпотентно — повторный вызов при уже существующем бакете безопасен."""
    existing = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    if BUCKET not in existing:
        s3.create_bucket(Bucket=BUCKET)


@app.post("/v1/upload")
def upload():
    # request.get_data() — сырые байты тела запроса, без попытки Flask
    # распарсить их как форму или JSON (нам нужен именно бинарник).
    raw = request.get_data()
    if not raw:
        return jsonify({"error": "empty body"}), 400

    try:
        # Image.open читает байты и определяет формат по содержимому
        # (а не по расширению файла или Content-Type) — так надёжнее.
        image = Image.open(io.BytesIO(raw))
        # convert("RGB") нужен, например, для PNG с альфа-каналом или
        # палитровых изображений — JPEG не поддерживает прозрачность.
        image = image.convert("RGB")

        buf = io.BytesIO()
        image.save(buf, format="JPEG", quality=JPEG_QUALITY, optimize=True)
        content = buf.getvalue()
        content_type = "image/jpeg"
        ext = "jpg"
    except Exception:
        # Pillow не смог распознать формат (например, прислали не картинку,
        # а произвольный бинарник) — сохраняем как есть, без сжатия,
        # чтобы не терять данные пользователя.
        content = raw
        content_type = request.headers.get("Content-Type", "application/octet-stream")
        ext = "bin"

    # UUID вместо оригинального имени файла — исключает коллизии имён
    # между разными пользователями и не раскрывает исходное имя файла.
    filename = f"{uuid.uuid4()}.{ext}"

    _ensure_bucket()
    s3.put_object(Bucket=BUCKET, Key=filename, Body=content, ContentType=content_type)

    return jsonify({"file": filename}), 201


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
