import asyncio
import logging
import mimetypes
from functools import lru_cache
from uuid import uuid4

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException, UploadFile, status

from .config import settings

logger = logging.getLogger(__name__)


@lru_cache
def _client():
    if not all(
        (
            settings.r2_account_id,
            settings.r2_access_key_id.get_secret_value(),
            settings.r2_secret_access_key.get_secret_value(),
            settings.r2_bucket_name,
        )
    ):
        return None
    return boto3.client(
        "s3",
        endpoint_url=f"https://{settings.r2_account_id}.r2.cloudflarestorage.com",
        aws_access_key_id=settings.r2_access_key_id.get_secret_value(),
        aws_secret_access_key=settings.r2_secret_access_key.get_secret_value(),
        region_name="auto",
    )


def _ensure_ready():
    client = _client()
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloudflare R2 storage is not configured.",
        )
    return client


def object_url(key: str) -> str:
    if settings.r2_public_base_url:
        return f"{settings.r2_public_base_url.rstrip('/')}/{key}"
    client = _ensure_ready()
    return client.generate_presigned_url(
        "get_object",
        Params={"Bucket": settings.r2_bucket_name, "Key": key},
        ExpiresIn=3600,
    )


async def save_upload(
    file: UploadFile,
    user_id: str,
    category: str,
    stable_id: str | None = None,
) -> str:
    if category not in {"audio", "profiles"}:
        raise ValueError("Unsupported upload category.")
    content_type = file.content_type or mimetypes.guess_type(file.filename or "")[0]
    allowed = (
        content_type is not None
        and (content_type.startswith("audio/") if category == "audio" else content_type.startswith("image/"))
    )
    if not allowed:
        raise HTTPException(status_code=415, detail=f"Upload must be {category}.")
    data = await file.read(settings.max_upload_bytes + 1)
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds the size limit.")
    suffix = mimetypes.guess_extension(content_type) or ""
    if stable_id is not None and (
        not stable_id or len(stable_id) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in stable_id)
    ):
        raise HTTPException(status_code=400, detail="Invalid upload ID.")
    object_name = stable_id or str(uuid4())
    key = f"{category}/{user_id}/{object_name}{suffix}"
    client = _ensure_ready()
    try:
        await asyncio.to_thread(
            client.put_object,
            Bucket=settings.r2_bucket_name,
            Key=key,
            Body=data,
            ContentType=content_type,
        )
    except (BotoCoreError, ClientError) as exc:
        logger.exception("Cloudflare R2 upload failed")
        raise HTTPException(status_code=502, detail="Could not store uploaded file.") from exc
    return key


async def delete_object(key: str) -> None:
    client = _client()
    if client is None:
        return
    try:
        await asyncio.to_thread(client.delete_object, Bucket=settings.r2_bucket_name, Key=key)
    except (BotoCoreError, ClientError):
        logger.exception("Could not delete Cloudflare R2 object %s", key)
        raise HTTPException(status_code=502, detail="Could not delete stored file.")