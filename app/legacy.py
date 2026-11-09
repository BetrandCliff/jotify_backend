import logging
from typing import Any

import httpx
from fastapi import HTTPException, status

from .config import settings

logger = logging.getLogger(__name__)


class LegacySupabase:
    def _require_config(self) -> tuple[str, str]:
        base_url = settings.supabase_url.rstrip("/")
        service_key = settings.supabase_service_role_key.get_secret_value()
        if not base_url or not service_key:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Legacy Supabase access is not configured.",
            )
        return base_url, service_key

    async def sign_in(self, email: str, password: str) -> dict[str, Any]:
        base_url, _ = self._require_config()
        anon_key = settings.supabase_anon_key.get_secret_value()
        if not anon_key:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Legacy Supabase sign-in is not configured.",
            )
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{base_url}/auth/v1/token",
                    params={"grant_type": "password"},
                    headers={"apikey": anon_key, "Content-Type": "application/json"},
                    json={"email": email, "password": password},
                )
        except httpx.HTTPError as exc:
            logger.exception("Legacy Supabase authentication request failed")
            raise HTTPException(status_code=502, detail="Legacy sign-in is temporarily unavailable.") from exc
        if response.status_code == 400 or response.status_code == 401:
            return {}
        if response.is_error:
            logger.error("Legacy Supabase auth returned HTTP %s", response.status_code)
            raise HTTPException(status_code=502, detail="Legacy sign-in is temporarily unavailable.")
        return response.json()

    async def get_user_data(self, user_id: str, table: str) -> list[dict[str, Any]]:
        if table not in {"profiles", "notes", "records"}:
            raise ValueError("Unsupported legacy table.")
        base_url, service_key = self._require_config()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{base_url}/rest/v1/{table}",
                    params={
                        "select": "*",
                        "id" if table == "profiles" else (
                            "createdby" if table == "notes" else "user_id"
                        ): f"eq.{user_id}",
                        "limit": "1000",
                    },
                    headers={
                        "apikey": service_key,
                        "Authorization": f"Bearer {service_key}",
                    },
                )
        except httpx.HTTPError as exc:
            logger.exception("Legacy Supabase data request failed")
            raise HTTPException(status_code=502, detail="Legacy data is temporarily unavailable.") from exc
        if response.is_error:
            logger.error("Legacy Supabase data request returned HTTP %s", response.status_code)
            raise HTTPException(status_code=502, detail="Legacy data is temporarily unavailable.")
        payload = response.json()
        if not isinstance(payload, list):
            raise HTTPException(status_code=502, detail="Legacy data response was invalid.")
        return payload

    async def delete_user(self, user_id: str) -> None:
        base_url, service_key = self._require_config()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.delete(
                    f"{base_url}/auth/v1/admin/users/{user_id}",
                    headers={
                        "apikey": service_key,
                        "Authorization": f"Bearer {service_key}",
                    },
                )
        except httpx.HTTPError as exc:
            logger.exception("Could not delete legacy Supabase account")
            raise HTTPException(status_code=502, detail="Could not delete legacy account.") from exc
        if response.is_error:
            logger.error("Legacy Supabase account deletion returned HTTP %s", response.status_code)
            raise HTTPException(status_code=502, detail="Could not delete legacy account.")


legacy_supabase = LegacySupabase()