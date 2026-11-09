import asyncio
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any
from uuid import uuid4

import jwt
from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import create_schema, dispose_db, get_db
from .emailing import send_code
from .legacy import legacy_supabase
from .models import (
    EmailToken,
    LegacyNoteOverride,
    LegacyRecordOverride,
    Note,
    Record,
    RefreshSession,
    User,
    utc_now,
)
from .schemas import (
    AuthResponse,
    EmailCodeRequest,
    EmailRequest,
    GoogleLoginRequest,
    LoginRequest,
    MessageResponse,
    NoteCreate,
    NoteResponse,
    NoteUpdate,
    RecordResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    UserResponse,
)
from .security import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    hash_secret,
    password_hash,
    verify_password,
)
from .storage import delete_object, object_url, save_upload

logger = logging.getLogger(__name__)
DbSession = Annotated[AsyncSession, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]


@asynccontextmanager
async def lifespan(_: FastAPI):
    await create_schema()
    yield
    await dispose_db()


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


def _email(value: str) -> str:
    return value.strip().lower()


def _code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


async def _create_email_token(db: AsyncSession, user: User, purpose: str) -> str:
    code = _code()
    existing = await db.scalars(
        select(EmailToken).where(
            EmailToken.user_id == user.id,
            EmailToken.purpose == purpose,
            EmailToken.used_at.is_(None),
        )
    )
    for token in existing:
        token.used_at = utc_now()
    db.add(
        EmailToken(
            id=str(uuid4()),
            user_id=user.id,
            token_hash=hash_secret(f"{purpose}:{code}"),
            purpose=purpose,
            expires_at=utc_now() + timedelta(minutes=settings.verification_token_minutes),
        )
    )
    await db.commit()
    return code


async def _issue_auth(db: AsyncSession, user: User) -> AuthResponse:
    refresh, refresh_session = create_refresh_token(user.id)
    db.add(refresh_session)
    await db.commit()
    return AuthResponse(
        access_token=create_access_token(user.id),
        refresh_token=refresh,
        user=UserResponse.model_validate(user),
    )


async def _validate_one_time_code(
    db: AsyncSession, email: str, code: str, purpose: str
) -> tuple[User, EmailToken]:
    token = await db.scalar(
        select(EmailToken)
        .join(User)
        .where(
            func.lower(User.email) == _email(email),
            EmailToken.purpose == purpose,
            EmailToken.token_hash == hash_secret(f"{purpose}:{code}"),
            EmailToken.used_at.is_(None),
        )
        .order_by(EmailToken.expires_at.desc())
    )
    if token is None or token.expires_at.replace(tzinfo=timezone.utc) <= utc_now():
        raise HTTPException(status_code=400, detail="The code is invalid or expired.")
    user = await db.get(User, token.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="The code is invalid or expired.")
    return user, token


async def _legacy_sign_in(email: str, password: str) -> tuple[dict[str, Any], dict[str, Any]]:
    auth_data = await legacy_supabase.sign_in(email, password)
    legacy_user = auth_data.get("user")
    if not legacy_user:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    if not legacy_user.get("email_confirmed_at"):
        raise HTTPException(status_code=403, detail="Please verify your email before signing in.")
    user_id = str(legacy_user.get("id", ""))
    if not user_id:
        raise HTTPException(status_code=502, detail="Legacy account response was invalid.")
    profiles = await legacy_supabase.get_user_data(user_id, "profiles")
    return legacy_user, profiles[0] if profiles else {}


async def _resolve_legacy_user(
    db: AsyncSession,
    email: str,
    password: str,
    known_user: User | None,
) -> User:
    legacy_user, profile = await _legacy_sign_in(email, password)
    user_id = str(legacy_user["id"])
    user = known_user or await db.get(User, user_id)
    if user is None:
        user = User(
            id=user_id,
            email=_email(email),
            full_name=str(profile.get("full_names") or legacy_user.get("user_metadata", {}).get("full_name") or ""),
            picture=profile.get("picture"),
            is_verified=True,
            auth_source="native",
            legacy_linked=True,
        )
        db.add(user)
    else:
        user.password_hash = password_hash.hash(password)
        user.is_verified = True
        user.legacy_linked = True
        user.auth_source = "native"
        user.email = _email(email)
        if profile.get("full_names"):
            user.full_name = str(profile["full_names"])
        if profile.get("picture"):
            user.picture = str(profile["picture"])
    user.password_hash = password_hash.hash(password)
    await db.commit()
    await db.refresh(user)
    return user


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(f"{settings.api_prefix}/auth/register", response_model=MessageResponse, status_code=201)
async def register(payload: RegisterRequest, db: DbSession):
    email = _email(str(payload.email))
    exists = await db.scalar(select(User.id).where(func.lower(User.email) == email))
    if exists:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    user = User(
        id=str(uuid4()),
        email=email,
        full_name=payload.full_name.strip(),
        password_hash=password_hash.hash(payload.password),
        is_verified=False,
        auth_source="native",
    )
    db.add(user)
    await db.commit()
    code = await _create_email_token(db, user, "verify")
    development = await send_code(email, code, "verify")
    return MessageResponse(
        message="Verification code sent." if not development else "Development verification code created.",
        development_code=code if development and not settings.is_production else None,
    )


@app.post(f"{settings.api_prefix}/auth/verify-email", response_model=AuthResponse)
async def verify_email(payload: EmailCodeRequest, db: DbSession):
    user, token = await _validate_one_time_code(db, str(payload.email), payload.code, "verify")
    token.used_at = utc_now()
    user.is_verified = True
    await db.commit()
    return await _issue_auth(db, user)


@app.post(f"{settings.api_prefix}/auth/resend-verification", response_model=MessageResponse)
async def resend_verification(payload: EmailRequest, db: DbSession):
    email = _email(str(payload.email))
    user = await db.scalar(select(User).where(func.lower(User.email) == email))
    if user is None or user.is_verified:
        return MessageResponse(message="If an unverified account exists, a code has been sent.")
    code = await _create_email_token(db, user, "verify")
    development = await send_code(email, code, "verify")
    return MessageResponse(
        message="Verification code sent.",
        development_code=code if development and not settings.is_production else None,
    )


@app.post(f"{settings.api_prefix}/auth/login", response_model=AuthResponse)
async def login(payload: LoginRequest, db: DbSession):
    email = _email(str(payload.email))
    user = await db.scalar(select(User).where(func.lower(User.email) == email))
    if user and verify_password(payload.password, user.password_hash):
        if not user.is_verified:
            raise HTTPException(status_code=403, detail="Please verify your email before signing in.")
    elif user is None or user.auth_source == "supabase":
        user = await _resolve_legacy_user(db, email, payload.password, user)
    else:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    return await _issue_auth(db, user)


@app.post(f"{settings.api_prefix}/auth/refresh", response_model=AuthResponse)
async def refresh(payload: RefreshRequest, db: DbSession):
    row = await db.scalar(
        select(RefreshSession)
        .where(RefreshSession.token_hash == hash_secret(payload.refresh_token))
        .with_for_update()
    )
    now = utc_now()
    if (
        row is None
        or row.revoked_at is not None
        or row.expires_at.replace(tzinfo=timezone.utc) <= now
    ):
        raise HTTPException(status_code=401, detail="Refresh token is invalid or expired.")
    user = await db.get(User, row.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Refresh token is invalid or expired.")
    row.revoked_at = now
    return await _issue_auth(db, user)


@app.post(f"{settings.api_prefix}/auth/logout", status_code=204)
async def logout(
    user: CurrentUser,
    db: DbSession,
    payload: RefreshRequest | None = Body(default=None),
):
    if payload is not None:
        row = await db.scalar(
            select(RefreshSession).where(
                RefreshSession.user_id == user.id,
                RefreshSession.token_hash == hash_secret(payload.refresh_token),
                RefreshSession.revoked_at.is_(None),
            )
        )
        if row is not None:
            row.revoked_at = utc_now()
            await db.commit()
    return Response(status_code=204)


@app.post(f"{settings.api_prefix}/auth/forgot-password", response_model=MessageResponse)
async def forgot_password(payload: EmailRequest, db: DbSession):
    email = _email(str(payload.email))
    user = await db.scalar(select(User).where(func.lower(User.email) == email))
    code = None
    if user is not None:
        code = await _create_email_token(db, user, "reset")
        development = await send_code(email, code, "reset")
    else:
        development = False
    return MessageResponse(
        message="If an account exists, a password reset code has been sent.",
        development_code=(
            code if code and development and not settings.is_production else None
        ),
    )


@app.post(f"{settings.api_prefix}/auth/reset-password", response_model=MessageResponse)
async def reset_password(payload: ResetPasswordRequest, db: DbSession):
    user, token = await _validate_one_time_code(db, str(payload.email), payload.code, "reset")
    token.used_at = utc_now()
    user.password_hash = password_hash.hash(payload.new_password)
    for session in await db.scalars(
        select(RefreshSession).where(
            RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None)
        )
    ):
        session.revoked_at = utc_now()
    await db.commit()
    return MessageResponse(message="Password updated.")


@app.get(f"{settings.api_prefix}/auth/me", response_model=UserResponse)
async def current_user(user: CurrentUser):
    return UserResponse.model_validate(user)


@app.post(f"{settings.api_prefix}/auth/google", response_model=AuthResponse)
async def google_login(payload: GoogleLoginRequest, db: DbSession):
    if not settings.google_client_id:
        raise HTTPException(status_code=503, detail="Google sign-in is not configured.")
    try:
        claims = await asyncio.to_thread(
            google_id_token.verify_oauth2_token,
            payload.id_token,
            google_requests.Request(),
            settings.google_client_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Google ID token is invalid.") from exc
    email = _email(claims.get("email", ""))
    if not email or not claims.get("email_verified"):
        raise HTTPException(status_code=401, detail="Google account email is not verified.")
    user = await db.scalar(select(User).where(func.lower(User.email) == email))
    if user is None:
        user = User(
            id=str(uuid4()),
            email=email,
            full_name=str(claims.get("name", ""))[:160],
            picture=claims.get("picture"),
            is_verified=True,
            auth_source="google",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    elif not user.is_verified:
        user.is_verified = True
        await db.commit()
    return await _issue_auth(db, user)


@app.get(f"{settings.api_prefix}/profile", response_model=UserResponse)
async def get_profile(user: CurrentUser):
    return UserResponse.model_validate(user)


@app.patch(f"{settings.api_prefix}/profile", response_model=UserResponse)
async def update_profile(
    user: CurrentUser,
    db: DbSession,
    full_names: Annotated[str | None, Form(max_length=160)] = None,
    email: Annotated[str | None, Form()] = None,
    picture: UploadFile | None = File(default=None),
):
    if email is not None and _email(email) != user.email:
        raise HTTPException(
            status_code=409,
            detail="Email changes require a separate verification flow and are not enabled.",
        )
    if full_names is not None:
        user.full_name = full_names.strip()
    if picture is not None:
        old_picture_key = user.picture_key
        key = await save_upload(picture, user.id, "profiles")
        user.picture = object_url(key)
        user.picture_key = key
        await db.commit()
        if old_picture_key:
            await delete_object(old_picture_key)
    else:
        await db.commit()
    return UserResponse.model_validate(user)


@app.delete(f"{settings.api_prefix}/profile", status_code=204)
async def delete_account(user: CurrentUser, db: DbSession):
    keys = list(
        await db.scalars(select(Record.object_key).where(Record.user_id == user.id))
    )
    if user.picture_key:
        keys.append(user.picture_key)
    await db.delete(user)
    await db.commit()
    for key in keys:
        await delete_object(key)
    return Response(status_code=204)


async def _legacy_notes(db: AsyncSession, user: User) -> list[NoteResponse]:
    if not user.legacy_linked:
        return []
    rows = await legacy_supabase.get_user_data(user.id, "notes")
    overrides = {
        row.legacy_id: row
        for row in await db.scalars(
            select(LegacyNoteOverride).where(LegacyNoteOverride.user_id == user.id)
        )
    }
    results = []
    for row in rows:
        item_id = str(row.get("id", ""))
        if not item_id:
            continue
        override = overrides.get(item_id)
        if override and override.deleted:
            continue
        results.append(
            NoteResponse(
                id=item_id,
                title=override.title if override and override.title is not None else str(row.get("title") or ""),
                details=override.details if override and override.details is not None else str(row.get("details") or ""),
                created_at=row.get("created_at") or utc_now().isoformat(),
                createdby=user.id,
                source="legacy",
            )
        )
    return results


@app.get(f"{settings.api_prefix}/notes", response_model=list[NoteResponse])
async def list_notes(user: CurrentUser, db: DbSession):
    local = await db.scalars(
        select(Note).where(Note.user_id == user.id).order_by(Note.created_at)
    )
    by_id = {
        note.id: NoteResponse(
            id=note.id,
            title=note.title,
            details=note.details,
            created_at=note.created_at,
            createdby=user.id,
            source="neon",
        )
        for note in local
    }
    for legacy in await _legacy_notes(db, user):
        by_id.setdefault(legacy.id, legacy)
    return sorted(by_id.values(), key=lambda item: str(item.created_at))


@app.post(f"{settings.api_prefix}/notes", response_model=NoteResponse, status_code=201)
async def create_note(payload: NoteCreate, user: CurrentUser, db: DbSession):
    note = Note(
        id=payload.id,
        user_id=user.id,
        title=payload.title,
        details=payload.details,
        created_at=payload.created_at or utc_now(),
    )
    db.add(note)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        existing = await db.scalar(
            select(Note).where(Note.id == payload.id, Note.user_id == user.id)
        )
        if existing is None:
            raise HTTPException(status_code=409, detail="A note with this ID already exists.") from exc
        return NoteResponse(
            id=existing.id,
            title=existing.title,
            details=existing.details,
            created_at=existing.created_at,
            createdby=user.id,
            source="neon",
        )
    return NoteResponse(
        id=note.id,
        title=note.title,
        details=note.details,
        created_at=note.created_at,
        createdby=user.id,
        source="neon",
    )


async def _find_legacy_note(db: AsyncSession, user: User, note_id: str) -> dict[str, Any] | None:
    if not user.legacy_linked:
        return None
    for row in await legacy_supabase.get_user_data(user.id, "notes"):
        if str(row.get("id", "")) == note_id:
            return row
    return None


@app.put(f"{settings.api_prefix}/notes/{{note_id}}", response_model=NoteResponse)
async def update_note(note_id: str, payload: NoteUpdate, user: CurrentUser, db: DbSession):
    note = await db.scalar(select(Note).where(Note.id == note_id, Note.user_id == user.id))
    if note is not None:
        note.title, note.details = payload.title, payload.details
        await db.commit()
        return NoteResponse(
            id=note.id, title=note.title, details=note.details,
            created_at=note.created_at, createdby=user.id, source="neon"
        )
    legacy = await _find_legacy_note(db, user, note_id)
    if legacy is None:
        raise HTTPException(status_code=404, detail="Note not found.")
    override = await db.scalar(
        select(LegacyNoteOverride).where(
            LegacyNoteOverride.user_id == user.id, LegacyNoteOverride.legacy_id == note_id
        )
    )
    if override is None:
        override = LegacyNoteOverride(id=str(uuid4()), user_id=user.id, legacy_id=note_id)
        db.add(override)
    override.title, override.details, override.deleted = payload.title, payload.details, False
    await db.commit()
    return NoteResponse(
        id=note_id, title=payload.title, details=payload.details,
        created_at=legacy.get("created_at") or utc_now().isoformat(),
        createdby=user.id, source="legacy"
    )


@app.delete(f"{settings.api_prefix}/notes/{{note_id}}", status_code=204)
async def delete_note(note_id: str, user: CurrentUser, db: DbSession):
    note = await db.scalar(select(Note).where(Note.id == note_id, Note.user_id == user.id))
    if note is not None:
        await db.delete(note)
        await db.commit()
        return Response(status_code=204)
    if await _find_legacy_note(db, user, note_id) is None:
        raise HTTPException(status_code=404, detail="Note not found.")
    override = await db.scalar(
        select(LegacyNoteOverride).where(
            LegacyNoteOverride.user_id == user.id, LegacyNoteOverride.legacy_id == note_id
        )
    )
    if override is None:
        override = LegacyNoteOverride(id=str(uuid4()), user_id=user.id, legacy_id=note_id)
        db.add(override)
    override.deleted = True
    await db.commit()
    return Response(status_code=204)


async def _legacy_records(db: AsyncSession, user: User) -> list[RecordResponse]:
    if not user.legacy_linked:
        return []
    rows = await legacy_supabase.get_user_data(user.id, "records")
    deleted = {
        row.legacy_id
        for row in await db.scalars(
            select(LegacyRecordOverride).where(
                LegacyRecordOverride.user_id == user.id, LegacyRecordOverride.deleted.is_(True)
            )
        )
    }
    return [
        RecordResponse(
            id=str(row["id"]),
            title=str(row.get("title") or ""),
            url=str(row.get("url") or ""),
            user_id=user.id,
            created_at=row.get("created_at") or utc_now().isoformat(),
            source="legacy",
        )
        for row in rows
        if row.get("id") and str(row["id"]) not in deleted
    ]


@app.get(f"{settings.api_prefix}/records", response_model=list[RecordResponse])
async def list_records(user: CurrentUser, db: DbSession):
    records = await db.scalars(
        select(Record).where(Record.user_id == user.id).order_by(Record.created_at)
    )
    by_id = {
        record.id: RecordResponse(
            id=record.id,
            title=record.title,
            url=object_url(record.object_key),
            user_id=user.id,
            created_at=record.created_at,
            source="neon",
        )
        for record in records
    }
    for legacy in await _legacy_records(db, user):
        by_id.setdefault(legacy.id, legacy)
    return sorted(by_id.values(), key=lambda item: str(item.created_at))


@app.post(f"{settings.api_prefix}/records", response_model=RecordResponse, status_code=201)
async def upload_record(
    user: CurrentUser,
    db: DbSession,
    id: Annotated[str, Form(min_length=1, max_length=128)],
    file: UploadFile = File(...),
    title: Annotated[str, Form(max_length=500)] = "",
    created_at: Annotated[datetime | None, Form()] = None,
):
    existing = await db.scalar(select(Record).where(Record.id == id, Record.user_id == user.id))
    key = await save_upload(file, user.id, "audio", stable_id=id)
    if existing is None:
        record = Record(
            id=id,
            user_id=user.id,
            title=title,
            object_key=key,
            created_at=created_at or utc_now(),
        )
        db.add(record)
    else:
        existing.title, existing.object_key = title, key
        record = existing
    await db.commit()
    return RecordResponse(
        id=record.id, title=record.title, url=object_url(record.object_key),
        user_id=user.id, created_at=record.created_at, source="neon"
    )


@app.delete(f"{settings.api_prefix}/records/{{record_id}}", status_code=204)
async def delete_record(record_id: str, user: CurrentUser, db: DbSession):
    record = await db.scalar(
        select(Record).where(Record.id == record_id, Record.user_id == user.id)
    )
    if record is not None:
        key = record.object_key
        await db.delete(record)
        await db.commit()
        await delete_object(key)
        return Response(status_code=204)
    if not any(item.id == record_id for item in await _legacy_records(db, user)):
        raise HTTPException(status_code=404, detail="Recording not found.")
    override = await db.scalar(
        select(LegacyRecordOverride).where(
            LegacyRecordOverride.user_id == user.id,
            LegacyRecordOverride.legacy_id == record_id,
        )
    )
    if override is None:
        db.add(LegacyRecordOverride(id=str(uuid4()), user_id=user.id, legacy_id=record_id, deleted=True))
    else:
        override.deleted = True
    await db.commit()
    return Response(status_code=204)


@app.get("/")
async def root() -> dict[str, str]:
    return {"name": settings.app_name, "docs": "/docs"}