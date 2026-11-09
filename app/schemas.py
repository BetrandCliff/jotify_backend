from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints
from typing import Annotated


Password = Annotated[str, StringConstraints(min_length=8, max_length=128)]


class RegisterRequest(BaseModel):
    email: EmailStr
    password: Password
    full_name: Annotated[str, StringConstraints(min_length=1, max_length=160)]


class LoginRequest(BaseModel):
    email: EmailStr
    password: Password


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=1024)


class EmailCodeRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^\d{6}$")


class EmailRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(EmailCodeRequest):
    new_password: Password


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    picture: str | None
    is_verified: bool

    model_config = ConfigDict(from_attributes=True)


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class MessageResponse(BaseModel):
    message: str
    development_code: str | None = None


class NoteCreate(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    title: str = Field(default="", max_length=500)
    details: str = Field(default="", max_length=100_000)
    created_at: datetime | None = None


class NoteUpdate(BaseModel):
    title: str = Field(default="", max_length=500)
    details: str = Field(default="", max_length=100_000)


class NoteResponse(BaseModel):
    id: str
    title: str
    details: str
    created_at: datetime | str
    createdby: str
    is_synced: int = 1
    source: str = "neon"


class RecordResponse(BaseModel):
    id: str
    title: str
    url: str
    user_id: str
    created_at: datetime | str
    is_synced: int = 1
    source: str = "neon"


class ProfileUpdate(BaseModel):
    full_names: str | None = Field(default=None, max_length=160)
    email: EmailStr | None = None


class GoogleLoginRequest(BaseModel):
    id_token: str = Field(min_length=16, max_length=8192)