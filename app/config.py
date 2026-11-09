from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "Planner API"
    app_env: str = "development"
    api_prefix: str = "/api/v1"
    cors_origins: str = "http://localhost:3000,http://localhost:8080"
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:password@localhost/planner",
        validation_alias="NEON_DATABASE_URL",
    )
    jwt_secret: SecretStr = Field(default=SecretStr(""), validation_alias="JWT_SECRET")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 20
    refresh_token_days: int = 30
    verification_token_minutes: int = 30
    password_reset_token_minutes: int = 30
    max_upload_bytes: int = 20 * 1024 * 1024

    supabase_url: str = ""
    supabase_anon_key: SecretStr = SecretStr("")
    supabase_service_role_key: SecretStr = SecretStr("")

    r2_account_id: str = ""
    r2_access_key_id: SecretStr = SecretStr("")
    r2_secret_access_key: SecretStr = SecretStr("")
    r2_bucket_name: str = ""
    r2_public_base_url: str = ""

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from_email: str = ""
    smtp_from_name: str = "Planner"
    smtp_use_tls: bool = True
    google_client_id: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    config = Settings()
    if config.is_production and len(config.jwt_secret.get_secret_value()) < 32:
        raise ValueError("JWT_SECRET must contain at least 32 characters in production.")
    if config.access_token_minutes < 1 or config.refresh_token_days < 1:
        raise ValueError("Token lifetimes must be positive.")
    return config


settings = get_settings()