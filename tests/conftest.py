import os

os.environ.setdefault("NEON_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret-with-more-than-thirty-two-characters")
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SUPABASE_URL", "https://legacy.example.test")
os.environ.setdefault("SUPABASE_ANON_KEY", "test-anon")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "test-service-role")

from fastapi.testclient import TestClient
import pytest

from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
