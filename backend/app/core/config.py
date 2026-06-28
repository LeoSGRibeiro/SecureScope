from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path
from typing import List
import secrets

_VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"


def _read_version() -> str:
    try:
        return _VERSION_FILE.read_text().strip()
    except OSError:
        return "0.0.0"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    # App
    APP_NAME: str = "ThreatLens"
    APP_VERSION: str = _read_version()
    APP_AUTHOR: str = "Leonardo Ribeiro"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # Security
    SECRET_KEY: str = secrets.token_urlsafe(64)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://securescope:securescope@db:5432/securescope"
    DATABASE_SYNC_URL: str = "postgresql://securescope:securescope@db:5432/securescope"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/2"

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:80"]

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    SCAN_RATE_LIMIT: int = 10

    # Scanner timeouts (seconds)
    HTTP_TIMEOUT: int = 15
    DNS_TIMEOUT: int = 10
    SSL_TIMEOUT: int = 10
    MAX_SCAN_DURATION: int = 300

    # File storage
    UPLOAD_DIR: str = "/app/uploads"
    REPORTS_DIR: str = "/app/reports"
    MAX_UPLOAD_SIZE: int = 10_485_760  # 10 MB

    # Email (optional)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    EMAILS_FROM: str = "noreply@securescope.local"

    # Ethical use
    REQUIRE_ETHICS_ACCEPTANCE: bool = True
    AUDIT_LOG_RETENTION_DAYS: int = 365


settings = Settings()
