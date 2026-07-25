"""Application configuration with environment variables."""
import os
from functools import lru_cache
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://quadseer:quadseer_dev_password@db:5432/quadseer"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

    # Security
    SECRET_KEY: str = "change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day

    # Celery
    CELERY_BROKER_URL: str = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/0"

    # OSINT API Keys
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""

    # Billing
    FLUTTERWAVE_SECRET_KEY: str = ""
    FLUTTERWAVE_PUBLIC_KEY: str = ""
    FLUTTERWAVE_WEBHOOK_HASH: str = ""

    # Email (NEW: SMTP support)
    SMTP_HOST: str = "smtp.sendgrid.net"
    SMTP_PORT: int = 587
    SMTP_USER: str = "apikey"
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "noreply@quadseer.local"
    SMTP_TLS: bool = True

    # Slack (NEW)
    SLACK_WEBHOOK_URL: str = ""

    # Sentry (NEW)
    SENTRY_DSN: str = ""

    # App
    APP_NAME: str = "QuadSeer"
    APP_URL: str = "http://localhost:8000"

    class Config:
        env_file = ".env"
        extra = "ignore"

@lru_cache()
def get_settings() -> Settings:
    return Settings()
