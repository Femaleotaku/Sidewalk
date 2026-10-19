# apps/api/src/core/config.py
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Typed application settings validated at startup using Pydantic BaseSettings.
    """

    # Required fields without defaults (must be provided via environment or .env)
    DATABASE_URL: str
    SECRET_KEY: str

    # Fields with sensible defaults
    ENVIRONMENT: str = "development"
    API_VERSION: str = "0.1.0"
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8081"]
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRES_MINUTES: int = 1440  # 24 hours
    LOGIN_MAX_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15
    LOG_LEVEL: str = "INFO"

    # Database connection pool (PostgreSQL only; SQLite ignores these)
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE_SECONDS: int = 1800

    # Rate limiting (slowapi). Use a shared store such as ``redis://host:6379/0`` when
    # running more than one worker; the in-memory default is per process.
    RATE_LIMIT_DEFAULT: str = "200/minute"
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_STORAGE_URI: str | None = None
    # Comma-separated proxy addresses whose X-Forwarded-For header is trusted.
    TRUSTED_PROXY_IPS: str = ""

    @property
    def trusted_proxy_ips(self) -> frozenset[str]:
        return frozenset(ip.strip() for ip in self.TRUSTED_PROXY_IPS.split(",") if ip.strip())

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    """
    Returns a cached instance of the application Settings.
    Fails at startup with a validation error if required fields are missing.
    """
    return Settings()
