from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    auth_issuer: str
    auth_audience: str = "myimpact-platform"
    auth_private_key_file: Path = Path("keys/private.pem")
    auth_public_key_file: Path = Path("keys/public.pem")
    auth_key_id: str = "myimpact-local-1"
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    refresh_token_max_days: int = 90
    cookie_secure: bool = True
    allowed_origins: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
