from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL


API_VERSION = "0.1.0"
DEFAULT_API_DB_PATH = Path("database") / "raven_soc_api.db"


def _allowed_origins() -> list[str]:
    configured = os.getenv("RAVEN_API_ALLOWED_ORIGINS")
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip() and origin.strip() != "*"]
    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


@dataclass(frozen=True)
class Settings:
    app_name: str = "RAVEN-SOC API"
    service_name: str = "raven-soc-api"
    version: str = API_VERSION
    ollama_url: str = DEFAULT_OLLAMA_URL
    default_ollama_model: str = DEFAULT_OLLAMA_MODEL
    api_database_path: Path = Path(os.getenv("RAVEN_API_DB_PATH", str(DEFAULT_API_DB_PATH)))
    allowed_cors_origins: tuple[str, ...] = tuple(_allowed_origins())
    environment_name: str = os.getenv("RAVEN_API_ENV", "development")
    default_host: str = "127.0.0.1"
    default_port: int = 8000
    repository_backend: str = os.getenv("RAVEN_API_REPOSITORY", "sqlite")


settings = Settings()
