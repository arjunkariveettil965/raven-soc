from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path

from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL


API_VERSION = "0.1.0"
DEFAULT_API_DB_PATH = Path("database") / "raven_soc_api.db"


def _validate_safe_db_path(db_path_str: str) -> Path:
    db_path = Path(db_path_str)
    try:
        # Check if the resolved database path escapes the workspace root
        resolved = db_path.resolve()
        workspace_root = Path.cwd().resolve()
        if workspace_root not in resolved.parents and resolved != workspace_root:
            return DEFAULT_API_DB_PATH
    except Exception:
        return DEFAULT_API_DB_PATH
    return db_path


def _allowed_origins() -> list[str]:
    configured = os.getenv("RAVEN_API_ALLOWED_ORIGINS")
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip() and origin.strip() != "*"]
    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ]


@dataclass(frozen=True)
class Settings:
    app_name: str = "RAVEN-SOC API"
    service_name: str = "raven-soc-api"
    version: str = API_VERSION
    ollama_url: str = os.getenv("RAVEN_OLLAMA_URL", DEFAULT_OLLAMA_URL)
    default_ollama_model: str = os.getenv("RAVEN_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
    api_database_path: Path = field(
        default_factory=lambda: _validate_safe_db_path(
            os.getenv("RAVEN_API_DB_PATH", str(DEFAULT_API_DB_PATH))
        )
    )
    allowed_cors_origins: tuple[str, ...] = tuple(_allowed_origins())
    environment_name: str = os.getenv("RAVEN_API_ENV", "development")
    default_host: str = os.getenv("RAVEN_API_HOST", "127.0.0.1")
    default_port: int = int(os.getenv("PORT", "8000"))
    repository_backend: str = os.getenv("RAVEN_API_REPOSITORY", "sqlite")


settings = Settings()
