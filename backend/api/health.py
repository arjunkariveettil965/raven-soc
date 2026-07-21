from __future__ import annotations

import sqlite3

from fastapi import APIRouter

from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL
from backend.settings import settings
from database.database import DATABASE_PATH


router = APIRouter(prefix="/health", tags=["health"])


def _database_available() -> bool:
    try:
        connection = sqlite3.connect(f"file:{DATABASE_PATH}?mode=ro", uri=True)
        try:
            connection.execute("SELECT 1").fetchone()
        finally:
            connection.close()
        return True
    except sqlite3.Error:
        return False


@router.get("")
def health() -> dict[str, object]:
    database_available = _database_available()
    return {
        "status": "healthy" if database_available else "unhealthy",
        "service": settings.service_name,
        "version": settings.version,
        "database": {"available": database_available},
        "ollama": {
            "configured_url": DEFAULT_OLLAMA_URL,
            "default_model": DEFAULT_OLLAMA_MODEL,
            "checked": False,
        },
        "capabilities": {
            "scenario_lab": True,
            "detection": True,
            "correlation": True,
            "hybrid_analyst": True,
            "simulated_defender": True,
        },
    }
