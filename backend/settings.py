from __future__ import annotations

from dataclasses import dataclass

from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL


API_VERSION = "0.1.0"


@dataclass(frozen=True)
class Settings:
    app_name: str = "RAVEN-SOC API"
    service_name: str = "raven-soc-api"
    version: str = API_VERSION
    ollama_url: str = DEFAULT_OLLAMA_URL
    default_ollama_model: str = DEFAULT_OLLAMA_MODEL


settings = Settings()
