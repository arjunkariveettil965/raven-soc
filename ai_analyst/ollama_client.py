from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "gemma3:1b"


def _join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}{path}"


def check_ollama_health(
    base_url: str = DEFAULT_OLLAMA_URL,
    timeout_seconds: float = 2.0,
) -> dict[str, object]:
    try:
        with urllib.request.urlopen(
            _join_url(base_url, "/api/tags"),
            timeout=timeout_seconds,
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        return {
            "available": False,
            "base_url": base_url,
            "models": [],
            "error": str(error),
        }

    models: list[str] = []
    for model in payload.get("models", []) if isinstance(payload, dict) else []:
        if isinstance(model, dict) and isinstance(model.get("name"), str):
            models.append(model["name"])

    return {
        "available": True,
        "base_url": base_url,
        "models": models,
        "error": None,
    }


def generate_structured_analysis(
    prompt: str,
    schema: dict[str, object],
    model: str = DEFAULT_OLLAMA_MODEL,
    base_url: str = DEFAULT_OLLAMA_URL,
    timeout_seconds: float = 90.0,
) -> dict[str, object]:
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are the constrained local Analyst Agent for RAVEN-SOC. "
                    "Use only supplied evidence. Return only data matching the "
                    "required JSON schema. Never generate commands, shell "
                    "instructions, PowerShell, or unapproved action names."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "stream": False,
        "format": schema,
        "options": {
            "temperature": 0,
        },
    }
    request = urllib.request.Request(
        _join_url(base_url, "/api/chat"),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response_payload: Any = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RuntimeError(f"Unable to connect to Ollama: {error}") from error
    except ValueError as error:
        raise RuntimeError(f"Invalid HTTP response from Ollama: {error}") from error

    try:
        content = response_payload["message"]["content"]
    except (TypeError, KeyError) as error:
        raise RuntimeError("Ollama response did not include message content.") from error

    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("Ollama response message content was empty.")

    try:
        analysis = json.loads(content)
    except ValueError as error:
        raise RuntimeError(f"Ollama returned invalid JSON: {error}") from error

    if not isinstance(analysis, dict):
        raise RuntimeError("Ollama JSON response must be a dictionary.")

    return analysis
