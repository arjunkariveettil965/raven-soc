import json
import urllib.error
from unittest.mock import patch

import pytest

from ai_analyst.ollama_client import check_ollama_health, generate_structured_analysis


class MockResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def test_health_check_returns_available_and_models():
    payload = {"models": [{"name": "gemma3:1b"}, {"name": "llama3.2:1b"}]}
    with patch("urllib.request.urlopen", return_value=MockResponse(payload)):
        health = check_ollama_health()

    assert health == {
        "available": True,
        "base_url": "http://localhost:11434",
        "models": ["gemma3:1b", "llama3.2:1b"],
        "error": None,
    }


def test_health_check_handles_connection_failure():
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
        health = check_ollama_health()

    assert health["available"] is False
    assert health["base_url"] == "http://localhost:11434"
    assert health["models"] == []
    assert "offline" in str(health["error"])


def test_structured_analysis_parses_valid_json():
    analysis = {"Status": "benign"}
    payload = {"message": {"content": json.dumps(analysis)}}
    with patch("urllib.request.urlopen", return_value=MockResponse(payload)):
        result = generate_structured_analysis("prompt", {"type": "object"})

    assert result == analysis


def test_structured_analysis_parses_markdown_fenced_json():
    analysis = {"Status": "benign"}
    payload = {"message": {"content": f"```json\n{json.dumps(analysis)}\n```"}}
    with patch("urllib.request.urlopen", return_value=MockResponse(payload)):
        result = generate_structured_analysis("prompt", {"type": "object"})

    assert result == analysis


def test_structured_analysis_invalid_json_raises_runtime_error():
    payload = {"message": {"content": "not-json"}}
    with patch("urllib.request.urlopen", return_value=MockResponse(payload)):
        with pytest.raises(RuntimeError, match="invalid JSON"):
            generate_structured_analysis("prompt", {"type": "object"})


def test_structured_analysis_missing_content_raises_runtime_error():
    payload = {"message": {}}
    with patch("urllib.request.urlopen", return_value=MockResponse(payload)):
        with pytest.raises(RuntimeError, match="message content"):
            generate_structured_analysis("prompt", {"type": "object"})
