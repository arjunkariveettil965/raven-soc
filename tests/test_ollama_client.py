import json
import urllib.error
from unittest.mock import patch

import pytest

from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, check_ollama_health, generate_structured_analysis


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
    payload = {"models": [{"name": DEFAULT_OLLAMA_MODEL}, {"name": "llama3.2:1b"}]}
    with patch("urllib.request.urlopen", return_value=MockResponse(payload)):
        health = check_ollama_health()

    assert health == {
        "available": True,
        "base_url": "http://localhost:11434",
        "models": [DEFAULT_OLLAMA_MODEL, "llama3.2:1b"],
        "error": None,
    }


def test_default_model_is_gemma_4b_it_qat():
    assert DEFAULT_OLLAMA_MODEL == "gemma3:4b-it-qat"


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


def test_structured_analysis_uses_custom_model_when_supplied():
    analysis = {"Status": "benign"}
    payload = {"message": {"content": json.dumps(analysis)}}
    captured = {}

    def capture_request(request, timeout):
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return MockResponse(payload)

    with patch("urllib.request.urlopen", side_effect=capture_request):
        result = generate_structured_analysis(
            "prompt",
            {"type": "object"},
            model="custom-local-model:latest",
        )

    assert result == analysis
    assert captured["payload"]["model"] == "custom-local-model:latest"


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
