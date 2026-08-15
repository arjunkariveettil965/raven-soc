import os
from pathlib import Path
import pytest

from backend.settings import Settings, DEFAULT_API_DB_PATH, _validate_safe_db_path

@pytest.fixture(autouse=True)
def reset_env(monkeypatch):
    # Ensure environment variable is cleared before each test
    monkeypatch.delenv("RAVEN_API_DB_PATH", raising=False)
    yield
    monkeypatch.delenv("RAVEN_API_DB_PATH", raising=False)

def test_validate_safe_db_path_accepts_valid_relative_path(monkeypatch):
    monkeypatch.setenv("RAVEN_API_DB_PATH", "database/custom.db")
    settings = Settings()
    expected = Path("database/custom.db")
    assert settings.api_database_path == expected
    assert _validate_safe_db_path("database/custom.db") == expected

def test_validate_safe_db_path_rejects_path_traversal(monkeypatch):
    monkeypatch.setenv("RAVEN_API_DB_PATH", "../../outside.db")
    settings = Settings()
    assert settings.api_database_path == DEFAULT_API_DB_PATH
    assert _validate_safe_db_path("../../outside.db") == DEFAULT_API_DB_PATH

def test_validate_safe_db_path_absolute_path_outside_workspace(monkeypatch, tmp_path):
    outside_path = tmp_path / "outside.db"
    outside_path.touch()
    monkeypatch.setenv("RAVEN_API_DB_PATH", str(outside_path))
    settings = Settings()
    assert settings.api_database_path == DEFAULT_API_DB_PATH
    assert _validate_safe_db_path(str(outside_path)) == DEFAULT_API_DB_PATH

def test_validate_safe_db_path_missing_env_uses_default():
    settings = Settings()
    assert settings.api_database_path == DEFAULT_API_DB_PATH
