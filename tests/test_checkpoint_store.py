import json

import pytest

from collector.checkpoint_store import (
    get_checkpoint,
    load_checkpoints,
    update_checkpoint,
)


def test_missing_file_returns_empty_checkpoints(tmp_path):
    assert load_checkpoints(tmp_path / "missing.json") == {}


def test_checkpoint_update_is_persisted(tmp_path):
    checkpoint_path = tmp_path / "live_checkpoints.json"

    update_checkpoint("System", 42, path=checkpoint_path)

    assert get_checkpoint("System", path=checkpoint_path) == 42


def test_checkpoint_cannot_move_backwards(tmp_path):
    checkpoint_path = tmp_path / "live_checkpoints.json"

    update_checkpoint("System", 42, path=checkpoint_path)
    update_checkpoint("System", 10, path=checkpoint_path)

    assert get_checkpoint("System", path=checkpoint_path) == 42


def test_invalid_json_raises_value_error(tmp_path):
    checkpoint_path = tmp_path / "live_checkpoints.json"
    checkpoint_path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid checkpoint JSON"):
        load_checkpoints(checkpoint_path)


def test_multiple_channels_are_preserved(tmp_path):
    checkpoint_path = tmp_path / "live_checkpoints.json"

    update_checkpoint("System", 5, path=checkpoint_path)
    update_checkpoint("Application", 9, path=checkpoint_path)

    assert json.loads(checkpoint_path.read_text(encoding="utf-8")) == {
        "Application": 9,
        "System": 5,
    }
