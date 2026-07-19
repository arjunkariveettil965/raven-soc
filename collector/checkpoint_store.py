from __future__ import annotations

import json
from pathlib import Path


DEFAULT_CHECKPOINT_PATH = Path("data/live_checkpoints.json")


def load_checkpoints(
    path: str | Path = DEFAULT_CHECKPOINT_PATH,
) -> dict[str, int]:
    checkpoint_path = Path(path)

    if not checkpoint_path.exists():
        return {}

    try:
        raw_checkpoints = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid checkpoint JSON in {checkpoint_path}: {error.msg}"
        ) from error

    if not isinstance(raw_checkpoints, dict):
        raise ValueError(
            f"Invalid checkpoint JSON in {checkpoint_path}: expected an object."
        )

    checkpoints: dict[str, int] = {}
    for channel, record_id in raw_checkpoints.items():
        try:
            checkpoints[str(channel)] = int(record_id)
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"Invalid checkpoint value for channel {channel!r}: {record_id!r}"
            ) from error

    return checkpoints


def save_checkpoints(
    checkpoints: dict[str, int],
    path: str | Path = DEFAULT_CHECKPOINT_PATH,
) -> None:
    checkpoint_path = Path(path)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = checkpoint_path.with_name(f"{checkpoint_path.name}.tmp")
    serializable_checkpoints = {
        channel: int(record_id)
        for channel, record_id in checkpoints.items()
    }

    temporary_path.write_text(
        json.dumps(serializable_checkpoints, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temporary_path.replace(checkpoint_path)


def get_checkpoint(
    channel: str,
    path: str | Path = DEFAULT_CHECKPOINT_PATH,
) -> int:
    return int(load_checkpoints(path=path).get(channel, 0))


def update_checkpoint(
    channel: str,
    record_id: int,
    path: str | Path = DEFAULT_CHECKPOINT_PATH,
) -> None:
    checkpoints = load_checkpoints(path=path)
    current_record_id = int(checkpoints.get(channel, 0))
    next_record_id = max(current_record_id, int(record_id))

    checkpoints[channel] = next_record_id
    save_checkpoints(checkpoints=checkpoints, path=path)
