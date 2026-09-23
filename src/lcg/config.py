"""Loading policy and decision files (YAML or JSON)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from lcg.models import Decision, Policy


class ConfigError(ValueError):
    """A policy or decision file is malformed."""


def load_policy(path: Path) -> Policy:
    data = _read_mapping(path)
    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid policy {path}: {exc}") from exc


def load_decisions(path: Path | None) -> list[Decision]:
    """Load decisions from a file or from every ``*.yaml`` in a directory."""
    if path is None:
        return []
    files = sorted(_decision_files(path))
    decisions: list[Decision] = []
    for file in files:
        for entry in _read_decision_entries(file):
            try:
                decisions.append(Decision.model_validate(entry))
            except ValidationError as exc:
                raise ConfigError(f"invalid decision in {file}: {exc}") from exc
    return decisions


def _decision_files(path: Path) -> list[Path]:
    if path.is_dir():
        return [p for p in path.iterdir() if p.suffix in {".yaml", ".yml", ".json"}]
    return [path]


def _read_decision_entries(path: Path) -> list[Any]:
    data = _read(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        entries = data.get("decisions", [data])
        if isinstance(entries, list):
            return entries
    raise ConfigError(f"{path} must contain a decision, a list of decisions or a 'decisions' key")


def _read(path: Path) -> Any:
    if not path.is_file():
        raise ConfigError(f"file not found: {path}")
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML/JSON: {exc}") from exc


def _read_mapping(path: Path) -> dict[str, Any]:
    data = _read(path)
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping")
    return data
