"""Configuration-file loading for the maintenance command-line interface."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .baseline import InputError, load_json

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "maintenance.json"
CONFIG_ENVIRONMENT_VARIABLE = "TARA_MAINTENANCE_CONFIG"
PATH_FIELDS = ("tara_path", "architecture_path", "changes_path", "output_path")


def find_config_path(explicit_path: str | None) -> Path | None:
    """Resolve an explicit/environment path, or discover the local config."""

    configured = explicit_path or os.environ.get(CONFIG_ENVIRONMENT_VARIABLE)
    if configured:
        return resolve_path(configured, Path.cwd())
    if DEFAULT_CONFIG_PATH.is_file():
        return DEFAULT_CONFIG_PATH
    return None


def load_config(path: Path) -> dict[str, Any]:
    """Load and validate non-secret local path configuration."""

    config = load_json(path)
    if config.get("schema_version") != "1.0":
        raise InputError(f"Config {path} must declare schema_version '1.0'")
    for field in PATH_FIELDS:
        value = config.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise InputError(f"Config {path}: {field} must be a non-empty string or null")
    return config


def resolve_path(value: str, base_directory: Path) -> Path:
    """Resolve a configured path without requiring it to exist."""

    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base_directory / path
    return path.resolve()
