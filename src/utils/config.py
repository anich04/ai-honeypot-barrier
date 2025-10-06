"""Configuration helpers for the AI Honeypot Barrier project."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from src.utils.io import load_yaml


def load_config(path: Path) -> Dict[str, Any]:
    config = load_yaml(Path(path)) or {}
    base_dir = Path(path).resolve().parent.parent

    if "paths" in config:
        resolved_paths: Dict[str, Path] = {}
        for key, value in config["paths"].items():
            path_value = Path(str(value))
            if not path_value.is_absolute():
                path_value = (base_dir / path_value).resolve()
            resolved_paths[key] = path_value
        config["paths"] = resolved_paths

    return config
