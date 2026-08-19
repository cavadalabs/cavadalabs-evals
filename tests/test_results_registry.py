from __future__ import annotations

import json
import runpy
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).parents[1]
TOOLS = runpy.run_path(str(ROOT / "scripts" / "validate_results_registry.py"))
validate_registry = cast(Callable[..., list[str]], TOOLS["validate_registry"])


def test_registry_v1_is_exactly_empty() -> None:
    registry = json.loads((ROOT / "results" / "registry.json").read_text(encoding="utf-8"))
    assert validate_registry(registry, initial_empty=True) == []


def test_registry_v1_fails_closed_on_any_result() -> None:
    registry: dict[str, Any] = {"registry_version": "1.0.0", "results": [{"rankable": False}]}
    assert "must remain empty" in "\n".join(validate_registry(registry))
