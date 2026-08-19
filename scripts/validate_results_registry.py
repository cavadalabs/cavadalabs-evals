#!/usr/bin/env python3
"""Keep the v1 public results registry empty until public verification is trustworthy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cavada_eval.protocol import _strict_json_loads


def _load(path: Path) -> dict[str, Any]:
    try:
        value = _strict_json_loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{path} must be a readable strict JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be a readable strict JSON object")
    return value


def validate_registry(
    registry: dict[str, Any],
    *,
    previous: dict[str, Any] | None = None,
    initial_empty: bool = False,
    **_unsupported: Any,
) -> list[str]:
    errors: list[str] = []
    if set(registry) != {"registry_version", "results"}:
        errors.append("registry fields must be exactly ['registry_version', 'results']")
    if registry.get("registry_version") != "1.0.0":
        errors.append("registry_version must be 1.0.0")
    if registry.get("results") != []:
        errors.append(
            "registry v1 must remain empty until sanitized public evidence, release approval, expiry, and revocation are independently verifiable"
        )
    if previous is not None and previous != {"registry_version": "1.0.0", "results": []}:
        errors.append("previous registry v1 must be the canonical empty registry")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registry", nargs="?", type=Path, default=Path("results/registry.json"))
    history = parser.add_mutually_exclusive_group()
    history.add_argument("--previous", type=Path)
    history.add_argument("--initial-empty", action="store_true")
    args = parser.parse_args()
    try:
        errors = validate_registry(
            _load(args.registry),
            previous=_load(args.previous) if args.previous else None,
            initial_empty=args.initial_empty,
        )
    except ValueError as exc:
        print(f"Invalid results registry: {exc}")
        return 1
    if errors:
        print("Invalid results registry:\n" + "\n".join(errors))
        return 1
    print("Results registry v1 is valid and intentionally empty")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
