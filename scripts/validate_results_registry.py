#!/usr/bin/env python3
"""Validate the reserved v1 or content-addressed v2 public results registry."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cavada_eval.protocol import _strict_json_loads
from cavada_eval.results_registry import validate_registry_v2, verify_github_attestation


def _load(path: Path) -> dict[str, Any]:
    try:
        value = _strict_json_loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{path} must be a readable strict JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be a readable strict JSON object")
    return value


def validate_registry(
    registry: dict[str, Any],
    *,
    previous: dict[str, Any] | None = None,
    initial_empty: bool = False,
    root: Path | None = None,
    verify_attestations_online: bool = False,
    **options: Any,
) -> list[str]:
    if registry.get("registry_version") == "2.0.0":
        return validate_registry_v2(
            registry,
            root=root,
            previous=previous,
            initial_empty=initial_empty,
            attestation_verifier=verify_github_attestation if verify_attestations_online else None,
            **options,
        )
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
    parser.add_argument(
        "--verify-attestations-online",
        action="store_true",
        help="Use gh attestation verify; without this flag v2 official records fail closed",
    )
    args = parser.parse_args()
    try:
        registry = _load(args.registry)
        errors = validate_registry(
            registry,
            previous=_load(args.previous) if args.previous else None,
            initial_empty=args.initial_empty,
            root=args.registry.parent,
            verify_attestations_online=args.verify_attestations_online,
        )
    except ValueError as exc:
        print(f"Invalid results registry: {exc}")
        return 1
    if errors:
        print("Invalid results registry:\n" + "\n".join(errors))
        return 1
    print(f"Results registry v{registry.get('registry_version')} is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
