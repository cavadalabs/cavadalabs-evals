#!/usr/bin/env python3
"""Check version and publication metadata without publishing anything."""

from __future__ import annotations

import argparse
import ast
import os
import re
import tomllib
from pathlib import Path

VERSION = re.compile(r"\d+\.\d+\.\d+(?:\.dev\d+)?")
STABLE_VERSION = re.compile(r"\d+\.\d+\.\d+")


def _assigned_version(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if len(values) != 1:
        raise ValueError(f"{path} must assign __version__ exactly once")
    return values[0]


def _cff_version(path: Path) -> str:
    values = [line.split(":", 1)[1].strip().strip("'\"") for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("version:")]
    if len(values) != 1:
        raise ValueError(f"{path} must contain one top-level version")
    return values[0]


def validate(root: Path, *, release: bool = False, tag: str = "") -> list[str]:
    errors: list[str] = []
    try:
        with (root / "pyproject.toml").open("rb") as handle:
            version = str(tomllib.load(handle)["project"]["version"])
        observed = {
            "src/cavada_eval/__init__.py": _assigned_version(root / "src/cavada_eval/__init__.py"),
            "CITATION.cff": _cff_version(root / "CITATION.cff"),
        }
        if VERSION.fullmatch(version) is None:
            errors.append("project version must be X.Y.Z or X.Y.Z.devN")
        errors.extend(f"version mismatch: {path}={value!r}, expected {version!r}" for path, value in observed.items() if value != version)
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        if f"## Unreleased ({version})" not in changelog:
            errors.append(f"CHANGELOG.md must identify the current development version {version}")
        required = (
            "README.md",
            "PROTOCOL.md",
            "GOVERNANCE.md",
            "RESULTS_POLICY.md",
            "docs/THREAT_MODEL.md",
            "results/registry.json",
            "results/registry-v2.json",
        )
        errors.extend(f"required release input is missing: {path}" for path in required if not (root / path).is_file())
        if release:
            if STABLE_VERSION.fullmatch(version) is None:
                errors.append("a release tag cannot use a development version")
            if tag != f"v{version}":
                errors.append(f"release tag must be v{version}, got {tag!r}")
    except (KeyError, OSError, SyntaxError, tomllib.TOMLDecodeError, ValueError) as exc:
        errors.append(str(exc))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--tag", default=os.getenv("GITHUB_REF_NAME", ""))
    args = parser.parse_args()
    errors = validate(args.root.resolve(), release=args.release, tag=args.tag)
    if errors:
        print("Release checks failed:\n- " + "\n- ".join(errors))
        return 1
    print("Release checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
