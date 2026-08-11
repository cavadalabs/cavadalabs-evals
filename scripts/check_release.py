#!/usr/bin/env python3
"""Fail closed on local metadata and public-release decisions."""

from __future__ import annotations

import argparse
import ast
import os
import re
import tomllib
from datetime import date
from pathlib import Path

VERSION = re.compile(r"\d+\.\d+\.\d+")
DECISIONS = {"ready", "blocked", "excluded", "reference-only"}
INVENTORY_HEADER = ["Material", "Current declaration", "Decision", "Condition"]
REQUIRED_ROWS = {
    "`suites/cavada-core-assistant-text-v1`",
    "`suites/security-privacy-smoke-v1`",
    "`suites/template`",
    "Repository organization approval",
    "Historical Git author email disclosure",
}


def _assigned_string(path: Path, name: str) -> str:
    values = [
        node.value.value
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if len(values) != 1:
        raise ValueError(f"{path} must assign {name} exactly once")
    return values[0]


def _cli_version(path: Path) -> str:
    values: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if not isinstance(node, ast.Call) or not any(isinstance(argument, ast.Constant) and argument.value == "--version" for argument in node.args):
            continue
        action = next((item.value.value for item in node.keywords if item.arg == "action" and isinstance(item.value, ast.Constant)), None)
        value = next((item.value.value for item in node.keywords if item.arg == "version" and isinstance(item.value, ast.Constant)), None)
        if action == "version" and isinstance(value, str):
            values.append(value)
    if len(values) != 1:
        raise ValueError(f"{path} must declare one static --version action")
    return values[0]


def _cff_field(path: Path, field: str) -> str:
    values = [
        line.split(":", 1)[1].strip().strip("'\"")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith(f"{field}:")
    ]
    if len(values) != 1:
        raise ValueError(f"{path} must declare one top-level {field}")
    return values[0]


def _inventory(path: Path) -> tuple[list[str], dict[str, str]]:
    errors: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    header = "| " + " | ".join(INVENTORY_HEADER) + " |"
    if lines.count(header) != 1:
        return [f"{path} must contain the exact publication inventory header"], {}
    start = lines.index(header)
    if start + 1 >= len(lines) or [cell.strip() for cell in lines[start + 1].strip()[1:-1].split("|")] != ["---"] * 4:
        return [f"{path} must contain a four-column separator"], {}
    rows: dict[str, str] = {}
    for number, line in enumerate(lines[start + 2 :], start + 3):
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip()[1:-1].split("|")]
        if len(cells) != 4 or any(not cell for cell in cells):
            errors.append(f"{path}:{number} must contain four non-empty cells")
            continue
        material, _, decision, _ = cells
        if material in rows:
            errors.append(f"{path}:{number} duplicates material {material!r}")
        if decision not in DECISIONS:
            errors.append(f"{path}:{number} has unknown decision {decision!r}")
        rows[material] = decision
    if not rows:
        errors.append(f"{path} contains no inventory rows")
    for material in sorted(REQUIRED_ROWS):
        if material not in rows:
            errors.append(f"{path} is missing required decision row {material!r}")
    return errors, rows


def validate(root: Path, *, release: bool = False, tag: str = "") -> list[str]:
    errors: list[str] = []
    try:
        with (root / "pyproject.toml").open("rb") as handle:
            version = str(tomllib.load(handle)["project"]["version"])
        versions = {
            "pyproject.toml": version,
            "src/cavada_eval/__init__.py": _assigned_string(root / "src/cavada_eval/__init__.py", "__version__"),
            "cavada-eval --version": _cli_version(root / "src/cavada_eval/cli.py").removeprefix("cavadalabs-evals "),
            "CITATION.cff": _cff_field(root / "CITATION.cff", "version"),
        }
        if not VERSION.fullmatch(version):
            errors.append("project version must be semantic X.Y.Z")
        for source, candidate in versions.items():
            if candidate != version:
                errors.append(f"version mismatch: {source}={candidate!r}, expected {version!r}")

        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        release_dates = re.findall(rf"^## {re.escape(version)} - (\d{{4}}-\d{{2}}-\d{{2}})\s*$", changelog, re.MULTILINE)
        if len(release_dates) != 1:
            errors.append(f"CHANGELOG.md must contain exactly one dated {version} release heading")
        else:
            try:
                date.fromisoformat(release_dates[0])
            except ValueError:
                errors.append("CHANGELOG.md release date must be a real calendar date")
            if _cff_field(root / "CITATION.cff", "date-released") != release_dates[0]:
                errors.append("CITATION.cff date-released must match the changelog release date")
        unreleased = re.search(r"^## Unreleased\s*$\n(?P<body>.*?)(?=^## |\Z)", changelog, re.MULTILINE | re.DOTALL)
        if unreleased is None:
            errors.append("CHANGELOG.md must contain an Unreleased section")
        elif release and unreleased.group("body").strip():
            errors.append("CHANGELOG.md Unreleased must be empty for a release tag")

        inventory_errors, decisions = _inventory(root / "docs/PUBLICATION_INVENTORY.md")
        errors.extend(inventory_errors)
        if release:
            if tag != f"v{version}":
                errors.append(f"release tag must be v{version}, got {tag!r}")
            blocked = sorted(
                material
                for material, decision in decisions.items()
                if decision == "blocked" or material in REQUIRED_ROWS and decision != "ready"
            )
            if blocked:
                errors.append("publication inventory remains blocked: " + ", ".join(blocked))
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
