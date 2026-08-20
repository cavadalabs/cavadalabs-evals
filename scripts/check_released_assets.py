#!/usr/bin/env python3
"""Reject mutations of assets already published by a semantic release tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import shutil
import subprocess
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable

SEMVER = re.compile(r"^(?:v)?(?P<version>\d+\.\d+\.\d+)$")
PROTOCOL_HEADING = re.compile(
    r"^# CavadaLabs (?P<family>Evaluation|LLM Serving Performance) Protocol v?(?P<version>\d+\.\d+(?:\.\d+)?)$"
)
RESULT_ARCHIVE = re.compile(r"^results/archive/sha256/(?P<digest>[a-f0-9]{64})\.tar$")
GIT = shutil.which("git")


@dataclass(frozen=True)
class Asset:
    kind: str
    family: str
    version: tuple[int, int, int]
    version_text: str
    source: str
    files: tuple[tuple[str, str], ...]

    @property
    def identity(self) -> tuple[str, str, tuple[int, int, int]]:
        return self.kind, self.family, self.version

    @property
    def display(self) -> str:
        if self.kind == "schema":
            return f"schema $id {self.family}/{self.version_text}"
        return f"{self.kind} {self.family}@{self.version_text}"


def _version(value: object, label: str) -> tuple[tuple[int, int, int], str]:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be semantic X.Y.Z")
    match = SEMVER.fullmatch(value)
    if match is None:
        raise ValueError(f"{label} must be semantic X.Y.Z")
    text = match.group("version")
    return tuple(map(int, text.split("."))), text  # type: ignore[return-value]


def _git(root: Path, *arguments: str) -> bytes:
    if GIT is None:
        raise ValueError("git is required")
    result = subprocess.run(  # noqa: S603 -- fixed executable; arguments never use a shell.
        [GIT, "-C", str(root), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(detail or f"git {' '.join(arguments)} failed")
    return result.stdout


def _tags(root: Path) -> list[str]:
    tags = _git(root, "tag", "--merged", "HEAD", "--list").decode("utf-8").splitlines()
    semantic = [(version, tag) for tag in tags if (version := _tag_version(tag)) is not None]
    if not semantic:
        raise ValueError("no semantic release tag is reachable from HEAD")
    return [tag for _, tag in sorted(semantic)]


def _tag_version(tag: str) -> tuple[int, int, int] | None:
    match = SEMVER.fullmatch(tag)
    return tuple(map(int, match.group("version").split("."))) if match else None  # type: ignore[return-value]


def _tag_snapshot(root: Path, tag: str) -> tuple[list[str], Callable[[str], bytes]]:
    paths = [item.decode("utf-8") for item in _git(root, "ls-tree", "-rz", "--name-only", tag).split(b"\0") if item]

    def read(relative: str) -> bytes:
        return _git(root, "show", f"{tag}:{relative}")

    return paths, read


def _worktree_snapshot(root: Path) -> tuple[list[str], Callable[[str], bytes]]:
    selected: set[Path] = set()
    for directory in (
        root / "suites",
        root / "schemas",
        root / "performance" / "plans",
        root / "performance" / "workloads",
        root / "results" / "archive",
    ):
        if directory.is_dir():
            selected.update(path for path in directory.rglob("*") if path.is_file() or path.is_symlink())
    selected.update(path for path in root.glob("*PROTOCOL*.md") if path.is_file() or path.is_symlink())
    paths = sorted(path.relative_to(root).as_posix() for path in selected)

    def read(relative: str) -> bytes:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"current asset is missing or unsafe: {relative}")
        return path.read_bytes()

    return paths, read


def _hashes(values: dict[str, bytes]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((name, hashlib.sha256(raw).hexdigest()) for name, raw in values.items()))


def _toml(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"invalid TOML in {label}: {exc}") from exc
    return value


def _schemas(paths: list[str], read: Callable[[str], bytes], source: str) -> list[Asset]:
    assets: list[Asset] = []
    for path in paths:
        if not path.startswith("schemas/") or not path.endswith(".json"):
            continue
        raw = read(path)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid JSON schema {source}:{path}") from exc
        identifier = value.get("$id") if isinstance(value, dict) else None
        if not isinstance(identifier, str) or "/" not in identifier:
            raise ValueError(f"schema {source}:{path} requires a versioned $id")
        family, version_value = identifier.rsplit("/", 1)
        version, version_text = _version(version_value, f"schema $id {identifier}")
        assets.append(Asset("schema", family, version, version_text, f"{source}:{path}", _hashes({"schema.json": raw})))
    return assets


def _suites(paths: list[str], read: Callable[[str], bytes], source: str) -> list[Asset]:
    assets: list[Asset] = []
    for config_path in paths:
        if not config_path.startswith("suites/") or not config_path.endswith("/suite.toml"):
            continue
        config = _toml(read(config_path), f"{source}:{config_path}")
        name = config.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"suite {source}:{config_path} requires a name")
        version, version_text = _version(config.get("version"), f"suite {name} version")
        prefix = config_path.removesuffix("suite.toml")
        members = {path.removeprefix(prefix): read(path) for path in paths if path.startswith(prefix)}
        assets.append(Asset("suite", name, version, version_text, f"{source}:{prefix}", _hashes(members)))
    return assets


def _safe_relative_asset(plan_path: str, relative: object) -> str:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"performance plan {plan_path} requires workload.path")
    candidate = posixpath.normpath(str(PurePosixPath(plan_path).parent / relative))
    if candidate.startswith("../") or candidate.startswith("/"):
        raise ValueError(f"performance plan {plan_path} has unsafe workload.path")
    return candidate


def _plans(paths: list[str], read: Callable[[str], bytes], source: str) -> list[Asset]:
    assets: list[Asset] = []
    available = set(paths)
    for path in paths:
        if not path.startswith("performance/plans/") or not path.endswith(".toml"):
            continue
        raw = read(path)
        plan = _toml(raw, f"{source}:{path}")
        name = plan.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"performance plan {source}:{path} requires a name")
        version, version_text = _version(plan.get("revision"), f"performance plan {name} revision")
        workload = plan.get("workload")
        workload_path = _safe_relative_asset(path, workload.get("path") if isinstance(workload, dict) else None)
        if workload_path not in available:
            raise ValueError(f"performance plan {source}:{path} references missing workload {workload_path}")
        assets.append(
            Asset(
                "performance-plan",
                name,
                version,
                version_text,
                f"{source}:{path}",
                _hashes({"plan.toml": raw, "workload": read(workload_path)}),
            )
        )
    return assets


def _protocols(paths: list[str], read: Callable[[str], bytes], source: str) -> list[Asset]:
    assets: list[Asset] = []
    for path in paths:
        if "/" in path or not re.fullmatch(r"(?:PERFORMANCE_)?PROTOCOL(?:_V\d+(?:_\d+)*)?\.md", path):
            continue
        raw = read(path)
        lines = raw.decode("utf-8", errors="strict").splitlines()
        if not lines:
            raise ValueError(f"protocol {source}:{path} is empty")
        first_line = lines[0]
        match = PROTOCOL_HEADING.fullmatch(first_line)
        if match is None:
            raise ValueError(f"protocol {source}:{path} requires a versioned heading")
        version_value = match.group("version")
        if version_value.count(".") == 1:
            version_value += ".0"
        version, version_text = _version(version_value, f"protocol {path} version")
        assets.append(
            Asset("protocol", match.group("family").casefold().replace(" ", "-"), version, version_text, f"{source}:{path}", _hashes({"document": raw}))
        )
    return assets


def _result_archives(paths: list[str], read: Callable[[str], bytes], source: str) -> list[Asset]:
    assets: list[Asset] = []
    for path in paths:
        match = RESULT_ARCHIVE.fullmatch(path)
        if match is None:
            continue
        raw = read(path)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != match.group("digest"):
            raise ValueError(f"results archive {source}:{path} digest does not match its content-addressed name")
        assets.append(Asset("results-archive", digest, (1, 0, 0), "1.0.0", f"{source}:{path}", _hashes({"archive.tar": raw})))
    return assets


def _assets(paths: list[str], read: Callable[[str], bytes], source: str) -> list[Asset]:
    return [
        *_schemas(paths, read, source),
        *_suites(paths, read, source),
        *_plans(paths, read, source),
        *_protocols(paths, read, source),
        *_result_archives(paths, read, source),
    ]


def validate(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    try:
        tags = _tags(root)
        released = [asset for tag in tags for asset in _assets(*_tag_snapshot(root, tag), tag)]
        current = _assets(*_worktree_snapshot(root), "worktree")
    except (OSError, ValueError) as exc:
        return [str(exc)]

    released_by_id: dict[tuple[str, str, tuple[int, int, int]], list[Asset]] = defaultdict(list)
    current_by_id: dict[tuple[str, str, tuple[int, int, int]], list[Asset]] = defaultdict(list)
    for asset in released:
        released_by_id[asset.identity].append(asset)
    for asset in current:
        current_by_id[asset.identity].append(asset)

    for scope, groups in (("semantic release tags", released_by_id.values()), ("the current tree", current_by_id.values())):
        for group in groups:
            fingerprints = {asset.files for asset in group}
            if len(fingerprints) > 1:
                asset = group[0]
                errors.append(f"{asset.display} has duplicate identity with different bytes across {scope}")

    for identity, historical in released_by_id.items():
        reference = historical[0]
        exact = current_by_id.get(identity, [])
        if exact:
            if any(asset.files != reference.files for asset in exact):
                errors.append(f"released {reference.display} differs in the current tree without a new semantic version")
            continue
        errors.append(f"released {reference.display} was removed; historical assets must remain byte-identical")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    errors = validate(args.root)
    if errors:
        print("Released asset checks failed:\n- " + "\n- ".join(errors))
        return 1
    print("Released asset checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
