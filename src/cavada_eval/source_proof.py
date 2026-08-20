from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import Any

from .artifacts import _read_regular
from .protocol import ProtocolError

MAX_PACK_BYTES = 16 * 1024 * 1024
MAX_OBJECTS = 4_096
MAX_INFLATED_BYTES = 64 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 30

_OID_LENGTH = {"sha1": 40, "sha256": 64}
_REGULAR_MODES = {"100644", "100755"}


class _GitFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class _ProofLayout:
    objects: frozenset[str]
    python_blobs: Mapping[str, str]
    uv_lock_blob: str


def _git_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _git(repo: Path | None, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        raise _GitFailure("Git is unavailable")
    command = [executable]
    if repo is not None:
        command.extend(("-C", str(repo)))
    command.extend(("-c", f"core.hooksPath={os.devnull}", "-c", "protocol.allow=never", *arguments))
    try:
        completed = subprocess.run(  # noqa: S603 -- resolved Git executable; arguments never use a shell.
            command,
            input=input_bytes,
            capture_output=True,
            check=False,
            env=_git_environment(),
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _GitFailure("Git command failed or timed out") from exc
    if completed.returncode != 0:
        raise _GitFailure("Git rejected the source proof operation")
    return completed.stdout


def _object_format(repo: Path) -> str:
    try:
        algorithm = _git(repo, "rev-parse", "--show-object-format").decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise _GitFailure("Git returned an invalid object format") from exc
    if algorithm not in _OID_LENGTH:
        raise _GitFailure("Git repository uses an unsupported object format")
    return algorithm


def _valid_oid(value: str, algorithm: str) -> bool:
    return len(value) == _OID_LENGTH[algorithm] and re.fullmatch(r"[0-9a-f]+", value) is not None


def _tree_entries(repo: Path, tree: str, algorithm: str) -> list[tuple[str, str, str, str]]:
    output = _git(repo, "ls-tree", "-z", tree)
    entries: list[tuple[str, str, str, str]] = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        try:
            header, raw_name = raw.split(b"\t", 1)
            mode, object_type, oid = header.decode("ascii").split(" ")
            name = raw_name.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise _GitFailure("Git tree contains a malformed entry") from exc
        if not _valid_oid(oid, algorithm):
            raise _GitFailure("Git tree contains an invalid object id")
        entries.append((mode, object_type, oid, name))
    return entries


def _commit_tree(repo: Path, commit: str, algorithm: str) -> str:
    try:
        object_type = _git(repo, "cat-file", "-t", commit).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise _GitFailure("Git returned an invalid commit type") from exc
    if object_type != "commit":
        raise _GitFailure("declared source commit is not a commit")
    raw = _git(repo, "cat-file", "commit", commit)
    headers = raw.split(b"\n\n", 1)[0].splitlines()
    tree_headers = [line[5:].decode("ascii") for line in headers if line.startswith(b"tree ")]
    if len(tree_headers) != 1 or not _valid_oid(tree_headers[0], algorithm):
        raise _GitFailure("source commit does not bind one valid root tree")
    return tree_headers[0]


def _proof_layout(repo: Path, commit: str, algorithm: str | None = None) -> _ProofLayout:
    algorithm = algorithm or _object_format(repo)
    if not _valid_oid(commit, algorithm):
        raise _GitFailure(f"source commit must be a full {algorithm} object id")
    root_tree = _commit_tree(repo, commit, algorithm)
    objects = {commit, root_tree}
    registered_paths: dict[str, str] = {}
    entry_count = 0

    def checked_entries(tree: str, prefix: str) -> dict[str, tuple[str, str, str]]:
        nonlocal entry_count
        rows: dict[str, tuple[str, str, str]] = {}
        folded_names: set[str] = set()
        for mode, object_type, oid, name in _tree_entries(repo, tree, algorithm):
            entry_count += 1
            windows = PureWindowsPath(name)
            if entry_count > MAX_OBJECTS:
                raise _GitFailure("source proof tree exceeds the path limit")
            if (
                not name
                or name in {".", ".."}
                or name != unicodedata.normalize("NFC", name)
                or "/" in name
                or "\\" in name
                or windows.drive
            ):
                raise _GitFailure("source proof tree contains an unsafe or non-NFC path")
            folded_name = name.casefold()
            full_path = f"{prefix}/{name}" if prefix else name
            folded_path = full_path.casefold()
            if folded_name in folded_names or (
                folded_path in registered_paths and registered_paths[folded_path] != full_path
            ):
                raise _GitFailure("source proof tree contains a case-colliding path")
            folded_names.add(folded_name)
            registered_paths[folded_path] = full_path
            if (mode, object_type) == ("040000", "tree"):
                pass
            elif mode in _REGULAR_MODES and object_type == "blob":
                pass
            elif mode == "120000" or object_type == "blob":
                raise _GitFailure("source proof tree contains a symlink or invalid blob mode")
            elif mode == "160000" or object_type == "commit":
                raise _GitFailure("source proof tree contains a submodule")
            else:
                raise _GitFailure("source proof tree contains an unsupported mode or object type")
            rows[name] = (mode, object_type, oid)
        return rows

    root_entries = checked_entries(root_tree, "")
    for required in ("pyproject.toml", "uv.lock", "src"):
        if required not in root_entries:
            raise _GitFailure(f"source commit is missing required path: {required}")
    pyproject_mode, pyproject_type, pyproject_blob = root_entries["pyproject.toml"]
    lock_mode, lock_type, lock_blob = root_entries["uv.lock"]
    src_mode, src_type, src_tree = root_entries["src"]
    if pyproject_mode not in _REGULAR_MODES or pyproject_type != "blob":
        raise _GitFailure("pyproject.toml is not a regular Git blob")
    if lock_mode not in _REGULAR_MODES or lock_type != "blob":
        raise _GitFailure("uv.lock is not a regular Git blob")
    if (src_mode, src_type) != ("040000", "tree"):
        raise _GitFailure("src is not a Git tree")
    objects.update((pyproject_blob, lock_blob, src_tree))

    src_entries = checked_entries(src_tree, "src")
    package = src_entries.get("cavada_eval")
    if package is None or package[:2] != ("040000", "tree"):
        raise _GitFailure("src/cavada_eval is not a Git tree")
    package_tree = package[2]
    objects.add(package_tree)
    python_blobs: dict[str, str] = {}
    pending = [("src/cavada_eval", package_tree)]
    visited_paths: set[tuple[str, str]] = set()
    while pending:
        prefix, tree = pending.pop()
        if (prefix, tree) in visited_paths:
            continue
        visited_paths.add((prefix, tree))
        for name, (mode, object_type, oid) in checked_entries(tree, prefix).items():
            path = f"{prefix}/{name}"
            if (mode, object_type) == ("040000", "tree"):
                objects.add(oid)
                pending.append((path, oid))
            elif path.endswith(".py"):
                relative = path.removeprefix("src/cavada_eval/")
                python_blobs[relative] = oid
                objects.add(oid)
    if not python_blobs:
        raise _GitFailure("source commit contains no Python implementation files")
    return _ProofLayout(frozenset(objects), python_blobs, lock_blob)


def _object_metadata(repo: Path, objects: frozenset[str] | None = None) -> dict[str, tuple[str, int]]:
    if objects is None:
        output = _git(
            repo,
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        )
    else:
        payload = "".join(f"{oid}\n" for oid in sorted(objects)).encode("ascii")
        output = _git(
            repo,
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            input_bytes=payload,
        )
    metadata: dict[str, tuple[str, int]] = {}
    try:
        for line in output.decode("ascii").splitlines():
            oid, object_type, size_text = line.split(" ")
            size = int(size_text)
            if oid in metadata or size < 0:
                raise ValueError
            metadata[oid] = (object_type, size)
    except (UnicodeDecodeError, ValueError) as exc:
        raise _GitFailure("Git returned malformed object metadata") from exc
    return metadata


def _check_resource_limits(metadata: Mapping[str, tuple[str, int]]) -> None:
    if len(metadata) > MAX_OBJECTS:
        raise _GitFailure("source proof exceeds the object-count limit")
    if sum(size for _, size in metadata.values()) > MAX_INFLATED_BYTES:
        raise _GitFailure("source proof exceeds the inflated-size limit")


def _pack_objects(repo: Path, objects: frozenset[str]) -> bytes:
    payload = "".join(f"{oid}\n" for oid in sorted(objects)).encode("ascii")
    pack = _git(
        repo,
        "pack-objects",
        "--stdout",
        "--window=0",
        "--depth=0",
        "--no-reuse-delta",
        "--no-reuse-object",
        "--no-thin",
        "--no-use-bitmap-index",
        "--threads=1",
        input_bytes=payload,
    )
    if len(pack) > MAX_PACK_BYTES:
        raise _GitFailure("source proof exceeds the pack-size limit")
    return pack


def _cat_blob(repo: Path, oid: str) -> bytes:
    return _git(repo, "cat-file", "blob", oid)


def _pack_input(value: object) -> tuple[bytes | None, list[str]]:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, Path):
        try:
            before = value.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                return None, ["source proof pack path is not a unique regular file"]
            if before.st_size > MAX_PACK_BYTES:
                return None, ["source proof exceeds the pack-size limit"]
            raw = _read_regular(value.parent, Path(value.name))
        except OSError:
            return None, ["source proof pack path is unreadable or changed while read"]
    else:
        return None, ["source proof pack must be bytes or a Path"]
    if not raw or len(raw) > MAX_PACK_BYTES:
        return None, ["source proof pack is empty or exceeds the pack-size limit"]
    return raw, []


def _implementation_mapping(files: Mapping[Any, Any]) -> tuple[dict[str, bytes], list[str]]:
    normalized: dict[str, bytes] = {}
    folded: set[str] = set()
    errors: list[str] = []
    for relative, raw in files.items():
        if not isinstance(relative, str) or not isinstance(raw, bytes):
            errors.append("implementation files must map package-relative strings to bytes")
            continue
        path = Path(relative)
        windows = PureWindowsPath(relative)
        if (
            not relative
            or not relative.endswith(".py")
            or relative != unicodedata.normalize("NFC", relative)
            or path.is_absolute()
            or windows.drive
            or "." in path.parts
            or ".." in path.parts
            or "\\" in relative
            or path.as_posix() != relative
            or windows.as_posix() != relative
        ):
            errors.append("implementation file mapping contains an unsafe or non-canonical path")
            continue
        if relative.casefold() in folded:
            errors.append("implementation file mapping contains case-colliding paths")
            continue
        folded.add(relative.casefold())
        normalized[relative] = raw
    if not normalized:
        errors.append("implementation file mapping must contain Python source bytes")
    return normalized, list(dict.fromkeys(errors))


def _delta_failures(repo: Path, index: Path, algorithm: str, actual_objects: set[str]) -> list[str]:
    output = _git(repo, "verify-pack", "-v", str(index))
    rows: set[str] = set()
    errors: list[str] = []
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return ["source proof pack index output is malformed"]
    for line in lines:
        fields = line.split()
        if not fields or not _valid_oid(fields[0], algorithm):
            continue
        if len(fields) != 5:
            errors.append("source proof pack contains a delta object")
        if fields[0] in rows:
            errors.append("source proof pack contains a duplicate object")
        rows.add(fields[0])
    if rows != actual_objects:
        errors.append("source proof pack index does not enumerate the exact object set")
    return list(dict.fromkeys(errors))


def build_source_commit_proof(repo_root: Path, commit: str) -> bytes:
    """Build a non-delta pack for one commit and its exact Python implementation closure."""
    try:
        root = repo_root.resolve(strict=True)
        algorithm = _object_format(root)
        layout = _proof_layout(root, commit, algorithm)
        metadata = _object_metadata(root, layout.objects)
        if set(metadata) != set(layout.objects):
            raise _GitFailure("Git did not resolve the exact source proof object set")
        _check_resource_limits(metadata)
        pack = _pack_objects(root, layout.objects)
        implementation = {path: _cat_blob(root, oid) for path, oid in layout.python_blobs.items()}
        lock_sha256 = hashlib.sha256(_cat_blob(root, layout.uv_lock_blob)).hexdigest()
        failures = verify_source_commit_proof(pack, commit, implementation, lock_sha256)
        if failures:
            raise _GitFailure("built source proof failed self-verification: " + "; ".join(failures))
        return pack
    except (OSError, _GitFailure) as exc:
        raise ProtocolError(f"cannot build source commit proof: {exc}") from exc


def verify_source_commit_proof(
    pack: bytes | Path,
    commit: str,
    implementation_files: Mapping[str, bytes],
    expected_uv_lock_sha256: str,
) -> list[str]:
    """Verify a source pack; implementation paths are relative to ``src/cavada_eval``."""
    raw, errors = _pack_input(pack)
    implementation, mapping_errors = _implementation_mapping(implementation_files)
    errors.extend(mapping_errors)
    algorithm = "sha1" if len(commit) == 40 else "sha256" if len(commit) == 64 else ""
    if not algorithm or not _valid_oid(commit, algorithm):
        errors.append("source commit must be one full lowercase SHA-1 or SHA-256 object id")
    if re.fullmatch(r"[0-9a-f]{64}", expected_uv_lock_sha256) is None:
        errors.append("expected uv.lock SHA-256 is invalid")
    if raw is None or errors:
        return list(dict.fromkeys(errors))

    try:
        with TemporaryDirectory(prefix="cavada-source-proof-") as temporary:
            workspace = Path(temporary)
            template = workspace / "empty-template"
            repository = workspace / "repository.git"
            template.mkdir()
            _git(
                None,
                "init",
                "--bare",
                "--quiet",
                f"--object-format={algorithm}",
                f"--template={template}",
                str(repository),
            )
            pack_directory = repository / "objects" / "pack"
            pack_directory.mkdir(parents=True, exist_ok=True)
            pack_path = pack_directory / "source-proof.pack"
            pack_path.write_bytes(raw)
            # The proof intentionally omits parents and unrelated tree blobs, so Git's
            # connectivity-oriented --strict mode cannot apply to this selective pack.
            # index-pack still verifies the pack checksum and every included object id.
            _git(repository, "index-pack", str(pack_path))
            index_path = pack_path.with_suffix(".idx")
            if not index_path.is_file():
                raise _GitFailure("Git did not create a source proof pack index")
            metadata = _object_metadata(repository)
            _check_resource_limits(metadata)
            actual_objects = set(metadata)
            errors.extend(_delta_failures(repository, index_path, algorithm, actual_objects))
            if commit not in actual_objects:
                errors.append("source proof does not contain the declared commit")
                return list(dict.fromkeys(errors))
            layout = _proof_layout(repository, commit, algorithm)
            expected_objects = set(layout.objects)
            if actual_objects != expected_objects:
                missing = len(expected_objects - actual_objects)
                extra = len(actual_objects - expected_objects)
                errors.append(f"source proof object set is not exact (missing={missing}, extra={extra})")
            if set(layout.python_blobs) != set(implementation):
                errors.append("source proof Python path set differs from implementation evidence")
            else:
                for relative, oid in sorted(layout.python_blobs.items()):
                    if _cat_blob(repository, oid) != implementation[relative]:
                        errors.append(f"source proof Python blob differs from implementation evidence: {relative}")
            if hashlib.sha256(_cat_blob(repository, layout.uv_lock_blob)).hexdigest() != expected_uv_lock_sha256:
                errors.append("source proof uv.lock digest mismatch")
    except (OSError, _GitFailure):
        errors.append("source proof pack failed Git integrity or structural validation")
    return list(dict.fromkeys(errors))
