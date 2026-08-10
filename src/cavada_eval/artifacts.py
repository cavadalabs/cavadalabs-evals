from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath
from typing import Any, BinaryIO

from .protocol import ProtocolError, atomic_json, atomic_text

BUNDLE_VERSION = "1.0.0"
EXCLUDED_FROM_BUNDLE = {"bundle.json", "checksums.txt", "signature.json", "verification.json"}


def _identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


@contextmanager
def _regular_file(root: Path, relative: Path) -> Iterator[BinaryIO]:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise OSError("unsafe relative file path")
    file_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_before = root.lstat()
    if not stat.S_ISDIR(root_before.st_mode):
        raise OSError("bundle root is not a regular directory")

    if os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd:
        directories: list[int] = []
        entries: list[tuple[int, str, os.stat_result]] = []
        descriptor = -1
        root_descriptor = os.open(root, directory_flags)
        directories.append(root_descriptor)
        try:
            if _identity(os.fstat(root_descriptor)) != _identity(root_before):
                raise OSError("bundle root changed before it was opened")
            parent = root_descriptor
            for part in relative.parts[:-1]:
                before = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    raise OSError("bundle path contains a non-directory")
                child = os.open(part, directory_flags, dir_fd=parent)
                directories.append(child)
                opened = os.fstat(child)
                if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(before):
                    raise OSError("bundle directory changed before it was opened")
                entries.append((parent, part, opened))
                parent = child
            name = relative.parts[-1]
            before_file = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(before_file.st_mode):
                raise OSError("bundle artifact is not a regular file")
            descriptor = os.open(name, file_flags, dir_fd=parent)
            opened_file = os.fstat(descriptor)
            if not stat.S_ISREG(opened_file.st_mode) or _identity(opened_file) != _identity(before_file):
                raise OSError("bundle artifact changed before it was opened")
            handle = os.fdopen(descriptor, "rb", closefd=False)
            try:
                yield handle
                if _identity(os.fstat(descriptor)) != _identity(opened_file):
                    raise OSError("bundle artifact changed while it was read")
                current_file = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISREG(current_file.st_mode) or _identity(current_file) != _identity(opened_file):
                    raise OSError("bundle artifact path changed while it was read")
                for entry_parent, entry_name, opened in reversed(entries):
                    current = os.stat(entry_name, dir_fd=entry_parent, follow_symlinks=False)
                    if not stat.S_ISDIR(current.st_mode) or _identity(current) != _identity(opened):
                        raise OSError("bundle directory changed while an artifact was read")
                if _identity(root.lstat()) != _identity(root_before):
                    raise OSError("bundle root changed while an artifact was read")
            finally:
                handle.close()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            for directory in reversed(directories):
                os.close(directory)
        return

    path = root / relative
    components = [root, *(root / Path(*relative.parts[:index]) for index in range(1, len(relative.parts) + 1))]
    before_components = [component.lstat() for component in components]
    if any(not stat.S_ISDIR(value.st_mode) for value in before_components[:-1]) or not stat.S_ISREG(before_components[-1].st_mode):
        raise OSError("bundle path is not regular")
    descriptor = os.open(path, file_flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before_components[-1]):
            raise OSError("file changed before it was opened")
        handle = os.fdopen(descriptor, "rb", closefd=False)
        try:
            yield handle
            after = os.fstat(descriptor)
            current_components = [component.lstat() for component in components]
            if _identity(after) != _identity(opened) or any(
                _identity(current) != _identity(before) for current, before in zip(current_components, before_components, strict=True)
            ):
                raise OSError("file changed while it was read")
        finally:
            handle.close()
    finally:
        os.close(descriptor)


def _read_regular(root: Path, relative: Path) -> bytes:
    with _regular_file(root, relative) as handle:
        return handle.read()


def _hash_regular(root: Path, relative: Path) -> str:
    digest = hashlib.sha256()
    with _regular_file(root, relative) as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*") if path.is_file() and not path.is_symlink() and path.relative_to(root).as_posix() not in EXCLUDED_FROM_BUNDLE
    )


def write_bundle(run_dir: Path, *, signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY", key_id: str = "") -> dict[str, Any]:
    files = {path.relative_to(run_dir).as_posix(): _hash_regular(run_dir, path.relative_to(run_dir)) for path in _files(run_dir)}
    bundle = {"bundle_version": BUNDLE_VERSION, "algorithm": "sha256", "files": files}
    atomic_json(run_dir / "bundle.json", bundle)
    atomic_text(run_dir / "checksums.txt", "".join(f"{digest}  {name}\n" for name, digest in files.items()))
    key = os.getenv(signing_key_env, "")
    if key:
        canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
        atomic_json(
            run_dir / "signature.json",
            {
                "algorithm": "hmac-sha256",
                "key_id": key_id or signing_key_env,
                "bundle_sha256": hashlib.sha256(canonical).hexdigest(),
                "signature": hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest(),
            },
        )
    return bundle


def verify_bundle(
    run_dir: Path,
    *,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    write_result: bool = False,
) -> dict[str, Any]:
    if run_dir.is_symlink():
        raise ProtocolError("unsafe bundle directory")
    bundle_path = run_dir / "bundle.json"
    if not bundle_path.is_file() or bundle_path.is_symlink():
        raise ProtocolError("missing bundle.json")
    try:
        bundle = json.loads(_read_regular(run_dir, Path("bundle.json")).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid bundle.json") from exc
    if (
        not isinstance(bundle, dict)
        or bundle.get("bundle_version") != BUNDLE_VERSION
        or bundle.get("algorithm") != "sha256"
        or not isinstance(bundle.get("files"), dict)
        or not bundle["files"]
    ):
        raise ProtocolError("unsupported or malformed bundle")
    failures: list[str] = []
    root = run_dir.resolve()
    for relative, expected in bundle["files"].items():
        if not isinstance(relative, str) or not relative or not isinstance(expected, str) or re.fullmatch(r"[a-f0-9]{64}", expected) is None:
            failures.append(f"malformed artifact entry: {relative}")
            continue
        candidate = Path(relative)
        windows_candidate = PureWindowsPath(relative)
        if candidate.is_absolute() or windows_candidate.drive or ".." in candidate.parts or ".." in windows_candidate.parts or candidate.as_posix() != relative:
            failures.append(f"unsafe artifact path: {relative}")
            continue
        path = run_dir / candidate
        try:
            current = run_dir
            unsafe_symlink = False
            for part in candidate.parts:
                current /= part
                if current.is_symlink():
                    unsafe_symlink = True
                    break
            safe_file = not unsafe_symlink and path.resolve().is_relative_to(root) and path.is_file()
        except (OSError, ValueError):
            safe_file = False
        if not safe_file:
            failures.append(f"missing or unsafe artifact: {relative}")
        else:
            try:
                if _hash_regular(run_dir, candidate) != expected:
                    failures.append(f"hash mismatch: {relative}")
            except OSError:
                failures.append(f"unreadable artifact: {relative}")
    for path in sorted(run_dir.rglob("*")):
        if path.is_symlink():
            failures.append(f"unsafe symlink artifact: {path.relative_to(run_dir).as_posix()}")
    actual_files = {path.relative_to(run_dir).as_posix() for path in _files(run_dir)}
    declared_files = set(map(str, bundle["files"]))
    for relative in sorted(actual_files - declared_files):
        failures.append(f"unlisted artifact: {relative}")
    expected_checksums = "".join(f"{digest}  {name}\n" for name, digest in bundle["files"].items())
    try:
        checksums_valid = _read_regular(run_dir, Path("checksums.txt")).decode("utf-8") == expected_checksums
    except (OSError, UnicodeDecodeError):
        checksums_valid = False
    if not checksums_valid:
        failures.append("checksums.txt does not match bundle")
    signature_status = "absent"
    signature_path = run_dir / "signature.json"
    if signature_path.is_file():
        signature_status = "unverified"
        signature: dict[str, Any] = {}
        if signature_path.is_symlink():
            failures.append("unsafe signature.json")
        else:
            try:
                value = json.loads(_read_regular(run_dir, Path("signature.json")).decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                value = None
            if not isinstance(value, dict):
                failures.append("invalid signature.json")
            else:
                signature = value
        canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
        if signature.get("algorithm") != "hmac-sha256" or signature.get("bundle_sha256") != hashlib.sha256(canonical).hexdigest():
            failures.append("signature metadata does not match bundle")
        key = os.getenv(signing_key_env, "")
        if key:
            expected = hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()
            signature_status = "valid" if hmac.compare_digest(str(signature.get("signature", "")), expected) else "invalid"
            if signature_status == "invalid":
                failures.append("invalid bundle signature")
    result = {"valid": not failures, "failures": failures, "signature": signature_status, "files": len(bundle["files"])}
    if write_result:
        atomic_json(run_dir / "verification.json", result)
    return result
