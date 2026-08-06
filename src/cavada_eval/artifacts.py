from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from .protocol import ProtocolError, atomic_json, atomic_text, sha256_file

BUNDLE_VERSION = "1.0.0"
EXCLUDED_FROM_BUNDLE = {"bundle.json", "checksums.txt", "signature.json", "verification.json"}


def _files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*") if path.is_file() and not path.is_symlink() and path.relative_to(root).as_posix() not in EXCLUDED_FROM_BUNDLE
    )


def write_bundle(run_dir: Path, *, signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY", key_id: str = "") -> dict[str, Any]:
    files = {path.relative_to(run_dir).as_posix(): sha256_file(path) for path in _files(run_dir)}
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
    bundle_path = run_dir / "bundle.json"
    if not bundle_path.is_file():
        raise ProtocolError("missing bundle.json")
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProtocolError("invalid bundle.json") from exc
    if bundle.get("bundle_version") != BUNDLE_VERSION or bundle.get("algorithm") != "sha256" or not isinstance(bundle.get("files"), dict):
        raise ProtocolError("unsupported or malformed bundle")
    failures: list[str] = []
    for relative, expected in bundle["files"].items():
        if not isinstance(relative, str) or relative.startswith("/") or ".." in Path(relative).parts:
            failures.append(f"unsafe artifact path: {relative}")
            continue
        path = run_dir / relative
        if not path.is_file() or path.is_symlink():
            failures.append(f"missing or unsafe artifact: {relative}")
        elif sha256_file(path) != expected:
            failures.append(f"hash mismatch: {relative}")
    actual_files = {path.relative_to(run_dir).as_posix() for path in _files(run_dir)}
    declared_files = set(map(str, bundle["files"]))
    for relative in sorted(actual_files - declared_files):
        failures.append(f"unlisted artifact: {relative}")
    expected_checksums = "".join(f"{digest}  {name}\n" for name, digest in bundle["files"].items())
    checksums_path = run_dir / "checksums.txt"
    if not checksums_path.is_file() or checksums_path.read_text(encoding="utf-8") != expected_checksums:
        failures.append("checksums.txt does not match bundle")
    signature_status = "absent"
    signature_path = run_dir / "signature.json"
    if signature_path.is_file():
        signature_status = "unverified"
        try:
            signature = json.loads(signature_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            signature = {}
            failures.append("invalid signature.json")
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
