from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .protocol import ProtocolError, atomic_json, contains_secret_like, require_mutable_output_root, sha256_bytes

ACTIONS = {"legal-hold", "release-hold", "deletion-request", "tombstone", "deletion-complete", "cryptographic-erasure"}


def _portable_reference(value: str) -> str:
    reference = value.strip()
    path = Path(reference)
    windows_path = PureWindowsPath(reference)
    if (
        path.is_absolute()
        or windows_path.drive
        or ".." in path.parts
        or ".." in windows_path.parts
        or reference.startswith("~")
        or reference.casefold().startswith("file:")
        or str(Path.home()) in reference
        or contains_secret_like(reference)
    ):
        raise ProtocolError("retention evidence must be a portable, non-secret reference")
    return reference


def retention_record(run_dir: Path, output_dir: Path, *, action: str, actor: str, evidence: str) -> dict[str, Any]:
    if action not in ACTIONS or not actor.strip() or not evidence.strip() or contains_secret_like(actor):
        raise ProtocolError("retention record requires a valid action, actor, and evidence reference")
    evidence = _portable_reference(evidence)
    require_mutable_output_root(output_dir)
    if output_dir.exists():
        raise ProtocolError("retention record output directory already exists")
    with tempfile.TemporaryDirectory(prefix="cavada-retention-source-") as temporary:
        snapshot = Path(temporary) / "run"
        try:
            shutil.copytree(run_dir, snapshot, symlinks=True)
        except OSError as exc:
            raise ProtocolError("retention record source bundle could not be snapshotted") from exc
        verification = verify_bundle(snapshot)
        if not verification["valid"]:
            raise ProtocolError("retention record source bundle is invalid")
        manifest_raw = (snapshot / "manifest.json").read_bytes()
        bundle_raw = (snapshot / "bundle.json").read_bytes()
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("retention record source manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise ProtocolError("retention record source manifest must be an object")
    record = {
        "retention_record_version": "1.0.0",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "run_id": manifest.get("run_id"),
        "source_bundle_sha256": sha256_bytes(bundle_raw),
        "action": action,
        "actor": actor,
        "evidence": evidence,
        "notice": "This record documents an external lifecycle action; it does not itself delete, encrypt, or place a legal hold on data.",
    }
    output_dir.mkdir(parents=True, mode=0o700)
    atomic_json(output_dir / "retention_record.json", record)
    write_bundle(output_dir)
    if not verify_bundle(output_dir, write_result=True)["valid"]:
        raise ProtocolError("retention record bundle verification failed")
    return record
