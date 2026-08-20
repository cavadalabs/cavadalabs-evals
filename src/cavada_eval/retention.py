from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .behavior_verify import verify_behavior_run
from .protocol import ProtocolError, atomic_json, sha256_file

ACTIONS = {"legal-hold", "release-hold", "deletion-request", "tombstone", "deletion-complete", "cryptographic-erasure"}


def retention_record(run_dir: Path, output_dir: Path, *, action: str, actor: str, evidence: str) -> dict[str, Any]:
    if action not in ACTIONS or not actor.strip() or not evidence.strip():
        raise ProtocolError("retention record requires a valid action, actor, and evidence reference")
    if output_dir.exists():
        raise ProtocolError("retention record output directory already exists")
    verification = verify_behavior_run(run_dir)
    if not verification["valid"]:
        raise ProtocolError("retention record source bundle is invalid")
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError("retention record source manifest is invalid") from exc
    record = {
        "retention_record_version": "1.0.0",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "run_id": manifest.get("run_id"),
        "source_bundle_sha256": sha256_file(run_dir / "bundle.json"),
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
