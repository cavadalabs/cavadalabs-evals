from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .protocol import ProtocolError, atomic_json, contains_secret_like, sha256_file

SHA256 = re.compile(r"^[a-f0-9]{64}$")
STATUSES = {"pass", "fail", "invalid", "error", "skipped"}


def import_external_results(source_path: Path, output_dir: Path) -> dict[str, Any]:
    if output_dir.exists():
        raise ProtocolError("external import output directory already exists")
    try:
        source = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError("external import must be valid JSON") from exc
    if not isinstance(source, dict) or source.get("adapter_version") != "1.0.0":
        raise ProtocolError("unsupported external adapter contract")
    metadata = source.get("source")
    required = {"name", "version", "commit", "license", "dataset_sha256", "evaluator_sha256", "invocation"}
    if not isinstance(metadata, dict) or not required <= set(metadata):
        raise ProtocolError(f"external source metadata is missing fields: {sorted(required - set(metadata or {}))}")
    if not SHA256.fullmatch(str(metadata["dataset_sha256"])) or not SHA256.fullmatch(str(metadata["evaluator_sha256"])):
        raise ProtocolError("external dataset and evaluator hashes must be SHA-256")
    if any(not isinstance(metadata[field], str) or not metadata[field].strip() for field in required):
        raise ProtocolError("external source metadata fields must be non-empty strings")
    results = source.get("results")
    if not isinstance(results, list) or not results:
        raise ProtocolError("external import requires non-empty results")
    for index, result in enumerate(results):
        if not isinstance(result, dict) or not isinstance(result.get("case_id"), str) or result.get("status") not in STATUSES:
            raise ProtocolError(f"external result {index} requires case_id and a valid status")
    if contains_secret_like(source):
        raise ProtocolError("external import contains secret-like material")
    manifest = {
        "external_import_version": "1.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_artifact": str(source_path.name),
        "source_artifact_sha256": sha256_file(source_path),
        "source": metadata,
        "suite": source.get("suite"),
        "result_count": len(results),
        "limitations": [
            "Imported evidence retains upstream methodology and license limitations",
            "No CavadaLabs official claim without explicit compatibility mapping",
        ],
    }
    output_dir.mkdir(parents=True, mode=0o700)
    atomic_json(output_dir / "manifest.json", manifest)
    atomic_json(output_dir / "imported_results.json", results)
    write_bundle(output_dir)
    verification = verify_bundle(output_dir, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("external import bundle verification failed")
    return manifest
