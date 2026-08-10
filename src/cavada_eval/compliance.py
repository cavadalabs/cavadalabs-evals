from __future__ import annotations

import html
import json
import shutil
import tempfile
import tomllib
from datetime import date
from pathlib import Path, PureWindowsPath
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .protocol import ProtocolError, atomic_json, atomic_text, contains_secret_like, require_mutable_output_root, sha256_bytes

STATUSES = {"automated_pass", "automated_fail", "manual_required", "not_applicable", "missing", "expired"}
MANUAL_RECORD_FIELDS = {
    "control_id",
    "status",
    "applicability",
    "owner",
    "effective_at",
    "expires_at",
    "residual_risk",
    "artifact",
}


def _artifact_identifier(value: Any, number: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(f"invalid evidence artifact on line {number}")
    artifact = value.strip()
    path = Path(artifact)
    windows_path = PureWindowsPath(artifact)
    if (
        path.is_absolute()
        or windows_path.drive
        or ".." in path.parts
        or ".." in windows_path.parts
        or artifact.startswith("~")
        or artifact.casefold().startswith("file:")
        or str(Path.home()) in artifact
        or contains_secret_like(artifact)
    ):
        raise ProtocolError(f"unsafe evidence artifact on line {number}")
    return artifact


def _records(path: Path | None, raw: bytes | None = None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    records: dict[str, dict[str, Any]] = {}
    try:
        lines = (path.read_bytes() if raw is None else raw).decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ProtocolError("evidence records are not readable") from exc
    for number, line in enumerate(lines, 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid evidence record line {number}") from exc
        required = {"control_id", "status", "applicability", "owner", "effective_at", "residual_risk"}
        if (
            not isinstance(value, dict)
            or value.get("status") not in STATUSES
            or not required <= set(value)
            or not set(value) <= MANUAL_RECORD_FIELDS
            or not all(isinstance(value[field], str) and value[field].strip() for field in required - {"status"})
        ):
            raise ProtocolError(f"invalid evidence record line {number}")
        control_id = str(value["control_id"])
        if control_id in records:
            raise ProtocolError(f"duplicate evidence control_id on line {number}")
        if value["status"] in {"automated_pass", "automated_fail"}:
            raise ProtocolError(f"manual evidence cannot claim an automated status on line {number}")
        try:
            date.fromisoformat(value["effective_at"])
            if value.get("expires_at"):
                date.fromisoformat(str(value["expires_at"]))
        except ValueError as exc:
            raise ProtocolError(f"invalid evidence date on line {number}") from exc
        artifact = _artifact_identifier(value.get("artifact"), number)
        records[control_id] = {**value, **({"artifact": artifact} if artifact is not None else {})}
    return records


def generate_control_report(run_dir: Path, catalog_path: Path, output_dir: Path, *, records_path: Path | None = None) -> dict[str, Any]:
    require_mutable_output_root(output_dir)
    if output_dir.exists():
        raise ProtocolError("control report output already exists")
    try:
        catalog_raw = catalog_path.read_bytes()
        catalog = tomllib.loads(catalog_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError("control catalog is not readable TOML") from exc
    try:
        records_raw = records_path.read_bytes() if records_path is not None else None
    except OSError as exc:
        raise ProtocolError("evidence records are not readable") from exc
    controls = catalog.get("controls")
    if not isinstance(controls, list) or not controls:
        raise ProtocolError("control catalog contains no controls")
    with tempfile.TemporaryDirectory(prefix="cavada-control-source-") as temporary:
        snapshot = Path(temporary) / "run"
        try:
            shutil.copytree(run_dir, snapshot, symlinks=True)
        except OSError as exc:
            raise ProtocolError("source run bundle could not be snapshotted") from exc
        verification = verify_bundle(snapshot)
        if not verification["valid"]:
            raise ProtocolError("source run bundle verification failed")
        bundle_raw = (snapshot / "bundle.json").read_bytes()
        manifest_raw = (snapshot / "manifest.json").read_bytes()
    try:
        bundle = json.loads(bundle_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:  # pragma: no cover - verify_bundle already checks this.
        raise ProtocolError("source run bundle is invalid") from exc
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("run manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise ProtocolError("run manifest must be an object")
    bundle_files = bundle.get("files") if isinstance(bundle, dict) else None
    manifest_artifacts = manifest.get("artifacts")
    recordkeeping_complete = (
        isinstance(bundle_files, dict)
        and isinstance(manifest_artifacts, dict)
        and bool(manifest_artifacts)
        and all(bundle_files.get(name) == digest for name, digest in manifest_artifacts.items())
    )
    manual = _records(records_path, records_raw)
    control_ids: set[str] = set()
    for control in controls:
        if not isinstance(control, dict) or not isinstance(control.get("id"), str) or not control["id"]:
            raise ProtocolError("control catalog contains an invalid control")
        if control["id"] in control_ids:
            raise ProtocolError(f"control catalog contains duplicate control_id: {control['id']}")
        control_ids.add(control["id"])
    unknown_records = set(manual) - control_ids
    if unknown_records:
        raise ProtocolError(f"evidence records reference unknown controls: {', '.join(sorted(unknown_records))}")
    results: list[dict[str, Any]] = []
    for control in controls:
        control_id = str(control.get("id"))
        source_prefix = "gdpr" if control_id.startswith("GDPR-") else "ai_act"
        source_version = catalog.get(f"{source_prefix}_source_version", catalog.get("version"))
        source_application = catalog.get(f"{source_prefix}_application", "applicability date not cataloged")
        record = manual.get(control_id)
        if record:
            status = record["status"]
            expires_at = record.get("expires_at")
            if isinstance(expires_at, str) and expires_at < date.today().isoformat():
                status = "expired"
            result = {**record, "status": status}
        elif control_id == "AI-ACT-12":
            result = {
                "control_id": control_id,
                "jurisdiction": "EU",
                "source": control.get("source"),
                "source_version": source_version,
                "source_application": source_application,
                "applicability": "technical record-keeping evidence only",
                "owner": "benchmark-operator",
                "status": "automated_pass" if recordkeeping_complete else "automated_fail",
                "artifact": "bundle.json",
                "effective_at": date.today().isoformat(),
                "residual_risk": "Retention, access, deployment logging, and legal applicability require accountable review.",
            }
        else:
            result = {
                "control_id": control_id,
                "jurisdiction": str(control.get("jurisdiction", "unspecified")),
                "source": control.get("source"),
                "source_version": source_version,
                "source_application": source_application,
                "applicability": "not assessed by benchmark execution",
                "owner": "unassigned",
                "status": "manual_required",
                "effective_at": date.today().isoformat(),
                "residual_risk": "No accountable applicability or legal assessment is attached.",
            }
        result.setdefault("jurisdiction", str(control.get("jurisdiction", "unspecified")))
        result.setdefault("source", control.get("source"))
        result.setdefault("source_version", source_version)
        result.setdefault("source_application", source_application)
        result["title"] = control.get("title")
        result["expected_evidence"] = control.get("evidence", [])
        results.append(result)
    report = {
        "evidence_report_version": "1.0.0",
        "catalog_version": catalog.get("version"),
        "source_bundle_sha256": sha256_bytes(bundle_raw),
        "source_manifest_sha256": sha256_bytes(manifest_raw),
        "control_catalog_sha256": sha256_bytes(catalog_raw),
        "manual_records_sha256": sha256_bytes(records_raw) if records_raw is not None else None,
        "run_id": manifest.get("run_id"),
        "suite": manifest.get("suite"),
        "controls": results,
        "status_counts": {status: sum(item["status"] == status for item in results) for status in sorted(STATUSES)},
        "combined_compliance_score": None,
        "disclaimer": "Engineering evidence only. No legal certification or combined compliance score.",
    }
    output_dir.mkdir(parents=True)
    atomic_json(output_dir / "control_evidence.json", report)
    rows = "".join(
        f"<tr><td>{html.escape(item['control_id'])}</td><td>{html.escape(str(item.get('title', '')))}</td><td>{html.escape(item['status'])}</td><td>{html.escape(item['applicability'])}</td><td>{html.escape(item['residual_risk'])}</td></tr>"
        for item in results
    )
    atomic_text(
        output_dir / "control_evidence.html",
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'"><title>Control evidence</title><style>body{{font:15px system-ui;max-width:1200px;margin:40px auto}}table{{border-collapse:collapse}}th,td{{border:1px solid #bbb;padding:8px;vertical-align:top}}</style><h1>Control evidence report</h1><p>Engineering evidence only. No legal certification or combined compliance score.</p><table><tr><th>Control</th><th>Title</th><th>Status</th><th>Applicability</th><th>Residual risk</th></tr>{rows}</table></html>\n',
    )
    write_bundle(output_dir)
    verification = verify_bundle(output_dir, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("control evidence bundle verification failed")
    return report
