from __future__ import annotations

import html
import json
import tomllib
from datetime import date
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .protocol import ProtocolError, atomic_json, atomic_text

STATUSES = {"automated_pass", "automated_fail", "manual_required", "not_applicable", "missing", "expired"}


def _records(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    records: dict[str, dict[str, Any]] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid evidence record line {number}") from exc
        required = {"control_id", "status", "applicability", "owner", "effective_at", "residual_risk"}
        if (
            not isinstance(value, dict)
            or value.get("status") not in STATUSES
            or not required <= set(value)
            or not all(isinstance(value[field], str) and value[field].strip() for field in required - {"status"})
        ):
            raise ProtocolError(f"invalid evidence record line {number}")
        try:
            date.fromisoformat(value["effective_at"])
            if value.get("expires_at"):
                date.fromisoformat(str(value["expires_at"]))
        except ValueError as exc:
            raise ProtocolError(f"invalid evidence date on line {number}") from exc
        records[str(value["control_id"])] = value
    return records


def generate_control_report(run_dir: Path, catalog_path: Path, output_dir: Path, *, records_path: Path | None = None) -> dict[str, Any]:
    if output_dir.exists():
        raise ProtocolError("control report output already exists")
    with catalog_path.open("rb") as handle:
        catalog = tomllib.load(handle)
    controls = catalog.get("controls")
    if not isinstance(controls, list):
        raise ProtocolError("control catalog contains no controls")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    verification = verify_bundle(run_dir)
    manual = _records(records_path)
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
                "status": "automated_pass" if verification["valid"] and manifest.get("artifacts") else "automated_fail",
                "artifact": str(run_dir / "bundle.json"),
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
