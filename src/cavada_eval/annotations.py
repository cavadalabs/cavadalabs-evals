from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from .protocol import ProtocolError, Suite, append_jsonl, atomic_json, atomic_text, sha256_file
from .runner import _target_answer


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ProtocolError(f"cannot read annotation source: {exc}") from exc
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid annotation source line {line_number}: {exc.msg}") from exc
        if not isinstance(row, dict):
            raise ProtocolError(f"invalid annotation source line {line_number}: expected object")
        rows.append(row)
    return rows


def export_annotation_package(suite: Suite, run_dir: Path, output: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    output = output.resolve()
    if output.exists():
        raise ProtocolError(f"annotation package output already exists: {output}")
    raw_path = run_dir / "raw_responses.jsonl"
    manifest_path = run_dir / "manifest.json"
    if not raw_path.is_file() or not manifest_path.is_file():
        raise ProtocolError("run directory must contain manifest.json and raw_responses.jsonl")
    cases = {str(case["id"]): case for case in suite.cases}
    package_rows: list[dict[str, Any]] = []
    linkage_rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for raw in _jsonl(raw_path):
        case_id = str(raw.get("case_id", ""))
        repetition = raw.get("repetition")
        response = raw.get("response")
        if case_id not in cases or not isinstance(repetition, int) or isinstance(repetition, bool) or not isinstance(response, dict):
            raise ProtocolError("raw response does not match the supplied suite")
        key = (case_id, repetition)
        if key in seen:
            raise ProtocolError(f"duplicate raw response observation: {case_id}/{repetition}")
        seen.add(key)
        answer, _ = _target_answer(suite, response)
        case = cases[case_id]
        package_id = f"P-{secrets.token_hex(12)}"
        package_rows.append(
            {
                "package_id": package_id,
                "module": case["category"],
                "risk_domain": case["risk_domain"],
                "severity": case["severity"],
                "language": case.get("language"),
                "locale": case.get("locale"),
                "input": case["input"],
                "conversation": case.get("messages"),
                "expected_behavior": case["expected_behavior"],
                "expected_behavior_reason": case["expected_behavior_reason"],
                "reference_answer": case.get("expected_output"),
                "response": answer,
                "label": None,
                "criterion_findings": {},
                "rationale": None,
                "failure_severity": None,
                "confidence": None,
                "escalation_flags": [],
            }
        )
        linkage_rows.append({"package_id": package_id, "case_id": case_id, "repetition": repetition})
    if not package_rows:
        raise ProtocolError("run contains no raw responses")
    secrets.SystemRandom().shuffle(package_rows)
    output.mkdir(parents=True)
    atomic_text(output / "annotations.jsonl", "")
    atomic_text(output / "linkage.restricted.jsonl", "")
    for row in package_rows:
        append_jsonl(output / "annotations.jsonl", row)
    for row in linkage_rows:
        append_jsonl(output / "linkage.restricted.jsonl", row)
    atomic_text(output / "RUBRIC.md", suite.rubric)
    handbook = suite.root / "LABEL_HANDBOOK.md"
    if handbook.is_file():
        atomic_text(output / "LABEL_HANDBOOK.md", handbook.read_text(encoding="utf-8"))
    manifest = {
        "protocol_version": suite.config["protocol_version"],
        "suite": suite.name,
        "suite_version": suite.version,
        "source_run_manifest_sha256": sha256_file(manifest_path),
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
        "observations": len(package_rows),
        "identity_blinded": True,
        "excluded_fields": ["model", "provider", "endpoint", "price", "latency", "split", "judge", "existing verdict"],
    }
    atomic_json(output / "package_manifest.json", manifest)
    return manifest
