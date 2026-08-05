from __future__ import annotations

import json
import random
import secrets
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import quantiles
from typing import Any

from .protocol import ProtocolError, Suite, append_jsonl, atomic_json, atomic_text, sha256_file
from .runner import _target_answer

ANNOTATION_LABELS = {"pass", "fail", "invalid", "borderline"}


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


def export_annotation_package(suite: Suite, run_dir: Path, output: Path, linkage_output: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    output = output.resolve()
    linkage_output = linkage_output.resolve()
    if output.exists() or linkage_output.exists():
        raise ProtocolError("annotation package or restricted linkage output already exists")
    if linkage_output == output or output in linkage_output.parents:
        raise ProtocolError("restricted linkage must be outside the reviewer package")
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
    linkage_output.parent.mkdir(parents=True, exist_ok=True)
    atomic_text(output / "annotations.jsonl", "")
    atomic_text(linkage_output, "")
    for row in package_rows:
        append_jsonl(output / "annotations.jsonl", row)
    for row in linkage_rows:
        append_jsonl(linkage_output, row)
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


def ingest_annotations(
    package: Path,
    linkage: Path,
    output: Path,
    *,
    reviewer_id: str,
    qualification_evidence: str,
    conflicts: str,
) -> dict[str, Any]:
    package = package.resolve()
    linkage = linkage.resolve()
    output = output.resolve()
    if output.exists():
        raise ProtocolError(f"annotation evidence output already exists: {output}")
    if not reviewer_id.strip() or not qualification_evidence.strip() or not conflicts.strip():
        raise ProtocolError("reviewer ID, qualification evidence, and conflicts declaration are required")
    manifest_path = package / "package_manifest.json"
    annotations_path = package / "annotations.jsonl"
    if not manifest_path.is_file() or not annotations_path.is_file() or not linkage.is_file():
        raise ProtocolError("annotation package, manifest, or restricted linkage is missing")
    try:
        package_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid annotation package manifest: {exc}") from exc
    if not isinstance(package_manifest, dict) or package_manifest.get("identity_blinded") is not True:
        raise ProtocolError("annotation package manifest does not declare identity blinding")
    package_rows = _jsonl(annotations_path)
    linkage_rows = _jsonl(linkage)
    linkage_map = {str(row.get("package_id")): row for row in linkage_rows}
    if len(linkage_map) != len(linkage_rows):
        raise ProtocolError("restricted linkage contains duplicate package IDs")
    evidence: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in package_rows:
        package_id = str(row.get("package_id", ""))
        if package_id in seen or package_id not in linkage_map:
            raise ProtocolError("annotation package IDs are duplicate or missing from linkage")
        seen.add(package_id)
        label = row.get("label")
        rationale = row.get("rationale")
        findings = row.get("criterion_findings")
        confidence = row.get("confidence")
        flags = row.get("escalation_flags")
        failure_severity = row.get("failure_severity")
        if label not in ANNOTATION_LABELS or not isinstance(rationale, str) or not rationale.strip():
            raise ProtocolError(f"incomplete annotation: {package_id}")
        if not isinstance(findings, dict) or not findings or not all(
            isinstance(key, str) and key and isinstance(value, bool) for key, value in findings.items()
        ):
            raise ProtocolError(f"criterion findings must map names to booleans: {package_id}")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= float(confidence) <= 1:
            raise ProtocolError(f"annotation confidence must be from 0 to 1: {package_id}")
        if not isinstance(flags, list) or not all(isinstance(flag, str) and flag for flag in flags):
            raise ProtocolError(f"annotation escalation flags are invalid: {package_id}")
        if label == "fail" and failure_severity not in {"low", "medium", "high", "critical"}:
            raise ProtocolError(f"failed annotation requires failure severity: {package_id}")
        if label != "fail" and failure_severity is not None:
            raise ProtocolError(f"only failed annotations may set failure severity: {package_id}")
        link = linkage_map[package_id]
        if not isinstance(link.get("case_id"), str) or not link["case_id"] or not isinstance(link.get("repetition"), int):
            raise ProtocolError(f"restricted linkage is invalid: {package_id}")
        evidence.append(
            {
                "package_id": package_id,
                "case_id": link.get("case_id"),
                "repetition": link.get("repetition"),
                "reviewer_id": reviewer_id,
                "label": label,
                "criterion_findings": findings,
                "rationale": rationale,
                "failure_severity": failure_severity,
                "confidence": float(confidence),
                "escalation_flags": flags,
            }
        )
    if seen != set(linkage_map):
        raise ProtocolError("annotation package and restricted linkage IDs do not match")
    output.mkdir(parents=True)
    atomic_text(output / "labels.jsonl", "")
    for row in evidence:
        append_jsonl(output / "labels.jsonl", row)
    manifest = {
        "reviewer_id": reviewer_id,
        "qualification_evidence": qualification_evidence,
        "conflicts": conflicts,
        "package_manifest_sha256": sha256_file(manifest_path),
        "completed_annotations_sha256": sha256_file(annotations_path),
        "restricted_linkage_sha256": sha256_file(linkage),
        "labels": len(evidence),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_json(output / "evidence_manifest.json", manifest)
    return manifest


def _kappa(pairs: list[tuple[str, str]]) -> float:
    if not pairs:
        return 0.0
    observed = sum(left == right for left, right in pairs) / len(pairs)
    left = Counter(value for value, _ in pairs)
    right = Counter(value for _, value in pairs)
    expected = sum(left[label] * right[label] for label in ANNOTATION_LABELS) / (len(pairs) ** 2)
    return 1.0 if expected == 1 and observed == 1 else (observed - expected) / (1 - expected) if expected < 1 else 0.0


def annotation_agreement(left: Path, right: Path, output: Path, *, bootstrap_samples: int = 10_000, seed: int = 20260805) -> dict[str, Any]:
    output = output.resolve()
    if output.exists():
        raise ProtocolError(f"annotation agreement output already exists: {output}")
    if bootstrap_samples < 100:
        raise ProtocolError("annotation agreement requires at least 100 bootstrap samples")
    left_rows = _jsonl(left.resolve() / "labels.jsonl")
    right_rows = _jsonl(right.resolve() / "labels.jsonl")
    if not left_rows or not right_rows:
        raise ProtocolError("annotation evidence is empty")
    for row in left_rows + right_rows:
        if (
            not isinstance(row.get("case_id"), str)
            or not isinstance(row.get("repetition"), int)
            or row.get("label") not in ANNOTATION_LABELS
            or not isinstance(row.get("reviewer_id"), str)
            or not row["reviewer_id"]
        ):
            raise ProtocolError("annotation evidence contains an invalid record")
    def key(row: dict[str, Any]) -> tuple[str, int]:
        return str(row["case_id"]), int(row["repetition"])

    left_map = {key(row): row for row in left_rows}
    right_map = {key(row): row for row in right_rows}
    if len(left_map) != len(left_rows) or len(right_map) != len(right_rows) or set(left_map) != set(right_map):
        raise ProtocolError("annotation evidence must contain identical unique observations")
    left_reviewers = {str(row["reviewer_id"]) for row in left_rows}
    right_reviewers = {str(row["reviewer_id"]) for row in right_rows}
    reviewer_ids = left_reviewers | right_reviewers
    if len(left_reviewers) != 1 or len(right_reviewers) != 1 or len(reviewer_ids) != 2:
        raise ProtocolError("agreement requires two distinct reviewers")
    keys = sorted(left_map)
    pairs = [(str(left_map[item]["label"]), str(right_map[item]["label"])) for item in keys]
    raw_agreement = sum(left_label == right_label for left_label, right_label in pairs) / len(pairs)
    rng = random.Random(seed)  # noqa: S311 -- deterministic statistical resampling, not cryptography.
    estimates = sorted(_kappa(rng.choices(pairs, k=len(pairs))) for _ in range(bootstrap_samples))
    cut = quantiles(estimates, n=40, method="inclusive")
    disagreements = [
        {"case_id": item[0], "repetition": item[1], "left": left_map[item]["label"], "right": right_map[item]["label"]}
        for item in keys
        if left_map[item]["label"] != right_map[item]["label"]
    ]
    result = {
        "reviewers": sorted(reviewer_ids),
        "observations": len(pairs),
        "raw_agreement": raw_agreement,
        "cohen_kappa": _kappa(pairs),
        "cohen_kappa_ci": {"lower": cut[0], "upper": cut[-1], "confidence": 0.95, "samples": bootstrap_samples, "seed": seed},
        "disagreements": len(disagreements),
    }
    output.mkdir(parents=True)
    atomic_json(output / "agreement.json", result)
    atomic_text(output / "disagreements.jsonl", "")
    for row in disagreements:
        append_jsonl(output / "disagreements.jsonl", row)
    return result
