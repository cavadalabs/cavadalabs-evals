from __future__ import annotations

import json
import random
import secrets
import shutil
import tempfile
import tomllib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import quantiles
from typing import Any

from .artifacts import verify_bundle
from .protocol import ProtocolError, Suite, append_jsonl, atomic_json, atomic_text, require_mutable_output_root, sha256_bytes, sha256_file
from .runner import _target_answer

ANNOTATION_LABELS = {"pass", "fail", "invalid", "borderline"}
EDITABLE_ANNOTATION_FIELDS = {"label", "criterion_findings", "rationale", "failure_severity", "confidence", "escalation_flags"}
EVIDENCE_BINDING_FIELDS = (
    "package_manifest_sha256",
    "restricted_linkage_sha256",
    "source_run_manifest_sha256",
    "source_run_bundle_sha256",
    "source_raw_responses_sha256",
    "dataset_sha256",
    "rubric_sha256",
)


def _immutable_item_sha256(row: dict[str, Any]) -> str:
    immutable = {key: value for key, value in row.items() if key not in EDITABLE_ANNOTATION_FIELDS}
    return sha256_bytes(json.dumps(immutable, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _jsonl(path: Path, content: bytes | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = (path.read_bytes() if content is None else content).decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
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
    require_mutable_output_root(output)
    require_mutable_output_root(linkage_output.parent)
    if output.exists() or linkage_output.exists():
        raise ProtocolError("annotation package or restricted linkage output already exists")
    if linkage_output == output or output in linkage_output.parents:
        raise ProtocolError("restricted linkage must be outside the reviewer package")
    raw_path = run_dir / "raw_responses.jsonl"
    manifest_path = run_dir / "manifest.json"
    if not raw_path.is_file() or not manifest_path.is_file():
        raise ProtocolError("run directory must contain manifest.json and raw_responses.jsonl")
    try:
        suite_config_raw = (suite.root / "suite.toml").read_bytes()
        dataset_raw = suite.dataset_path.read_bytes()
        rubric_raw = suite.rubric_path.read_bytes()
        suite_config = tomllib.loads(suite_config_raw.decode("utf-8"))
        rubric = rubric_raw.decode("utf-8")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError("annotation suite inputs are unreadable") from exc
    if suite_config != suite.config or tuple(_jsonl(suite.dataset_path, dataset_raw)) != suite.cases or rubric != suite.rubric:
        raise ProtocolError("annotation suite changed after loading")
    with tempfile.TemporaryDirectory(prefix="cavada-annotation-source-") as temporary:
        snapshot = Path(temporary) / "run"
        try:
            shutil.copytree(run_dir, snapshot, symlinks=True)
        except OSError as exc:
            raise ProtocolError("annotation source run could not be snapshotted") from exc
        if not verify_bundle(snapshot)["valid"]:
            raise ProtocolError("annotation source run bundle is invalid")
        source_manifest_raw = (snapshot / "manifest.json").read_bytes()
        raw_responses = (snapshot / "raw_responses.jsonl").read_bytes()
        source_bundle_raw = (snapshot / "bundle.json").read_bytes()
    try:
        source_manifest = json.loads(source_manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("annotation source run manifest is invalid") from exc
    if not isinstance(source_manifest, dict):
        raise ProtocolError("annotation source run manifest is invalid")
    expected_suite = {
        "name": suite.name,
        "version": suite.version,
        "dataset_sha256": sha256_bytes(dataset_raw),
        "rubric_sha256": sha256_bytes(rubric_raw),
        "suite_config_sha256": sha256_bytes(suite_config_raw),
    }
    source_suite = source_manifest.get("suite")
    raw_sha256 = sha256_bytes(raw_responses)
    if (
        not isinstance(source_suite, dict)
        or any(source_suite.get(field) != value for field, value in expected_suite.items())
        or source_manifest.get("protocol_version") != suite.config["protocol_version"]
        or source_manifest.get("status") not in {"passed", "failed"}
        or not isinstance(source_manifest.get("artifacts"), dict)
        or source_manifest["artifacts"].get("raw_responses.jsonl") != raw_sha256
    ):
        raise ProtocolError("annotation source run does not match the exact finalized suite evidence")
    cases = {str(case["id"]): case for case in suite.cases}
    package_rows: list[dict[str, Any]] = []
    linkage_rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for raw in _jsonl(raw_path, raw_responses):
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
        linkage_rows.append(
            {
                "package_id": package_id,
                "case_id": case_id,
                "repetition": repetition,
                "item_sha256": _immutable_item_sha256(package_rows[-1]),
            }
        )
    if not package_rows:
        raise ProtocolError("run contains no raw responses")
    secrets.SystemRandom().shuffle(package_rows)
    output.mkdir(parents=True, mode=0o700)
    linkage_output.parent.mkdir(parents=True, exist_ok=True)
    atomic_text(output / "annotations.jsonl", "")
    for row in package_rows:
        append_jsonl(output / "annotations.jsonl", row)
    atomic_text(output / "RUBRIC.md", suite.rubric)
    handbook = suite.root / "LABEL_HANDBOOK.md"
    handbook_raw = handbook.read_bytes() if handbook.is_file() else None
    if handbook_raw is not None:
        try:
            atomic_text(output / "LABEL_HANDBOOK.md", handbook_raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ProtocolError("annotation label handbook is not valid UTF-8") from exc
    manifest = {
        "annotation_package_version": "1.0.0",
        "protocol_version": suite.config["protocol_version"],
        "suite": suite.name,
        "suite_version": suite.version,
        "source_run_manifest_sha256": sha256_bytes(source_manifest_raw),
        "source_run_bundle_sha256": sha256_bytes(source_bundle_raw),
        "source_raw_responses_sha256": raw_sha256,
        "dataset_sha256": expected_suite["dataset_sha256"],
        "rubric_sha256": expected_suite["rubric_sha256"],
        "label_handbook_sha256": sha256_bytes(handbook_raw) if handbook_raw is not None else None,
        "observations": len(package_rows),
        "identity_blinded": True,
        "excluded_fields": ["model", "provider", "endpoint", "price", "latency", "split", "judge", "existing verdict"],
    }
    atomic_json(output / "package_manifest.json", manifest)
    package_manifest_sha256 = sha256_file(output / "package_manifest.json")
    atomic_text(linkage_output, "")
    for row in linkage_rows:
        append_jsonl(linkage_output, {**row, "package_manifest_sha256": package_manifest_sha256})
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
    require_mutable_output_root(output)
    if output.exists():
        raise ProtocolError(f"annotation evidence output already exists: {output}")
    if not reviewer_id.strip() or not qualification_evidence.strip() or not conflicts.strip():
        raise ProtocolError("reviewer ID, qualification evidence, and conflicts declaration are required")
    manifest_path = package / "package_manifest.json"
    annotations_path = package / "annotations.jsonl"
    rubric_path = package / "RUBRIC.md"
    handbook_path = package / "LABEL_HANDBOOK.md"
    if not manifest_path.is_file() or not annotations_path.is_file() or not linkage.is_file() or not rubric_path.is_file():
        raise ProtocolError("annotation package, manifest, or restricted linkage is missing")
    try:
        manifest_raw = manifest_path.read_bytes()
        annotations_raw = annotations_path.read_bytes()
        linkage_raw = linkage.read_bytes()
        rubric_raw = rubric_path.read_bytes()
        package_manifest = json.loads(manifest_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid annotation package manifest: {exc}") from exc
    if (
        not isinstance(package_manifest, dict)
        or package_manifest.get("annotation_package_version") != "1.0.0"
        or package_manifest.get("identity_blinded") is not True
        or any(
            not _is_sha256(package_manifest.get(field))
            for field in (
                "source_run_manifest_sha256",
                "source_run_bundle_sha256",
                "source_raw_responses_sha256",
                "dataset_sha256",
                "rubric_sha256",
            )
        )
    ):
        raise ProtocolError("annotation package manifest does not declare identity blinding")
    if sha256_bytes(rubric_raw) != package_manifest.get("rubric_sha256"):
        raise ProtocolError("annotation package rubric is missing or changed")
    expected_handbook = package_manifest.get("label_handbook_sha256")
    if expected_handbook is not None:
        try:
            handbook_raw = handbook_path.read_bytes() if handbook_path.is_file() else None
        except OSError as exc:
            raise ProtocolError("annotation package label handbook is missing or changed") from exc
        if handbook_raw is None or sha256_bytes(handbook_raw) != expected_handbook:
            raise ProtocolError("annotation package label handbook is missing or changed")
    package_rows = _jsonl(annotations_path, annotations_raw)
    linkage_rows = _jsonl(linkage, linkage_raw)
    linkage_map = {str(row.get("package_id")): row for row in linkage_rows}
    if len(linkage_map) != len(linkage_rows):
        raise ProtocolError("restricted linkage contains duplicate package IDs")
    manifest_sha256 = sha256_bytes(manifest_raw)
    if package_manifest.get("observations") != len(package_rows) or len(package_rows) != len(linkage_rows):
        raise ProtocolError("annotation package observation count does not match its linkage")
    evidence: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in package_rows:
        package_id = row.get("package_id")
        if not isinstance(package_id, str) or not package_id or package_id in seen or package_id not in linkage_map:
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
        if (
            not isinstance(findings, dict)
            or not findings
            or not all(isinstance(key, str) and key and isinstance(value, bool) for key, value in findings.items())
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
        if (
            not isinstance(link.get("case_id"), str)
            or not link["case_id"]
            or not isinstance(link.get("repetition"), int)
            or isinstance(link.get("repetition"), bool)
            or link.get("package_manifest_sha256") != manifest_sha256
            or link.get("item_sha256") != _immutable_item_sha256(row)
        ):
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
        "package_manifest_sha256": manifest_sha256,
        "completed_annotations_sha256": sha256_bytes(annotations_raw),
        "restricted_linkage_sha256": sha256_bytes(linkage_raw),
        "source_run_manifest_sha256": package_manifest.get("source_run_manifest_sha256"),
        "source_run_bundle_sha256": package_manifest.get("source_run_bundle_sha256"),
        "source_raw_responses_sha256": package_manifest.get("source_raw_responses_sha256"),
        "dataset_sha256": package_manifest.get("dataset_sha256"),
        "rubric_sha256": package_manifest.get("rubric_sha256"),
        "labels_sha256": sha256_file(output / "labels.jsonl"),
        "labels": len(evidence),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_json(output / "evidence_manifest.json", manifest)
    return manifest


def _annotation_evidence(path: Path) -> tuple[dict[tuple[str, int], dict[str, Any]], str, dict[str, Any], str]:
    labels_path = path.resolve() / "labels.jsonl"
    manifest_path = path.resolve() / "evidence_manifest.json"
    if not labels_path.is_file() or not manifest_path.is_file():
        raise ProtocolError("annotation evidence requires labels.jsonl and evidence_manifest.json")
    try:
        manifest_raw = manifest_path.read_bytes()
        labels_raw = labels_path.read_bytes()
        manifest = json.loads(manifest_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid annotation evidence manifest: {exc}") from exc
    reviewer_id = manifest.get("reviewer_id") if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or not isinstance(reviewer_id, str)
        or not reviewer_id
        or manifest.get("labels_sha256") != sha256_bytes(labels_raw)
        or any(not _is_sha256(manifest.get(field)) for field in EVIDENCE_BINDING_FIELDS)
    ):
        raise ProtocolError("annotation evidence identity or labels hash is invalid")
    rows = _jsonl(labels_path, labels_raw)
    evidence: dict[tuple[str, int], dict[str, Any]] = {}
    for row in rows:
        if (
            not isinstance(row.get("case_id"), str)
            or not isinstance(row.get("repetition"), int)
            or row.get("label") not in ANNOTATION_LABELS
            or row.get("reviewer_id") != reviewer_id
        ):
            raise ProtocolError("annotation evidence contains an invalid record")
        key = str(row["case_id"]), int(row["repetition"])
        if key in evidence:
            raise ProtocolError("annotation evidence contains duplicate observations")
        evidence[key] = row
    if not evidence:
        raise ProtocolError("annotation evidence is empty")
    return evidence, reviewer_id, manifest, sha256_bytes(manifest_raw)


def _paired_evidence(
    left: Path, right: Path
) -> tuple[
    dict[tuple[str, int], dict[str, Any]],
    dict[tuple[str, int], dict[str, Any]],
    tuple[str, str],
    dict[str, str],
    tuple[str, str],
]:
    left_map, left_reviewer, left_manifest, left_manifest_sha256 = _annotation_evidence(left)
    right_map, right_reviewer, right_manifest, right_manifest_sha256 = _annotation_evidence(right)
    if set(left_map) != set(right_map):
        raise ProtocolError("annotation evidence must contain identical unique observations")
    if left_reviewer == right_reviewer:
        raise ProtocolError("agreement requires two distinct reviewers")
    for field in EVIDENCE_BINDING_FIELDS:
        if left_manifest[field] != right_manifest[field]:
            raise ProtocolError("agreement requires annotations from the same exact source package")
    bindings = {field: str(left_manifest[field]) for field in EVIDENCE_BINDING_FIELDS}
    return left_map, right_map, (left_reviewer, right_reviewer), bindings, (left_manifest_sha256, right_manifest_sha256)


def _blind_review(row: dict[str, Any]) -> dict[str, Any]:
    return {
        field: row.get(field)
        for field in (
            "label",
            "criterion_findings",
            "rationale",
            "failure_severity",
            "confidence",
            "escalation_flags",
        )
    }


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
    require_mutable_output_root(output)
    if output.exists():
        raise ProtocolError(f"annotation agreement output already exists: {output}")
    if bootstrap_samples < 100:
        raise ProtocolError("annotation agreement requires at least 100 bootstrap samples")
    left_map, right_map, reviewers, bindings, _ = _paired_evidence(left, right)
    keys = sorted(left_map)
    pairs = [(str(left_map[item]["label"]), str(right_map[item]["label"])) for item in keys]
    raw_agreement = sum(left_label == right_label for left_label, right_label in pairs) / len(pairs)
    rng = random.Random(seed)  # noqa: S311 -- deterministic statistical resampling, not cryptography.
    estimates = sorted(_kappa(rng.choices(pairs, k=len(pairs))) for _ in range(bootstrap_samples))
    cut = quantiles(estimates, n=40, method="inclusive")
    order_rng = random.Random(seed)  # noqa: S311 -- identity blinding, not cryptography.
    disagreements: list[dict[str, Any]] = []
    for item in keys:
        if left_map[item]["label"] == right_map[item]["label"]:
            continue
        reviews = [_blind_review(left_map[item]), _blind_review(right_map[item])]
        order_rng.shuffle(reviews)
        disagreements.append(
            {
                "case_id": item[0],
                "repetition": item[1],
                "reviews": reviews,
                "decision": {
                    "label": None,
                    "criterion_findings": {},
                    "rationale": None,
                    "failure_severity": None,
                    "confidence": None,
                    "escalation_flags": [],
                },
            }
        )
    result = {
        "reviewers": sorted(reviewers),
        "source_package": bindings,
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


def ingest_adjudications(
    agreement: Path,
    left: Path,
    right: Path,
    output: Path,
    *,
    adjudicator_id: str,
    qualification_evidence: str,
    conflicts: str,
) -> dict[str, Any]:
    agreement = agreement.resolve()
    output = output.resolve()
    require_mutable_output_root(output)
    if output.exists():
        raise ProtocolError(f"adjudication evidence output already exists: {output}")
    if not adjudicator_id.strip() or not qualification_evidence.strip() or not conflicts.strip():
        raise ProtocolError("adjudicator ID, qualification evidence, and conflicts declaration are required")
    agreement_path = agreement / "agreement.json"
    decisions_path = agreement / "disagreements.jsonl"
    if not agreement_path.is_file() or not decisions_path.is_file():
        raise ProtocolError("agreement evidence requires agreement.json and disagreements.jsonl")
    try:
        agreement_raw = agreement_path.read_bytes()
        decisions_raw = decisions_path.read_bytes()
    except OSError as exc:
        raise ProtocolError("agreement evidence is unreadable") from exc
    left_map, right_map, reviewers, _, evidence_manifest_sha256 = _paired_evidence(left, right)
    if adjudicator_id in reviewers:
        raise ProtocolError("adjudicator must be distinct from both reviewers")
    expected = {key for key in left_map if left_map[key]["label"] != right_map[key]["label"]}
    decisions: dict[tuple[str, int], dict[str, Any]] = {}
    for row in _jsonl(decisions_path, decisions_raw):
        key = row.get("case_id"), row.get("repetition")
        if not isinstance(key[0], str) or not isinstance(key[1], int) or key in decisions:
            raise ProtocolError("adjudication package contains an invalid or duplicate observation")
        if key not in expected:
            raise ProtocolError("adjudication package includes an observation without reviewer disagreement")
        source_reviews = {_json_key(_blind_review(left_map[key])), _json_key(_blind_review(right_map[key]))}
        package_reviews = row.get("reviews")
        if not isinstance(package_reviews, list) or len(package_reviews) != 2 or {_json_key(value) for value in package_reviews} != source_reviews:
            raise ProtocolError("adjudication package reviewer evidence was changed")
        decision = row.get("decision")
        if not isinstance(decision, dict):
            raise ProtocolError("adjudication decision is missing")
        label = decision.get("label")
        rationale = decision.get("rationale")
        findings = decision.get("criterion_findings")
        confidence = decision.get("confidence")
        flags = decision.get("escalation_flags")
        failure_severity = decision.get("failure_severity")
        if label not in ANNOTATION_LABELS or not isinstance(rationale, str) or not rationale.strip():
            raise ProtocolError("adjudication decision is incomplete")
        if (
            not isinstance(findings, dict)
            or not findings
            or not all(isinstance(name, str) and name and isinstance(value, bool) for name, value in findings.items())
        ):
            raise ProtocolError("adjudication criterion findings must map names to booleans")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= float(confidence) <= 1:
            raise ProtocolError("adjudication confidence must be from 0 to 1")
        if not isinstance(flags, list) or not all(isinstance(flag, str) and flag for flag in flags):
            raise ProtocolError("adjudication escalation flags are invalid")
        if label == "fail" and failure_severity not in {"low", "medium", "high", "critical"}:
            raise ProtocolError("failed adjudication requires failure severity")
        if label != "fail" and failure_severity is not None:
            raise ProtocolError("only failed adjudications may set failure severity")
        decisions[key] = {
            "case_id": key[0],
            "repetition": key[1],
            "source_reviews": [left_map[key], right_map[key]],
            "adjudicator_id": adjudicator_id,
            **decision,
            "confidence": float(confidence),
        }
    if set(decisions) != expected:
        raise ProtocolError("every reviewer disagreement requires exactly one adjudication")
    output.mkdir(parents=True)
    atomic_text(output / "adjudications.jsonl", "")
    for key in sorted(decisions):
        append_jsonl(output / "adjudications.jsonl", decisions[key])
    manifest = {
        "adjudicator_id": adjudicator_id,
        "qualification_evidence": qualification_evidence,
        "conflicts": conflicts,
        "reviewers": sorted(reviewers),
        "agreement_sha256": sha256_bytes(agreement_raw),
        "completed_disagreements_sha256": sha256_bytes(decisions_raw),
        "left_evidence_manifest_sha256": evidence_manifest_sha256[0],
        "right_evidence_manifest_sha256": evidence_manifest_sha256[1],
        "adjudications_sha256": sha256_file(output / "adjudications.jsonl"),
        "adjudications": len(decisions),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_json(output / "evidence_manifest.json", manifest)
    return manifest


def _json_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
