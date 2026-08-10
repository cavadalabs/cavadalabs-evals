from __future__ import annotations

import csv
import json
import math
import re
import shutil
import tomllib
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from shutil import copyfile as _snapshot_copyfile
from tempfile import TemporaryDirectory
from typing import Any, cast

from .artifacts import verify_bundle
from .calibration import judge_evidence_errors
from .metrics import METRIC_VERSION
from .profiles import ADAPTER_CONTRACT_VERSION
from .protocol import (
    PROTOCOL_VERSION,
    REPORT_VERSION,
    SCHEMA_VERSION,
    ProtocolError,
    Suite,
    apply_gates,
    canonical_host,
    sha256_bytes,
    sha256_file,
    summarize,
    validate_suite,
)
from .statistics import bootstrap_mean_interval, distribution, paired_binary_comparison, stratified_bootstrap_mean_interval

_PLACEHOLDERS = {"", "unavailable", "unassigned", "unassessed", "not-assessed", "replace-me"}
_BLINDING_PLACEHOLDERS = _PLACEHOLDERS | {"model", "target", "unknown", "unspecified", "none", "null", "n/a"}
_PROHIBITED_CLAIM_FRAGMENTS = ("accredited", "certified", "legally compliant", "universally correct", "universally safe", "universally secure")
_DECISIONS = ("statistical", "security", "privacy_legal", "disclosure", "release")
_EVIDENCE = ("authorization", "conflict_assessment", "legal_applicability", "approver_qualification")
_HASH = re.compile(r"[a-f0-9]{64}")
_MANIFEST_FIELDS = {
    "protocol_version",
    "protocol_sha256",
    "schema_version",
    "report_version",
    "metric_version",
    "adapter_contract_version",
    "run_id",
    "status",
    "official_requested",
    "official",
    "started_at",
    "finished_at",
    "abort_reason",
    "suite",
    "target",
    "judge",
    "judge_qualification",
    "engagement",
    "external_judge_authorized",
    "external_authorization",
    "artifact_security",
    "parameters",
    "pricing",
    "source",
    "environment",
    "signing",
    "reproduction_command",
    "public_reproduction_command",
    "metrics",
    "artifacts",
}
_PARAMETER_FIELDS = {
    "mode",
    "case_review_policy",
    "preset",
    "preset_version",
    "repetitions",
    "judge_repetitions",
    "max_cases",
    "selected_cases",
    "timeout_seconds",
    "max_target_calls",
    "max_judge_calls",
    "max_total_tokens",
    "max_elapsed_seconds",
    "max_estimated_cost",
    "non_inferiority_margin",
    "concurrency",
    "requests_per_second",
    "progress_events",
    "case_order_policy",
    "case_order_sha256",
    "cache",
}
_METRIC_FIELDS = {
    "total",
    "observations",
    "pass",
    "fail",
    "invalid",
    "error",
    "skipped",
    "pass_rate",
    "pass_rate_ci",
    "pass_rate_ci95",
    "officially_valid",
    "analysis_unit",
    "evaluation_cases",
    "target_observations",
    "evidence_reconciliation",
    "constructs",
    "aggregate_scope",
    "legacy_overall_metrics_claimable",
    "case_level",
    "case_categories",
    "pass_rate_bootstrap_ci",
    "pass_rate_stratified_bootstrap_ci",
    "distribution_shift",
    "slices",
    "slice_disparities",
    "stability",
    "judge_calibration",
    "performance",
    "performance_by_phase",
    "budgets",
    "cost",
    "gate_failures",
    "aborted",
}
_REQUIRED_METRIC_FIELDS = _METRIC_FIELDS - {"case_level", "case_categories", "distribution_shift", "cost"}
_REQUIRED_RUN_ARTIFACTS = {
    "requests.jsonl",
    "raw_responses.jsonl",
    "judgments.jsonl",
    "engine_results.jsonl",
    "case_results.jsonl",
    "metrics.json",
    "category_results.csv",
    "failures.jsonl",
    "events.jsonl",
    "adjudication_queue.jsonl",
    "environment.json",
    "asset_inventory.json",
    "protocol_snapshot.md",
    "suite_snapshot.toml",
    "dataset_snapshot.jsonl",
    "rubric_snapshot.md",
    "suite_evidence_manifest.json",
    "judge_qualification_snapshot.json",
    "judge_approval_snapshot.json",
    "dataset_card.md",
    "report.html",
    "report_public.html",
    "report.pdf",
    "report_public.pdf",
    "summary.json",
    "junit.xml",
}


def canonical_protocol_path() -> Path:
    for path in (Path(__file__).resolve().parents[2] / "PROTOCOL.md", Path(__file__).resolve().parent / "_resources" / "PROTOCOL.md"):
        if path.is_file() and not path.is_symlink():
            return path
    raise ProtocolError(f"canonical protocol {PROTOCOL_VERSION} is unavailable")


def _safe_package_path(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ProtocolError(f"{label} path is missing")
    candidate = Path(relative)
    windows = PureWindowsPath(relative)
    if (
        candidate.is_absolute()
        or windows.drive
        or ".." in candidate.parts
        or ".." in windows.parts
        or candidate.as_posix() != relative
        or windows.as_posix() != relative
    ):
        raise ProtocolError(f"{label} path is unsafe")
    return root / candidate


def suite_governance_snapshots(root: Path, config: dict[str, Any]) -> dict[str, bytes]:
    """Read only the hash-pinned governance closure referenced by an official suite."""
    snapshots: dict[str, bytes] = {}

    def evidence(owner: Any, field: str, label: str, *, record: bool = False) -> dict[str, Any] | None:
        if not isinstance(owner, dict):
            return None
        relative = owner.get(field)
        expected_hash = owner.get(f"{field}_sha256")
        if (relative is None or relative == "") and (expected_hash is None or expected_hash == ""):
            return None
        if not isinstance(expected_hash, str) or _HASH.fullmatch(expected_hash) is None:
            raise ProtocolError(f"{label} requires a pinned SHA-256")
        path = _safe_package_path(root, relative, label)
        if path.is_symlink() or not path.is_file():
            raise ProtocolError(f"{label} must be a regular suite-local file")
        raw = path.read_bytes()
        if sha256_bytes(raw) != expected_hash:
            raise ProtocolError(f"{label} hash mismatch")
        previous = snapshots.setdefault(str(relative), raw)
        if previous != raw:
            raise ProtocolError(f"{label} path has conflicting contents")
        if not record:
            return None
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"{label} must be valid JSON") from exc
        if not isinstance(value, dict):
            raise ProtocolError(f"{label} must be a JSON object")
        return value

    calibration = config.get("calibration")
    integrity = config.get("dataset_integrity")
    report = evidence(calibration, "evidence", "calibration report", record=True)
    approval = evidence(calibration, "independent_review_evidence", "calibration independent approval", record=True)
    semantic = evidence(integrity, "semantic_review_evidence", "semantic contamination evidence", record=True)
    for field, label in (
        ("analysis_plan", "calibration analysis plan"),
        ("human_label_evidence", "calibration human-label evidence"),
        ("holdout_manifest", "calibration holdout manifest"),
        ("pilot_audit", "calibration pilot audit"),
        ("statistical_review", "calibration statistical review"),
        ("semantic_contamination_evidence", "calibration semantic-contamination evidence"),
    ):
        evidence(report, field, label)
    evidence(approval, "approver_qualification_evidence", "calibration approver qualification evidence")
    for field, label in (
        ("comparison_corpus", "semantic comparison corpus"),
        ("candidate_pairs_evidence", "semantic candidate-pair evidence"),
        ("reviewer_evidence", "semantic independent-review evidence"),
    ):
        evidence(semantic, field, label)
    return dict(sorted(snapshots.items()))


def official_revision(value: Any, label: str) -> None:
    if isinstance(value, str) and re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64}|sha256:[a-f0-9]{64})", value):
        return
    if isinstance(value, str) and value.startswith("opaque-immutable:"):
        identifier = value.removeprefix("opaque-immutable:")
        placeholders = {"main", "master", "head", "latest", "current", "stable", "default", "dev", "prod"}
        parts = {part.casefold() for part in re.split(r"[^A-Za-z0-9]+", identifier) if part}
        if len(identifier) >= 8 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/+~-]*", identifier) and not parts & placeholders:
            return
    raise ProtocolError(
        f"official {label} revision must be a full lowercase commit/content hash or opaque-immutable:<provider-id>"
    )


def parse_judgment(raw: dict[str, Any]) -> tuple[dict[str, Any], str]:
    try:
        content = raw["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ProtocolError("Judge returned no message content") from exc
    if not isinstance(content, str):
        raise ProtocolError("Judge content is not text")
    text = content.strip()
    if text.startswith("```"):
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError("Judge output is not valid JSON") from exc
    if not isinstance(parsed, dict) or set(parsed) != {"verdict", "score", "reason", "criteria"}:
        raise ProtocolError("Judge output must contain exactly verdict, score, reason, and criteria")
    if parsed.get("verdict") not in {"pass", "fail"}:
        raise ProtocolError("Judge verdict must be pass or fail")
    score = parsed.get("score")
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 5:
        raise ProtocolError("Judge score must be an integer from 0 to 5")
    if not isinstance(parsed.get("reason"), str) or not parsed["reason"].strip():
        raise ProtocolError("Judge reason is required")
    if not isinstance(parsed.get("criteria"), dict):
        raise ProtocolError("Judge criteria must be an object")
    return parsed, content


def reconcile_behavior_evidence(
    selected_cases: tuple[dict[str, Any], ...],
    repetitions: int,
    requests: list[dict[str, Any]],
    responses: list[dict[str, Any]],
    judgments: list[dict[str, Any]],
    results: list[dict[str, Any]],
    *,
    expected_judgments_per_observation: int = 0,
    consensus: str = "majority",
) -> dict[str, Any]:
    expected = {
        (str(case["id"]), repetition)
        for case in selected_cases
        if (case.get("review") or {}).get("status") != "rejected"
        for repetition in range(1, repetitions + 1)
    }
    errors: list[str] = []

    def keys(rows: list[dict[str, Any]], label: str) -> set[tuple[str, int]]:
        values: set[tuple[str, int]] = set()
        for row in rows:
            case_id, repetition = row.get("case_id"), row.get("repetition")
            if not isinstance(case_id, str) or not isinstance(repetition, int) or isinstance(repetition, bool):
                errors.append(f"{label} contains a malformed observation identity")
                continue
            key = (case_id, repetition)
            if key in values:
                errors.append(f"{label} contains duplicate observation {case_id}/{repetition}")
            values.add(key)
        return values

    result_rows = [row for row in results if row.get("repetition") is not None]
    target_requests = [row for row in requests if row.get("kind") == "target"]
    judge_requests = [row for row in requests if row.get("kind") == "judge"]
    result_keys = keys(result_rows, "case results")
    for name, observed in (
        ("case results", result_keys),
        ("target requests", keys(target_requests, "target requests")),
        ("target responses", keys(responses, "target responses")),
    ):
        if observed != expected:
            errors.append(f"{name} do not exactly match the scheduled observations")

    def judge_keys(rows: list[dict[str, Any]], label: str) -> set[tuple[str, int, int]]:
        values: set[tuple[str, int, int]] = set()
        for row in rows:
            case_id, repetition, judge_repetition = row.get("case_id"), row.get("repetition"), row.get("judge_repetition")
            if (
                not isinstance(case_id, str)
                or not isinstance(repetition, int)
                or isinstance(repetition, bool)
                or not isinstance(judge_repetition, int)
                or isinstance(judge_repetition, bool)
            ):
                errors.append(f"{label} contains a malformed judge observation identity")
                continue
            key = (case_id, repetition, judge_repetition)
            if key in values:
                errors.append(f"{label} contains duplicate judge observation {case_id}/{repetition}/{judge_repetition}")
            values.add(key)
        return values

    request_judge_keys = judge_keys(judge_requests, "judge requests")
    output_judge_keys = judge_keys(judgments, "judge outputs")
    if request_judge_keys != output_judge_keys:
        errors.append("judge requests and outputs do not exactly reconcile")
    if expected_judgments_per_observation:
        judgments_by_observation: dict[tuple[str, int], list[dict[str, Any]]] = {}
        for row in judgments:
            case_id, repetition = row.get("case_id"), row.get("repetition")
            if not isinstance(case_id, str) or not isinstance(repetition, int) or isinstance(repetition, bool):
                continue
            judgments_by_observation.setdefault((case_id, repetition), []).append(row)
        for row in result_rows:
            case_id, repetition = row.get("case_id"), row.get("repetition")
            if not isinstance(case_id, str) or not isinstance(repetition, int) or isinstance(repetition, bool):
                continue
            key = (case_id, repetition)
            status = row.get("status")
            reason = str(row.get("reason") or "")
            selected = judgments_by_observation.get(key, [])
            judge_terminal = status in {"pass", "invalid"} or (status == "fail" and reason.startswith("judge "))
            if judge_terminal and len(selected) != expected_judgments_per_observation:
                errors.append(f"case result {key[0]}/{key[1]} does not have the exact judge evidence count")
                continue
            if status == "fail" and reason in {"deterministic check failed", "metric engine hard check failed"} and selected:
                errors.append(f"deterministic case result {key[0]}/{key[1]} unexpectedly has judge evidence")
                continue
            if not judge_terminal:
                continue
            verdicts = [
                judgment.get("verdict")
                for item in selected
                if isinstance((judgment := item.get("judgment")), dict) and judgment.get("verdict") in {"pass", "fail"}
            ]
            passes = verdicts.count("pass")
            fails = verdicts.count("fail")
            if len(verdicts) != expected_judgments_per_observation or passes == fails or (
                consensus == "unanimous" and passes and fails
            ):
                reconciled_status = "invalid"
            else:
                reconciled_status = "pass" if passes > fails else "fail"
            if status != reconciled_status:
                errors.append(f"case result {key[0]}/{key[1]} disagrees with preserved judge evidence")
            if reconciled_status in {"pass", "fail"}:
                scores = [
                    score
                    for item in selected
                    if isinstance((judgment := item.get("judgment")), dict)
                    and isinstance((score := judgment.get("score")), int)
                    and not isinstance(score, bool)
                ]
                expected_score = sum(scores) / len(scores) if len(scores) == expected_judgments_per_observation else None
                expected_agreement = max(passes, fails) / len(verdicts) if verdicts else None
                if row.get("score") != expected_score or row.get("judge_agreement") != expected_agreement:
                    errors.append(f"case result {key[0]}/{key[1]} score or agreement differs from preserved judge evidence")
    return {
        "valid": not errors,
        "expected_observations": len(expected),
        "case_results": len(result_rows),
        "target_requests": len(target_requests),
        "target_responses": len(responses),
        "judge_requests": len(judge_requests),
        "judge_outputs": len(judgments),
        "errors": errors,
    }


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"{label} must be a readable JSON object") from exc
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a readable JSON object")
    if not _finite_json(value):
        raise ProtocolError(f"{label} contains a non-finite number")
    return value


def _read_regular_object(path: Path, label: str) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        raise ProtocolError(f"{label} must be a regular JSON file")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"{label} must be a readable JSON object") from exc
    if not isinstance(value, dict) or not _finite_json(value):
        raise ProtocolError(f"{label} must be a finite JSON object")
    return value, sha256_bytes(raw)


def _finite_json(value: Any) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _finite_json(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_finite_json(item) for item in value)
    return True


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ProtocolError(f"{path.name} must be readable") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid {path.name} line {line_number}") from exc
        if not isinstance(value, dict) or not _finite_json(value):
            raise ProtocolError(f"invalid {path.name} line {line_number}: expected a finite JSON object")
        rows.append(value)
    return rows


def _object(
    value: Any,
    required: set[str],
    label: str,
    errors: list[str],
    *,
    allowed: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return {}
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - (allowed or required))
    if missing:
        errors.append(f"{label} is missing fields: {missing}")
    if unknown:
        errors.append(f"{label} has unknown fields: {unknown}")
    return value


def _integer(value: Any, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _number(value: Any, *, minimum: float = 0, maximum: float | None = None, exclusive_minimum: bool = False) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
        return False
    numeric = float(value)
    if numeric < minimum or (exclusive_minimum and numeric == minimum):
        return False
    return maximum is None or numeric <= maximum


def _hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _same_rows(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> bool:
    def canonical(row: dict[str, Any]) -> str:
        return json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    return sorted(map(canonical, left)) == sorted(map(canonical, right))


def _distribution_shift_metrics(rows: list[dict[str, Any]], *, confidence: float, samples: int, seed: int) -> dict[str, Any] | None:
    shift_cases = {
        str(row.get("case_id")): row
        for row in rows
        if row.get("operating_condition") == "distribution-shift" and _usable(row.get("distribution_shift_reference_id"))
    }
    if not shift_cases:
        return None
    statuses: dict[str, set[str]] = {}
    for row in rows:
        statuses.setdefault(str(row.get("case_id")), set()).add(str(row.get("status")))

    def outcome(case_id: str) -> bool | None:
        values = statuses.get(case_id, set())
        if values == {"pass"}:
            return True
        if values and values <= {"pass", "fail"}:
            return False
        return None

    baseline: dict[str, bool] = {}
    shifted: dict[str, bool] = {}
    categories: dict[str, tuple[dict[str, bool], dict[str, bool]]] = {}
    for pair_id, row in shift_cases.items():
        left = outcome(str(row["distribution_shift_reference_id"]))
        right = outcome(pair_id)
        if left is None or right is None:
            continue
        baseline[pair_id], shifted[pair_id] = left, right
        category_pair = categories.setdefault(str(row.get("category")), ({}, {}))
        category_pair[0][pair_id], category_pair[1][pair_id] = left, right
    return {
        "declared_pairs": len(shift_cases),
        "valid_pairs": len(baseline),
        "invalid_pairs": len(shift_cases) - len(baseline),
        "comparison": paired_binary_comparison(baseline, shifted, confidence=confidence, samples=samples, seed=seed) if baseline else None,
        "by_category": {
            category: paired_binary_comparison(left, right, confidence=confidence, samples=samples, seed=seed)
            for category, (left, right) in sorted(categories.items())
        },
    }


def _payload_binding_errors(
    run_dir: Path,
    suite_config: dict[str, Any],
    cases: list[dict[str, Any]],
    rubric: str,
    suite_evidence: dict[str, str],
    manifest: dict[str, Any],
    requests: list[dict[str, Any]],
    responses: list[dict[str, Any]],
) -> list[str]:
    from .runner import JUDGE_MAX_TOKENS, _judge_system_prompt, _target_answer, build_judge_payload, build_target_payload, target_case_prompt

    errors: list[str] = []
    case_by_id: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in case_by_id:
            return ["dataset snapshot contains a missing or duplicate case identity"]
        case_by_id[case_id] = case
    target_value = manifest.get("target")
    judge_value = manifest.get("judge")
    target_config_value = suite_config.get("target")
    target_manifest: dict[str, Any] = target_value if isinstance(target_value, dict) else {}
    judge_manifest: dict[str, Any] = judge_value if isinstance(judge_value, dict) else {}
    target_config: dict[str, Any] = target_config_value if isinstance(target_config_value, dict) else {}
    target_kind = str(target_config.get("kind", "json"))
    if target_manifest.get("kind") != target_kind:
        errors.append("manifest target kind differs from the canonical suite snapshot")
    target_rows = [row for row in requests if row.get("kind") == "target"]

    def safe_path(root: Path, relative: Any, label: str) -> Path:
        return _safe_package_path(root, relative, label)

    with TemporaryDirectory(prefix="cavada-release-inputs-") as temporary:
        root = Path(temporary)
        try:
            dataset_path = safe_path(root, suite_config.get("dataset"), "suite dataset")
            rubric_path = safe_path(root, suite_config.get("rubric"), "suite rubric")
            for destination, source, label in (
                (root / "suite.toml", run_dir / "suite_snapshot.toml", "suite configuration"),
                (dataset_path, run_dir / "dataset_snapshot.jsonl", "suite dataset"),
                (rubric_path, run_dir / "rubric_snapshot.md", "suite rubric"),
            ):
                destination.parent.mkdir(parents=True, exist_ok=True)
                source_raw = source.read_bytes()
                if destination.exists() and destination.read_bytes() != source_raw:
                    raise ProtocolError(f"{label} snapshot path conflicts with another canonical input")
                destination.write_bytes(source_raw)
        except (OSError, ProtocolError) as exc:
            errors.append(f"canonical suite cannot be materialized: {exc}")
            dataset_path = run_dir / "dataset_snapshot.jsonl"
            rubric_path = run_dir / "rubric_snapshot.md"
        asset_parts = [
            part
            for case in cases
            for value in [case.get("input"), *(message.get("content") for message in case.get("messages", []) if isinstance(message, dict))]
            if isinstance(value, list)
            for part in value
            if isinstance(part, dict) and part.get("type") in {"image", "audio", "video", "document"}
        ]
        if asset_parts:
            try:
                inventory_value = json.loads((run_dir / "asset_inventory.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"asset inventory cannot reconstruct canonical case inputs: {exc}")
                inventory_value = []
            inventory = inventory_value if isinstance(inventory_value, list) else []
            by_digest = {
                str(item.get("sha256")): item
                for item in inventory
                if isinstance(item, dict) and _hash(item.get("sha256"))
            }
            for part in asset_parts:
                digest = part.get("sha256")
                entry = by_digest.get(str(digest))
                try:
                    if not _hash(digest) or entry is None:
                        raise ProtocolError("asset inventory lacks a case-pinned snapshot")
                    source = safe_path(run_dir, entry.get("snapshot"), "asset snapshot")
                    if source.is_symlink() or not source.is_file() or sha256_file(source) != digest:
                        raise ProtocolError("asset snapshot differs from its case-pinned digest")
                    destination = safe_path(root, part.get("asset"), "case asset")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if destination.exists() and sha256_file(destination) != digest:
                        raise ProtocolError("case asset path maps to conflicting digests")
                    if not destination.exists():
                        shutil.copyfile(source, destination)
                except (OSError, ProtocolError) as exc:
                    errors.append(str(exc))
                    break

        system_prompt = target_config.get("system_prompt")
        if system_prompt:
            content: str | None = None
            if target_rows:
                payload = target_rows[0].get("payload")
                messages = payload.get("messages") if isinstance(payload, dict) else None
                first = messages[0] if isinstance(messages, list) and messages else None
                if isinstance(first, dict) and first.get("role") == "system" and isinstance(first.get("content"), str):
                    content = first["content"]
            if content is None or sha256_bytes(content.encode("utf-8")) != target_config.get("system_prompt_sha256"):
                errors.append("target system prompt cannot be reconstructed from its pinned request evidence")
            else:
                try:
                    destination = safe_path(root, system_prompt, "target system prompt")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text(content, encoding="utf-8")
                except (OSError, ProtocolError) as exc:
                    errors.append(str(exc))

        for relative, digest in suite_evidence.items():
            try:
                source = run_dir / "suite_evidence" / digest
                if source.is_symlink() or not source.is_file() or sha256_file(source) != digest:
                    raise ProtocolError("suite governance snapshot differs from its declared digest")
                destination = safe_path(root, relative, "suite governance evidence")
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() and sha256_file(destination) != digest:
                    raise ProtocolError("suite governance evidence path conflicts with another canonical input")
                if not destination.exists():
                    destination.write_bytes(source.read_bytes())
            except (OSError, ProtocolError) as exc:
                errors.append(str(exc))
                break

        snapshot_suite = Suite(
            root,
            suite_config,
            tuple(cases),
            rubric,
            dataset_path,
            rubric_path,
        )
        try:
            reconstructed_evidence = {
                relative: sha256_bytes(raw) for relative, raw in suite_governance_snapshots(root, suite_config).items()
            }
            if reconstructed_evidence != suite_evidence:
                errors.append("suite governance evidence manifest does not match the canonical closed reference set")
        except ProtocolError as exc:
            errors.append(f"suite governance evidence cannot be reconstructed: {exc}")
        errors.extend(f"snapshot suite: {error}" for error in validate_suite(snapshot_suite, official=True))
        recorded_hash = target_manifest.get("recorded_responses_sha256")
        if target_kind == "recorded" and recorded_hash != target_config.get("responses_sha256"):
            errors.append("recorded response source hash differs from the canonical suite snapshot")
        for row in target_rows:
            selected_case = case_by_id.get(str(row.get("case_id")))
            if selected_case is None:
                errors.append("target request references a case outside the dataset snapshot")
                break
            try:
                expected = build_target_payload(
                    snapshot_suite,
                    target_case_prompt(selected_case, target_kind),
                    cast(str | None, target_manifest.get("request_model")),
                    recorded_responses_sha256=cast(str | None, recorded_hash),
                )
            except (OSError, ProtocolError) as exc:
                errors.append(f"target payload cannot be reconstructed from canonical inputs: {exc}")
                break
            if row.get("payload") != expected:
                errors.append("target payload differs from the canonical dataset and suite snapshots")
                break

        response_by_observation = {(str(row.get("case_id")), row.get("repetition")): row for row in responses}
        specs = {
            str(item.get("id")): item
            for item in judge_manifest.get("models", [])
            if isinstance(item, dict)
        }
        expected_system = _judge_system_prompt(snapshot_suite)
        if judge_manifest.get("prompt_sha256") != sha256_bytes(expected_system.encode("utf-8")):
            errors.append("judge prompt hash differs from the canonical rubric snapshot")
        if judge_manifest.get("temperature") != 0 or judge_manifest.get("max_tokens") != JUDGE_MAX_TOKENS:
            errors.append("judge parameters differ from the runtime payload contract")
        identities = [
            value.strip().casefold()
            for value in (
                target_manifest.get("label"),
                target_manifest.get("expected_reported_model"),
                target_manifest.get("revision"),
                target_manifest.get("request_model"),
            )
            if isinstance(value, str) and value.strip().casefold() not in _BLINDING_PLACEHOLDERS
        ]
        for row in (item for item in requests if item.get("kind") == "judge"):
            payload = row.get("payload")
            payload_text = json.dumps(payload, ensure_ascii=False, sort_keys=True).casefold()
            if any(identity in payload_text for identity in identities):
                errors.append("judge payload exposes target identity")
                break
            selected_case = case_by_id.get(str(row.get("case_id")))
            response = response_by_observation.get((str(row.get("case_id")), row.get("repetition")))
            spec = specs.get(str(row.get("judge_id")))
            raw = response.get("response") if isinstance(response, dict) else None
            if selected_case is None or spec is None or not isinstance(response, dict) or not isinstance(raw, dict):
                errors.append("judge payload lacks its canonical case, target response, or judge specification")
                break
            try:
                answer, reported_model = _target_answer(snapshot_suite, raw)
                expected = build_judge_payload(snapshot_suite, str(spec.get("model")), selected_case, answer, raw)
            except (OSError, ProtocolError) as exc:
                errors.append(f"judge payload cannot be reconstructed from canonical inputs: {exc}")
                break
            if reported_model != response.get("reported_model") or payload != expected:
                errors.append("judge payload differs from the canonical case, rubric, target response, or judge parameters")
                break
    return errors


def _deterministic_engine_errors(
    suite_config: dict[str, Any],
    cases: list[dict[str, Any]],
    requests: list[dict[str, Any]],
    responses: list[dict[str, Any]],
    results: list[dict[str, Any]],
    engine_rows: list[dict[str, Any]],
) -> list[str]:
    from .deepeval_adapter import evaluate_metrics as evaluate_deepeval_metrics
    from .metrics import deterministic_evaluation
    from .runner import _get, _target_answer

    errors: list[str] = []
    case_by_id = {str(case.get("id")): case for case in cases}

    def observation(row: dict[str, Any]) -> tuple[str, int] | None:
        case_id, repetition = row.get("case_id"), row.get("repetition")
        if not isinstance(case_id, str) or not isinstance(repetition, int) or isinstance(repetition, bool) or repetition < 1:
            return None
        return case_id, repetition

    def indexed(rows: list[dict[str, Any]], label: str) -> dict[tuple[str, int], dict[str, Any]]:
        values: dict[tuple[str, int], dict[str, Any]] = {}
        for row in rows:
            key = observation(row)
            if key is None or key in values:
                errors.append(f"{label} contains a malformed or duplicate observation identity")
                continue
            values[key] = row
        return values

    response_by_observation = indexed(responses, "target response ledger")
    result_by_observation = indexed(results, "case result ledger")
    engine_by_observation = indexed(engine_rows, "engine result ledger")
    judge_observations = {
        key
        for row in requests
        if row.get("kind") == "judge" and (key := observation(row)) is not None
    }
    target_value = suite_config.get("target")
    metrics_value = suite_config.get("metrics")
    target: dict[str, Any] = target_value if isinstance(target_value, dict) else {}
    metrics: dict[str, Any] = metrics_value if isinstance(metrics_value, dict) else {}
    deep_value = metrics.get("deepeval", []) if isinstance(metrics, dict) else []
    deep_config = deep_value if isinstance(deep_value, list) and all(isinstance(item, dict) for item in deep_value) else []
    if deep_value != deep_config:
        errors.append("canonical suite DeepEval configuration is malformed")
    expected_engine_keys: set[tuple[str, int]] = set()
    identity_fields = {
        "case_id",
        "category",
        "risk_domain",
        "severity",
        "language",
        "locale",
        "split",
        "operating_condition",
        "distribution_shift_reference_id",
        "scenario_id",
        "case_review_status",
        "performance_phase",
        "repetition",
    }
    for key, result in result_by_observation.items():
        case = case_by_id.get(key[0])
        response = response_by_observation.get(key)
        raw = response.get("response") if isinstance(response, dict) else None
        if case is None or not isinstance(raw, dict):
            errors.append("deterministic evaluation lacks its canonical case or target response")
            continue
        canonical_projection = {
            "case_id": str(case["id"]),
            "category": case["category"],
            "risk_domain": case["risk_domain"],
            "severity": case["severity"],
            "language": case.get("language", "missing"),
            "locale": case.get("locale", "missing"),
            "split": case.get("split", "missing"),
            "operating_condition": case.get("operating_condition", "missing"),
            "distribution_shift_reference_id": case.get("distribution_shift_reference_id"),
            "scenario_id": case.get("scenario_group_id") or case.get("scenario_id"),
            "case_review_status": case["review"]["status"],
            "performance_phase": case.get("performance_phase", "steady"),
            "repetition": key[1],
        }
        if any(result.get(field) != value for field, value in canonical_projection.items()):
            errors.append("case result identity or case projection differs from the canonical dataset")
            continue
        try:
            answer, _ = _target_answer(Suite(Path(), suite_config, (), "", Path(), Path()), raw)
            retrieval = _get(raw, str(target.get("retrieved_ids_field", "retrieved_ids"))) or []
            tools = _get(raw, str(target.get("tools_field", "tool_calls"))) or []
            deterministic = deterministic_evaluation(case, answer, target_raw=raw, retrieved_ids=retrieval, tool_calls=tools)
        except ProtocolError as exc:
            errors.append(f"deterministic evaluation cannot be reconstructed: {exc}")
            continue
        if result.get("deterministic") != deterministic:
            errors.append("case result deterministic projection differs from the canonical case and target response")
        if not deterministic["hard_pass"]:
            if result.get("status") != "fail" or result.get("reason") != "deterministic check failed" or key in judge_observations or key in engine_by_observation:
                errors.append("failed hard deterministic checks do not match the terminal case and judge/engine ledgers")
            continue
        if not deep_config:
            continue
        expected_engine_keys.add(key)
        engine_row = engine_by_observation.get(key)
        if engine_row is None:
            errors.append("DeepEval configuration lacks exact engine evidence for a deterministic-pass observation")
            continue
        if set(engine_row) != identity_fields | {"results"} or any(engine_row.get(field) != result.get(field) for field in identity_fields):
            errors.append("engine result identity or case projection differs from case_results.jsonl")
        try:
            expected_results = evaluate_deepeval_metrics(cast(list[dict[str, Any]], deep_config), case, answer, official=True)
        except ProtocolError as exc:
            errors.append(f"official DeepEval evidence cannot be recalculated offline: {exc}")
            continue
        if engine_row.get("results") != expected_results:
            errors.append("DeepEval evidence differs from the exact configured metric projection")
            continue
        hard_failed = any(item.get("hard_fail") is True and item.get("success") is not True for item in expected_results)
        if hard_failed:
            if (
                result.get("status") != "fail"
                or result.get("reason") != "metric engine hard check failed"
                or result.get("engine_results") != expected_results
                or key in judge_observations
            ):
                errors.append("failed hard engine checks do not match the terminal case and judge ledgers")
        elif result.get("reason") == "metric engine hard check failed" or "engine_results" in result:
            errors.append("case result claims a hard engine failure not present in exact engine evidence")
    if set(engine_by_observation) != expected_engine_keys:
        errors.append("engine result ledger does not exactly match configured deterministic-pass observations")
    return errors


def _external_authorization_errors(manifest: dict[str, Any], finished_at: datetime, now: datetime) -> list[str]:
    errors: list[str] = []
    target_value = manifest.get("target")
    judge_value = manifest.get("judge")
    target: dict[str, Any] = target_value if isinstance(target_value, dict) else {}
    judge: dict[str, Any] = judge_value if isinstance(judge_value, dict) else {}
    loopback = {"127.0.0.1", "localhost", "::1"}
    external_hosts: set[str] = set()
    for label, endpoint in (("target", target.get("endpoint")), ("judge", judge.get("endpoint"))):
        if label == "target" and target.get("kind") == "recorded":
            continue
        parsed = urllib.parse.urlsplit(str(endpoint))
        if parsed.hostname is None or parsed.scheme not in {"http", "https"}:
            errors.append(f"manifest {label} endpoint is not an HTTP(S) authority")
            continue
        try:
            host = canonical_host(parsed.hostname)
        except ProtocolError as exc:
            errors.append(f"manifest {label} endpoint host is invalid: {exc}")
            continue
        if host not in loopback:
            external_hosts.add(host)
            if parsed.scheme != "https":
                errors.append(f"manifest external {label} endpoint must use HTTPS")

    authorization_value = manifest.get("external_authorization")
    authorization = authorization_value if isinstance(authorization_value, dict) else None
    authorized_flag = manifest.get("external_judge_authorized")
    if authorized_flag is not bool(authorization):
        errors.append("external_judge_authorized is inconsistent with the authorization record")
    classification = ((manifest.get("suite") or {}).get("data_classification") if isinstance(manifest.get("suite"), dict) else None)
    if external_hosts and authorization is None:
        qualifier = "non-public " if classification not in {"public", "synthetic"} else ""
        errors.append(f"{qualifier}external endpoints require an exact authorization record")
        return errors
    if authorization is None:
        return errors
    if not external_hosts:
        errors.append("external authorization exists without an external endpoint")
    if set(authorization) != {"authorization_id", "approver", "purpose", "destinations", "expires_at", "sha256"}:
        errors.append("external authorization projection is not exact")
    if (
        not all(_usable(authorization.get(field)) for field in ("authorization_id", "approver", "purpose"))
        or not _hash(authorization.get("sha256"))
        or authorization.get("sha256") == "0" * 64
    ):
        errors.append("external authorization identity, purpose, approver, or digest is invalid")
    destinations = authorization.get("destinations")
    destination_hosts: list[str] = []
    if not isinstance(destinations, list) or not destinations:
        errors.append("external authorization destinations are missing")
    else:
        for destination in destinations:
            if (
                not isinstance(destination, dict)
                or set(destination) != {"host", "region", "purpose"}
                or not _usable(destination.get("region"))
                or not _usable(destination.get("purpose"))
            ):
                errors.append("external authorization destination requires exact host, region, and purpose")
                continue
            try:
                destination_hosts.append(canonical_host(destination.get("host")))
            except ProtocolError as exc:
                errors.append(f"external authorization destination host is invalid: {exc}")
    if len(destination_hosts) != len(set(destination_hosts)) or set(destination_hosts) != external_hosts:
        errors.append("external authorization host set differs from the exact external target/judge endpoints")
    try:
        expires_at = _time(authorization.get("expires_at"), "external authorization expires_at")
        if not finished_at < expires_at or not now < expires_at:
            errors.append("external authorization is expired for the run or public release")
    except ProtocolError as exc:
        errors.append(str(exc))
    return errors


def _suite_evidence_snapshot(
    run_dir: Path,
    artifacts: dict[str, Any],
) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    try:
        value = _read_object(run_dir / "suite_evidence_manifest.json", "suite governance evidence manifest")
    except ProtocolError as exc:
        return {}, [str(exc)]
    evidence: dict[str, str] = {}
    for relative, digest in value.items():
        try:
            _safe_package_path(Path(), relative, "suite governance evidence")
        except ProtocolError as exc:
            errors.append(str(exc))
            continue
        if not _hash(digest):
            errors.append("suite governance evidence manifest contains an invalid digest")
            continue
        evidence[relative] = digest
    if not evidence:
        errors.append("official run lacks its closed suite governance evidence set")
    expected_blobs = {f"suite_evidence/{digest}" for digest in evidence.values()}
    actual_blobs = {name for name in artifacts if name.startswith("suite_evidence/")}
    if actual_blobs != expected_blobs:
        errors.append("suite governance evidence blobs do not exactly match the closed manifest")
    for name in expected_blobs:
        digest = name.removeprefix("suite_evidence/")
        path = run_dir / name
        if artifacts.get(name) != digest or path.is_symlink() or not path.is_file() or sha256_file(path) != digest:
            errors.append("suite governance evidence blob differs from its declared digest")
            break
    return evidence, errors


def _judge_evidence_snapshot_errors(
    run_dir: Path,
    manifest: dict[str, Any],
    artifacts: dict[str, Any],
    now: datetime,
) -> list[str]:
    errors: list[str] = []
    projected_value = manifest.get("judge_qualification")
    projected: dict[str, Any] = projected_value if isinstance(projected_value, dict) else {}
    expected_hashes = {
        "judge_qualification_snapshot.json": projected.get("qualification_sha256"),
        "judge_approval_snapshot.json": projected.get("approval_sha256"),
    }
    for name, digest in expected_hashes.items():
        if artifacts.get(name) != digest:
            errors.append(f"{name} hash differs from its authoritative manifest digest")
    support_digest = projected.get("approver_qualification_evidence_sha256")
    expected_support = {f"judge_evidence/{support_digest}"} if _hash(support_digest) else set()
    actual_support = {name for name in artifacts if name.startswith("judge_evidence/")}
    if actual_support != expected_support:
        errors.append("judge supporting evidence does not exactly match its manifest projection")
    try:
        qualification = _read_object(run_dir / "judge_qualification_snapshot.json", "judge qualification snapshot")
        approval = _read_object(run_dir / "judge_approval_snapshot.json", "judge approval snapshot")
    except ProtocolError as exc:
        return [*errors, str(exc)]
    expected_projection = {
        "qualification_sha256": sha256_file(run_dir / "judge_qualification_snapshot.json"),
        "approval_sha256": sha256_file(run_dir / "judge_approval_snapshot.json"),
        "approval_id": approval.get("approval_id"),
        "approver_id": approval.get("approver_id"),
        "approved_at": approval.get("approved_at"),
        "expires_at": approval.get("expires_at"),
        "approver_qualification_evidence_sha256": approval.get("approver_qualification_evidence_sha256"),
    }
    if projected != expected_projection:
        errors.append("manifest judge qualification projection differs from its exact snapshots")
    with TemporaryDirectory(prefix="cavada-release-judge-") as temporary:
        approval_root = Path(temporary)
        try:
            destination = _safe_package_path(
                approval_root,
                approval.get("approver_qualification_evidence"),
                "judge approver qualification evidence",
            )
            source = run_dir / f"judge_evidence/{support_digest}"
            if (
                not _hash(support_digest)
                or artifacts.get(f"judge_evidence/{support_digest}") != support_digest
                or source.is_symlink()
                or not source.is_file()
                or sha256_file(source) != support_digest
            ):
                raise ProtocolError("judge approver qualification snapshot is missing or hash-mismatched")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            errors.extend(
                judge_evidence_errors(
                    qualification,
                    approval,
                    qualification_sha256=str(projected.get("qualification_sha256") or ""),
                    expected_judge=manifest.get("judge"),
                    rubric_sha256=str((manifest.get("suite") or {}).get("rubric_sha256") or ""),
                    approval_root=approval_root,
                    now=now,
                )
            )
        except (OSError, ProtocolError) as exc:
            errors.append(str(exc))
    engagement_value = manifest.get("engagement")
    engagement: dict[str, Any] = engagement_value if isinstance(engagement_value, dict) else {}
    if approval.get("approver_id") in {engagement.get("execution_owner_id"), engagement.get("commercial_owner_id")}:
        errors.append("judge approval is not independent of the engagement execution and commercial owners")
    return errors


def _official_behavior_run_errors(run_dir: Path, manifest: dict[str, Any], bundle: dict[str, Any], now: datetime) -> list[str]:
    errors: list[str] = []
    if set(manifest) != _MANIFEST_FIELDS:
        return ["manifest does not implement the exact completed behavior-run contract"]
    versions = (
        manifest.get("protocol_version"),
        manifest.get("schema_version"),
        manifest.get("report_version"),
        manifest.get("metric_version"),
        manifest.get("adapter_contract_version"),
    )
    if versions != (PROTOCOL_VERSION, SCHEMA_VERSION, REPORT_VERSION, METRIC_VERSION, ADAPTER_CONTRACT_VERSION):
        errors.append("manifest behavior contract versions are unsupported")
    if not _hash(manifest.get("protocol_sha256")):
        errors.append("manifest protocol snapshot digest is missing or malformed")
    if (
        manifest.get("status") != "passed"
        or manifest.get("official") is not True
        or manifest.get("official_requested") is not True
        or manifest.get("abort_reason") != ""
    ):
        errors.append("manifest is not a completed, non-aborted official behavior run")
    if not all(_usable(manifest.get(field)) for field in ("run_id", "reproduction_command", "public_reproduction_command")):
        errors.append("manifest run and reproduction identity is incomplete")
    try:
        started_at = _time(manifest.get("started_at"), "run started_at")
        finished_at = _time(manifest.get("finished_at"), "run finished_at")
        if not started_at <= finished_at <= now:
            errors.append("run timestamps are inconsistent or in the future")
    except ProtocolError as exc:
        errors.append(str(exc))
        started_at = finished_at = now
    errors.extend(_external_authorization_errors(manifest, finished_at, now))

    suite = _object(
        manifest.get("suite"),
        {"name", "version", "status", "dataset_sha256", "rubric_sha256", "suite_config_sha256", "data_classification", "profile"},
        "manifest suite",
        errors,
    )
    if (
        not _usable(suite.get("name"))
        or re.fullmatch(r"\d+\.\d+\.\d+", str(suite.get("version", ""))) is None
        or suite.get("status") != "approved"
        or not all(_hash(suite.get(field)) for field in ("dataset_sha256", "rubric_sha256", "suite_config_sha256"))
        or not _usable(suite.get("data_classification"))
        or not _usable(suite.get("profile"))
    ):
        errors.append("manifest suite is not an exact approved immutable suite")

    target = _object(
        manifest.get("target"),
        {"label", "expected_reported_model", "revision", "endpoint", "request_model", "api_key_env", "kind", "capabilities", "recorded_responses_sha256"},
        "manifest target",
        errors,
    )
    if not _usable(target.get("label")) or not _usable(target.get("expected_reported_model")) or target.get("kind") not in {"json", "openai", "recorded"}:
        errors.append("manifest target identity is incomplete")
    if not isinstance(target.get("endpoint"), str) or "?" in str(target.get("endpoint")) or "#" in str(target.get("endpoint")):
        errors.append("manifest target endpoint is not official-safe")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(target.get("api_key_env", ""))) is None:
        errors.append("manifest target credential reference is malformed")
    try:
        official_revision(target.get("revision"), "target")
    except ProtocolError as exc:
        errors.append(str(exc))

    judge = _object(
        manifest.get("judge"),
        {
            "requested_model",
            "expected_reported_model",
            "revision",
            "endpoint",
            "prompt_sha256",
            "response_schema",
            "temperature",
            "max_tokens",
            "judge_repetitions",
            "models",
            "consensus",
            "api_key_env",
        },
        "manifest judge",
        errors,
    )
    if (
        not _usable(judge.get("requested_model"))
        or not _usable(judge.get("expected_reported_model"))
        or not _hash(judge.get("prompt_sha256"))
        or judge.get("response_schema") != "judgment.schema.json@1.0.0"
        or judge.get("temperature") != 0
        or not _integer(judge.get("max_tokens"), minimum=1)
        or not _integer(judge.get("judge_repetitions"), minimum=1)
        or judge.get("consensus") not in {"majority", "unanimous"}
        or not isinstance(judge.get("endpoint"), str)
        or "?" in str(judge.get("endpoint"))
        or "#" in str(judge.get("endpoint"))
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(judge.get("api_key_env", ""))) is None
    ):
        errors.append("manifest judge configuration is incomplete or non-official")
    try:
        official_revision(judge.get("revision"), "judge")
    except ProtocolError as exc:
        errors.append(str(exc))
    model_values = judge.get("models")
    models = model_values if isinstance(model_values, list) else []
    if not models:
        errors.append("manifest judge models must be a non-empty array")
    model_ids: set[str] = set()
    expected_models: set[str] = set()
    for index, item in enumerate(models, 1):
        model = _object(item, {"id", "model", "expected_model", "revision"}, f"manifest judge model {index}", errors)
        if not all(_usable(model.get(field)) for field in ("id", "model", "expected_model")):
            errors.append(f"manifest judge model {index} identity is incomplete")
        if model.get("id") in model_ids or model.get("expected_model") in expected_models:
            errors.append("manifest judge models must have distinct ids and expected identities")
        model_ids.add(str(model.get("id")))
        expected_models.add(str(model.get("expected_model")))
        try:
            official_revision(model.get("revision"), f"judge model {index}")
        except ProtocolError as exc:
            errors.append(str(exc))
    if models and any(
        judge.get(field) != models[0].get(model_field)
        for field, model_field in (("requested_model", "model"), ("expected_reported_model", "expected_model"), ("revision", "revision"))
    ):
        errors.append("manifest primary judge projection does not match its model entry")

    qualification = _object(
        manifest.get("judge_qualification"),
        {"qualification_sha256", "approval_sha256", "approval_id", "approver_id", "approved_at", "expires_at", "approver_qualification_evidence_sha256"},
        "manifest judge qualification",
        errors,
    )
    if not all(_hash(qualification.get(field)) for field in ("qualification_sha256", "approval_sha256", "approver_qualification_evidence_sha256")) or not all(
        _usable(qualification.get(field)) for field in ("approval_id", "approver_id")
    ):
        errors.append("manifest judge qualification evidence is incomplete")
    try:
        qualified_at = _time(qualification.get("approved_at"), "judge qualification approved_at")
        qualification_expires = _time(qualification.get("expires_at"), "judge qualification expires_at")
        if not qualified_at <= started_at <= finished_at <= now < qualification_expires:
            errors.append("judge qualification is not effective for execution and release")
    except ProtocolError as exc:
        errors.append(str(exc))

    recorded_engagement = _object(
        manifest.get("engagement"),
        {
            "engagement_id",
            "sha256",
            "status",
            "cavadalabs_roles",
            "jurisdictions",
            "permitted_claims",
            "prohibited_claims",
            "execution_owner_id",
            "commercial_owner_id",
            "approved_at",
            "expires_at",
            "authorization_evidence_sha256",
            "conflict_assessment_evidence_sha256",
            "legal_applicability_evidence_sha256",
            "approver_qualification_evidence_sha256",
        },
        "manifest engagement",
        errors,
    )
    engagement_hashes = ("sha256", "authorization_evidence_sha256", "conflict_assessment_evidence_sha256", "legal_applicability_evidence_sha256", "approver_qualification_evidence_sha256")
    if recorded_engagement.get("status") != "approved" or not all(_hash(recorded_engagement.get(field)) for field in engagement_hashes):
        errors.append("manifest engagement projection is incomplete")

    parameters = _object(manifest.get("parameters"), _PARAMETER_FIELDS, "manifest parameters", errors)
    if parameters.get("mode") != "official" or parameters.get("case_review_policy") != "approved-only" or parameters.get("max_cases") != 0:
        errors.append("manifest parameters do not record a complete official run")
    for field in ("repetitions", "judge_repetitions", "selected_cases", "concurrency"):
        if not _integer(parameters.get(field), minimum=1):
            errors.append(f"manifest parameter {field} must be a positive integer")
    for field in ("max_target_calls", "max_judge_calls", "max_total_tokens"):
        if not _integer(parameters.get(field)):
            errors.append(f"manifest parameter {field} must be a non-negative integer")
    for field, exclusive in (("timeout_seconds", True), ("max_elapsed_seconds", False), ("max_estimated_cost", False), ("requests_per_second", False)):
        if not _number(parameters.get(field), exclusive_minimum=exclusive):
            errors.append(f"manifest parameter {field} must be a finite non-negative number")
    margin = parameters.get("non_inferiority_margin")
    if margin is not None and not _number(margin, maximum=1):
        errors.append("manifest non-inferiority margin must be null or a finite rate")
    if parameters.get("judge_repetitions") != judge.get("judge_repetitions") or not isinstance(parameters.get("progress_events"), bool):
        errors.append("manifest runtime and judge repetition parameters are inconsistent")
    if not _usable(parameters.get("case_order_policy")) or not _hash(parameters.get("case_order_sha256")) or parameters.get("cache") != {"target": "disabled", "judge": "disabled"}:
        errors.append("manifest case ordering or cache policy is incomplete")
    if parameters.get("preset") not in {"", "reference"} or (parameters.get("preset") == "reference" and not _usable(parameters.get("preset_version"))):
        errors.append("manifest official preset is unsupported")

    source = _object(manifest.get("source"), {"commit", "dirty", "status_sha256"}, "manifest source", errors)
    if re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", str(source.get("commit", ""))) is None or source.get("dirty") is not False or not _hash(source.get("status_sha256")):
        errors.append("manifest source is not an immutable clean revision")

    security = _object(
        manifest.get("artifact_security"),
        {"classification", "retention", "storage_attestation", "encryption_state", "immutability_state"},
        "manifest artifact security",
        errors,
    )
    if security.get("classification") != suite.get("data_classification"):
        errors.append("manifest artifact classification differs from the suite")
    if suite.get("data_classification") not in {"public", "synthetic"}:
        storage = _object(
            security.get("storage_attestation"),
            {"attestation_id", "approver", "encryption_at_rest", "immutability", "effective_at", "expires_at", "sha256"},
            "manifest storage attestation",
            errors,
        )
        if storage.get("encryption_at_rest") is not True or storage.get("immutability") is not True or not _hash(storage.get("sha256")):
            errors.append("non-public release lacks encrypted immutable storage evidence")
        try:
            if not _time(storage.get("effective_at"), "storage effective_at") <= finished_at <= now < _time(storage.get("expires_at"), "storage expires_at"):
                errors.append("storage attestation is not effective for execution and release")
        except ProtocolError as exc:
            errors.append(str(exc))

    metrics = _read_object(run_dir / "metrics.json", "run metrics")
    if manifest.get("metrics") != metrics:
        errors.append("manifest metrics do not exactly match metrics.json")
    if not _REQUIRED_METRIC_FIELDS <= set(metrics) or set(metrics) - _METRIC_FIELDS:
        errors.append("metrics.json does not implement the complete behavior metrics contract")
    if (
        metrics.get("officially_valid") is not True
        or metrics.get("aborted") is not False
        or metrics.get("gate_failures") != []
        or any(metrics.get(field) != 0 for field in ("error", "invalid", "skipped"))
    ):
        errors.append("official metrics contain an abort, gate failure, error, invalid, or skipped unit")
    for field in ("total", "observations", "pass", "fail", "invalid", "error", "skipped", "evaluation_cases", "target_observations"):
        if not _integer(metrics.get(field)):
            errors.append(f"metrics {field} must be a non-negative integer")
    if metrics.get("pass", 0) + metrics.get("fail", 0) != metrics.get("total"):
        errors.append("official metrics status counts do not reconcile")
    budgets = metrics.get("budgets")
    if not isinstance(budgets, dict) or budgets.get("exhausted") is not False:
        errors.append("official metrics record an invalid or exhausted budget")

    artifacts = manifest.get("artifacts")
    bundle_files = bundle.get("files")
    expected_artifacts = {name: digest for name, digest in bundle_files.items() if name != "manifest.json"} if isinstance(bundle_files, dict) else {}
    if not isinstance(artifacts, dict) or artifacts != expected_artifacts:
        errors.append("manifest artifact map does not exactly match the hashed bundle files")
        artifacts = {}
    if not _REQUIRED_RUN_ARTIFACTS <= set(artifacts):
        errors.append("official run is missing required evidence or report artifacts")
    snapshot_hashes = {
        "protocol_snapshot.md": manifest.get("protocol_sha256"),
        "suite_snapshot.toml": suite.get("suite_config_sha256"),
        "dataset_snapshot.jsonl": suite.get("dataset_sha256"),
        "rubric_snapshot.md": suite.get("rubric_sha256"),
    }
    for name, expected_hash in snapshot_hashes.items():
        if artifacts.get(name) != expected_hash:
            errors.append(f"{name} hash differs from its authoritative manifest digest")
    suite_evidence, suite_evidence_errors = _suite_evidence_snapshot(run_dir, artifacts)
    errors.extend(suite_evidence_errors)
    errors.extend(_judge_evidence_snapshot_errors(run_dir, manifest, artifacts, now))
    try:
        canonical_protocol = canonical_protocol_path().read_bytes()
        recorded_protocol = (run_dir / "protocol_snapshot.md").read_bytes()
    except OSError as exc:
        raise ProtocolError("protocol_snapshot.md and its canonical protocol resource must be readable") from exc
    if recorded_protocol != canonical_protocol or manifest.get("protocol_sha256") != sha256_bytes(canonical_protocol):
        errors.append(f"protocol snapshot is not the canonical bytes for protocol {PROTOCOL_VERSION}")
    try:
        suite_config = tomllib.loads((run_dir / "suite_snapshot.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError("suite_snapshot.toml must be a readable TOML configuration") from exc
    snapshot_cases = _read_jsonl(run_dir / "dataset_snapshot.jsonl")
    try:
        snapshot_rubric = (run_dir / "rubric_snapshot.md").read_text(encoding="utf-8")
    except OSError as exc:
        raise ProtocolError("rubric_snapshot.md must be readable") from exc
    if any(suite_config.get(field) != suite.get(field) for field in ("name", "version", "status", "data_classification")):
        errors.append("suite snapshot identity differs from the manifest suite")
    if (suite_config.get("pricing") or None) != manifest.get("pricing"):
        errors.append("suite snapshot pricing differs from the manifest")
    for suite_field, parameter_field in (
        ("official_min_repetitions", "repetitions"),
        ("official_min_judge_repetitions", "judge_repetitions"),
    ):
        minimum = suite_config.get(suite_field, 1)
        if not _integer(minimum, minimum=1) or not _integer(parameters.get(parameter_field), minimum=int(minimum or 1)):
            errors.append(f"manifest {parameter_field} is below the immutable suite minimum")
    environment = _read_object(run_dir / "environment.json", "environment evidence")
    if manifest.get("environment") != environment:
        errors.append("manifest environment does not exactly match environment.json")

    requests = _read_jsonl(run_dir / "requests.jsonl")
    responses = _read_jsonl(run_dir / "raw_responses.jsonl")
    judgments = _read_jsonl(run_dir / "judgments.jsonl")
    engine_results = _read_jsonl(run_dir / "engine_results.jsonl")
    results = _read_jsonl(run_dir / "case_results.jsonl")
    events = _read_jsonl(run_dir / "events.jsonl")
    errors.extend(
        _payload_binding_errors(
            run_dir,
            suite_config,
            snapshot_cases,
            snapshot_rubric,
            suite_evidence,
            manifest,
            requests,
            responses,
        )
    )
    errors.extend(_deterministic_engine_errors(suite_config, snapshot_cases, requests, responses, results, engine_results))
    if any("status" in row or "error" in row for row in requests + responses + judgments):
        errors.append("official request, response, and judgment ledgers must contain only successful terminal evidence")
    if any(not _usable(row.get("request_id")) or not isinstance(row.get("payload"), dict) or not row["payload"] for row in requests):
        errors.append("official request ledger requires a non-empty payload and request ID for every dispatch")
    request_ids = [str(row.get("request_id")) for row in requests]
    if len(request_ids) != len(set(request_ids)):
        errors.append("official request ledger contains duplicate request IDs")

    def observation_key(row: dict[str, Any]) -> tuple[str, int]:
        repetition = row.get("repetition")
        return str(row.get("case_id")), repetition if isinstance(repetition, int) and not isinstance(repetition, bool) else 0

    def judge_key(row: dict[str, Any]) -> tuple[str, int, int]:
        case_id, repetition = observation_key(row)
        judge_repetition = row.get("judge_repetition")
        return case_id, repetition, judge_repetition if isinstance(judge_repetition, int) and not isinstance(judge_repetition, bool) else 0

    target_requests = {observation_key(row): row for row in requests if row.get("kind") == "target"}
    target_responses = {observation_key(row): row for row in responses}
    judge_requests = {judge_key(row): row for row in requests if row.get("kind") == "judge"}

    def transport_matches(row: dict[str, Any], request: dict[str, Any] | None, *, recorded_allowed: bool) -> bool:
        transport = row.get("transport")
        if request is None or not isinstance(transport, dict) or transport.get("request_id") != request.get("request_id"):
            return False
        attempts = transport.get("attempts")
        return (
            isinstance(attempts, int)
            and not isinstance(attempts, bool)
            and attempts in ({0, 1} if recorded_allowed else {1})
            and _integer(transport.get("request_bytes"))
            and _integer(transport.get("response_bytes"))
            and _number(transport.get("total_ms"))
        )

    for row in responses:
        raw = row.get("response")
        if not isinstance(raw, dict) or not raw or not transport_matches(row, target_requests.get(observation_key(row)), recorded_allowed=True):
            errors.append("target response evidence lacks raw output or exact request/transport binding")
            break
    for row in judgments:
        raw = row.get("raw")
        raw_content = row.get("raw_content")
        if not isinstance(raw, dict) or not raw or not isinstance(raw_content, str) or not raw_content.strip():
            errors.append("judge evidence lacks raw output and raw content")
            break
        if not transport_matches(row, judge_requests.get(judge_key(row)), recorded_allowed=False):
            errors.append("judge evidence lacks exact request/transport binding")
            break
        try:
            parsed_judgment, parsed_content = parse_judgment(raw)
        except ProtocolError:
            errors.append("judge raw output cannot be reconstructed under the official judgment contract")
            break
        if parsed_judgment != row.get("judgment") or parsed_content != raw_content or raw.get("model") != row.get("reported_model"):
            errors.append("judge projection differs from its preserved raw output")
            break
    target_projection_fields = {
        "target_latency_ms",
        "target_headers_ms",
        "target_response_bytes",
        "ttft_ms",
        "inter_chunk_ms",
        "input_tokens",
        "output_tokens",
        "output_tokens_per_second",
    }
    for result in results:
        response = target_responses.get(observation_key(result))
        raw = response.get("response") if isinstance(response, dict) else None
        transport = response.get("transport") if isinstance(response, dict) else None
        if not isinstance(raw, dict) or not isinstance(transport, dict):
            continue
        expected_projection: dict[str, Any] = {
            "target_latency_ms": transport.get("total_ms"),
            "target_headers_ms": transport.get("headers_ms"),
            "target_response_bytes": transport.get("response_bytes"),
        }
        if "ttft_ms" in transport:
            expected_projection["ttft_ms"] = transport["ttft_ms"]
        if isinstance(transport.get("inter_chunk_ms"), dict):
            expected_projection["inter_chunk_ms"] = transport["inter_chunk_ms"]
        usage = raw.get("usage")
        if isinstance(usage, dict):
            expected_projection["input_tokens"] = usage.get("prompt_tokens")
            expected_projection["output_tokens"] = usage.get("completion_tokens")
            output_tokens = usage.get("completion_tokens")
            latency_ms = transport.get("total_ms")
            if isinstance(output_tokens, (int, float)) and isinstance(latency_ms, (int, float)) and latency_ms > 0:
                expected_projection["output_tokens_per_second"] = float(output_tokens) / (float(latency_ms) / 1000)
        actual_projection = {field: result[field] for field in target_projection_fields if field in result}
        if actual_projection != expected_projection:
            errors.append("case result target telemetry or usage differs from preserved response evidence")
            break
    timing_events: dict[tuple[str, int, str], dict[str, Any]] = {}
    for event in events:
        event_name = event.get("event")
        if event_name not in {"observation_started", "observation_finished"}:
            continue
        key = (*observation_key(event), str(event_name))
        if key in timing_events:
            errors.append("observation timing evidence contains duplicate terminal events")
            continue
        timing_events[key] = event
    for result in results:
        observation = observation_key(result)
        started_event = timing_events.get((*observation, "observation_started"))
        finished_event = timing_events.get((*observation, "observation_finished"))
        started_ns = started_event.get("monotonic_ns") if isinstance(started_event, dict) else None
        finished_ns = finished_event.get("monotonic_ns") if isinstance(finished_event, dict) else None
        finished_status = finished_event.get("status") if isinstance(finished_event, dict) else None
        if (
            not isinstance(started_ns, int)
            or isinstance(started_ns, bool)
            or not isinstance(finished_ns, int)
            or isinstance(finished_ns, bool)
            or finished_ns < started_ns
            or result.get("duration_ms") != round((finished_ns - started_ns) / 1_000_000, 1)
            or finished_status != result.get("status")
        ):
            errors.append("case result duration or status differs from preserved monotonic observation events")
            break
    expected_timing_keys = {
        (*observation_key(result), event_name)
        for result in results
        for event_name in ("observation_started", "observation_finished")
    }
    if set(timing_events) != expected_timing_keys:
        errors.append("observation timing events do not exactly match case results")
    if not results or any(not _usable(row.get("case_id")) or not _integer(row.get("repetition"), minimum=1) for row in results):
        errors.append("case result ledger lacks exact observation identities")
    if any(row.get("case_review_status") != "approved" for row in results):
        errors.append("official case result ledger contains a non-approved case")
    case_ids = tuple(str(case.get("id")) for case in snapshot_cases if _usable(case.get("id")))
    result_case_ids = {str(row.get("case_id")) for row in results if _usable(row.get("case_id"))}
    if len(case_ids) != len(set(case_ids)) or set(case_ids) != result_case_ids or len(case_ids) != parameters.get("selected_cases"):
        errors.append("canonical dataset snapshot, selected case count, and result ledger differ")
    if parameters.get("case_order_sha256") != sha256_bytes("\n".join(case_ids).encode("utf-8")):
        errors.append("manifest case order differs from the canonical dataset snapshot")
    selected_cases = tuple(snapshot_cases)
    repetitions_value = parameters.get("repetitions")
    judge_repetitions_value = parameters.get("judge_repetitions")
    repetitions = cast(int, repetitions_value) if _integer(repetitions_value, minimum=1) else 0
    judge_repetitions = cast(int, judge_repetitions_value) if _integer(judge_repetitions_value, minimum=1) else 0
    reconciliation = reconcile_behavior_evidence(
        selected_cases,
        repetitions,
        requests,
        responses,
        judgments,
        results,
        expected_judgments_per_observation=judge_repetitions * len(models),
        consensus=str(judge.get("consensus", "")),
    )
    if not reconciliation["valid"]:
        errors.extend(str(error) for error in reconciliation["errors"])
    if metrics.get("evidence_reconciliation") != reconciliation:
        errors.append("preserved behavior ledgers do not match the recorded evidence reconciliation")

    if any(row.get("reported_model") != target.get("expected_reported_model") for row in responses):
        errors.append("target response ledger differs from the expected model identity")
    specs = {str(item.get("id")): item for item in models if isinstance(item, dict)}
    judge_rows = [item for item in requests if item.get("kind") == "judge"] + judgments
    judgment_ids = {id(row) for row in judgments}
    for row in judge_rows:
        spec = specs.get(str(row.get("judge_id")))
        model_repetition = row.get("model_repetition")
        if (
            spec is None
            or row.get("requested_model") != spec.get("model")
            or row.get("judge_revision") != spec.get("revision")
            or not _integer(model_repetition, minimum=1)
            or int(model_repetition or 0) > judge_repetitions
        ):
            errors.append("judge ledger differs from the exact manifest judge configuration")
            break
        if id(row) in judgment_ids and row.get("reported_model") != spec.get("expected_model"):
            errors.append("judge output ledger differs from the expected model identity")
            break

    statistics_value = suite_config.get("statistics")
    statistics_config = statistics_value if isinstance(statistics_value, dict) else {}
    configured_confidence = statistics_config.get("confidence", 0.95)
    confidence_value = (metrics.get("pass_rate_ci") or {}).get("confidence") if isinstance(metrics.get("pass_rate_ci"), dict) else None
    if not _number(configured_confidence, maximum=1, exclusive_minimum=True):
        errors.append("suite snapshot confidence is malformed")
        confidence = 0.95
    else:
        confidence = float(cast(float, configured_confidence))
    if confidence_value != confidence:
        errors.append("metrics confidence differs from the immutable suite configuration")
    case_metrics, case_categories = summarize(results, confidence=confidence)
    from .runner import _scenario_analysis_rows

    scenario_rows = _scenario_analysis_rows(results, selected_cases)
    expected_analysis_unit = "scenario" if scenario_rows is not None else "case"
    if metrics.get("analysis_unit") != expected_analysis_unit:
        errors.append("metrics analysis unit differs from the canonical dataset scenario structure")
    analysis_rows = scenario_rows if scenario_rows is not None else results
    if scenario_rows is not None:
        if "scenario_results.jsonl" not in artifacts:
            errors.append("scenario analysis is missing scenario_results.jsonl")
        else:
            preserved_scenarios = _read_jsonl(run_dir / "scenario_results.jsonl")
            if preserved_scenarios != scenario_rows:
                errors.append("scenario result ledger differs from the canonical case results and dataset")
        if metrics.get("case_level") != case_metrics or metrics.get("case_categories") != case_categories:
            errors.append("case-level metrics do not reconcile with case_results.jsonl")
    elif "scenario_results.jsonl" in artifacts or "case_level" in metrics or "case_categories" in metrics:
        errors.append("case analysis contains unsupported scenario evidence or metrics")
    calculated, categories = summarize(analysis_rows, confidence=confidence)
    core_metrics = ("total", "observations", "pass", "fail", "invalid", "error", "skipped", "pass_rate", "pass_rate_ci", "pass_rate_ci95", "officially_valid")
    for field in core_metrics:
        if metrics.get(field) != calculated.get(field):
            errors.append(f"metrics {field} does not reconcile with the immutable result ledger")
    if metrics.get("evaluation_cases") != case_metrics["total"] or metrics.get("target_observations") != case_metrics["observations"]:
        errors.append("metrics case and observation counts do not reconcile with case_results.jsonl")
    constructs = sorted(str(row["category"]) for row in categories)
    aggregate_scope = "single-construct" if len(constructs) <= 1 else "not-applicable"
    if (
        metrics.get("constructs") != constructs
        or metrics.get("aggregate_scope") != aggregate_scope
        or metrics.get("legacy_overall_metrics_claimable") is not (aggregate_scope == "single-construct")
    ):
        errors.append("metrics construct scope does not reconcile with the result ledger")

    bootstrap_samples = statistics_config.get("bootstrap_samples", 10_000)
    bootstrap_seed = statistics_config.get("seed", 0)
    if not _integer(bootstrap_samples, minimum=100) or not isinstance(bootstrap_seed, int) or isinstance(bootstrap_seed, bool):
        errors.append("suite snapshot bootstrap configuration is malformed")
        bootstrap_samples, bootstrap_seed = 10_000, 0
    statuses_by_case: dict[str, list[str]] = {}
    for row in analysis_rows:
        statuses_by_case.setdefault(str(row.get("case_id")), []).append(str(row.get("status")))
    case_binary = [1.0 if set(statuses) == {"pass"} else 0.0 for statuses in statuses_by_case.values() if set(statuses) <= {"pass", "fail"}]
    expected_bootstrap = (
        bootstrap_mean_interval(case_binary, confidence=confidence, samples=bootstrap_samples, seed=bootstrap_seed)
        if case_binary
        else {"lower": 0.0, "upper": 0.0, "confidence": confidence, "samples": bootstrap_samples, "seed": bootstrap_seed}
    )
    category_binary: dict[str, list[float]] = {}
    for case_id, statuses in statuses_by_case.items():
        case_rows = [row for row in analysis_rows if str(row.get("case_id")) == case_id]
        if case_rows and set(statuses) <= {"pass", "fail"}:
            category_binary.setdefault(str(case_rows[0].get("category")), []).append(1.0 if set(statuses) == {"pass"} else 0.0)
    expected_stratified = stratified_bootstrap_mean_interval(
        category_binary,
        confidence=confidence,
        samples=bootstrap_samples,
        seed=bootstrap_seed,
    )
    if metrics.get("pass_rate_bootstrap_ci") != expected_bootstrap or metrics.get("pass_rate_stratified_bootstrap_ci") != expected_stratified:
        errors.append("bootstrap metrics do not reconcile with the immutable result ledger and suite configuration")

    expected_slices: dict[str, dict[str, Any]] = {}
    for dimension in ("risk_domain", "severity", "language", "locale", "split", "operating_condition"):
        expected_slices[dimension] = {
            value: summarize([row for row in analysis_rows if str(row.get(dimension, "missing")) == value], confidence=confidence)[0]
            for value in sorted({str(row.get(dimension, "missing")) for row in analysis_rows})
        }
    expected_disparities = {
        dimension: max((float(item["pass_rate"]) for item in values.values()), default=0.0)
        - min((float(item["pass_rate"]) for item in values.values()), default=0.0)
        for dimension, values in expected_slices.items()
    }
    if metrics.get("slices") != expected_slices or metrics.get("slice_disparities") != expected_disparities:
        errors.append("slice metrics do not reconcile with the immutable result ledger")

    case_statuses: dict[str, list[str]] = {}
    for row in results:
        case_statuses.setdefault(str(row.get("case_id")), []).append(str(row.get("status")))
    repetition_pass_rates = [
        sum(status == "pass" for status in valid) / len(valid)
        for statuses in case_statuses.values()
        if (valid := [status for status in statuses if status in {"pass", "fail"}])
    ]
    expected_stability = {
        "case_pass_fraction": distribution(repetition_pass_rates),
        "stable_case_fraction": sum(value in {0.0, 1.0} for value in repetition_pass_rates) / len(repetition_pass_rates) if repetition_pass_rates else 0.0,
        "judge_agreement": distribution(row["judge_agreement"] for row in results if isinstance(row.get("judge_agreement"), (int, float))),
        "judge_score": distribution(row["score"] for row in results if isinstance(row.get("score"), (int, float))),
    }
    if metrics.get("stability") != expected_stability:
        errors.append("stability metrics do not reconcile with the immutable result ledger")
    if metrics.get("judge_calibration") != {}:
        errors.append("public release cannot claim judge calibration not reconstructible from the release ledger")

    expected_shift = _distribution_shift_metrics(results, confidence=confidence, samples=bootstrap_samples, seed=bootstrap_seed)
    if (metrics.get("distribution_shift") if "distribution_shift" in metrics else None) != expected_shift:
        errors.append("distribution-shift metrics do not reconcile with the immutable result ledger")

    performance_value = metrics.get("performance")
    performance = performance_value if isinstance(performance_value, dict) else {}
    elapsed_seconds = performance.get("elapsed_seconds")
    if not _number(elapsed_seconds, exclusive_minimum=True):
        errors.append("performance elapsed_seconds is malformed")
        elapsed = 1.0
    else:
        elapsed = float(cast(float, elapsed_seconds))
    expected_performance = {
        "target_latency_ms": distribution(row["target_latency_ms"] for row in results if isinstance(row.get("target_latency_ms"), (int, float))),
        "evaluation_duration_ms": distribution(row["duration_ms"] for row in results if isinstance(row.get("duration_ms"), (int, float))),
        "target_response_bytes": distribution(row["target_response_bytes"] for row in results if isinstance(row.get("target_response_bytes"), (int, float))),
        "input_tokens": distribution(row["input_tokens"] for row in results if isinstance(row.get("input_tokens"), (int, float))),
        "output_tokens": distribution(row["output_tokens"] for row in results if isinstance(row.get("output_tokens"), (int, float))),
        "ttft_ms": distribution(row["ttft_ms"] for row in results if isinstance(row.get("ttft_ms"), (int, float))),
        "output_tokens_per_second": distribution(row["output_tokens_per_second"] for row in results if isinstance(row.get("output_tokens_per_second"), (int, float))),
        "elapsed_seconds": elapsed,
        "observations_per_second": len(results) / elapsed,
        "target_calls_per_second": len(target_requests) / elapsed,
        "observation_success_rate": sum(row.get("status") in {"pass", "fail"} for row in results) / len(results) if results else 0.0,
        "observation_error_rate": sum(row.get("status") == "error" for row in results) / len(results) if results else 0.0,
    }
    expected_performance_by_phase = {
        phase: distribution(
            row["target_latency_ms"] for row in results if row.get("performance_phase") == phase and isinstance(row.get("target_latency_ms"), (int, float))
        )
        for phase in ("cold", "warmup", "steady", "soak")
    }
    if performance != expected_performance or metrics.get("performance_by_phase") != expected_performance_by_phase:
        errors.append("performance metrics do not reconcile with the immutable result ledger")

    token_totals = {"target_input": 0.0, "target_output": 0.0, "judge_input": 0.0, "judge_output": 0.0}
    pricing = manifest.get("pricing") if isinstance(manifest.get("pricing"), dict) else None
    usage_required = bool(pricing or parameters.get("max_total_tokens") or parameters.get("max_estimated_cost"))

    def add_usage(raw: Any, kind: str) -> None:
        usage = raw.get("usage") if isinstance(raw, dict) else None
        if usage is None:
            if usage_required:
                errors.append("provider usage evidence is required for priced or usage-budgeted release evidence")
            return
        if not isinstance(usage, dict) or not all(_integer(usage.get(field)) for field in ("prompt_tokens", "completion_tokens")):
            errors.append("provider usage evidence in the release ledger is malformed")
            return
        token_totals[f"{kind}_input"] += float(usage["prompt_tokens"])
        token_totals[f"{kind}_output"] += float(usage["completion_tokens"])

    for row in responses:
        add_usage(row.get("response"), "target")
    for row in judgments:
        add_usage(row.get("raw"), "judge")
    expected_budgets = {
        "target_calls": len(target_requests),
        "judge_calls": len(judge_requests),
        "total_tokens": sum(token_totals.values()),
        "exhausted": False,
    }
    if metrics.get("budgets") != expected_budgets:
        errors.append("budget metrics do not reconcile with the immutable request and provider ledgers")
    if pricing is None:
        if "cost" in metrics:
            errors.append("cost metrics exist without an immutable pricing configuration")
    else:
        expected_cost = {
            "currency": pricing.get("currency"),
            "source": pricing.get("source"),
            "effective_at": pricing.get("effective_at"),
            "input_tokens": token_totals["target_input"],
            "output_tokens": token_totals["target_output"],
            "judge_input_tokens": token_totals["judge_input"],
            "judge_output_tokens": token_totals["judge_output"],
            "estimated_total": sum(
                token_totals[f"{kind}_{direction}"] * float(pricing.get(f"{prefix}_per_million", 0)) / 1_000_000
                for kind, direction, prefix in (
                    ("target", "input", "input"),
                    ("target", "output", "output"),
                    ("judge", "input", "judge_input"),
                    ("judge", "output", "judge_output"),
                )
            ),
        }
        if metrics.get("cost") != expected_cost:
            errors.append("cost metrics do not reconcile with immutable pricing and provider usage")

    gate_suite = Suite(run_dir, suite_config, (), "", run_dir / "dataset.jsonl", run_dir / "rubric.md")
    expected_gate_failures = apply_gates(gate_suite, calculated, categories)
    minimum_calibration_accuracy = (suite_config.get("judge") or {}).get("minimum_calibration_accuracy")
    if minimum_calibration_accuracy is not None:
        expected_gate_failures.append(
            {"category": "judge-calibration", "metric": "accuracy_ci.lower", "minimum": float(minimum_calibration_accuracy), "actual": None}
        )
    if metrics.get("gate_failures") != expected_gate_failures or expected_gate_failures:
        errors.append("gate results do not reconcile with the immutable suite snapshot and result ledger")

    failures = _read_jsonl(run_dir / "failures.jsonl")
    if not _same_rows(failures, [row for row in results if row.get("status") != "pass"]):
        errors.append("failure ledger does not reconcile with case_results.jsonl")
    category_fields = ("category", "total", "pass", "fail", "invalid", "error", "pass_rate", "ci95_lower", "ci95_upper", "confidence")
    try:
        with (run_dir / "category_results.csv").open(newline="", encoding="utf-8") as handle:
            csv_rows = list(csv.DictReader(handle))
    except (OSError, csv.Error) as exc:
        raise ProtocolError("category_results.csv must be readable") from exc
    expected_csv_rows = [
        {field: "" if row.get(field) is None else str(row.get(field)) for field in category_fields}
        for row in categories
    ]
    if csv_rows != expected_csv_rows:
        errors.append("category_results.csv does not reconcile with the immutable result ledger")
    summary = _read_object(run_dir / "summary.json", "run summary")
    summary_target_value = summary.get("target")
    summary_target: dict[str, Any] = summary_target_value if isinstance(summary_target_value, dict) else {}
    if (
        summary.get("protocol_version") != PROTOCOL_VERSION
        or summary.get("report_version") != REPORT_VERSION
        or summary.get("run_id") != manifest.get("run_id")
        or summary.get("status") != "passed"
        or summary.get("metrics") != metrics
        or summary.get("categories") != categories
        or summary.get("suite") != suite
        or summary_target.get("revision") != target.get("revision")
    ):
        errors.append("summary report projection differs from the immutable manifest or metrics")
    return errors


def _time(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(f"{label} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ProtocolError(f"{label} must include a timezone")
    return parsed


def _usable(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() not in _PLACEHOLDERS


def _evidence_error(container: Path, relative: Any, expected_hash: Any, label: str) -> str | None:
    if not _usable(relative) or not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or expected_hash == "0" * 64:
        return f"{label} path and non-placeholder SHA-256 are required"
    path = Path(str(relative))
    if path.is_absolute() or ".." in path.parts:
        return f"{label} path must stay inside its restricted evidence package"
    resolved = (container.parent / path).resolve()
    if not resolved.is_relative_to(container.parent.resolve()) or not resolved.is_file() or resolved.is_symlink():
        return f"{label} must be a regular file inside its restricted evidence package"
    if sha256_file(resolved) != expected_hash:
        return f"{label} hash mismatch"
    return None


def verified_engagement(
    path: Path,
    suite: Suite,
    *,
    expected_model: str,
    model_revision: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    record, record_sha256 = _read_regular_object(path, "engagement governance record")
    now = now or datetime.now(timezone.utc)
    errors: list[str] = []
    if record.get("engagement_version") != "1.1.0" or record.get("status") != "approved":
        errors.append("engagement must be version 1.1.0 with approved status")
    approved_at = _time(record.get("approved_at"), "engagement approved_at")
    expires_at = _time(record.get("expires_at"), "engagement expires_at")
    if not approved_at <= now < expires_at:
        errors.append("engagement is not currently effective")
    expected_suite = {
        "protocol_version": PROTOCOL_VERSION,
        "name": suite.name,
        "version": suite.version,
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
        "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
    }
    if record.get("suite") != expected_suite:
        errors.append("engagement does not match the exact suite configuration")
    expected_sut = {"expected_model": expected_model, "revision": model_revision}
    sut = record.get("sut")
    if not isinstance(sut, dict) or any(sut.get(key) != value for key, value in expected_sut.items()):
        errors.append("engagement does not match the exact SUT identity and revision")
    roles = record.get("cavadalabs_roles")
    if not isinstance(roles, list) or not {"evaluator", "testing-laboratory"} & set(map(str, roles)):
        errors.append("engagement must assign CavadaLabs an evaluator or testing-laboratory role")
    if record.get("conflicts_assessed") is not True:
        errors.append("engagement conflicts must be assessed")
    for field in ("counterparty_roles", "jurisdictions", "requested_claims"):
        values = record.get(field)
        if not isinstance(values, list) or not values or not all(_usable(item) for item in values):
            errors.append(f"engagement {field} is missing or contains placeholders")
    conflicts = record.get("conflicts")
    if not isinstance(conflicts, list) or any(not _usable(item) for item in conflicts):
        errors.append("engagement conflicts must be a reviewed array")
    for name in _EVIDENCE:
        error = _evidence_error(path, record.get(f"{name}_evidence"), record.get(f"{name}_evidence_sha256"), f"engagement {name} evidence")
        if error:
            errors.append(error)
    for field in (
        "engagement_id",
        "execution_owner_id",
        "commercial_owner_id",
        "scope",
        "system_owner_reference",
        "complaints_process_reference",
        "appeals_process_reference",
        "correction_revocation_reference",
        "disclosure_policy_reference",
        "approver_id",
    ):
        if not _usable(record.get(field)):
            errors.append(f"engagement {field} is missing or a placeholder")
    if record.get("approver_id") in {record.get("execution_owner_id"), record.get("commercial_owner_id")}:
        errors.append("engagement approver must be independent of execution and commercial ownership")
    if record.get("surveillance_required") is True and not _usable(record.get("surveillance_plan_reference")):
        errors.append("engagement requires a surveillance plan reference")
    permitted = record.get("permitted_claims")
    prohibited = record.get("prohibited_claims")
    if not isinstance(permitted, list) or not permitted or not all(_usable(item) for item in permitted):
        errors.append("engagement permitted claims are missing or contain placeholders")
        permitted = []
    if not isinstance(prohibited, list) or not prohibited or not all(_usable(item) for item in prohibited):
        errors.append("engagement prohibited claims are missing or contain placeholders")
        prohibited = []
    if {str(item).casefold() for item in permitted} & {str(item).casefold() for item in prohibited}:
        errors.append("engagement permitted and prohibited claims overlap")
    if any(fragment in str(claim).casefold() for claim in permitted for fragment in _PROHIBITED_CLAIM_FRAGMENTS):
        errors.append("engagement permits an unsupported certification, legal, or universal claim")
    if errors:
        raise ProtocolError("invalid engagement governance record:\n" + "\n".join(errors))
    return {
        "engagement_id": record["engagement_id"],
        "sha256": record_sha256,
        "status": record["status"],
        "cavadalabs_roles": roles,
        "jurisdictions": record.get("jurisdictions"),
        "permitted_claims": permitted,
        "prohibited_claims": prohibited,
        "execution_owner_id": record["execution_owner_id"],
        "commercial_owner_id": record["commercial_owner_id"],
        "approved_at": record["approved_at"],
        "expires_at": record["expires_at"],
        "authorization_evidence_sha256": record["authorization_evidence_sha256"],
        "conflict_assessment_evidence_sha256": record["conflict_assessment_evidence_sha256"],
        "legal_applicability_evidence_sha256": record["legal_applicability_evidence_sha256"],
        "approver_qualification_evidence_sha256": record["approver_qualification_evidence_sha256"],
    }


def verified_public_release(run_dir: Path, engagement_path: Path, approval_path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    if run_dir.is_symlink() or not run_dir.is_dir():
        raise ProtocolError("cannot release an unsafe run directory")
    with TemporaryDirectory(prefix="cavada-release-run-") as temporary:
        snapshot = Path(temporary) / "run"
        shutil.copytree(run_dir, snapshot, symlinks=True, copy_function=_snapshot_copyfile)
        return _verified_public_release_snapshot(snapshot, engagement_path, approval_path, now=now)


def _verified_public_release_snapshot(
    run_dir: Path,
    engagement_path: Path,
    approval_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    verification = verify_bundle(run_dir)
    if not verification["valid"]:
        raise ProtocolError("cannot release an invalid bundle")
    manifest = _read_object(run_dir / "manifest.json", "run manifest")
    bundle = _read_object(run_dir / "bundle.json", "run bundle")
    now = now or datetime.now(timezone.utc)
    run_errors = _official_behavior_run_errors(run_dir, manifest, bundle, now)
    if run_errors:
        raise ProtocolError("invalid official behavior run for public release:\n" + "\n".join(run_errors))
    engagement, engagement_sha256 = _read_regular_object(engagement_path, "engagement governance record")
    recorded = manifest.get("engagement")
    expected_recorded = {
        "engagement_id": engagement.get("engagement_id"),
        "sha256": engagement_sha256,
        "status": engagement.get("status"),
        "cavadalabs_roles": engagement.get("cavadalabs_roles"),
        "jurisdictions": engagement.get("jurisdictions"),
        "permitted_claims": engagement.get("permitted_claims"),
        "prohibited_claims": engagement.get("prohibited_claims"),
        "execution_owner_id": engagement.get("execution_owner_id"),
        "commercial_owner_id": engagement.get("commercial_owner_id"),
        "approved_at": engagement.get("approved_at"),
        "expires_at": engagement.get("expires_at"),
        "authorization_evidence_sha256": engagement.get("authorization_evidence_sha256"),
        "conflict_assessment_evidence_sha256": engagement.get("conflict_assessment_evidence_sha256"),
        "legal_applicability_evidence_sha256": engagement.get("legal_applicability_evidence_sha256"),
        "approver_qualification_evidence_sha256": engagement.get("approver_qualification_evidence_sha256"),
    }
    suite = manifest["suite"]
    expected_engagement_suite = {
        "protocol_version": PROTOCOL_VERSION,
        "name": suite["name"],
        "version": suite["version"],
        "dataset_sha256": suite["dataset_sha256"],
        "rubric_sha256": suite["rubric_sha256"],
        "suite_config_sha256": suite["suite_config_sha256"],
    }
    expected_sut = {"expected_model": manifest["target"]["expected_reported_model"], "revision": manifest["target"]["revision"]}
    if (
        recorded != expected_recorded
        or engagement.get("engagement_version") != "1.1.0"
        or engagement.get("suite") != expected_engagement_suite
        or engagement.get("sut") != expected_sut
    ):
        raise ProtocolError("release engagement does not match the run manifest")
    if engagement.get("status") != "approved" or not _time(engagement.get("approved_at"), "engagement approved_at") <= now < _time(
        engagement.get("expires_at"), "engagement expires_at"
    ):
        raise ProtocolError("release engagement is not currently effective")
    engagement_evidence_errors = [
        error
        for name in _EVIDENCE
        if (error := _evidence_error(
            engagement_path,
            engagement.get(f"{name}_evidence"),
            engagement.get(f"{name}_evidence_sha256"),
            f"engagement {name} evidence",
        ))
    ]
    if engagement_evidence_errors:
        raise ProtocolError("invalid release engagement evidence:\n" + "\n".join(engagement_evidence_errors))

    approval, approval_sha256 = _read_regular_object(approval_path, "release approval")
    errors: list[str] = []
    bundle_hash = sha256_file(run_dir / "bundle.json")
    expected = {
        "release_version": "1.0.0",
        "status": "approved",
        "run_id": manifest.get("run_id"),
        "bundle_sha256": bundle_hash,
        "manifest_sha256": sha256_file(run_dir / "manifest.json"),
        "engagement_id": engagement.get("engagement_id"),
        "engagement_sha256": engagement_sha256,
        "assurance_level": "approved",
    }
    for field, value in expected.items():
        if approval.get(field) != value:
            errors.append(f"release approval {field} does not match")
    if not _usable(approval.get("release_id")):
        errors.append("release approval release_id is missing or a placeholder")
    approved_at = _time(approval.get("approved_at"), "release approved_at")
    expires_at = _time(approval.get("expires_at"), "release expires_at")
    finished_at = _time(manifest.get("finished_at"), "run finished_at")
    engagement_expiry = _time(engagement.get("expires_at"), "engagement expires_at")
    if not finished_at <= approved_at <= now < expires_at <= engagement_expiry:
        errors.append("release approval timing is invalid or outside the engagement validity period")
    claims = approval.get("permitted_claims")
    engagement_claims = set(map(str, engagement.get("permitted_claims", [])))
    if not isinstance(claims, list) or not claims or not set(map(str, claims)) <= engagement_claims:
        errors.append("release claims are empty or exceed the approved engagement claims")
    if approval.get("limitations_acknowledged") is not True:
        errors.append("release approval must acknowledge the report limitations")
    decisions = approval.get("decisions")
    reviewers: dict[str, str] = {}
    decision_statuses: dict[str, str] = {}
    owners = {engagement.get("execution_owner_id"), engagement.get("commercial_owner_id")}
    if not isinstance(decisions, dict) or set(decisions) != set(_DECISIONS):
        errors.append("release approval requires the exact statistical, security, privacy_legal, disclosure, and release decisions")
    else:
        for name in _DECISIONS:
            decision = decisions[name]
            allowed_status = {"passed", "not-applicable"} if name == "privacy_legal" else {"passed"}
            if not isinstance(decision, dict) or decision.get("status") not in allowed_status or decision.get("independent") is not True:
                errors.append(f"release {name} decision did not pass independent review")
                continue
            reviewer = decision.get("reviewer_id")
            if not _usable(reviewer) or reviewer in owners:
                errors.append(f"release {name} reviewer is missing or not independent of execution/commercial ownership")
            else:
                reviewers[name] = str(reviewer)
            decision_statuses[name] = str(decision["status"])
            if not _usable(decision.get("rationale")):
                errors.append(f"release {name} decision lacks rationale")
            for evidence_name in ("review", "qualification"):
                error = _evidence_error(
                    approval_path,
                    decision.get(f"{evidence_name}_evidence"),
                    decision.get(f"{evidence_name}_evidence_sha256"),
                    f"release {name} {evidence_name} evidence",
                )
                if error:
                    errors.append(error)
            conflicts = decision.get("conflicts")
            if not isinstance(conflicts, list):
                errors.append(f"release {name} conflicts must be an array")
            elif conflicts and not _usable(decision.get("conflict_mitigation")):
                errors.append(f"release {name} conflicts require documented mitigation")
    if reviewers.get("release") in {value for key, value in reviewers.items() if key != "release"}:
        errors.append("release decision maker must be distinct from the technical, legal/privacy, and disclosure reviewers")
    if errors:
        raise ProtocolError("invalid public release approval:\n" + "\n".join(errors))
    return {
        "release_version": "1.0.0",
        "release_id": approval.get("release_id"),
        "run_id": manifest["run_id"],
        "bundle_sha256": bundle_hash,
        "manifest_sha256": expected["manifest_sha256"],
        "engagement_id": engagement["engagement_id"],
        "engagement_sha256": expected["engagement_sha256"],
        "approval_sha256": approval_sha256,
        "assurance_level": "approved",
        "permitted_claims": claims,
        "decision_statuses": decision_statuses,
        "evaluation_started_at": manifest["started_at"],
        "evaluation_finished_at": manifest["finished_at"],
        "approved_at": approval["approved_at"],
        "expires_at": approval["expires_at"],
    }
