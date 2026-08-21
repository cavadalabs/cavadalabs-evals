from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
import tomllib
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import Any

from .artifacts import _read_regular, snapshot_bundle_files, verify_bundle
from .assets import asset_inventory
from .metrics import METRIC_VERSION, deterministic_evaluation
from .profiles import ADAPTER_CONTRACT_VERSION, BENCHMARK_PRESET_VERSION, stratified_cases
from .protocol import (
    MANIFEST_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    REPORT_VERSION,
    ProtocolError,
    Suite,
    _closed_object_errors,
    _strict_json_loads,
    apply_gates,
    atomic_json,
    dataset_card,
    load_suite,
    sha256_bytes,
    sha256_file,
    summarize,
    write_category_csv,
)
from .statistics import bootstrap_mean_interval, distribution, stratified_bootstrap_mean_interval

_HASH = re.compile(r"[a-f0-9]{64}")
_ENGAGEMENT_EVIDENCE = ("authorization", "conflict_assessment", "legal_applicability", "approver_qualification")
_DERIVED_REPORT_ARTIFACTS = {
    "category_results.csv",
    "report.html",
    "report_public.html",
    "report.pdf",
    "report_public.pdf",
    "summary.json",
    "junit.xml",
    "figures/overall_scores.svg",
    "figures/category_scores.svg",
    "figures/latency.svg",
    "figures/status_distribution.svg",
    "figures/stability.svg",
    "figures/failure_severity.svg",
    "figures/slice_disparity.svg",
    "figures/judge_calibration.svg",
    "figures/latency_cdf.svg",
    "figures/distribution_shift.svg",
}
_REQUIRED_OFFICIAL_ARTIFACTS = {
    "requests.jsonl",
    "raw_responses.jsonl",
    "judgments.jsonl",
    "case_results.jsonl",
    "metrics.json",
    "timing.json",
    "failures.jsonl",
    "adjudication_queue.jsonl",
    "environment.json",
    "asset_inventory.json",
    "dataset_card.md",
    "protocol_snapshot.md",
    "suite_snapshot.toml",
    "dataset_snapshot.jsonl",
    "rubric_snapshot.md",
    "implementation_evidence_manifest.json",
    "source_commit_proof.pack",
    "suite_evidence_manifest.json",
    "judge_qualification_evidence/qualification_evidence.json",
    "judge_qualification_evidence/bundle.json",
    "judge_qualification_evidence/checksums.txt",
    "engagement_snapshot.json",
    "engagement_evidence_manifest.json",
} | _DERIVED_REPORT_ARTIFACTS
_REQUIRED_BEHAVIOR_ARTIFACTS = _REQUIRED_OFFICIAL_ARTIFACTS - {
    "source_commit_proof.pack",
    "judge_qualification_evidence/qualification_evidence.json",
    "judge_qualification_evidence/bundle.json",
    "judge_qualification_evidence/checksums.txt",
    "engagement_snapshot.json",
    "engagement_evidence_manifest.json",
}
_OPTIONAL_BEHAVIOR_ARTIFACTS = {
    "engine_results.jsonl",
    "scenario_results.jsonl",
    "events.jsonl",
    "judge_qualification_snapshot.json",
    "judge_approval_snapshot.json",
}
_DYNAMIC_BEHAVIOR_ARTIFACT_PREFIXES = (
    "assets/",
    "implementation_evidence/",
    "suite_evidence/",
)
_OFFICIAL_DYNAMIC_ARTIFACT_PREFIXES = (
    "engagement_evidence/",
    "judge_qualification_evidence/",
)
VERIFICATION_RESULT_VERSION = "2.0.0"
JUDGE_QUALIFICATION_SNAPSHOT = "judge_qualification_evidence"
_OBSERVATION_FIELDS = {
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
    "performance_phase",
    "repetition",
}
_JUDGE_EVIDENCE_FIELDS = {
    "judge_id",
    "requested_model",
    "judge_revision",
    "judge_repetition",
    "model_repetition",
}
_TRANSPORT_FIELDS = {
    "request_id",
    "attempts",
    "request_bytes",
    "response_bytes",
    "headers_ms",
    "total_ms",
    "ttft_ms",
    "inter_chunk_ms",
    "streaming",
    "recorded",
    "http_status",
    "retry_failures",
}
_DISTRIBUTION_FIELDS = {"count", "min", "max", "mean", "median", "stdev", "p50", "p90", "p95", "p99"}
_WIRE_BODY_FIELDS = {
    "wire_body_base64",
    "wire_body_sha256",
    "wire_body_bytes",
    "wire_body_truncated",
}
_RETRY_FAILURE_FIELDS = {
    "attempt",
    "error",
    "http_status",
    "response_bytes",
    "duration_ms",
} | _WIRE_BODY_FIELDS
_WIRE_ERROR_FIELDS = {"status", "error", "error_stage"} | _WIRE_BODY_FIELDS
_RESULT_FIELDS = _OBSERVATION_FIELDS | {
    "status",
    "reason",
    "score",
    "judge_agreement",
    "deterministic",
    "engine_results",
    "duration_ms",
    "target_latency_ms",
    "target_headers_ms",
    "target_response_bytes",
    "ttft_ms",
    "inter_chunk_ms",
    "input_tokens",
    "output_tokens",
    "output_tokens_per_second",
}
OFFICIAL_MANIFEST_FIELDS = {
    "protocol_version",
    "schema_version",
    "report_version",
    "metric_version",
    "adapter_contract_version",
    "run_id",
    "status",
    "official_requested",
    "official",
    "assurance",
    "model_claim_allowed",
    "benchmark_claim_allowed",
    "started_at",
    "finished_at",
    "resumed_at",
    "reproduction_command",
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
    "protocol_sha256",
    "metrics",
    "artifacts",
}
OFFICIAL_METRIC_FIELDS = {
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


def _strict_json(raw: str) -> Any:
    return _strict_json_loads(raw)


def _safe_path(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ProtocolError(f"{label} path is missing")
    path = Path(relative)
    windows = PureWindowsPath(relative)
    if (
        path.is_absolute()
        or windows.drive
        or ".." in path.parts
        or ".." in windows.parts
        or path.as_posix() != relative
        or windows.as_posix() != relative
    ):
        raise ProtocolError(f"{label} path is unsafe")
    candidate = root / path
    try:
        if root.is_symlink() or any((root / Path(*path.parts[:index])).is_symlink() for index in range(1, len(path.parts) + 1)):
            raise ProtocolError(f"{label} path is unsafe")
        candidate.resolve(strict=False).relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise ProtocolError(f"{label} path is unsafe") from exc
    return candidate


def qualification_package_snapshot_files(package: Path) -> dict[str, bytes]:
    """Read a verified qualification package once as an immutable snapshot."""
    return snapshot_bundle_files(package, allow_verification=False, verify_hmac=False)


def verify_judge_qualification_for_run(
    package: Path,
    *,
    suite: Suite,
    judge_configuration: dict[str, Any],
    now: datetime,
) -> tuple[Any, list[str]]:
    """Apply the one qualification reconstruction and exact-bind it to a behavior run."""
    from .qualification_evidence import (
        QUALIFICATION_EVIDENCE_VERSION,
        reconstruct_judge_qualification,
    )

    result = reconstruct_judge_qualification(
        package,
        now=now,
        base_behavior_verifier=verify_behavior_base,
    )
    failures = [f"judge qualification: {failure}" for failure in result.failures]
    if result.package_version != QUALIFICATION_EVIDENCE_VERSION:
        failures.append("judge qualification package version is unsupported")
    report = result.reconstructed_report
    expected_source_suite = {
        "name": suite.name,
        "version": suite.version,
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
    }
    if not isinstance(report, dict):
        failures.append("judge qualification report was not reconstructed from package bytes")
    else:
        if report.get("source_suite") != expected_source_suite:
            failures.append("judge qualification package does not bind the exact behavior suite")
        if report.get("rubric_sha256") != expected_source_suite["rubric_sha256"]:
            failures.append("judge qualification package does not bind the exact behavior rubric")
        if report.get("judge_configuration") != judge_configuration:
            failures.append("judge qualification package does not bind the exact judge configuration")
    if result.source_suite_configuration_sha256 != sha256_file(suite.root / "suite.toml"):
        failures.append("judge qualification package does not bind the exact behavior suite configuration")
    return result, list(dict.fromkeys(failures))


def _pinned_file(
    root: Path,
    owner: Any,
    field: str,
    label: str,
    *,
    require_digest: bool = True,
    require_unique: bool = True,
) -> tuple[str, bytes] | None:
    if not isinstance(owner, dict):
        return None
    value = owner.get(field)
    legacy_digest = owner.get(f"{field}_sha256")
    if (value is None or value == "") and (legacy_digest is None or legacy_digest == ""):
        return None
    if isinstance(value, dict):
        reference_fields = {"relative_path", "sha256", "artifact_type", "schema_version"}
        if set(value) != reference_fields:
            raise ProtocolError(f"{label} must be an exact artifact reference")
        if legacy_digest not in {None, ""}:
            raise ProtocolError(f"{label} mixes artifact-reference and legacy digest fields")
        relative, expected = value.get("relative_path"), value.get("sha256")
        if not isinstance(value.get("artifact_type"), str) or not value["artifact_type"].strip():
            raise ProtocolError(f"{label} artifact type is missing")
        if not isinstance(value.get("schema_version"), str) or re.fullmatch(r"\d+\.\d+\.\d+", value["schema_version"]) is None:
            raise ProtocolError(f"{label} schema version is invalid")
    else:
        relative, expected = value, legacy_digest
    if require_digest and (not isinstance(expected, str) or _HASH.fullmatch(expected) is None):
        raise ProtocolError(f"{label} requires a pinned SHA-256")
    path = _safe_path(root, relative, label)
    try:
        raw = _read_regular(root, path.relative_to(root), require_unique=require_unique)
    except (OSError, ValueError) as exc:
        raise ProtocolError(f"{label} must be a regular package-local file") from exc

    if expected not in {None, ""} and (not isinstance(expected, str) or _HASH.fullmatch(expected) is None or sha256_bytes(raw) != expected):
        raise ProtocolError(f"{label} hash mismatch")
    return str(relative), raw


def suite_snapshot_files(suite: Suite, *, require_pins: bool = True) -> dict[str, bytes]:
    """Return the closed, hash-pinned files needed to revalidate an official suite."""
    snapshots: dict[str, bytes] = {}

    def add(owner: Any, field: str, label: str, *, record: bool = False) -> dict[str, Any] | None:
        pinned = _pinned_file(
            suite.root,
            owner,
            field,
            label,
            require_digest=require_pins,
            require_unique=False,
        )
        if pinned is None:
            return None
        relative, raw = pinned
        if relative in snapshots and snapshots[relative] != raw:
            raise ProtocolError(f"{label} conflicts with another suite snapshot")
        snapshots[relative] = raw
        if not record:
            return None
        try:
            value = _strict_json(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError(f"{label} must be valid JSON") from exc
        if not isinstance(value, dict):
            raise ProtocolError(f"{label} must be a JSON object")
        return value

    def store(path: Path, label: str, expected: str | None = None) -> bytes:
        try:
            relative = path.resolve().relative_to(suite.root.resolve()).as_posix()
        except ValueError as exc:
            raise ProtocolError(f"{label} escapes the suite") from exc
        try:
            raw = _read_regular(suite.root, Path(relative), require_unique=False)
        except OSError as exc:
            raise ProtocolError(f"{label} must be a regular suite-local file") from exc
        if expected is not None and sha256_bytes(raw) != expected:
            raise ProtocolError(f"{label} hash mismatch")
        if relative in snapshots and snapshots[relative] != raw:
            raise ProtocolError(f"{label} conflicts with another suite snapshot")
        snapshots[relative] = raw
        return raw

    calibration = suite.config.get("calibration")
    integrity = suite.config.get("dataset_integrity")
    add(suite.config.get("judge"), "qualification_blueprint", "judge qualification blueprint")
    blueprint_approval = add(
        suite.config.get("judge"),
        "qualification_blueprint_approval",
        "judge qualification blueprint approval",
        record=True,
    )
    blueprint_reviewer = add(
        blueprint_approval,
        "approver_qualification_evidence",
        "judge blueprint approver qualification evidence",
        record=True,
    )
    if isinstance(blueprint_approval, dict) and blueprint_approval.get("approval_version") == "2.0.0":
        supports = blueprint_reviewer.get("supporting_evidence") if isinstance(blueprint_reviewer, dict) else None
        if not isinstance(supports, list) or not supports:
            raise ProtocolError("judge blueprint approver qualification evidence must reference supporting evidence")
        for index, reference in enumerate(supports):
            add(
                {"reference": reference},
                "reference",
                f"judge blueprint approver supporting evidence {index + 1}",
            )
    report = add(calibration, "evidence", "calibration report", record=True)
    approval = add(calibration, "independent_review_evidence", "calibration independent approval", record=True)
    semantic = add(integrity, "semantic_review_evidence", "semantic contamination evidence", record=True)
    for field, label in (
        ("analysis_plan", "calibration analysis plan"),
        ("human_label_evidence", "calibration human-label evidence"),
        ("holdout_manifest", "calibration holdout manifest"),
        ("pilot_audit", "calibration pilot audit"),
        ("statistical_review", "calibration statistical review"),
        ("semantic_contamination_evidence", "calibration semantic-contamination evidence"),
    ):
        add(report, field, label)
    campaign = add(report, "pilot_campaign", "calibration pilot campaign", record=True)
    if campaign is not None and isinstance(report, dict):
        campaign_path = _safe_path(suite.root, report.get("pilot_campaign"), "calibration pilot campaign")
        campaign_root = campaign_path.parent
        for field, label in (
            ("judge_qualification", "pilot judge qualification"),
            ("judge_independent_approval", "pilot judge independent approval"),
            ("transcript_review", "pilot transcript review"),
        ):
            record = campaign.get(field)
            if not isinstance(record, dict) or not isinstance(record.get("path"), str) or not isinstance(record.get("sha256"), str):
                raise ProtocolError(f"{label} path and SHA-256 are required")
            store(_safe_path(campaign_root, record["path"], label), label, str(record["sha256"]))
        runs = campaign.get("runs")
        if not isinstance(runs, list):
            raise ProtocolError("pilot campaign runs must be an array")
        for index, record in enumerate(runs, 1):
            relative = record.get("path") if isinstance(record, dict) else None
            run_root = _safe_path(campaign_root, relative, f"pilot run {index}")
            if run_root.is_symlink() or not run_root.is_dir():
                raise ProtocolError(f"pilot run {index} must be a regular suite-local directory")
            verification = verify_bundle(run_root, verify_hmac=False)
            if not verification["valid"]:
                raise ProtocolError(f"pilot run {index} bundle is invalid")
            bundle_raw = store(run_root / "bundle.json", f"pilot run {index} bundle")
            try:
                bundle = _strict_json(bundle_raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise ProtocolError(f"pilot run {index} bundle is invalid JSON") from exc
            files = bundle.get("files") if isinstance(bundle, dict) else None
            if not isinstance(files, dict):
                raise ProtocolError(f"pilot run {index} bundle file set is malformed")
            store(run_root / "checksums.txt", f"pilot run {index} checksums")
            if (run_root / "signature.json").exists():
                store(run_root / "signature.json", f"pilot run {index} signature")
            for relative_file, digest in files.items():
                if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
                    raise ProtocolError(f"pilot run {index} contains a malformed artifact digest")
                store(
                    _safe_path(run_root, relative_file, f"pilot run {index} artifact"),
                    f"pilot run {index} artifact",
                    digest,
                )
    add(approval, "approver_qualification_evidence", "calibration approver qualification evidence")
    for field, label in (
        ("comparison_corpus", "semantic comparison corpus"),
        ("candidate_pairs_evidence", "semantic candidate-pair evidence"),
        ("reviewer_evidence", "semantic independent-review evidence"),
    ):
        add(semantic, field, label)

    target = suite.config.get("target")
    add(target, "responses", "recorded target responses")
    add(target, "system_prompt", "target system prompt")
    for case in suite.cases:
        values = [case.get("input"), *(message.get("content") for message in case.get("messages", []) if isinstance(message, dict))]
        for value in values:
            if not isinstance(value, list):
                continue
            for part in value:
                if isinstance(part, dict) and part.get("type") in {"image", "audio", "video", "document"}:
                    add(part, "asset", f"case {case.get('id')} asset")
    return dict(sorted(snapshots.items()))


def engagement_snapshot_files(path: Path) -> tuple[bytes, dict[str, bytes]]:
    try:
        raw = _read_regular(path.parent, Path(path.name))
        record = _strict_json(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError("engagement must be a readable JSON object") from exc
    if not isinstance(record, dict):
        raise ProtocolError("engagement must be a readable JSON object")
    snapshots: dict[str, bytes] = {}
    for name in _ENGAGEMENT_EVIDENCE:
        pinned = _pinned_file(path.parent, record, f"{name}_evidence", f"engagement {name} evidence")
        if pinned is not None:
            relative, evidence = pinned
            if relative in snapshots and snapshots[relative] != evidence:
                raise ProtocolError(f"engagement {name} evidence conflicts with another snapshot")
            snapshots[relative] = evidence
    return raw, dict(sorted(snapshots.items()))


def _finite(value: Any) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _finite(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_finite(item) for item in value)
    return True


def _successful_http_status(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 200 <= value < 300


def _object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = _strict_json(_read_regular(path.parent, Path(path.name)).decode("utf-8"))
    except ValueError as exc:
        raise ProtocolError(f"{label} is invalid: {exc}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"{label} must be a readable JSON object") from exc
    if not isinstance(value, dict) or not _finite(value):
        raise ProtocolError(f"{label} must be a finite JSON object")
    return value


def _canonical_protocol_bytes() -> bytes:
    for candidate in (Path(__file__).resolve().parents[2] / "PROTOCOL.md", Path(__file__).with_name("PROTOCOL.md")):
        if candidate.is_file() and not candidate.is_symlink():
            return candidate.read_bytes()
    raise ProtocolError("canonical protocol asset is unavailable")


def _jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = _read_regular(path.parent, Path(path.name)).decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"{path.name} must be a regular UTF-8 JSONL file") from exc
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = _strict_json(line)
        except ValueError as exc:
            raise ProtocolError(f"invalid {path.name} line {line_number}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid {path.name} line {line_number}") from exc
        if not isinstance(value, dict) or not _finite(value):
            raise ProtocolError(f"invalid {path.name} line {line_number}: expected a finite JSON object")
        rows.append(value)
    return rows


def _complete_wire_body(row: dict[str, Any]) -> bytes | None:
    encoded = row.get("wire_body_base64")
    if not isinstance(encoded, str) or row.get("wire_body_truncated") is not False:
        return None
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _openai_stream_object(raw_body: bytes) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    content: list[str] = []
    usage: dict[str, Any] = {}
    reported_model = ""
    try:
        lines = raw_body.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ProtocolError("OpenAI stream wire body is not UTF-8") from exc
    for line in lines:
        line = line.strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            event = _strict_json(data)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError("OpenAI stream wire body contains invalid JSON") from exc
        if not isinstance(event, dict):
            raise ProtocolError("OpenAI stream wire body contains a non-object event")
        events.append(event)
        reported_model = str(event.get("model") or reported_model)
        if isinstance(event.get("usage"), dict):
            usage = event["usage"]
        try:
            delta = event["choices"][0]["delta"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError):
            delta = None
        if isinstance(delta, str) and delta:
            content.append(delta)
    return {
        "model": reported_model,
        "choices": [{"message": {"content": "".join(content)}}],
        "usage": usage,
        "stream_events": events,
    }


def _materialize_files(root: Path, manifest_path: Path, blob_root: Path, label: str) -> dict[str, str]:
    manifest = _object(manifest_path, f"{label} manifest")
    materialized: dict[str, str] = {}
    for relative, digest in manifest.items():
        if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
            raise ProtocolError(f"{label} manifest contains a malformed digest")
        try:
            raw = _read_regular(blob_root, Path(digest))
        except OSError:
            raw = b""
        if sha256_bytes(raw) != digest:
            raise ProtocolError(f"{label} blob {digest} is missing or corrupt")
        destination = _safe_path(root, relative, label)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and destination.read_bytes() != raw:
            raise ProtocolError(f"{label} path conflicts with another snapshot")
        destination.write_bytes(raw)
        materialized[str(relative)] = digest
    entries = list(blob_root.iterdir()) if blob_root.is_dir() and not blob_root.is_symlink() else []
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise ProtocolError(f"{label} blob set must contain only direct regular files")
    declared = {path.name for path in entries}
    if declared != set(materialized.values()):
        raise ProtocolError(f"{label} blob set is not closed")
    return materialized


def _materialize_suite(run_dir: Path, *, official: bool = False) -> tuple[TemporaryDirectory[str], Suite]:
    temporary = TemporaryDirectory(prefix="cavada-behavior-suite-")
    root = Path(temporary.name)
    try:
        config_raw = _read_regular(run_dir, Path("suite_snapshot.toml"))
        config = tomllib.loads(config_raw.decode("utf-8"))
        dataset = _safe_path(root, config.get("dataset", "dataset.jsonl"), "suite dataset")
        rubric = _safe_path(root, config.get("rubric", "rubric.md"), "suite rubric")
        for destination, source in (
            (root / "suite.toml", run_dir / "suite_snapshot.toml"),
            (dataset, run_dir / "dataset_snapshot.jsonl"),
            (rubric, run_dir / "rubric_snapshot.md"),
        ):
            try:
                raw = config_raw if source.name == "suite_snapshot.toml" else _read_regular(run_dir, source.relative_to(run_dir))
            except (OSError, ValueError) as exc:
                raise ProtocolError(f"{source.name} must be a regular snapshot") from exc
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        expected = _materialize_files(root, run_dir / "suite_evidence_manifest.json", run_dir / "suite_evidence", "suite evidence")
        suite = load_suite(root, official=official)
        observed = {
            relative: sha256_bytes(raw)
            for relative, raw in suite_snapshot_files(suite, require_pins=official).items()
        }
        if observed != expected:
            raise ProtocolError("suite evidence manifest does not match the closed official reference set")
        return temporary, suite
    except Exception:
        temporary.cleanup()
        raise


def _dotted(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            current = None
    return current


def _keys(rows: list[dict[str, Any]], label: str, failures: list[str]) -> set[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    for row in rows:
        case_id, repetition = row.get("case_id"), row.get("repetition")
        if not isinstance(case_id, str) or not isinstance(repetition, int) or isinstance(repetition, bool):
            failures.append(f"{label} contains a malformed observation identity")
            continue
        key = case_id, repetition
        if key in seen:
            failures.append(f"{label} contains duplicate observation {case_id}/{repetition}")
        seen.add(key)
    return seen


def _ledger_shape_errors(
    requests: list[dict[str, Any]],
    responses: list[dict[str, Any]],
    judgments: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> list[str]:
    """Close protocol-owned ledger envelopes while preserving opaque wire bodies."""
    failures: list[str] = []

    def finite_number(value: Any, *, minimum: float = 0.0, maximum: float | None = None) -> bool:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
            and float(value) >= minimum
            and (maximum is None or float(value) <= maximum)
        )

    def observation_errors(row: dict[str, Any], label: str) -> None:
        missing = sorted(_OBSERVATION_FIELDS - set(row))
        if missing:
            failures.append(f"{label} is missing fields: {missing}")
        if not isinstance(row.get("case_id"), str) or not row["case_id"]:
            failures.append(f"{label}.case_id must be a non-empty string")
        repetition = row.get("repetition")
        if not isinstance(repetition, int) or isinstance(repetition, bool) or repetition < 1:
            failures.append(f"{label}.repetition must be a positive integer")

    def transport_errors(value: Any, label: str) -> None:
        failures.extend(_closed_object_errors(value, _TRANSPORT_FIELDS, label))
        if not isinstance(value, dict):
            return
        core = {"request_id", "attempts", "request_bytes", "response_bytes", "headers_ms", "total_ms"}
        missing = sorted(core - set(value))
        if missing:
            failures.append(f"{label} is missing fields: {missing}")
        if not isinstance(value.get("request_id"), str) or not value["request_id"]:
            failures.append(f"{label}.request_id must be a non-empty string")
        for field in ("attempts", "request_bytes", "response_bytes"):
            item = value.get(field)
            if item is not None and (not isinstance(item, int) or isinstance(item, bool) or item < 0):
                failures.append(f"{label}.{field} must be a non-negative integer")
        http_status = value.get("http_status")
        if http_status is not None and (
            not isinstance(http_status, int)
            or isinstance(http_status, bool)
            or not 100 <= http_status <= 599
        ):
            failures.append(f"{label}.http_status must be an integer from 100 to 599")
        for field in ("headers_ms", "total_ms", "ttft_ms"):
            if value.get(field) is not None and not finite_number(value[field]):
                failures.append(f"{label}.{field} must be a finite non-negative number")
        for field in ("streaming", "recorded"):
            if field in value and not isinstance(value[field], bool):
                failures.append(f"{label}.{field} must be boolean")
        inter_chunk = value.get("inter_chunk_ms")
        if inter_chunk is not None:
            failures.extend(_closed_object_errors(inter_chunk, _DISTRIBUTION_FIELDS, f"{label}.inter_chunk_ms"))
            if isinstance(inter_chunk, dict):
                count = inter_chunk.get("count")
                if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                    failures.append(f"{label}.inter_chunk_ms.count must be a non-negative integer")
                for field in _DISTRIBUTION_FIELDS - {"count"}:
                    if not finite_number(inter_chunk.get(field)):
                        failures.append(f"{label}.inter_chunk_ms.{field} must be a finite non-negative number")
        retry_failures = value.get("retry_failures")
        if retry_failures is not None:
            if not isinstance(retry_failures, list):
                failures.append(f"{label}.retry_failures must be an array")
            else:
                attempts = value.get("attempts")
                if isinstance(attempts, int) and not isinstance(attempts, bool) and len(retry_failures) != max(0, attempts - 1):
                    failures.append(f"{label}.retry_failures does not reconcile with attempts")
                for index, retry in enumerate(retry_failures):
                    retry_label = f"{label}.retry_failures[{index}]"
                    failures.extend(_closed_object_errors(retry, _RETRY_FAILURE_FIELDS, retry_label))
                    if not isinstance(retry, dict):
                        continue
                    if retry.get("attempt") != index + 1:
                        failures.append(f"{retry_label}.attempt is not sequential")
                    if not isinstance(retry.get("error"), str) or not retry["error"]:
                        failures.append(f"{retry_label}.error must be non-empty text")
                    status = retry.get("http_status")
                    if status is not None and (
                        not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599
                    ):
                        failures.append(f"{retry_label}.http_status must be null or an integer from 100 to 599")
                    response_bytes = retry.get("response_bytes")
                    if not isinstance(response_bytes, int) or isinstance(response_bytes, bool) or response_bytes < 0:
                        failures.append(f"{retry_label}.response_bytes must be a non-negative integer")
                    if not finite_number(retry.get("duration_ms")):
                        failures.append(f"{retry_label}.duration_ms must be a finite non-negative number")
                    wire_errors(retry, retry_label)

    def wire_errors(row: dict[str, Any], label: str) -> None:
        wire_fields = {"wire_body_base64", "wire_body_sha256", "wire_body_bytes", "wire_body_truncated"}
        present = wire_fields & set(row)
        if present and present != wire_fields:
            failures.append(f"{label} has incomplete raw wire-body evidence")
            return
        if present:
            try:
                raw = base64.b64decode(str(row["wire_body_base64"]), validate=True)
            except (binascii.Error, ValueError, TypeError):
                failures.append(f"{label} has invalid raw wire-body base64")
                return
            if sha256_bytes(raw) != row.get("wire_body_sha256") or len(raw) != row.get("wire_body_bytes"):
                failures.append(f"{label} raw wire-body hash or size does not reconcile")
            if not isinstance(row.get("wire_body_truncated"), bool):
                failures.append(f"{label}.wire_body_truncated must be boolean")
        if row.get("error_stage") is not None and row.get("error_stage") not in {"transport", "decode", "schema", "projection"}:
            failures.append(f"{label} has an unsupported error stage")

    for index, row in enumerate(requests):
        observation_errors(row, f"requests.jsonl[{index}]")
        kind = row.get("kind")
        allowed = _OBSERVATION_FIELDS | {"kind", "request_id", "endpoint", "payload"}
        if kind == "judge":
            allowed |= _JUDGE_EVIDENCE_FIELDS
        elif kind != "target":
            failures.append(f"requests.jsonl[{index}] has unsupported kind")
        failures.extend(_closed_object_errors(row, allowed, f"requests.jsonl[{index}]"))
        required = _OBSERVATION_FIELDS | {"kind", "request_id", "endpoint", "payload"} | (
            _JUDGE_EVIDENCE_FIELDS if kind == "judge" else set()
        )
        missing = sorted(required - set(row))
        if missing:
            failures.append(f"requests.jsonl[{index}] is missing fields: {missing}")
        if not isinstance(row.get("endpoint"), str) or not row["endpoint"]:
            failures.append(f"requests.jsonl[{index}].endpoint must be a non-empty string")
    for index, row in enumerate(responses):
        observation_errors(row, f"raw_responses.jsonl[{index}]")
        failures.extend(
            _closed_object_errors(
                row,
                _OBSERVATION_FIELDS | {"reported_model", "response", "transport"} | _WIRE_ERROR_FIELDS,
                f"raw_responses.jsonl[{index}]",
            )
        )
        missing = sorted((_OBSERVATION_FIELDS | {"reported_model", "response", "transport"}) - set(row))
        if missing:
            failures.append(f"raw_responses.jsonl[{index}] is missing fields: {missing}")
        wire_errors(row, f"raw_responses.jsonl[{index}]")
        transport_errors(row.get("transport"), f"raw_responses.jsonl[{index}].transport")
    for index, row in enumerate(judgments):
        observation_errors(row, f"judgments.jsonl[{index}]")
        allowed = _OBSERVATION_FIELDS | _JUDGE_EVIDENCE_FIELDS
        if row.get("status") == "invalid":
            allowed |= {"reported_model", "raw", "raw_content", "transport"} | _WIRE_ERROR_FIELDS
        else:
            allowed |= {"reported_model", "judgment", "raw", "raw_content", "transport"} | _WIRE_BODY_FIELDS
        failures.extend(_closed_object_errors(row, allowed, f"judgments.jsonl[{index}]"))
        required = _OBSERVATION_FIELDS | _JUDGE_EVIDENCE_FIELDS
        required |= {"status", "error"} if row.get("status") == "invalid" else {
            "reported_model",
            "judgment",
            "raw",
            "raw_content",
            "transport",
        }
        missing = sorted(required - set(row))
        if missing:
            failures.append(f"judgments.jsonl[{index}] is missing fields: {missing}")
        wire_errors(row, f"judgments.jsonl[{index}]")
        judgment = row.get("judgment")
        if judgment is not None:
            failures.extend(
                _closed_object_errors(
                    judgment,
                    {"verdict", "score", "reason", "criteria"},
                    f"judgments.jsonl[{index}].judgment",
                )
            )
            if isinstance(judgment, dict):
                if judgment.get("verdict") not in {"pass", "fail"}:
                    failures.append(f"judgments.jsonl[{index}].judgment.verdict is invalid")
                score = judgment.get("score")
                if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 5:
                    failures.append(f"judgments.jsonl[{index}].judgment.score must be an integer from 0 to 5")
                if not isinstance(judgment.get("reason"), str) or not judgment["reason"]:
                    failures.append(f"judgments.jsonl[{index}].judgment.reason must be a non-empty string")
                if not isinstance(judgment.get("criteria"), dict):
                    failures.append(f"judgments.jsonl[{index}].judgment.criteria must be an object")
        transport = row.get("transport")
        if transport is not None:
            transport_errors(transport, f"judgments.jsonl[{index}].transport")
    for index, row in enumerate(results):
        observation_errors(row, f"case_results.jsonl[{index}]")
        failures.extend(_closed_object_errors(row, _RESULT_FIELDS, f"case_results.jsonl[{index}]"))
        missing = sorted((_OBSERVATION_FIELDS | {"status", "reason"}) - set(row))
        if missing:
            failures.append(f"case_results.jsonl[{index}] is missing fields: {missing}")
        if row.get("status") not in {"pass", "fail", "invalid", "error", "skipped"}:
            failures.append(f"case_results.jsonl[{index}].status is invalid")
        if not isinstance(row.get("reason"), str) or not row["reason"]:
            failures.append(f"case_results.jsonl[{index}].reason must be a non-empty string")
        if row.get("score") is not None and not finite_number(row["score"], maximum=5.0):
            failures.append(f"case_results.jsonl[{index}].score must be a finite number from 0 to 5")
        if row.get("judge_agreement") is not None and not finite_number(row["judge_agreement"], maximum=1.0):
            failures.append(f"case_results.jsonl[{index}].judge_agreement must be a finite number from 0 to 1")
        for field in (
            "duration_ms",
            "target_latency_ms",
            "target_headers_ms",
            "target_response_bytes",
            "ttft_ms",
            "input_tokens",
            "output_tokens",
            "output_tokens_per_second",
        ):
            if row.get(field) is not None and not finite_number(row[field]):
                failures.append(f"case_results.jsonl[{index}].{field} must be a finite non-negative number")
        if row.get("inter_chunk_ms") is not None:
            failures.extend(
                _closed_object_errors(
                    row["inter_chunk_ms"],
                    _DISTRIBUTION_FIELDS,
                    f"case_results.jsonl[{index}].inter_chunk_ms",
                )
            )
    return failures


def _selected_cases_from_manifest(
    suite: Suite,
    parameters: dict[str, Any],
) -> tuple[tuple[dict[str, Any], ...], list[str]]:
    failures: list[str] = []
    max_cases = parameters.get("max_cases")
    if not isinstance(max_cases, int) or isinstance(max_cases, bool) or max_cases < 0:
        failures.append("behavior manifest max_cases is invalid")
        max_cases = 0
    preset = parameters.get("preset")
    if preset is not None and not isinstance(preset, str):
        failures.append("behavior manifest preset is invalid")
        preset = ""
    selected = (
        stratified_cases(suite.cases, max_cases)
        if preset
        else (suite.cases[:max_cases] if max_cases > 0 else suite.cases)
    )
    expected_policy = "deterministic stratified scenario groups" if preset and max_cases > 0 else "dataset order"
    expected_order_sha256 = sha256_bytes("\n".join(str(case["id"]) for case in selected).encode("utf-8"))
    if parameters.get("selected_cases") != len(selected):
        failures.append("behavior manifest selected_cases does not reconstruct from the suite")
    if parameters.get("case_order_policy") != expected_policy or parameters.get("case_order_sha256") != expected_order_sha256:
        failures.append("behavior manifest case selection policy or order digest does not reconstruct")
    return selected, failures


def _ledger_errors(suite: Suite, manifest: dict[str, Any], run_dir: Path) -> list[str]:
    from .runner import (
        _judge_result,
        _judge_system_prompt,
        _target_answer,
        build_judge_payload,
        build_target_payload,
        target_case_prompt,
    )

    failures: list[str] = []
    parameters_value = manifest.get("parameters")
    parameters: dict[str, Any] = parameters_value if isinstance(parameters_value, dict) else {}
    repetitions = parameters.get("repetitions")
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        return ["official manifest repetitions are invalid"]
    requests = _jsonl(run_dir / "requests.jsonl")
    responses = _jsonl(run_dir / "raw_responses.jsonl")
    judgments = _jsonl(run_dir / "judgments.jsonl")
    results = _jsonl(run_dir / "case_results.jsonl")
    failures.extend(_ledger_shape_errors(requests, responses, judgments, results))
    selected_cases, selection_failures = _selected_cases_from_manifest(suite, parameters)
    failures.extend(selection_failures)
    expected = {(str(case["id"]), repetition) for case in selected_cases for repetition in range(1, repetitions + 1)}
    target_requests = [row for row in requests if row.get("kind") == "target"]
    judge_requests = [row for row in requests if row.get("kind") == "judge"]
    result_keys = _keys(results, "case results", failures)
    target_request_keys = _keys(target_requests, "target requests", failures)
    response_keys = _keys(responses, "target responses", failures)
    if result_keys != expected:
        failures.append("case results do not exactly match the scheduled observations")
    if target_request_keys != response_keys or not target_request_keys <= expected:
        failures.append("target request and response ledgers do not exactly reconcile")
    result_by_key = {(str(row.get("case_id")), int(row.get("repetition", 0))): row for row in results}
    target_required = {
        key for key, row in result_by_key.items() if row.get("status") in {"pass", "fail", "invalid"}
    }
    if not target_required <= target_request_keys:
        failures.append("completed target observations lack request or response evidence")
    if any(result_by_key.get(key, {}).get("status") == "skipped" for key in target_request_keys):
        failures.append("skipped observations contain unexpected target evidence")

    response_by_key = {(str(row.get("case_id")), int(row.get("repetition", 0))): row for row in responses}
    target_request_by_key = {(str(row.get("case_id")), int(row.get("repetition", 0))): row for row in target_requests}
    judgments_by_key: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in judgments:
        key = str(row.get("case_id")), int(row.get("repetition", 0))
        judgments_by_key.setdefault(key, []).append(row)
    judge_value = manifest.get("judge")
    judge: dict[str, Any] = judge_value if isinstance(judge_value, dict) else {}
    models_value = judge.get("models")
    models: list[Any] = models_value if isinstance(models_value, list) else []
    specs = {str(item.get("id")): item for item in models if isinstance(item, dict)}
    judge_repetitions = parameters.get("judge_repetitions")
    repetitions_per_judge = judge_repetitions if isinstance(judge_repetitions, int) and not isinstance(judge_repetitions, bool) else 0
    expected_judgments = repetitions_per_judge * len(specs)
    request_judge_ids = {
        (row.get("case_id"), row.get("repetition"), row.get("judge_id"), row.get("judge_repetition")) for row in judge_requests
    }
    output_judge_ids = {
        (row.get("case_id"), row.get("repetition"), row.get("judge_id"), row.get("judge_repetition")) for row in judgments
    }
    successful_output_judge_ids = {
        (row.get("case_id"), row.get("repetition"), row.get("judge_id"), row.get("judge_repetition"))
        for row in judgments
        if row.get("status") != "invalid"
    }
    if (
        len(request_judge_ids) != len(judge_requests)
        or len(output_judge_ids) != len(judgments)
        or not successful_output_judge_ids <= request_judge_ids <= output_judge_ids
    ):
        failures.append("judge request and output ledgers do not exactly reconcile")
    judge_request_by_id = {
        (str(row.get("case_id")), int(row.get("repetition", 0)), str(row.get("judge_id")), int(row.get("judge_repetition", 0))): row
        for row in judge_requests
    }

    cases = {str(case["id"]): case for case in selected_cases}
    target_value = manifest.get("target")
    target: dict[str, Any] = target_value if isinstance(target_value, dict) else {}
    target_config = suite.config.get("target") or {}
    recorded_by_case: dict[str, dict[str, Any]] = {}
    if target_config.get("kind", "json") == "recorded":
        try:
            recorded_path = _safe_path(suite.root, target_config.get("responses"), "recorded target responses")
            recorded_rows = _jsonl(recorded_path)
        except (OSError, ProtocolError, ValueError) as exc:
            failures.append(f"recorded target evidence cannot be reconstructed: {exc}")
            recorded_rows = []
        for index, recorded_row in enumerate(recorded_rows):
            case_id = recorded_row.get("case_id")
            if not isinstance(case_id, str) or not case_id or case_id in recorded_by_case:
                failures.append(f"recorded target evidence row {index} has an invalid or duplicate case_id")
                continue
            response_value = recorded_row.get("response")
            recorded_by_case[case_id] = dict(response_value) if isinstance(response_value, dict) else recorded_row
    for result in results:
        key = str(result.get("case_id")), int(result.get("repetition", 0))
        response = response_by_key.get(key)
        target_request = target_request_by_key.get(key)
        case = cases.get(key[0])
        raw = response.get("response") if isinstance(response, dict) else None
        selected = judgments_by_key.get(key, [])
        if case is None:
            failures.append(f"scheduled observation {key[0]}/{key[1]} does not exist in selected suite evidence")
            continue
        expected_metadata = {
            "category": case["category"],
            "risk_domain": case["risk_domain"],
            "severity": case["severity"],
            "language": case.get("language", "missing"),
            "locale": case.get("locale", "missing"),
            "split": case.get("split", "missing"),
            "operating_condition": case.get("operating_condition", "missing"),
            "distribution_shift_reference_id": case.get("distribution_shift_reference_id"),
            "scenario_id": case.get("scenario_group_id") or case.get("scenario_id"),
            "performance_phase": case.get("performance_phase", "steady"),
        }
        expected_observation = {"case_id": key[0], "repetition": key[1], **expected_metadata}
        evidence_rows = [("case result", result)]
        if isinstance(target_request, dict):
            evidence_rows.append(("target request", target_request))
        if isinstance(response, dict):
            evidence_rows.append(("target response", response))
        evidence_rows.extend(("judgment", row) for row in selected)
        evidence_rows.extend(
            ("judge request", row)
            for row in judge_requests
            if (str(row.get("case_id")), int(row.get("repetition", 0))) == key
        )
        for evidence_label, evidence_row in evidence_rows:
            changed_metadata = sorted(
                field for field, expected_value in expected_observation.items() if evidence_row.get(field) != expected_value
            )
            if changed_metadata:
                failures.append(
                    f"{evidence_label} metadata differs from suite evidence for {key[0]}/{key[1]}: {changed_metadata}"
                )
        status = result.get("status")
        if status == "skipped":
            expected_reason = (
                "case not approved"
                if case.get("review", {}).get("status") != "approved"
                else "run aborted by a prior observation"
            )
            if result.get("reason") != expected_reason or response is not None or target_request is not None or selected:
                failures.append(f"skipped observation evidence is contradictory for {key[0]}/{key[1]}")
            continue
        if response is None and target_request is None and status == "error":
            if not isinstance(result.get("reason"), str) or not result["reason"]:
                failures.append(f"error observation lacks a reason for {key[0]}/{key[1]}")
            if selected:
                failures.append(f"target-less error observation retains judge evidence for {key[0]}/{key[1]}")
            continue
        if not isinstance(response, dict) or not isinstance(target_request, dict):
            failures.append(f"scheduled observation {key[0]}/{key[1]} has incomplete target evidence")
            continue
        if target_config.get("kind", "json") == "recorded":
            expected_recorded = recorded_by_case.get(key[0])
            if expected_recorded is not None and raw != expected_recorded:
                failures.append(f"recorded target response differs from its hash-pinned source for {key[0]}/{key[1]}")
            target_transport = response.get("transport")
            if not isinstance(target_transport, dict) or target_transport.get("recorded") is not True:
                failures.append(f"recorded target transport is not marked recorded for {key[0]}/{key[1]}")
        try:
            expected_target_payload = build_target_payload(
                suite,
                target_case_prompt(case, str((suite.config.get("target") or {}).get("kind", "json"))),
                target.get("request_model") if isinstance(target.get("request_model"), str) else None,
                recorded_responses_sha256=(
                    target.get("recorded_responses_sha256")
                    if isinstance(target.get("recorded_responses_sha256"), str)
                    else None
                ),
            )
        except (OSError, ProtocolError, ValueError) as exc:
            failures.append(f"target payload cannot be reconstructed for {key[0]}/{key[1]}: {exc}")
        else:
            if target_request.get("payload") != expected_target_payload:
                failures.append(f"target request differs from suite snapshots for {key[0]}/{key[1]}")
        if target_request.get("endpoint") != target.get("endpoint"):
            failures.append(f"target request endpoint differs from the manifest for {key[0]}/{key[1]}")
        target_transport = response.get("transport")
        if not isinstance(target_transport, dict) or target_transport.get("request_id") != target_request.get("request_id"):
            failures.append(f"target transport does not bind its request for {key[0]}/{key[1]}")
        target_kind = (suite.config.get("target") or {}).get("kind", "json")
        if response.get("status") == "error":
            if status != "error" or result.get("reason") != response.get("error") or selected:
                failures.append(f"target error evidence is contradictory for {key[0]}/{key[1]}")
            if response.get("error_stage") == "projection" and isinstance(raw, dict):
                try:
                    _target_answer(suite, raw)
                except ProtocolError as exc:
                    if response.get("error") != str(exc):
                        failures.append(f"target projection error differs from raw evidence for {key[0]}/{key[1]}")
                else:
                    failures.append(f"target projection error is contradicted by raw evidence for {key[0]}/{key[1]}")
            if (
                target_kind != "recorded"
                and response.get("error_stage") in {"decode", "schema", "projection"}
                and (
                    not isinstance(target_transport, dict)
                    or not _successful_http_status(target_transport.get("http_status"))
                )
            ):
                failures.append(f"target terminal HTTP status is missing or contradictory for {key[0]}/{key[1]}")
            continue
        if not isinstance(raw, dict):
            failures.append(
                f"scheduled observation {key[0]}/{key[1]} has missing or malformed target evidence: "
                "malformed target response"
            )
            continue
        if target_config.get("kind", "json") != "recorded":
            if not isinstance(target_transport, dict) or not _successful_http_status(target_transport.get("http_status")):
                failures.append(f"successful target response lacks a successful HTTP status for {key[0]}/{key[1]}")
            target_wire = _complete_wire_body(response)
            if target_wire is None:
                failures.append(f"successful target response lacks complete wire bytes for {key[0]}/{key[1]}")
            else:
                try:
                    wire_projection = (
                        _openai_stream_object(target_wire)
                        if target_config.get("kind") == "openai" and target_config.get("stream") is True
                        else _strict_json(target_wire.decode("utf-8"))
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, ProtocolError, ValueError) as exc:
                    failures.append(f"target wire body cannot be reconstructed for {key[0]}/{key[1]}: {exc}")
                else:
                    if wire_projection != raw:
                        failures.append(f"target parsed response differs from wire bytes for {key[0]}/{key[1]}")
        try:
            answer, reported = _target_answer(suite, raw)
            deterministic = deterministic_evaluation(
                case,
                answer,
                target_raw=raw,
                retrieved_ids=_dotted(raw, str(target_config.get("retrieved_ids_field", "retrieved_ids"))) or [],
                tool_calls=_dotted(raw, str(target_config.get("tools_field", "tool_calls"))) or [],
            )
        except ProtocolError as exc:
            failures.append(str(exc))
            continue
        if response.get("reported_model") != reported:
            failures.append(f"target identity mismatch in observation {key[0]}/{key[1]}")
        expected_target_model = target.get("expected_reported_model")
        expected_target_identity_error = f"Target identity mismatch: expected {expected_target_model!r}, got {reported!r}"
        if reported != expected_target_model and not (status == "error" and result.get("reason") == expected_target_identity_error):
            failures.append(f"target identity mismatch in observation {key[0]}/{key[1]}")
        if isinstance(target_transport, dict):
            projected = {
                "target_latency_ms": target_transport.get("total_ms"),
                "target_headers_ms": target_transport.get("headers_ms"),
                "target_response_bytes": target_transport.get("response_bytes"),
            }
            if "ttft_ms" in target_transport:
                projected["ttft_ms"] = target_transport["ttft_ms"]
            if isinstance(target_transport.get("inter_chunk_ms"), dict):
                projected["inter_chunk_ms"] = target_transport["inter_chunk_ms"]
            usage = raw.get("usage")
            if isinstance(usage, dict):
                projected["input_tokens"] = usage.get("prompt_tokens")
                projected["output_tokens"] = usage.get("completion_tokens")
                output_tokens = usage.get("completion_tokens")
                latency_ms = target_transport.get("total_ms")
                if isinstance(output_tokens, (int, float)) and isinstance(latency_ms, (int, float)) and latency_ms > 0:
                    projected["output_tokens_per_second"] = float(output_tokens) / (float(latency_ms) / 1000)
            performance_fields = {
                "target_latency_ms",
                "target_headers_ms",
                "target_response_bytes",
                "ttft_ms",
                "inter_chunk_ms",
                "input_tokens",
                "output_tokens",
                "output_tokens_per_second",
            }
            changed = sorted(
                field
                for field in performance_fields
                if (field in result) != (field in projected) or result.get(field) != projected.get(field)
            )
            if changed:
                failures.append(f"case result performance projection differs from raw evidence for {key[0]}/{key[1]}: {changed}")
        if result.get("deterministic") != deterministic:
            if status != "error":
                failures.append(f"deterministic result differs from raw evidence for {key[0]}/{key[1]}")
        if not deterministic["hard_pass"]:
            if result.get("status") != "fail" or result.get("reason") != "deterministic check failed" or selected:
                failures.append(f"deterministic failure was overridden for {key[0]}/{key[1]}")
            continue
        if status != "error" and len(selected) != expected_judgments:
            failures.append(f"observation {key[0]}/{key[1]} lacks exact judge evidence")
            continue
        observed_models = {(row.get("judge_id"), row.get("model_repetition")) for row in selected}
        expected_models = {(judge_id, model_repetition) for judge_id in specs for model_repetition in range(1, repetitions_per_judge + 1)}
        if status != "error" and observed_models != expected_models:
            failures.append(f"observation {key[0]}/{key[1]} lacks the exact multi-judge repetition matrix")
        verdicts: list[str] = []
        scores: list[int] = []
        for row in selected:
            spec = specs.get(str(row.get("judge_id")))
            judgment = row.get("judgment")
            raw_judge = row.get("raw")
            request = judge_request_by_id.get(
                (key[0], key[1], str(row.get("judge_id")), int(row.get("judge_repetition", 0)))
            )
            if not isinstance(spec, dict):
                failures.append(f"malformed judge evidence for {key[0]}/{key[1]}")
                continue
            if (
                row.get("requested_model") != spec.get("model")
                or row.get("judge_revision") != spec.get("revision")
            ):
                failures.append(f"judge evidence differs from manifest configuration for {key[0]}/{key[1]}")
            if row.get("status") == "invalid" and request is None:
                if not isinstance(row.get("error"), str) or not row["error"]:
                    failures.append(f"invalid judge evidence lacks an error for {key[0]}/{key[1]}")
                continue
            if not isinstance(request, dict):
                failures.append(f"judge evidence lacks its request for {key[0]}/{key[1]}")
                continue
            if request.get("requested_model") != spec.get("model") or request.get("judge_revision") != spec.get("revision"):
                failures.append(f"judge request differs from manifest configuration for {key[0]}/{key[1]}")
            if request.get("endpoint") != judge.get("endpoint"):
                failures.append(f"judge request endpoint differs from the manifest for {key[0]}/{key[1]}")
            try:
                expected_judge_payload = build_judge_payload(suite, str(spec.get("model", "")), case, answer, raw)
            except (OSError, ProtocolError, ValueError) as exc:
                failures.append(f"judge payload cannot be reconstructed for {key[0]}/{key[1]}: {exc}")
            else:
                if request.get("payload") != expected_judge_payload:
                    failures.append(f"judge request differs from suite and response snapshots for {key[0]}/{key[1]}")
            judge_transport = row.get("transport")
            if not isinstance(judge_transport, dict) or judge_transport.get("request_id") != request.get("request_id"):
                failures.append(f"judge transport does not bind its request for {key[0]}/{key[1]}")
            if row.get("status") == "invalid":
                if not isinstance(row.get("error"), str) or not row["error"]:
                    failures.append(f"invalid judge evidence lacks an error for {key[0]}/{key[1]}")
                if row.get("error_stage") in {"decode", "schema", "projection"} and (
                    not isinstance(judge_transport, dict)
                    or not _successful_http_status(judge_transport.get("http_status"))
                ):
                    failures.append(f"judge terminal HTTP status is missing or contradictory for {key[0]}/{key[1]}")
                continue
            if not isinstance(judgment, dict) or not isinstance(raw_judge, dict):
                failures.append(f"malformed successful judge evidence for {key[0]}/{key[1]}")
                continue
            judge_wire = _complete_wire_body(row)
            if not isinstance(judge_transport, dict) or not _successful_http_status(judge_transport.get("http_status")):
                failures.append(f"successful judge response lacks a successful HTTP status for {key[0]}/{key[1]}")
            if judge_wire is None:
                failures.append(f"successful judge response lacks complete wire bytes for {key[0]}/{key[1]}")
            else:
                try:
                    wire_judgment = _strict_json(judge_wire.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    failures.append(f"judge wire body cannot be reconstructed for {key[0]}/{key[1]}: {exc}")
                else:
                    if wire_judgment != raw_judge:
                        failures.append(f"judge parsed response differs from wire bytes for {key[0]}/{key[1]}")
            try:
                parsed, content = _judge_result(raw_judge)
            except ProtocolError:
                parsed, content = None, None
            if parsed != judgment or row.get("raw_content") != content:
                failures.append(f"judge projection differs from raw output for {key[0]}/{key[1]}")
                continue
            if raw_judge.get("model") != row.get("reported_model"):
                failures.append(f"judge identity mismatch for {key[0]}/{key[1]}")
            expected_judge_identity_error = (
                f"Judge identity mismatch: expected {spec.get('expected_model')!r}, got {row.get('reported_model')!r}"
            )
            if row.get("reported_model") != spec.get("expected_model") and not (
                status == "error" and result.get("reason") == expected_judge_identity_error
            ):
                failures.append(f"judge identity mismatch for {key[0]}/{key[1]}")
            verdicts.append(str(judgment["verdict"]))
            score = judgment.get("score")
            if isinstance(score, int) and not isinstance(score, bool):
                scores.append(score)
        passes, fails = verdicts.count("pass"), verdicts.count("fail")
        if status == "error":
            if not isinstance(result.get("reason"), str) or not result["reason"]:
                failures.append(f"error observation lacks a reason for {key[0]}/{key[1]}")
            continue
        consensus = judge.get("consensus")
        expected_status = "invalid" if len(verdicts) != expected_judgments or passes == fails or (consensus == "unanimous" and passes and fails) else ("pass" if passes > fails else "fail")
        if result.get("status") != expected_status:
            failures.append(f"case result disagrees with judge evidence for {key[0]}/{key[1]}")
        if expected_status in {"pass", "fail"}:
            agreement = max(passes, fails) / len(verdicts)
            score = sum(scores) / len(scores) if len(scores) == expected_judgments else None
            if result.get("judge_agreement") != agreement or result.get("score") != score:
                failures.append(f"judge score or agreement differs for {key[0]}/{key[1]}")

    request_ids = [row.get("request_id") for row in requests]
    if any(not isinstance(value, str) or not value for value in request_ids) or len(request_ids) != len(set(request_ids)):
        failures.append("request ledger contains missing or duplicate request IDs")
    expected_prompt_hash = sha256_bytes(_judge_system_prompt(suite).encode("utf-8"))
    if judge.get("prompt_sha256") != expected_prompt_hash:
        failures.append("judge prompt hash differs from the rubric snapshot")
    if (run_dir / "engine_results.jsonl").is_file() and _jsonl(run_dir / "engine_results.jsonl"):
        failures.append("official behavior verification does not support external metric-engine evidence")
    return failures


def _official_metrics_structure_errors(metrics: Any) -> list[str]:
    failures = _closed_object_errors(metrics, OFFICIAL_METRIC_FIELDS, "official metrics")
    if not isinstance(metrics, dict):
        return failures
    ci_fields = {"lower", "upper", "confidence"}
    distribution_fields = {"count", "min", "max", "mean", "median", "stdev", "p50", "p90", "p95", "p99"}
    summary_fields = {
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
    }

    def closed(value: Any, fields: set[str], label: str) -> None:
        if isinstance(value, dict):
            failures.extend(_closed_object_errors(value, fields, label))

    def interval(value: Any, label: str, *, bootstrap: bool = False, stratified: bool = False) -> None:
        fields = ci_fields | ({"samples", "seed"} if bootstrap else set()) | ({"strata"} if stratified else set())
        closed(value, fields, label)

    def summary(value: Any, label: str) -> None:
        if not isinstance(value, dict):
            return
        closed(value, summary_fields, label)
        interval(value.get("pass_rate_ci"), f"{label}.pass_rate_ci")
        closed(value.get("pass_rate_ci95"), {"lower", "upper"}, f"{label}.pass_rate_ci95")

    def distribution(value: Any, label: str) -> None:
        closed(value, distribution_fields, label)

    interval(metrics.get("pass_rate_ci"), "official metrics.pass_rate_ci")
    closed(metrics.get("pass_rate_ci95"), {"lower", "upper"}, "official metrics.pass_rate_ci95")
    interval(metrics.get("pass_rate_bootstrap_ci"), "official metrics.pass_rate_bootstrap_ci", bootstrap=True)
    interval(
        metrics.get("pass_rate_stratified_bootstrap_ci"),
        "official metrics.pass_rate_stratified_bootstrap_ci",
        bootstrap=True,
        stratified=True,
    )
    summary(metrics.get("case_level"), "official metrics.case_level")
    categories = metrics.get("case_categories")
    category_fields = {"category", "total", "pass", "fail", "invalid", "error", "pass_rate", "ci95_lower", "ci95_upper", "confidence"}
    if isinstance(categories, list):
        for index, category in enumerate(categories):
            failures.extend(_closed_object_errors(category, category_fields, f"official metrics.case_categories[{index}]"))
    slices = metrics.get("slices")
    if isinstance(slices, dict):
        for dimension, values in slices.items():
            if isinstance(values, dict):
                for value, measured in values.items():
                    summary(measured, f"official metrics.slices.{dimension}.{value}")
    stability = metrics.get("stability")
    closed(stability, {"case_pass_fraction", "stable_case_fraction", "judge_agreement", "judge_score"}, "official metrics.stability")
    if isinstance(stability, dict):
        for field in ("case_pass_fraction", "judge_agreement", "judge_score"):
            distribution(stability.get(field), f"official metrics.stability.{field}")
    calibration_fields = {
        "true_pass",
        "true_fail",
        "false_pass",
        "false_fail",
        "cases",
        "samples",
        "invalid_cases",
        "observations",
        "accuracy",
        "failure_sensitivity",
        "failure_sensitivity_ci",
        "pass_specificity",
        "pass_specificity_ci",
        "false_pass_rate",
        "false_fail_rate",
        "balanced_accuracy",
        "repeated_cases",
        "stable_repeated_case_fraction",
    }

    def calibration(value: Any, label: str, *, with_slices: bool) -> None:
        if not isinstance(value, dict):
            return
        closed(value, calibration_fields | ({"slices"} if with_slices else set()), label)
        interval(value.get("failure_sensitivity_ci"), f"{label}.failure_sensitivity_ci")
        interval(value.get("pass_specificity_ci"), f"{label}.pass_specificity_ci")
        nested = value.get("slices")
        if with_slices and isinstance(nested, dict):
            for dimension, values in nested.items():
                if isinstance(values, dict):
                    for slice_value, measured in values.items():
                        calibration(measured, f"{label}.slices.{dimension}.{slice_value}", with_slices=False)

    calibrations = metrics.get("judge_calibration")
    if isinstance(calibrations, dict):
        for judge_id, result in calibrations.items():
            calibration(result, f"official metrics.judge_calibration.{judge_id}", with_slices=True)
    performance = metrics.get("performance")
    performance_distributions = {
        "target_latency_ms",
        "target_response_bytes",
        "input_tokens",
        "output_tokens",
        "ttft_ms",
        "output_tokens_per_second",
    }
    closed(
        performance,
        performance_distributions
        | {"elapsed_seconds", "observations_per_second", "target_calls_per_second", "observation_success_rate", "observation_error_rate"},
        "official metrics.performance",
    )
    if isinstance(performance, dict):
        for field in performance_distributions:
            distribution(performance.get(field), f"official metrics.performance.{field}")
    phases = metrics.get("performance_by_phase")
    closed(phases, {"cold", "warmup", "steady", "soak"}, "official metrics.performance_by_phase")
    if isinstance(phases, dict):
        for phase, value in phases.items():
            distribution(value, f"official metrics.performance_by_phase.{phase}")
    closed(metrics.get("budgets"), {"target_calls", "judge_calls", "total_tokens", "exhausted"}, "official metrics.budgets")
    closed(
        metrics.get("cost"),
        {"currency", "source", "effective_at", "input_tokens", "output_tokens", "judge_input_tokens", "judge_output_tokens", "estimated_total"},
        "official metrics.cost",
    )
    gates = metrics.get("gate_failures")
    if isinstance(gates, list):
        for index, gate in enumerate(gates):
            failures.extend(_closed_object_errors(gate, {"category", "metric", "minimum", "actual"}, f"official metrics.gate_failures[{index}]"))
    shift = metrics.get("distribution_shift")
    closed(shift, {"declared_pairs", "valid_pairs", "invalid_pairs", "comparison", "by_category"}, "official metrics.distribution_shift")
    comparison_fields = {
        "cases",
        "baseline_pass_rate",
        "candidate_pass_rate",
        "absolute_delta",
        "relative_delta",
        "delta_ci",
        "mcnemar",
        "wins",
        "ties",
        "losses",
    }

    def comparison(value: Any, label: str) -> None:
        if not isinstance(value, dict):
            return
        closed(value, comparison_fields, label)
        interval(value.get("delta_ci"), f"{label}.delta_ci", bootstrap=True)
        closed(value.get("mcnemar"), {"baseline_only", "candidate_only", "discordant", "p_value"}, f"{label}.mcnemar")

    if isinstance(shift, dict):
        comparison(shift.get("comparison"), "official metrics.distribution_shift.comparison")
        categories_value = shift.get("by_category")
        if isinstance(categories_value, dict):
            for category, value in categories_value.items():
                comparison(value, f"official metrics.distribution_shift.by_category.{category}")
    return failures


def _manifest_structure_errors(manifest: Any, *, require_assurance: bool) -> list[str]:
    label = "official manifest" if require_assurance else "behavior manifest"
    failures = _closed_object_errors(manifest, OFFICIAL_MANIFEST_FIELDS, label)
    if not isinstance(manifest, dict):
        return failures

    def nonempty_string(value: Any) -> bool:
        return isinstance(value, str) and bool(value)

    def finite_number(value: Any, *, minimum: float = 0.0, maximum: float | None = None) -> bool:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
            and float(value) >= minimum
            and (maximum is None or float(value) <= maximum)
        )

    missing = sorted((OFFICIAL_MANIFEST_FIELDS - {"resumed_at"}) - set(manifest))
    if missing:
        failures.append(f"{label} is missing fields: {missing}")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        failures.append(f"official manifest schema_version must be {MANIFEST_SCHEMA_VERSION}")
    if manifest.get("protocol_version") != PROTOCOL_VERSION:
        failures.append(f"behavior manifest protocol_version must be {PROTOCOL_VERSION}")
    if manifest.get("report_version") != REPORT_VERSION:
        failures.append(f"behavior manifest report_version must be {REPORT_VERSION}")
    if manifest.get("adapter_contract_version") != ADAPTER_CONTRACT_VERSION:
        failures.append(f"behavior manifest adapter_contract_version must be {ADAPTER_CONTRACT_VERSION}")
    if manifest.get("metric_version") != METRIC_VERSION:
        failures.append(f"official manifest metric_version must be {METRIC_VERSION}")
    for field in ("run_id", "started_at", "finished_at", "reproduction_command"):
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            failures.append(f"behavior manifest {field} must be a non-empty string")
    if not isinstance(manifest.get("abort_reason"), str):
        failures.append("behavior manifest abort_reason must be a string")
    if manifest.get("status") not in {"running", "passed", "failed", "invalid", "cancelled"}:
        failures.append("behavior manifest status is invalid")
    if manifest.get("assurance") not in {"conformance-fixture", "development", "candidate", "official"}:
        failures.append("behavior manifest assurance is invalid")
    for field in (
        "official_requested",
        "official",
        "model_claim_allowed",
        "benchmark_claim_allowed",
        "external_judge_authorized",
    ):
        if not isinstance(manifest.get(field), bool):
            failures.append(f"behavior manifest {field} must be boolean")
    resumed = manifest.get("resumed_at")
    if resumed is not None and (
        not isinstance(resumed, list) or any(not isinstance(value, str) or not value for value in resumed)
    ):
        failures.append("behavior manifest resumed_at must be an array of timestamp strings")
    protocol_sha256 = manifest.get("protocol_sha256")
    if not isinstance(protocol_sha256, str) or _HASH.fullmatch(protocol_sha256) is None:
        failures.append("behavior manifest protocol_sha256 is invalid")
    artifacts_value = manifest.get("artifacts")
    if not isinstance(artifacts_value, dict) or any(
        not isinstance(name, str)
        or not name
        or not isinstance(digest, str)
        or _HASH.fullmatch(digest) is None
        for name, digest in artifacts_value.items()
    ):
        failures.append("behavior manifest artifacts must map non-empty paths to SHA-256 digests")
    object_fields = {
        "suite": {"name", "version", "status", "dataset_sha256", "rubric_sha256", "suite_config_sha256", "data_classification", "profile"},
        "target": {"label", "expected_reported_model", "revision", "endpoint", "request_model", "kind", "capabilities", "recorded_responses_sha256"},
        "judge": {"requested_model", "expected_reported_model", "revision", "endpoint", "prompt_sha256", "response_schema", "temperature", "models", "consensus"},
        "judge_qualification": {"artifact_type", "package_version", "package_path", "package_sha256"},
        "engagement": {
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
        "external_authorization": {
            "authorization_id",
            "approver",
            "purpose",
            "destinations",
            "effective_at",
            "expires_at",
        },
        "artifact_security": {"classification", "retention", "storage_attestation", "encryption_state", "immutability_state"},
        "parameters": {
            "mode",
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
            "concurrency",
            "requests_per_second",
            "progress_events",
            "case_order_policy",
            "case_order_sha256",
            "cache",
        },
        "pricing": {"currency", "source", "effective_at", "input_per_million", "output_per_million", "judge_input_per_million", "judge_output_per_million"},
        "source": {"commit", "dirty", "status_sha256", "implementation_sha256"},
        "environment": {"python", "platform", "hardware", "uv_lock_sha256"},
    }
    exact_fields = set(object_fields) - {"external_authorization", "pricing"}
    for field, allowed in object_fields.items():
        value = manifest.get(field)
        if value is not None:
            failures.extend(_closed_object_errors(value, allowed, f"{label}.{field}"))
            required = allowed
            if field == "pricing":
                required = {"currency", "source", "effective_at", "input_per_million", "output_per_million"}
            missing_nested = sorted(required - set(value)) if isinstance(value, dict) else []
            if missing_nested:
                failures.append(f"{label}.{field} is missing fields: {missing_nested}")
        elif field in exact_fields and (require_assurance or field not in {"judge_qualification", "engagement"}):
            failures.append(f"{label}.{field} must be an object")
    judge = manifest.get("judge")
    if isinstance(judge, dict) and isinstance(judge.get("models"), list):
        for index, model in enumerate(judge["models"]):
            failures.extend(_closed_object_errors(model, {"id", "model", "expected_model", "revision"}, f"{label}.judge.models[{index}]"))
            if not isinstance(model, dict) or any(
                not nonempty_string(model.get(field)) for field in ("id", "model", "expected_model", "revision")
            ):
                failures.append(f"{label}.judge.models[{index}] has invalid or missing identity fields")
        identifiers = [model.get("id") for model in judge["models"] if isinstance(model, dict)]
        if len(identifiers) != len(judge["models"]) or len(identifiers) != len(set(map(str, identifiers))):
            failures.append("official manifest judge model ids must be present and unique")
    if isinstance(judge, dict):
        for field in ("requested_model", "expected_reported_model", "revision", "endpoint", "response_schema"):
            if not nonempty_string(judge.get(field)):
                failures.append(f"{label}.judge.{field} must be a non-empty string")
        prompt_sha256 = judge.get("prompt_sha256")
        if not isinstance(prompt_sha256, str) or _HASH.fullmatch(prompt_sha256) is None:
            failures.append(f"{label}.judge.prompt_sha256 is invalid")
        if not finite_number(judge.get("temperature"), maximum=2.0):
            failures.append(f"{label}.judge.temperature must be a finite number from 0 to 2")
        if judge.get("consensus") not in {"majority", "unanimous"}:
            failures.append(f"{label}.judge.consensus is invalid")
        if not isinstance(judge.get("models"), list) or not judge["models"]:
            failures.append(f"{label}.judge.models must be a non-empty array")
    target = manifest.get("target")
    if isinstance(target, dict):
        for field in ("label", "expected_reported_model", "revision", "endpoint"):
            if not nonempty_string(target.get(field)):
                failures.append(f"{label}.target.{field} must be a non-empty string")
        if target.get("request_model") is not None and not nonempty_string(target.get("request_model")):
            failures.append(f"{label}.target.request_model must be null or a non-empty string")
        if target.get("kind") not in {"json", "openai", "recorded"}:
            failures.append(f"{label}.target.kind is invalid")
        capabilities = target.get("capabilities")
        if not isinstance(capabilities, list) or any(not nonempty_string(value) for value in capabilities) or len(capabilities) != len(set(capabilities)):
            failures.append(f"{label}.target.capabilities must be an array of unique non-empty strings")
        recorded_digest = target.get("recorded_responses_sha256")
        if recorded_digest is not None and (not isinstance(recorded_digest, str) or _HASH.fullmatch(recorded_digest) is None):
            failures.append(f"{label}.target.recorded_responses_sha256 is invalid")
    authorization = manifest.get("external_authorization")
    if isinstance(authorization, dict) and isinstance(authorization.get("destinations"), list):
        for index, destination in enumerate(authorization["destinations"]):
            failures.extend(_closed_object_errors(destination, {"host", "region", "purpose"}, f"{label}.external_authorization.destinations[{index}]"))
    security = manifest.get("artifact_security")
    if isinstance(security, dict) and isinstance(security.get("storage_attestation"), dict):
        failures.extend(
            _closed_object_errors(
                security["storage_attestation"],
                {
                    "attestation_id",
                    "approver",
                    "encryption_at_rest",
                    "immutability",
                    "access_policy_reference",
                    "audit_log_reference",
                    "retention_policy_reference",
                    "backup_restore_reference",
                    "effective_at",
                    "expires_at",
                },
                f"{label}.artifact_security.storage_attestation",
            )
        )
    parameters = manifest.get("parameters")
    if isinstance(parameters, dict) and parameters.get("cache") is not None:
        failures.extend(_closed_object_errors(parameters["cache"], {"target", "judge"}, f"{label}.parameters.cache"))
        if parameters["cache"] != {"target": "disabled", "judge": "disabled"}:
            failures.append(f"{label}.parameters.cache must disable target and judge caches")
    if isinstance(parameters, dict):
        preset = parameters.get("preset")
        expected_preset_version = BENCHMARK_PRESET_VERSION if isinstance(preset, str) and preset else None
        if parameters.get("preset_version") != expected_preset_version:
            failures.append(f"{label}.parameters.preset_version does not match the selected preset")
        if parameters.get("mode") not in {
            "smoke",
            "regression",
            "candidate",
            "official",
            "redteam",
            "performance",
            "load",
            "soak",
            "offline",
            "monitoring",
        }:
            failures.append(f"{label}.parameters.mode is invalid")
        if parameters.get("preset") not in {None, "smoke", "quick", "standard", "reference"}:
            failures.append(f"{label}.parameters.preset is invalid")
        for field in ("repetitions", "judge_repetitions", "concurrency"):
            value = parameters.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                failures.append(f"{label}.parameters.{field} must be a positive integer")
        if isinstance(parameters.get("concurrency"), int) and not isinstance(parameters["concurrency"], bool) and parameters["concurrency"] > 64:
            failures.append(f"{label}.parameters.concurrency must not exceed 64")
        for field in ("max_cases", "selected_cases", "max_target_calls", "max_judge_calls", "max_total_tokens"):
            value = parameters.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                failures.append(f"{label}.parameters.{field} must be a non-negative integer")
        for field in ("max_elapsed_seconds", "max_estimated_cost", "requests_per_second"):
            if not finite_number(parameters.get(field)):
                failures.append(f"{label}.parameters.{field} must be a finite non-negative number")
        if not finite_number(parameters.get("timeout_seconds")) or float(parameters["timeout_seconds"]) <= 0:
            failures.append(f"{label}.parameters.timeout_seconds must be a finite positive number")
        if not isinstance(parameters.get("progress_events"), bool):
            failures.append(f"{label}.parameters.progress_events must be boolean")
        if not nonempty_string(parameters.get("case_order_policy")):
            failures.append(f"{label}.parameters.case_order_policy must be a non-empty string")
        case_order_sha256 = parameters.get("case_order_sha256")
        if not isinstance(case_order_sha256, str) or _HASH.fullmatch(case_order_sha256) is None:
            failures.append(f"{label}.parameters.case_order_sha256 is invalid")
    environment = manifest.get("environment")
    if isinstance(environment, dict) and environment.get("hardware") is not None:
        failures.extend(
            _closed_object_errors(
                environment["hardware"],
                {"machine", "processor", "cpu_count", "memory_bytes", "gpus", "gpu_inventory_source"},
                f"{label}.environment.hardware",
            )
        )
    source = manifest.get("source")
    if isinstance(source, dict):
        commit = source.get("commit")
        if not isinstance(commit, str) or (commit and re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit) is None):
            failures.append(f"{label}.source.commit is invalid")
        if not isinstance(source.get("dirty"), bool):
            failures.append(f"{label}.source.dirty must be boolean")
        for field in ("status_sha256", "implementation_sha256"):
            value = source.get(field)
            if not isinstance(value, str) or _HASH.fullmatch(value) is None:
                failures.append(f"{label}.source.{field} is invalid")
    if isinstance(environment, dict):
        for field in ("python", "platform"):
            if not nonempty_string(environment.get(field)):
                failures.append(f"{label}.environment.{field} must be a non-empty string")
        uv_digest = environment.get("uv_lock_sha256")
        if not isinstance(uv_digest, str) or (uv_digest and _HASH.fullmatch(uv_digest) is None):
            failures.append(f"{label}.environment.uv_lock_sha256 is invalid")
        hardware = environment.get("hardware")
        if isinstance(hardware, dict):
            if not isinstance(hardware.get("machine"), str):
                failures.append(f"{label}.environment.hardware.machine must be a string")
            cpu_count = hardware.get("cpu_count")
            if cpu_count is not None and (
                not isinstance(cpu_count, int) or isinstance(cpu_count, bool) or cpu_count < 1
            ):
                failures.append(f"{label}.environment.hardware.cpu_count is invalid")
            memory_bytes = hardware.get("memory_bytes")
            if not isinstance(memory_bytes, int) or isinstance(memory_bytes, bool) or memory_bytes < 0:
                failures.append(f"{label}.environment.hardware.memory_bytes is invalid")
            gpus = hardware.get("gpus")
            if gpus is not None and (
                not isinstance(gpus, list) or any(not nonempty_string(value) for value in gpus)
            ):
                failures.append(f"{label}.environment.hardware.gpus must be an array of non-empty strings")
    if isinstance(manifest.get("metrics"), dict):
        failures.extend(_official_metrics_structure_errors(manifest["metrics"]))
    return failures


def _official_manifest_structure_errors(manifest: Any) -> list[str]:
    """Compatibility entry point for the strict current official manifest contract."""
    return _manifest_structure_errors(manifest, require_assurance=True)


def _assurance_evidence_errors(run_dir: Path, suite: Suite, manifest: dict[str, Any], now: datetime) -> list[str]:
    """Reconstruct the qualification and engagement assurance closures."""
    failures: list[str] = []
    try:
        qualification_value = manifest.get("judge_qualification")
        qualification_manifest: dict[str, Any] = qualification_value if isinstance(qualification_value, dict) else {}
        package_path = _safe_path(
            run_dir,
            qualification_manifest.get("package_path"),
            "judge qualification package",
        )
        judge_value = manifest.get("judge")
        judge_configuration = judge_value if isinstance(judge_value, dict) else {}
        qualification, qualification_failures = verify_judge_qualification_for_run(
            package_path,
            suite=suite,
            judge_configuration=judge_configuration,
            now=now,
        )
        failures.extend(qualification_failures)
        expected_reference = {
            "artifact_type": "judge-qualification-evidence-package",
            "package_version": qualification.package_version,
            "package_path": JUDGE_QUALIFICATION_SNAPSHOT,
            "package_sha256": qualification.package_sha256,
        }
        if qualification_manifest != expected_reference:
            failures.append("judge qualification package reference differs from reconstructed package bytes")

        with TemporaryDirectory(prefix="cavada-behavior-engagement-") as engagement_root_text:
            engagement_root = Path(engagement_root_text)
            engagement_path = engagement_root / "engagement.json"
            engagement_path.write_bytes(_read_regular(run_dir, Path("engagement_snapshot.json")))
            _materialize_files(
                engagement_root,
                run_dir / "engagement_evidence_manifest.json",
                run_dir / "engagement_evidence",
                "engagement evidence",
            )
            from .release import verified_engagement

            target_value = manifest.get("target")
            target = target_value if isinstance(target_value, dict) else {}
            engagement = verified_engagement(
                engagement_path,
                suite,
                expected_model=str(target.get("expected_reported_model", "")),
                model_revision=str(target.get("revision", "")),
                now=now,
            )
            if manifest.get("engagement") != engagement:
                failures.append("manifest engagement differs from reconstructed evidence and claim scope")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ProtocolError, ValueError, TypeError) as exc:
        failures.append(f"official assurance evidence reconstruction failed: {exc}")
    return list(dict.fromkeys(failures))


def _operational_semantic_errors(manifest: dict[str, Any], suite: Suite) -> list[str]:
    """Reconstruct factual security metadata for every assurance level."""
    failures: list[str] = []
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    target_value = manifest.get("target")
    target = target_value if isinstance(target_value, dict) else {}
    judge_value = manifest.get("judge")
    judge = judge_value if isinstance(judge_value, dict) else {}
    target_host = urllib.parse.urlparse(str(target.get("endpoint", ""))).hostname
    target_host = target_host.casefold() if isinstance(target_host, str) else None
    judge_host = urllib.parse.urlparse(str(judge.get("endpoint", ""))).hostname
    judge_host = judge_host.casefold() if isinstance(judge_host, str) else None
    external_judge = judge_host not in loopback_hosts
    external_hosts = {
        host
        for host in (None if target.get("kind") == "recorded" else target_host, judge_host)
        if host not in loopback_hosts and host is not None
    }
    authorization_value = manifest.get("external_authorization")
    authorization = authorization_value if isinstance(authorization_value, dict) else None
    authorization_covers_run = False
    authorized_hosts: set[str] = set()
    if authorization is not None:
        required_authorization = {
            "authorization_id",
            "approver",
            "purpose",
            "destinations",
            "effective_at",
            "expires_at",
        }
        authorization_fields_valid = set(authorization) == required_authorization and all(
            isinstance(authorization.get(field), str) and authorization[field].strip()
            for field in ("authorization_id", "approver", "purpose")
        )
        if not authorization_fields_valid:
            failures.append("external authorization fields are incomplete, empty, or unknown")
        destinations = authorization.get("destinations")
        authorized_hosts = {
            str(destination.get("host")).casefold()
            for destination in destinations or []
            if isinstance(destination, dict) and isinstance(destination.get("host"), str)
        }
        try:
            effective = datetime.fromisoformat(str(authorization.get("effective_at", "")).replace("Z", "+00:00"))
            expires = datetime.fromisoformat(str(authorization.get("expires_at", "")).replace("Z", "+00:00"))
            started = datetime.fromisoformat(str(manifest.get("started_at", "")).replace("Z", "+00:00"))
            finished = datetime.fromisoformat(str(manifest.get("finished_at", "")).replace("Z", "+00:00"))
            valid_times = (
                all(value.tzinfo is not None for value in (effective, expires, started, finished))
                and effective <= started <= finished < expires
            )
        except ValueError:
            valid_times = False
        if not valid_times:
            failures.append("external authorization does not cover the behavior run timestamps")
        destinations_valid = (
            isinstance(destinations, list)
            and bool(destinations)
            and len(authorized_hosts) == len(destinations)
            and all(
                isinstance(destination, dict)
                and set(destination) == {"host", "region", "purpose"}
                and all(isinstance(destination.get(field), str) and destination[field].strip() for field in destination)
                for destination in destinations
            )
        )
        if not destinations_valid:
            failures.append("external authorization destinations are missing, malformed, or duplicated")
        authorization_covers_run = authorization_fields_valid and valid_times and destinations_valid
        if not external_hosts <= authorized_hosts:
            failures.append(f"external authorization omits hosts: {sorted(external_hosts - authorized_hosts)}")
    classification = suite.config.get("data_classification")
    if classification not in {"public", "synthetic"} and external_hosts and (
        authorization is None or not authorization_covers_run or not external_hosts <= authorized_hosts
    ):
        failures.append(f"non-public suite lacks external authorization for hosts: {sorted(external_hosts - authorized_hosts)}")
    judge_authorized = external_judge and authorization_covers_run and judge_host in authorized_hosts
    if manifest.get("external_judge_authorized") is not judge_authorized:
        failures.append("external_judge_authorized does not reconstruct from destination authorization")

    security_value = manifest.get("artifact_security")
    security = security_value if isinstance(security_value, dict) else {}
    storage_value = security.get("storage_attestation")
    storage = storage_value if isinstance(storage_value, dict) else None
    expected_encryption = "attested" if storage is not None and storage.get("encryption_at_rest") is True else "not-attested"
    expected_immutability = "attested" if storage is not None and storage.get("immutability") is True else "not-attested"
    if (
        security.get("classification") != classification
        or security.get("retention") != (suite.config.get("governance") or {}).get("retention")
    ):
        failures.append("artifact security classification or retention differs from the suite")
    if security.get("encryption_state") != expected_encryption or security.get("immutability_state") != expected_immutability:
        failures.append("artifact security states do not reconstruct from storage attestation")
    if storage is not None:
        required_storage = {
            "attestation_id",
            "approver",
            "encryption_at_rest",
            "immutability",
            "access_policy_reference",
            "audit_log_reference",
            "retention_policy_reference",
            "backup_restore_reference",
            "effective_at",
            "expires_at",
        }
        if (
            set(storage) != required_storage
            or any(
                not isinstance(storage.get(field), str) or not storage[field].strip()
                for field in required_storage - {"encryption_at_rest", "immutability", "effective_at", "expires_at"}
            )
            or not isinstance(storage.get("encryption_at_rest"), bool)
            or not isinstance(storage.get("immutability"), bool)
        ):
            failures.append("storage attestation fields are incomplete, empty, or unknown")
        try:
            effective = datetime.fromisoformat(str(storage.get("effective_at", "")).replace("Z", "+00:00"))
            expires = datetime.fromisoformat(str(storage.get("expires_at", "")).replace("Z", "+00:00"))
            started = datetime.fromisoformat(str(manifest.get("started_at", "")).replace("Z", "+00:00"))
            finished = datetime.fromisoformat(str(manifest.get("finished_at", "")).replace("Z", "+00:00"))
            if (
                any(value.tzinfo is None for value in (effective, expires, started, finished))
                or not effective <= started <= finished < expires
            ):
                raise ValueError
        except ValueError:
            failures.append("storage attestation does not cover the behavior run timestamps")
    return failures


def _operational_assurance_errors(manifest: dict[str, Any], suite: Suite, now: datetime) -> list[str]:
    """Reconstruct destination authorization and storage assurance from the manifest bytes."""
    failures: list[str] = []
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    local_hosts = loopback_hosts | {"recorded-local", "local"}

    def endpoint_host(value: Any) -> str | None:
        parsed = urllib.parse.urlparse(str(value))
        hostname = parsed.hostname
        return hostname.casefold() if isinstance(hostname, str) else None

    def external_host(value: Any) -> str | None:
        hostname = endpoint_host(value)
        return hostname if hostname is not None and hostname not in local_hosts else None

    def secure_endpoint(value: Any, *, recorded: bool = False) -> bool:
        if recorded:
            return True
        parsed = urllib.parse.urlparse(str(value))
        hostname = parsed.hostname.casefold() if isinstance(parsed.hostname, str) else None
        return hostname in loopback_hosts or (parsed.scheme == "https" and hostname is not None)

    def time(value: Any, label: str) -> datetime | None:
        if not isinstance(value, str):
            failures.append(f"{label} must be a timezone-aware timestamp")
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is None or parsed.tzinfo is None:
            failures.append(f"{label} must be a timezone-aware timestamp")
            return None
        return parsed

    started = time(manifest.get("started_at"), "official run started_at")
    target_value = manifest.get("target")
    target = target_value if isinstance(target_value, dict) else {}
    judge_value = manifest.get("judge")
    judge = judge_value if isinstance(judge_value, dict) else {}
    target_recorded = target.get("kind") == "recorded"
    target_endpoint_host = None if target_recorded else endpoint_host(target.get("endpoint"))
    judge_endpoint_host = endpoint_host(judge.get("endpoint"))
    target_host = None if target_recorded else external_host(target.get("endpoint"))
    judge_host = external_host(judge.get("endpoint"))
    external_hosts = {value for value in (target_host, judge_host) if value is not None}
    if not secure_endpoint(target.get("endpoint"), recorded=target_recorded) or not secure_endpoint(judge.get("endpoint")):
        failures.append("official endpoints must use HTTPS or loopback transport")
    allowed_value = suite.config.get("network")
    allowed_hosts = {
        str(value).casefold()
        for value in (allowed_value.get("allowed_hosts", []) if isinstance(allowed_value, dict) else [])
    }
    used_hosts = {value for value in (target_endpoint_host, judge_endpoint_host) if value is not None}
    if allowed_hosts and not used_hosts <= allowed_hosts:
        failures.append(f"official endpoint hosts are outside suite.network.allowed_hosts: {sorted(used_hosts - allowed_hosts)}")

    authorization_value = manifest.get("external_authorization")
    authorization = authorization_value if isinstance(authorization_value, dict) else None
    authorized_hosts: set[str] = set()
    if authorization is not None:
        required = {"authorization_id", "approver", "purpose", "destinations", "effective_at", "expires_at"}
        if set(authorization) != required:
            failures.append("official external authorization fields are incomplete or unknown")
        for field in ("authorization_id", "approver", "purpose"):
            if not isinstance(authorization.get(field), str) or not authorization[field].strip():
                failures.append(f"official external authorization {field} must be non-empty")
        destinations = authorization.get("destinations")
        if not isinstance(destinations, list) or not destinations:
            failures.append("official external authorization destinations must be non-empty")
        else:
            for index, destination in enumerate(destinations):
                if not isinstance(destination, dict) or set(destination) != {"host", "region", "purpose"}:
                    failures.append(f"official external authorization destination {index} is incomplete or unknown")
                    continue
                if any(not isinstance(destination.get(field), str) or not destination[field].strip() for field in destination):
                    failures.append(f"official external authorization destination {index} contains empty fields")
                    continue
                authorized_hosts.add(str(destination["host"]).casefold())
            if len(authorized_hosts) != len(destinations):
                failures.append("official external authorization destination hosts must be unique")
        effective = time(authorization.get("effective_at"), "official external authorization effective_at")
        expires = time(authorization.get("expires_at"), "official external authorization expires_at")
        if effective is not None and expires is not None and (
            expires <= effective or effective > now or expires <= now or (started is not None and effective > started)
        ):
            failures.append("official external authorization is not effective for the run and verification time")
    if external_hosts and authorization is None:
        failures.append(f"official external destinations lack authorization: {sorted(external_hosts)}")
    elif not external_hosts <= authorized_hosts:
        failures.append(f"official external authorization omits hosts: {sorted(external_hosts - authorized_hosts)}")
    security_value = manifest.get("artifact_security")
    security = security_value if isinstance(security_value, dict) else {}
    classification = suite.config.get("data_classification")
    storage_value = security.get("storage_attestation")
    storage = storage_value if isinstance(storage_value, dict) else None
    if storage is not None:
        required_storage = {
            "attestation_id",
            "approver",
            "encryption_at_rest",
            "immutability",
            "access_policy_reference",
            "audit_log_reference",
            "retention_policy_reference",
            "backup_restore_reference",
            "effective_at",
            "expires_at",
        }
        if set(storage) != required_storage:
            failures.append("official storage attestation fields are incomplete or unknown")
        for field in required_storage - {"encryption_at_rest", "immutability", "effective_at", "expires_at"}:
            if not isinstance(storage.get(field), str) or not storage[field].strip():
                failures.append(f"official storage attestation {field} must be non-empty")
        if not isinstance(storage.get("encryption_at_rest"), bool) or not isinstance(storage.get("immutability"), bool):
            failures.append("official storage attestation encryption and immutability must be boolean")
        effective = time(storage.get("effective_at"), "official storage attestation effective_at")
        expires = time(storage.get("expires_at"), "official storage attestation expires_at")
        if effective is not None and expires is not None and (
            expires <= effective or effective > now or expires <= now or (started is not None and effective > started)
        ):
            failures.append("official storage attestation is not effective for the run and verification time")
    if classification not in {"public", "synthetic"} and (
        storage is None or storage.get("encryption_at_rest") is not True or storage.get("immutability") is not True
    ):
        failures.append("non-public official evidence requires current encrypted immutable storage assurance")
    parameters_value = manifest.get("parameters")
    parameters = parameters_value if isinstance(parameters_value, dict) else {}
    if parameters.get("max_cases") != 0:
        failures.append("official behavior runs must evaluate the complete suite without max_cases")
    for field, suite_field in (
        ("repetitions", "official_min_repetitions"),
        ("judge_repetitions", "official_min_judge_repetitions"),
    ):
        observed = parameters.get(field)
        minimum = suite.config.get(suite_field, 1)
        if (
            not isinstance(observed, int)
            or isinstance(observed, bool)
            or not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or observed < minimum
        ):
            failures.append(f"official {field} is below the suite minimum")
    repetitions = parameters.get("repetitions")
    judge_repetitions = parameters.get("judge_repetitions")
    models = judge.get("models")
    if (
        isinstance(repetitions, int)
        and not isinstance(repetitions, bool)
        and isinstance(judge_repetitions, int)
        and not isinstance(judge_repetitions, bool)
        and isinstance(models, list)
    ):
        planned_target_calls = len(suite.cases) * repetitions
        planned_judge_calls = planned_target_calls * judge_repetitions * len(models)
        for field, planned in (("max_target_calls", planned_target_calls), ("max_judge_calls", planned_judge_calls)):
            limit = parameters.get(field)
            if isinstance(limit, int) and not isinstance(limit, bool) and limit and limit < planned:
                failures.append(f"official {field} is below the complete suite plan")
    return list(dict.fromkeys(failures))


def _behavior_errors(
    run_dir: Path,
    manifest: dict[str, Any],
    bundle: dict[str, Any],
    now: datetime,
    *,
    assurance_checks: bool,
) -> tuple[list[str], list[str]]:
    assurance_level = manifest.get("assurance")
    official_assurance = assurance_checks and assurance_level in {"official", "conformance-fixture"}
    failures = _manifest_structure_errors(manifest, require_assurance=official_assurance)
    assurance_failures: list[str] = []
    if official_assurance and (
        manifest.get("status") != "passed"
        or manifest.get("official") is not True
        or manifest.get("official_requested") is not True
        or manifest.get("abort_reason") != ""
    ):
        assurance_failures.append("manifest is not a completed non-aborted official behavior run")
    if assurance_checks and assurance_level == "candidate":
        if (
            manifest.get("official") is not False
            or manifest.get("official_requested") is not False
            or manifest.get("model_claim_allowed") is not False
            or manifest.get("benchmark_claim_allowed") is not False
        ):
            assurance_failures.append("candidate behavior runs cannot make official, model, benchmark, or ranking claims")
    elif assurance_checks and assurance_level not in {"official", "conformance-fixture"}:
        assurance_failures.append("behavior manifest assurance level is unsupported")
    parameters_value = manifest.get("parameters")
    parameters: dict[str, Any] = parameters_value if isinstance(parameters_value, dict) else {}
    if official_assurance and (
        parameters.get("preset") != "reference" or parameters.get("mode") != "official"
    ):
        assurance_failures.append("official behavior runs require the reference preset and official mode")
    source_value = manifest.get("source")
    source = source_value if isinstance(source_value, dict) else {}
    if official_assurance and (
        not isinstance(source_value, dict)
        or re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", str(source.get("commit", ""))) is None
        or source.get("dirty") is not False
        or _HASH.fullmatch(str(source.get("status_sha256", ""))) is None
        or _HASH.fullmatch(str(source.get("implementation_sha256", ""))) is None
    ):
        assurance_failures.append("official source evidence must identify a clean immutable commit and status")
    elif official_assurance and source["status_sha256"] != sha256_bytes(b""):
        assurance_failures.append("clean official source evidence requires the empty git status digest")
    try:
        started = datetime.fromisoformat(str(manifest.get("started_at", "")).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(str(manifest.get("finished_at", "")).replace("Z", "+00:00"))
        if started.tzinfo is None or finished.tzinfo is None or not started <= finished <= now:
            failures.append("run timestamps are invalid or inconsistent")
    except (TypeError, ValueError):
        failures.append("run timestamps are invalid or inconsistent")

    artifacts = manifest.get("artifacts")
    bundle_files = bundle.get("files")
    if not isinstance(artifacts, dict) or not isinstance(bundle_files, dict):
        return failures + ["behavior artifact maps are malformed"], assurance_failures
    if not _REQUIRED_BEHAVIOR_ARTIFACTS <= set(artifacts):
        failures.append(f"behavior run is missing required artifacts: {sorted(_REQUIRED_BEHAVIOR_ARTIFACTS - set(artifacts))}")
    if official_assurance and not _REQUIRED_OFFICIAL_ARTIFACTS <= set(artifacts):
        assurance_failures.append(f"official run is missing required artifacts: {sorted(_REQUIRED_OFFICIAL_ARTIFACTS - set(artifacts))}")
    expected_bundle_files = set(artifacts) | {"manifest.json"}
    if set(bundle_files) != expected_bundle_files:
        failures.append("behavior bundle closed file set differs from the manifest artifact map")
    allowed_artifacts = _REQUIRED_BEHAVIOR_ARTIFACTS | _OPTIONAL_BEHAVIOR_ARTIFACTS
    allowed_prefixes: tuple[str, ...] = _DYNAMIC_BEHAVIOR_ARTIFACT_PREFIXES
    if official_assurance:
        allowed_artifacts |= _REQUIRED_OFFICIAL_ARTIFACTS
        allowed_prefixes += _OFFICIAL_DYNAMIC_ARTIFACT_PREFIXES
    unknown_artifacts = sorted(
        name
        for name in artifacts
        if name not in allowed_artifacts
        and not any(name.startswith(prefix) and name != prefix for prefix in allowed_prefixes)
    )
    if unknown_artifacts:
        failures.append(f"behavior manifest declares unsupported artifacts: {unknown_artifacts}")
    if any(bundle_files.get(name) != digest for name, digest in artifacts.items()):
        failures.append("manifest artifact map differs from bundle.json")

    suite_temporary: TemporaryDirectory[str] | None = None
    try:
        suite_temporary, suite = _materialize_suite(run_dir)
        if official_assurance:
            try:
                load_suite(suite.root, official=True)
            except (OSError, tomllib.TOMLDecodeError, ProtocolError, ValueError) as exc:
                assurance_failures.append(f"official suite validation failed: {exc}")
        target_config = suite.config.get("target") or {}
        report_config = suite.config.get("report") or {}
        target_value = manifest.get("target")
        target_manifest = target_value if isinstance(target_value, dict) else {}
        expected_target_kind = target_config.get("kind", "json") if isinstance(target_config, dict) else "json"
        expected_capabilities = target_config.get("capabilities", []) if isinstance(target_config, dict) else []
        expected_recorded_digest = (
            sha256_file(suite.root / str(target_config.get("responses")))
            if expected_target_kind == "recorded" and isinstance(target_config.get("responses"), str)
            else None
        )
        if (
            target_manifest.get("kind") != expected_target_kind
            or target_manifest.get("capabilities") != expected_capabilities
            or target_manifest.get("recorded_responses_sha256") != expected_recorded_digest
        ):
            failures.append("manifest target adapter contract differs from the suite snapshot")
        failures.extend(_operational_semantic_errors(manifest, suite))
        conformance_fixture = report_config.get("assurance") == "conformance-fixture"
        expected_assurance = "conformance-fixture" if conformance_fixture else "official"
        expected_claim_allowed = not conformance_fixture
        if official_assurance and conformance_fixture and (
            target_config.get("kind") != "recorded"
            or report_config.get("model_claim_allowed") is not False
            or report_config.get("benchmark_claim_allowed") is not False
        ):
            assurance_failures.append("conformance fixtures must use recorded targets and prohibit claims")
        if official_assurance and (
            manifest.get("assurance") != expected_assurance
            or manifest.get("model_claim_allowed") is not expected_claim_allowed
            or manifest.get("benchmark_claim_allowed") is not expected_claim_allowed
        ):
            assurance_failures.append("manifest assurance and claim flags differ from reconstructed suite semantics")
        judge_value = manifest.get("judge")
        judge_manifest = judge_value if isinstance(judge_value, dict) else {}
        judge_host = urllib.parse.urlparse(str(judge_manifest.get("endpoint", ""))).hostname
        if official_assurance and conformance_fixture and judge_host not in {"127.0.0.1", "localhost", "::1"}:
            assurance_failures.append("conformance fixtures require a loopback judge")
        suite_value = manifest.get("suite")
        suite_manifest: dict[str, Any] = suite_value if isinstance(suite_value, dict) else {}
        expected_suite = {
            "name": suite.name,
            "version": suite.version,
            "status": suite.status,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
            "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
            "data_classification": suite.config.get("data_classification"),
            "profile": suite.config.get("profile", "text-generation"),
        }
        if suite_manifest != expected_suite:
            failures.append("manifest suite differs from reconstructed official snapshots")
        protocol_hash = manifest.get("protocol_sha256")
        protocol_snapshot = _read_regular(run_dir, Path("protocol_snapshot.md"))
        if not isinstance(protocol_hash, str) or protocol_hash != sha256_bytes(protocol_snapshot):
            failures.append("protocol snapshot differs from the manifest digest")
        try:
            canonical_protocol = _canonical_protocol_bytes()
        except (OSError, ProtocolError) as exc:
            failures.append(str(exc))
        else:
            if protocol_snapshot != canonical_protocol:
                failures.append("protocol snapshot differs from the canonical protocol asset")
        if manifest.get("environment") != _object(run_dir / "environment.json", "environment evidence"):
            failures.append("manifest environment differs from environment.json")

        with TemporaryDirectory(prefix="cavada-behavior-implementation-") as implementation_root_text:
            implementation_root = Path(implementation_root_text)
            implementation_files = _materialize_files(
                implementation_root,
                run_dir / "implementation_evidence_manifest.json",
                run_dir / "implementation_evidence",
                "implementation evidence",
            )
            if not implementation_files or any(not path.endswith(".py") for path in implementation_files):
                failures.append("implementation evidence must be a non-empty Python source closure")
            else:
                from .runner import _python_source_digest

                if _python_source_digest(implementation_root) != source.get("implementation_sha256"):
                    failures.append("implementation evidence does not match the manifest source digest")
                if official_assurance:
                    from .source_proof import verify_source_commit_proof

                    implementation_bytes = {
                        relative: _read_regular(implementation_root, Path(relative))
                        for relative in implementation_files
                    }
                    environment_value = manifest.get("environment")
                    environment = environment_value if isinstance(environment_value, dict) else {}
                    source_proof_failures = verify_source_commit_proof(
                        run_dir / "source_commit_proof.pack",
                        str(source.get("commit", "")),
                        implementation_bytes,
                        str(environment.get("uv_lock_sha256", "")),
                    )
                    assurance_failures.extend(
                        f"official source commit proof: {failure}" for failure in source_proof_failures
                    )

        if official_assurance:
            assurance_failures.extend(_operational_assurance_errors(manifest, suite, now))
            assurance_failures.extend(_assurance_evidence_errors(run_dir, suite, manifest, now))

        metrics = _object(run_dir / "metrics.json", "run metrics")
        failures.extend(_official_metrics_structure_errors(metrics))
        if manifest.get("metrics") != metrics:
            failures.append("manifest metrics differ from metrics.json")
        if official_assurance and (
            metrics.get("officially_valid") is not True
            or metrics.get("aborted") is not False
            or metrics.get("gate_failures") != []
            or any(
            metrics.get(field) != 0 for field in ("invalid", "error", "skipped")
            )
        ):
            assurance_failures.append("official metrics contain abort, invalid, error, skipped, or gate failure evidence")
        results = _jsonl(run_dir / "case_results.jsonl")
        from .runner import _distribution_shift_summary, _judge_calibration_summary, _scenario_analysis_rows, _usage_tokens

        selected_cases, _ = _selected_cases_from_manifest(suite, parameters if isinstance(parameters, dict) else {})
        try:
            if _read_regular(run_dir, Path("dataset_card.md")) != dataset_card(suite).encode("utf-8"):
                failures.append("dataset card does not reconstruct from suite snapshots")
        except OSError:
            failures.append("dataset card is missing or unsafe")
        with TemporaryDirectory(prefix="cavada-behavior-assets-") as asset_root_text:
            asset_root = Path(asset_root_text)
            expected_inventory = asset_inventory(selected_cases, suite_root=suite.root, snapshot_dir=asset_root / "assets")
            try:
                actual_inventory = _strict_json(
                    _read_regular(run_dir, Path("asset_inventory.json")).decode("utf-8")
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise ProtocolError("asset inventory is not strict JSON") from exc
            if actual_inventory != expected_inventory:
                failures.append("asset inventory does not reconstruct from selected suite cases")
            expected_assets = {
                path.name: path.read_bytes() for path in sorted((asset_root / "assets").glob("*")) if path.is_file()
            }
            actual_asset_paths = sorted((run_dir / "assets").glob("*")) if (run_dir / "assets").is_dir() else []
            if any(path.is_symlink() or not path.is_file() for path in actual_asset_paths):
                failures.append("behavior asset snapshots contain unsafe entries")
            else:
                actual_assets = {path.name: _read_regular(run_dir / "assets", Path(path.name)) for path in actual_asset_paths}
                if actual_assets != expected_assets:
                    failures.append("behavior asset snapshots do not reconstruct from selected suite cases")
        statistics_config = suite.config.get("statistics") or {}
        confidence = float(statistics_config.get("confidence", 0.95))
        bootstrap_samples = int(statistics_config.get("bootstrap_samples", 10_000))
        bootstrap_seed = int(statistics_config.get("seed", 0))
        case_metrics, case_categories = summarize(results, confidence=confidence)
        scenarios = _scenario_analysis_rows(results, selected_cases)
        analysis = scenarios if scenarios is not None else results
        calculated, categories = summarize(analysis, confidence=confidence)
        for field in ("total", "observations", "pass", "fail", "invalid", "error", "skipped", "pass_rate", "pass_rate_ci", "pass_rate_ci95", "officially_valid"):
            if metrics.get(field) != calculated.get(field):
                failures.append(f"metrics {field} does not reconcile with case_results.jsonl")
        if metrics.get("analysis_unit") != ("scenario" if scenarios is not None else "case") or metrics.get("evaluation_cases") != case_metrics["total"] or metrics.get(
            "target_observations"
        ) != case_metrics["observations"]:
            failures.append("metric analysis unit or observation counts do not reconcile")
        scenario_path = run_dir / "scenario_results.jsonl"
        recorded_scenarios = _jsonl(scenario_path) if scenario_path.is_file() else []
        if scenarios is not None:
            if (
                not scenario_path.is_file()
                or recorded_scenarios != scenarios
                or metrics.get("case_level") != case_metrics
                or metrics.get("case_categories") != case_categories
            ):
                failures.append("scenario and case-level metrics do not reconcile")
        elif recorded_scenarios:
            failures.append("scenario results exist without reconstructible scenario evidence")
        reconstructed: dict[str, Any] = {
            **calculated,
            "analysis_unit": "scenario" if scenarios is not None else "case",
            "evaluation_cases": case_metrics["total"],
            "target_observations": case_metrics["observations"],
        }
        if scenarios is not None:
            reconstructed.update({"case_level": case_metrics, "case_categories": case_categories})
        statuses_by_case: dict[str, list[str]] = {}
        for row in analysis:
            statuses_by_case.setdefault(str(row["case_id"]), []).append(str(row["status"]))
        binary = [
            1.0 if set(statuses_by_case[case_id]) == {"pass"} else 0.0
            for case_id in sorted(statuses_by_case)
            if set(statuses_by_case[case_id]) <= {"pass", "fail"}
        ]
        reconstructed["pass_rate_bootstrap_ci"] = (
            bootstrap_mean_interval(binary, confidence=confidence, samples=bootstrap_samples, seed=bootstrap_seed)
            if binary
            else {"lower": 0.0, "upper": 0.0, "confidence": confidence, "samples": bootstrap_samples, "seed": bootstrap_seed}
        )
        category_binary: dict[str, list[float]] = {}
        for case_id in sorted(statuses_by_case):
            statuses = statuses_by_case[case_id]
            selected = [row for row in analysis if str(row.get("case_id")) == case_id]
            if selected and set(statuses) <= {"pass", "fail"}:
                category_binary.setdefault(str(selected[0]["category"]), []).append(1.0 if set(statuses) == {"pass"} else 0.0)
        reconstructed["pass_rate_stratified_bootstrap_ci"] = stratified_bootstrap_mean_interval(
            category_binary,
            confidence=confidence,
            samples=bootstrap_samples,
            seed=bootstrap_seed,
        )
        shift = _distribution_shift_summary(
            results,
            selected_cases,
            confidence=confidence,
            samples=bootstrap_samples,
            seed=bootstrap_seed,
        )
        if shift is not None:
            reconstructed["distribution_shift"] = shift
        reconstructed["slices"] = {
            dimension: {
                value: summarize([row for row in analysis if str(row.get(dimension, "missing")) == value], confidence=confidence)[0]
                for value in sorted({str(row.get(dimension, "missing")) for row in analysis})
            }
            for dimension in ("risk_domain", "severity", "language", "locale", "split", "operating_condition")
        }
        reconstructed["slice_disparities"] = {
            dimension: max((float(item["pass_rate"]) for item in values.values()), default=0.0)
            - min((float(item["pass_rate"]) for item in values.values()), default=0.0)
            for dimension, values in reconstructed["slices"].items()
        }
        result_statuses: dict[str, list[str]] = {}
        for row in results:
            result_statuses.setdefault(str(row["case_id"]), []).append(str(row["status"]))
        repetition_rates = [
            sum(status == "pass" for status in valid) / len(valid)
            for statuses in result_statuses.values()
            if (valid := [status for status in statuses if status in {"pass", "fail"}])
        ]
        reconstructed["stability"] = {
            "case_pass_fraction": distribution(repetition_rates),
            "stable_case_fraction": sum(value in {0.0, 1.0} for value in repetition_rates) / len(repetition_rates) if repetition_rates else 0.0,
            "judge_agreement": distribution(row["judge_agreement"] for row in results if isinstance(row.get("judge_agreement"), (int, float))),
            "judge_score": distribution(row["score"] for row in results if isinstance(row.get("score"), (int, float))),
        }
        judgments = _jsonl(run_dir / "judgments.jsonl")
        reconstructed["judge_calibration"] = _judge_calibration_summary(judgments, suite)
        timing = _object(run_dir / "timing.json", "timing evidence")
        timing_fields = {"started_at", "finished_at", "elapsed_seconds"}
        failures.extend(_closed_object_errors(timing, timing_fields, "timing evidence"))
        if set(timing) != timing_fields:
            failures.append(f"timing evidence is missing fields: {sorted(timing_fields - set(timing))}")
        elapsed = 1.0
        try:
            timing_started = datetime.fromisoformat(str(timing.get("started_at", "")).replace("Z", "+00:00"))
            timing_finished = datetime.fromisoformat(str(timing.get("finished_at", "")).replace("Z", "+00:00"))
            reconstructed_elapsed = (timing_finished - timing_started).total_seconds()
            declared_elapsed = timing.get("elapsed_seconds")
            if (
                timing_started.tzinfo is None
                or timing_finished.tzinfo is None
                or timing_started.utcoffset() != timezone.utc.utcoffset(None)
                or timing_finished.utcoffset() != timezone.utc.utcoffset(None)
                or timing.get("started_at") != manifest.get("started_at")
                or timing.get("finished_at") != manifest.get("finished_at")
                or not isinstance(declared_elapsed, (int, float))
                or isinstance(declared_elapsed, bool)
                or not math.isfinite(float(declared_elapsed))
                or declared_elapsed != reconstructed_elapsed
                or reconstructed_elapsed <= 0
            ):
                failures.append("timing evidence does not reconstruct from the manifest timestamps")
            else:
                elapsed = reconstructed_elapsed
        except (TypeError, ValueError):
            failures.append("timing evidence does not contain valid timezone-aware timestamps")
        requests = _jsonl(run_dir / "requests.jsonl")
        responses = _jsonl(run_dir / "raw_responses.jsonl")
        target_requests = [row for row in requests if row.get("kind") == "target"]
        judge_requests = [row for row in requests if row.get("kind") == "judge"]
        reconstructed["performance"] = {
            "target_latency_ms": distribution(row["target_latency_ms"] for row in results if isinstance(row.get("target_latency_ms"), (int, float))),
            "target_response_bytes": distribution(row["target_response_bytes"] for row in results if isinstance(row.get("target_response_bytes"), (int, float))),
            "input_tokens": distribution(row["input_tokens"] for row in results if isinstance(row.get("input_tokens"), (int, float))),
            "output_tokens": distribution(row["output_tokens"] for row in results if isinstance(row.get("output_tokens"), (int, float))),
            "ttft_ms": distribution(row["ttft_ms"] for row in results if isinstance(row.get("ttft_ms"), (int, float))),
            "output_tokens_per_second": distribution(
                row["output_tokens_per_second"] for row in results if isinstance(row.get("output_tokens_per_second"), (int, float))
            ),
            "elapsed_seconds": elapsed,
            "observations_per_second": len(results) / elapsed,
            "target_calls_per_second": len(target_requests) / elapsed,
            "observation_success_rate": sum(row.get("status") in {"pass", "fail"} for row in results) / len(results) if results else 0.0,
            "observation_error_rate": sum(row.get("status") == "error" for row in results) / len(results) if results else 0.0,
        }
        reconstructed["performance_by_phase"] = {
            phase: distribution(
                row["target_latency_ms"]
                for row in results
                if row.get("performance_phase") == phase and isinstance(row.get("target_latency_ms"), (int, float))
            )
            for phase in ("cold", "warmup", "steady", "soak")
        }
        token_totals = {"target_input": 0.0, "target_output": 0.0, "judge_input": 0.0, "judge_output": 0.0}
        for rows, kind in ((responses, "target"), (judgments, "judge")):
            for row in rows:
                raw = row.get("response") or row.get("raw") or {}
                if isinstance(raw, dict):
                    input_tokens, output_tokens = _usage_tokens(raw)
                    token_totals[f"{kind}_input"] += input_tokens
                    token_totals[f"{kind}_output"] += output_tokens
        reconstructed["budgets"] = {
            "target_calls": len(target_requests),
            "judge_calls": len(judge_requests),
            "total_tokens": sum(token_totals.values()),
            "exhausted": str(manifest.get("abort_reason", "")).startswith("budget exhausted"),
        }
        budget_limits = {
            "target_calls": parameters.get("max_target_calls"),
            "judge_calls": parameters.get("max_judge_calls"),
            "total_tokens": parameters.get("max_total_tokens"),
        }
        for field, limit in budget_limits.items():
            observed = reconstructed["budgets"][field]
            if isinstance(limit, int) and not isinstance(limit, bool) and limit and observed > limit:
                if field != "total_tokens" or manifest.get("abort_reason") != "budget exhausted: total tokens":
                    failures.append(f"behavior {field} exceeds its declared execution budget")
        pricing_value = suite.config.get("pricing")
        pricing = pricing_value if isinstance(pricing_value, dict) else None
        if manifest.get("pricing") != pricing:
            failures.append("manifest pricing differs from the suite snapshot")
        if pricing is not None:
            reconstructed["cost"] = {
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
        reconstructed["aborted"] = bool(manifest.get("abort_reason"))
        semantic_metric_fields = {
            "pass_rate_bootstrap_ci",
            "pass_rate_stratified_bootstrap_ci",
            "slices",
            "slice_disparities",
            "stability",
            "judge_calibration",
            "performance",
            "performance_by_phase",
            "budgets",
            *( ["case_level", "case_categories"] if scenarios is not None else [] ),
            *( ["distribution_shift"] if shift is not None else [] ),
            *( ["cost"] if pricing is not None else [] ),
        }
        for field in semantic_metric_fields:
            if metrics.get(field) != reconstructed.get(field):
                failures.append(f"metrics {field} does not reconcile with immutable evidence")
        for absent in ({"case_level", "case_categories"} if scenarios is None else set()) | ({"distribution_shift"} if shift is None else set()) | ({"cost"} if pricing is None else set()):
            if absent in metrics:
                failures.append(f"metrics {absent} exists without reconstructible evidence")
        expected_gates = apply_gates(suite, reconstructed, categories)
        if metrics.get("gate_failures") != expected_gates:
            failures.append("gate results do not reconcile with reconstructed behavior evidence")
        expected_status = (
            "passed"
            if not manifest.get("abort_reason") and metrics.get("officially_valid") is True and not expected_gates
            else "failed"
        )
        if manifest.get("status") != expected_status:
            failures.append("manifest status does not reconcile with reconstructed behavior evidence")
        expected_official = manifest.get("official_requested") is True and expected_status == "passed"
        if manifest.get("official") is not expected_official:
            failures.append("manifest official result does not reconcile with requested assurance and reconstructed status")
        from .reporting import generate_reports

        with TemporaryDirectory(prefix="cavada-behavior-reports-") as report_root_text:
            report_root = Path(report_root_text)
            write_category_csv(report_root / "category_results.csv", categories)
            generated_reports = generate_reports(report_root, manifest, metrics, categories, results)
            for name in ["category_results.csv", *generated_reports]:
                try:
                    declared = _read_regular(run_dir, Path(name))
                    reconstructed_report = _read_regular(report_root, Path(name))
                except OSError:
                    failures.append(f"derived report is missing or unsafe: {name}")
                    continue
                if declared != reconstructed_report:
                    failures.append(f"derived report does not reconstruct from behavior evidence: {name}")
        failures.extend(_ledger_errors(suite, manifest, run_dir))
        expected_failures = [row for row in results if row.get("status") != "pass"]
        actual_failures = _jsonl(run_dir / "failures.jsonl")
        def canonical(row: dict[str, Any]) -> str:
            return json.dumps(row, sort_keys=True, separators=(",", ":"))

        if sorted(map(canonical, actual_failures)) != sorted(map(canonical, expected_failures)):
            failures.append("failure ledger does not reconcile with case_results.jsonl")
        expected_adjudication = [
            row for row in results if row.get("status") == "invalid" and row.get("severity") == "critical"
        ]
        if _jsonl(run_dir / "adjudication_queue.jsonl") != expected_adjudication:
            failures.append("adjudication queue does not reconcile with critical invalid case results")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, ProtocolError, ValueError, TypeError) as exc:
        failures.append(f"behavior semantic reconstruction failed: {exc}")
    finally:
        if suite_temporary is not None:
            suite_temporary.cleanup()
    return list(dict.fromkeys(failures)), list(dict.fromkeys(assurance_failures))


def _recognized_behavior_manifest(manifest: dict[str, Any]) -> bool:
    return "official" in manifest or "official_requested" in manifest or {"suite", "target", "judge"} <= set(manifest)


def _verify_behavior_snapshot(
    run_dir: Path,
    *,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    now: datetime | None = None,
    assurance_checks: bool,
) -> dict[str, Any]:
    verify_hmac = bool(os.environ.get(signing_key_env))
    try:
        integrity = verify_bundle(run_dir, signing_key_env=signing_key_env, verify_hmac=verify_hmac)
    except ProtocolError as exc:
        integrity = {"valid": False, "failures": [str(exc)], "signature": "unavailable", "files": 0}
    if integrity.get("signature") == "valid":
        # HMAC is an internal integrity check, not a publicly verifiable signature.
        # Keep the serialized verification result stable when the local key is absent.
        integrity["signature"] = "unverified"
    integrity_failures = list(map(str, integrity["failures"]))
    artifact_type = "unsupported"
    semantic_valid: bool | None = None
    assurance_valid: bool | None = None
    semantic_failures: list[str] = []
    assurance_failures: list[str] = []
    assurance_level: Any = None
    model_claim_allowed: Any = None
    benchmark_claim_allowed: Any = None
    claim_scope: list[str] = []
    if not integrity_failures:
        try:
            manifest = _object(run_dir / "manifest.json", "run manifest")
            if _recognized_behavior_manifest(manifest):
                artifact_type = "behavior-run"
                assurance_level = manifest.get("assurance")
                model_claim_allowed = manifest.get("model_claim_allowed")
                benchmark_claim_allowed = manifest.get("benchmark_claim_allowed")
                engagement = manifest.get("engagement")
                permitted = engagement.get("permitted_claims") if isinstance(engagement, dict) else None
                if (model_claim_allowed is True or benchmark_claim_allowed is True) and isinstance(permitted, list):
                    claim_scope = [value for value in permitted if isinstance(value, str)]
                bundle = _object(run_dir / "bundle.json", "run bundle")
                semantic_failures, assurance_failures = _behavior_errors(
                    run_dir,
                    manifest,
                    bundle,
                    now or datetime.now(timezone.utc),
                    assurance_checks=assurance_checks,
                )
                semantic_valid = not semantic_failures
                assurance_valid = not assurance_failures if assurance_checks else None
            else:
                semantic_failures = ["unsupported artifact type: manifest is not a recognized behavior run"]
        except (OSError, ProtocolError, TypeError, ValueError) as exc:
            semantic_failures = [str(exc)]
            semantic_valid = False
            assurance_valid = False if assurance_checks else None
    failures = [*integrity_failures, *semantic_failures, *assurance_failures]
    valid = not integrity_failures and semantic_valid is True and (assurance_valid is True or not assurance_checks)
    result = {
        **integrity,
        "verification_result_version": VERIFICATION_RESULT_VERSION,
        "artifact_type": artifact_type,
        "valid": valid,
        "failures": failures,
        "integrity_valid": integrity["valid"],
        "semantic_valid": semantic_valid,
        "assurance_valid": assurance_valid,
        "integrity_failures": integrity_failures,
        "semantic_failures": semantic_failures,
        "assurance_failures": assurance_failures,
        "semantic": {"required": artifact_type == "behavior-run", "valid": semantic_valid, "failures": semantic_failures},
        "assurance": assurance_level,
        "assurance_level": assurance_level,
        "claim_scope": claim_scope,
        # Public-release approval does not authorize ranking. M1 keeps every
        # behavior run non-rankable until a separate ranking policy exists.
        "rankable": False,
        "model_claim_allowed": model_claim_allowed,
        "benchmark_claim_allowed": benchmark_claim_allowed,
    }
    return result


def _integrity_failure_result(failure: str) -> dict[str, Any]:
    return {
        "valid": False,
        "failures": [failure],
        "signature": "unavailable",
        "files": 0,
        "bundle_sha256": None,
        "verification_result_version": VERIFICATION_RESULT_VERSION,
        "artifact_type": "unsupported",
        "integrity_valid": False,
        "semantic_valid": None,
        "assurance_valid": None,
        "integrity_failures": [failure],
        "semantic_failures": [],
        "assurance_failures": [],
        "semantic": {"required": False, "valid": None, "failures": []},
        "assurance": None,
        "assurance_level": None,
        "claim_scope": [],
        "rankable": False,
        "model_claim_allowed": None,
        "benchmark_claim_allowed": None,
    }


def _verify_behavior(
    run_dir: Path,
    *,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    write_result: bool = False,
    now: datetime | None = None,
    assurance_checks: bool,
) -> dict[str, Any]:
    """Verify semantics only against one hash-bound snapshot of the whole bundle."""
    verify_hmac = bool(os.environ.get(signing_key_env))
    try:
        snapshot = snapshot_bundle_files(run_dir, signing_key_env=signing_key_env, verify_hmac=verify_hmac)
    except ProtocolError as exc:
        result = _integrity_failure_result(str(exc))
    else:
        with TemporaryDirectory(prefix="cavada-behavior-snapshot-") as temporary:
            snapshot_root = Path(temporary)
            for relative, raw in snapshot.items():
                destination = snapshot_root / Path(relative)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
            result = _verify_behavior_snapshot(
                snapshot_root,
                signing_key_env=signing_key_env,
                now=now,
                assurance_checks=assurance_checks,
            )
        result["bundle_sha256"] = sha256_bytes(snapshot["bundle.json"])
        if write_result:
            try:
                current = snapshot_bundle_files(run_dir, signing_key_env=signing_key_env, verify_hmac=verify_hmac)
            except ProtocolError as exc:
                changed = f"behavior bundle changed before verification result write: {exc}"
            else:
                changed = "" if current == snapshot else "behavior bundle changed before verification result write"
            if changed:
                result["valid"] = False
                result["integrity_valid"] = False
                result["integrity_failures"] = [*result["integrity_failures"], changed]
                result["failures"] = [*result["failures"], changed]
    if write_result:
        atomic_json(run_dir / "verification.json", result)
    return result


def verify_behavior_base(run_dir: Path, now: datetime) -> dict[str, Any]:
    """Verify integrity and base semantics without recursively applying assurance policy."""
    return _verify_behavior(run_dir, now=now, assurance_checks=False)


def verify_behavior_run(
    run_dir: Path,
    *,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    write_result: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify behavior bundle integrity, reconstructed semantics, and declared assurance."""
    return _verify_behavior(
        run_dir,
        signing_key_env=signing_key_env,
        write_result=write_result,
        now=now,
        assurance_checks=True,
    )
