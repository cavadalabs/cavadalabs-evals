from __future__ import annotations

import csv
import json
import math
import random
import re
import shutil
import tempfile
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, cast

from .artifacts import verify_bundle
from .performance import (
    PERFORMANCE_PROTOCOL_VERSION,
    PERFORMANCE_RUNTIME_VERSION,
    SUPPORTED_PERFORMANCE_PROTOCOL_VERSIONS,
    PerformanceRuntime,
    _campaign_summary,
    _cell_metrics_for_protocol,
    _content_addressed_revision,
    _expand_cells,
    _finite_json,
    _measured_request_count,
    _measurement_window,
    _open_loop_offsets,
    _performance_reports,
    _require_official_reference_inputs,
    _write_cells_csv,
    canonical_performance_protocol_path,
    load_performance_plan,
)
from .performance_release import (
    _PERFORMANCE_PLAN_REPORT_VERSIONS,
    PERMITTED_CLAIM,
    _performance_publication_version,
    _public_cells,
    _public_observations,
    _public_presentation_manifest,
)
from .protocol import PROTOCOL_VERSION, REPORT_VERSION, ProtocolError, contains_secret_like, sha256_bytes, sha256_file, wilson_interval
from .release import _PROHIBITED_CLAIM_FRAGMENTS, _usable, official_revision
from .system_evidence import load_system_evidence, public_system_evidence

_HASH = re.compile(r"[a-f0-9]{64}")
_USER_PATH = re.compile(r"(?:/Users/|/home/|[A-Za-z]:[\\/]Users[\\/])")
_BUNDLE_METADATA = {"bundle.json", "checksums.txt", "signature.json"}
_TEXT_SUFFIXES = {".csv", ".html", ".json", ".jsonl", ".md", ".pdf", ".svg", ".toml", ".txt"}
_BEHAVIOR_PUBLIC_FILES = {
    "report_public.html",
    "report_public.pdf",
    "summary.json",
    "category_results.csv",
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
_BEHAVIOR_RELEASE_FIELDS = {
    "release_version",
    "release_id",
    "run_id",
    "bundle_sha256",
    "manifest_sha256",
    "engagement_id",
    "engagement_sha256",
    "approval_sha256",
    "assurance_level",
    "permitted_claims",
    "decision_statuses",
    "evaluation_started_at",
    "evaluation_finished_at",
    "approved_at",
    "expires_at",
    "public_files",
}
_DECISIONS = {"statistical", "security", "privacy_legal", "disclosure", "release"}
_CATEGORY_FIELDS = ("category", "total", "pass", "fail", "invalid", "error", "pass_rate", "ci95_lower", "ci95_upper", "confidence")
_CATEGORY_SUMMARY_FIELDS = {
    "category",
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
    "ci95_lower",
    "ci95_upper",
    "confidence",
}
_BEHAVIOR_SUMMARY_FIELDS = {
    "protocol_version",
    "report_version",
    "run_id",
    "status",
    "suite",
    "target",
    "metrics",
    "categories",
    "gates",
    "limitations",
}
_BEHAVIOR_CORE_METRICS = {
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
    "gate_failures",
    "aborted",
}
_PERFORMANCE_FIELDS = {
    "publication_version",
    "performance_protocol_version",
    "protocol_sha256",
    "run_id",
    "evaluation_started_at",
    "evaluation_finished_at",
    "status",
    "assurance",
    "official",
    "source_manifest_sha256",
    "source_bundle_sha256",
    "plan",
    "workload",
    "runtime",
    "system_evidence",
    "source",
    "cells",
    "warmups",
    "request_reconciliation",
    "token_usage",
    "estimated_cost",
    "release",
    "limitations",
}
_PERFORMANCE_CORE_FILES = {
    "public_manifest.json",
    "summary.json",
    "cells.jsonl",
    "cells.csv",
    "observations.jsonl",
    "protocol_snapshot.md",
    "plan.toml",
    "workload.jsonl",
}
_PERFORMANCE_REPORT_ROOTS = {"report.html", "report.pdf"}
_PLAN_FIELDS = {"name", "revision", "sha256", "profile", "data_classification"}
_PLAN_OPTIONAL_FIELDS = {"open_loop_arrival_distribution", "execution_seed", "minimum_p99_observations", "load_generator"}
_WORKLOAD_FIELDS = {"id", "revision", "mode", "sha256", "asset_set_sha256", "assets", "cases"}
_RUNTIME_FIELDS = {
    "runtime_version",
    "id",
    "request_model",
    "expected_model",
    "model_revision",
    "engine",
    "engine_revision",
    "model_artifact_revision",
    "dtype",
    "quantization",
    "gpu_count",
    "gpu_model",
    "tensor_parallel",
    "max_context_tokens",
    "launch_command_sanitized",
    "pricing",
    "sha256",
}
_RECONCILIATION_FIELDS = {
    "planned",
    "scheduled",
    "accepted",
    "responses",
    "warmup_outcomes",
    "measured_outcomes",
    "terminal_outcomes",
    "ledgers_complete",
    "campaign_complete",
}
_PERFORMANCE_RELEASE_FIELDS = {
    "release_version",
    "release_id",
    "approval_sha256",
    "approver_id",
    "engagement_id",
    "engagement_sha256",
    "permitted_claims",
    "approved_at",
    "expires_at",
}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ProtocolError(f"public bundle is missing a regular {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"invalid public {label}") from exc
    if not isinstance(value, dict) or not _finite_json(value):
        raise ProtocolError(f"public {label} must be a finite JSON object")
    return cast(dict[str, Any], value)


def _read_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        raise ProtocolError(f"public bundle is missing a regular {path.name}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        if any(not line.strip() for line in lines):
            raise ValueError("blank JSONL line")
        rows = [json.loads(line, object_pairs_hook=_pairs, parse_constant=_constant) for line in lines]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"invalid public {label}") from exc
    if any(not isinstance(row, dict) or not _finite_json(row) for row in rows):
        raise ProtocolError(f"public {label} must contain finite JSON objects")
    return cast(list[dict[str, Any]], rows)


def _object(value: Any, fields: set[str], label: str, *, optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or not fields <= set(value) or set(value) - fields - (optional or set()):
        raise ProtocolError(f"public {label} has an invalid shape")
    return cast(dict[str, Any], value)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(f"public {label} must be non-empty text")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise ProtocolError(f"public {label} must be a lowercase SHA-256")
    return value


def _time(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(_text(value, label).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(f"public {label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ProtocolError(f"public {label} must include a timezone")
    return parsed


def _nonnegative(value: Any, label: str, *, integer: bool = False) -> float:
    valid_type = isinstance(value, int) if integer else isinstance(value, (int, float))
    if not valid_type or isinstance(value, bool) or not math.isfinite(float(value)) or value < 0:
        raise ProtocolError(f"public {label} must be a non-negative {'integer' if integer else 'number'}")
    return float(value)


def _content_files(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and path.relative_to(root).as_posix() not in _BUNDLE_METADATA
    }


def _reject_restricted_text(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or path.suffix.casefold() not in _TEXT_SUFFIXES:
            continue
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8", errors="ignore" if path.suffix.casefold() == ".pdf" else "strict")
        except (OSError, UnicodeDecodeError) as exc:
            raise ProtocolError(f"public textual artifact is not valid UTF-8: {path.relative_to(root)}") from exc
        if contains_secret_like(text) or _USER_PATH.search(text):
            raise ProtocolError(f"public textual artifact contains restricted evidence: {path.relative_to(root)}")


def _cross_check_public_system_evidence(runtime: dict[str, Any], source: dict[str, Any], evidence: dict[str, Any]) -> None:
    software = cast(dict[str, Any], evidence["software"])
    engine = cast(dict[str, Any], software["engine"])
    model = cast(dict[str, Any], software["model"])
    serving = cast(dict[str, Any], evidence["serving"])
    expected = {
        "software.engine.name": runtime["engine"],
        "software.engine.revision": runtime["engine_revision"],
        "software.model.name": runtime["expected_model"],
        "software.model.revision": runtime["model_revision"],
        "software.model.artifact_sha256": runtime["model_artifact_revision"],
        "serving.tensor_parallel": runtime["tensor_parallel"],
        "serving.max_context_tokens": runtime["max_context_tokens"],
        "serving.launch_command_sanitized": runtime["launch_command_sanitized"],
    }
    actual = {
        "software.engine.name": engine["name"],
        "software.engine.revision": engine["revision"],
        "software.model.name": model["name"],
        "software.model.revision": model["revision"],
        "software.model.artifact_sha256": model["artifact_sha256"],
        "serving.tensor_parallel": serving["tensor_parallel"],
        "serving.max_context_tokens": serving["max_context_tokens"],
        "serving.launch_command_sanitized": serving["launch_command_sanitized"],
    }
    mismatches = [path for path, value in expected.items() if actual[path] != value]
    for path, runtime_value, evidence_value in (
        ("software.model.dtype", runtime["dtype"], model["dtype"]),
        ("software.model.quantization", runtime["quantization"], model["quantization"]),
    ):
        if str(runtime_value).casefold() != str(evidence_value).casefold():
            mismatches.append(path)
    runtime_digest = runtime.get("container_image_digest")
    evidence_digest = engine["container_image_digest"]
    if (runtime_digest and evidence_digest != runtime_digest) or (not runtime_digest and evidence_digest is not None):
        mismatches.append("software.engine.container_image_digest")
    client = cast(dict[str, Any], evidence["load_generator"])["client"]
    if client.get("name") != "cavadalabs-evals" or source.get("commit") and client.get("revision") != source.get("commit"):
        mismatches.append("load_generator.client")
    accelerators = cast(dict[str, Any], evidence["server"])["accelerators"]
    if not isinstance(accelerators, list):
        mismatches.append("server.accelerators unavailable")
    else:
        if len(accelerators) != runtime["gpu_count"]:
            mismatches.append("server.accelerators count")
        if any(not isinstance(item, dict) or item.get("model") != runtime["gpu_model"] for item in accelerators):
            mismatches.append("server.accelerators model")
    if mismatches:
        raise ProtocolError(f"public system evidence differs from performance runtime: {sorted(mismatches)}")


def _rate(value: Any, label: str) -> float:
    number = _nonnegative(value, label)
    if number > 1:
        raise ProtocolError(f"public {label} must be between zero and one")
    return number


def _interval(value: Any, lower: float, upper: float, confidence: float, label: str) -> None:
    interval = _object(value, {"lower", "upper", "confidence"}, label)
    if (
        _rate(interval.get("lower"), f"{label} lower") != lower
        or _rate(interval.get("upper"), f"{label} upper") != upper
        or _rate(interval.get("confidence"), f"{label} confidence") != confidence
    ):
        raise ProtocolError(f"public {label} does not reconcile")


def _ci95(value: Any, lower: float, upper: float, confidence: float, label: str) -> None:
    if confidence != 0.95:
        if value is not None:
            raise ProtocolError(f"public {label} must be null outside 95% confidence")
        return
    interval = _object(value, {"lower", "upper"}, label)
    if _rate(interval.get("lower"), f"{label} lower") != lower or _rate(interval.get("upper"), f"{label} upper") != upper:
        raise ProtocolError(f"public {label} does not reconcile")


def _category_totals(categories: Any, label: str) -> tuple[dict[str, int], float]:
    if not isinstance(categories, list) or not categories:
        raise ProtocolError(f"public {label} must be a non-empty array")
    totals = {field: 0 for field in ("total", "observations", "pass", "fail", "invalid", "error", "skipped")}
    names: set[str] = set()
    ordered_names: list[str] = []
    confidence: float | None = None
    for index, value in enumerate(categories, 1):
        row = _object(value, _CATEGORY_SUMMARY_FIELDS, f"{label} row {index}")
        name = _text(row.get("category"), f"{label} row {index} category")
        if name in names:
            raise ProtocolError(f"public {label} contains duplicate categories")
        names.add(name)
        ordered_names.append(name)
        counts: dict[str, int] = {}
        for field in totals:
            _nonnegative(row.get(field), f"{label} {name} {field}", integer=True)
            counts[field] = cast(int, row[field])
            totals[field] += counts[field]
        if counts["total"] != sum(counts[field] for field in ("pass", "fail", "invalid", "error", "skipped")):
            raise ProtocolError(f"public {label} {name} status counts do not reconcile")
        if counts["observations"] < counts["total"]:
            raise ProtocolError(f"public {label} {name} observations are below its analysis units")
        row_confidence = _rate(row.get("confidence"), f"{label} {name} confidence")
        if row_confidence in {0.0, 1.0} or confidence is not None and row_confidence != confidence:
            raise ProtocolError(f"public {label} confidence is invalid or inconsistent")
        confidence = row_confidence
        judged = counts["pass"] + counts["fail"]
        expected_rate = counts["pass"] / judged if judged else 0.0
        lower, upper = wilson_interval(counts["pass"], judged, row_confidence)
        if _rate(row.get("pass_rate"), f"{label} {name} pass_rate") != expected_rate:
            raise ProtocolError(f"public {label} {name} pass rate does not reconcile")
        _interval(row.get("pass_rate_ci"), lower, upper, row_confidence, f"{label} {name} pass_rate_ci")
        _ci95(row.get("pass_rate_ci95"), lower, upper, row_confidence, f"{label} {name} pass_rate_ci95")
        if _rate(row.get("ci95_lower"), f"{label} {name} ci95_lower") != lower or _rate(row.get("ci95_upper"), f"{label} {name} ci95_upper") != upper:
            raise ProtocolError(f"public {label} {name} confidence intervals do not reconcile")
    if ordered_names != sorted(ordered_names):
        raise ProtocolError(f"public {label} categories are not in canonical order")
    return totals, cast(float, confidence)


def _behavior_metrics(metrics: Any, categories: Any, *, status: Any) -> None:
    if not isinstance(metrics, dict) or not _BEHAVIOR_CORE_METRICS <= set(metrics) or not _finite_json(metrics):
        raise ProtocolError("public behavior summary metrics are malformed")
    totals, confidence = _category_totals(categories, "behavior categories")
    for field, expected in totals.items():
        _nonnegative(metrics.get(field), f"behavior metrics {field}", integer=True)
        if metrics.get(field) != expected:
            raise ProtocolError(f"public behavior metrics {field} does not reconcile with categories")
    judged = totals["pass"] + totals["fail"]
    expected_rate = totals["pass"] / judged if judged else 0.0
    lower, upper = wilson_interval(totals["pass"], judged, confidence)
    if _rate(metrics.get("pass_rate"), "behavior metrics pass_rate") != expected_rate:
        raise ProtocolError("public behavior metrics pass_rate does not reconcile with categories")
    _interval(metrics.get("pass_rate_ci"), lower, upper, confidence, "behavior metrics pass_rate_ci")
    _ci95(metrics.get("pass_rate_ci95"), lower, upper, confidence, "behavior metrics pass_rate_ci95")
    officially_valid = totals["invalid"] == totals["error"] == totals["skipped"] == 0
    if metrics.get("officially_valid") is not officially_valid:
        raise ProtocolError("public behavior officially_valid does not reconcile with categories")
    for field in ("evaluation_cases", "target_observations"):
        _nonnegative(metrics.get(field), f"behavior metrics {field}", integer=True)
    analysis_unit = metrics.get("analysis_unit")
    expected_fields = _BEHAVIOR_CORE_METRICS | ({"case_level", "case_categories"} if analysis_unit == "scenario" else set())
    if set(metrics) != expected_fields:
        raise ProtocolError("public behavior metrics differ from the exact reconstructible projection")
    if analysis_unit == "case":
        if metrics.get("evaluation_cases") != totals["total"] or metrics.get("target_observations") != totals["observations"]:
            raise ProtocolError("public behavior case counts do not reconcile with categories")
        if "case_level" in metrics or "case_categories" in metrics:
            raise ProtocolError("public behavior case analysis contains unexpected scenario projections")
    elif analysis_unit == "scenario":
        case_metrics = metrics.get("case_level")
        case_categories = metrics.get("case_categories")
        if not isinstance(case_metrics, dict):
            raise ProtocolError("public behavior scenario analysis lacks case metrics")
        case_totals, case_confidence = _category_totals(case_categories, "behavior case categories")
        case_judged = case_totals["pass"] + case_totals["fail"]
        case_lower, case_upper = wilson_interval(case_totals["pass"], case_judged, case_confidence)
        expected_case = {
            **case_totals,
            "pass_rate": case_totals["pass"] / case_judged if case_judged else 0.0,
            "pass_rate_ci": {"lower": case_lower, "upper": case_upper, "confidence": case_confidence},
            "pass_rate_ci95": {"lower": case_lower, "upper": case_upper} if case_confidence == 0.95 else None,
            "officially_valid": case_totals["invalid"] == case_totals["error"] == case_totals["skipped"] == 0,
        }
        if set(case_metrics) != set(expected_case):
            raise ProtocolError("public behavior case metrics have an invalid shape")
        for field in case_totals:
            _nonnegative(case_metrics.get(field), f"behavior case metrics {field}", integer=True)
        _rate(case_metrics.get("pass_rate"), "behavior case metrics pass_rate")
        _interval(case_metrics.get("pass_rate_ci"), case_lower, case_upper, case_confidence, "behavior case metrics pass_rate_ci")
        _ci95(case_metrics.get("pass_rate_ci95"), case_lower, case_upper, case_confidence, "behavior case metrics pass_rate_ci95")
        if not isinstance(case_metrics.get("officially_valid"), bool):
            raise ProtocolError("public behavior case officially_valid must be boolean")
        if case_metrics != expected_case:
            raise ProtocolError("public behavior case metrics do not reconcile with case categories")
        if metrics.get("evaluation_cases") != case_totals["total"] or metrics.get("target_observations") != case_totals["observations"]:
            raise ProtocolError("public behavior scenario case counts do not reconcile")
    else:
        raise ProtocolError("public behavior analysis_unit is unsupported")
    if metrics.get("gate_failures") != [] or metrics.get("aborted") is not False:
        raise ProtocolError("public behavior passed release contains gate failures or an abort")
    if status != "passed" or not officially_valid:
        raise ProtocolError("public behavior status is incoherent with its metrics")


def _behavior_gates(gates: Any, metrics: dict[str, Any], categories: list[dict[str, Any]]) -> None:
    if not isinstance(gates, list) or not gates:
        raise ProtocolError("public behavior summary must preserve its preregistered gates")
    by_category = {row["category"]: row for row in categories}
    for index, value in enumerate(gates, 1):
        gate = _object(value, {"category", "metric", "min", "confidence"}, f"behavior gate {index}")
        category = gate.get("category")
        if category is not None and (not isinstance(category, str) or category not in by_category):
            raise ProtocolError(f"public behavior gate {index} has an unknown category")
        metric = gate.get("metric")
        if metric not in {"pass_rate_ci.lower", "pass_rate_ci95.lower"}:
            raise ProtocolError(f"public behavior gate {index} is not a confidence-interval lower-bound gate")
        source = by_category[category] if isinstance(category, str) else metrics
        actual: Any = source
        for part in str(metric).split("."):
            actual = actual.get(part) if isinstance(actual, dict) else None
        minimum = _rate(gate.get("min"), f"behavior gate {index} minimum")
        confidence = _rate(gate.get("confidence"), f"behavior gate {index} confidence")
        expected_confidence = cast(dict[str, Any], source["pass_rate_ci"])["confidence"]
        if confidence != expected_confidence or metric == "pass_rate_ci95.lower" and confidence != 0.95:
            raise ProtocolError(f"public behavior gate {index} confidence differs from its result")
        if not isinstance(actual, (int, float)) or isinstance(actual, bool) or float(actual) < minimum:
            raise ProtocolError(f"public behavior gate {index} failed its preregistered threshold")


def _behavior(root: Path) -> str:
    release = _read_json(root / "public_release.json", "behavior release")
    if set(release) != _BEHAVIOR_RELEASE_FIELDS:
        raise ProtocolError("public behavior release has an invalid shape")
    for field in ("release_id", "run_id", "engagement_id"):
        _text(release.get(field), f"behavior release {field}")
    for field in ("bundle_sha256", "manifest_sha256", "engagement_sha256", "approval_sha256"):
        _digest(release.get(field), f"behavior release {field}")
    if release.get("release_version") != "1.0.0" or release.get("assurance_level") != "approved":
        raise ProtocolError("public behavior release is not an approved version 1.0.0 projection")
    claims = release.get("permitted_claims")
    if not isinstance(claims, list) or not claims or any(not isinstance(item, str) or not item.strip() for item in claims) or len(set(claims)) != len(claims):
        raise ProtocolError("public behavior release claims are malformed")
    if any(fragment in claim.casefold() for claim in claims for fragment in _PROHIBITED_CLAIM_FRAGMENTS):
        raise ProtocolError("public behavior release contains an unsupported certification, legal, or universal claim")
    decisions = _object(release.get("decision_statuses"), _DECISIONS, "behavior decision statuses")
    if any(value not in ({"passed", "not-applicable"} if name == "privacy_legal" else {"passed"}) for name, value in decisions.items()):
        raise ProtocolError("public behavior release decisions are not approved")
    started_at = _time(release.get("evaluation_started_at"), "behavior release evaluation_started_at")
    finished_at = _time(release.get("evaluation_finished_at"), "behavior release evaluation_finished_at")
    approved_at = _time(release.get("approved_at"), "behavior release approved_at")
    now = datetime.now(timezone.utc)
    if not started_at <= finished_at <= approved_at <= now < _time(release.get("expires_at"), "behavior release expires_at"):
        raise ProtocolError("public behavior release is not currently effective")

    public_files = release.get("public_files")
    if not isinstance(public_files, dict) or not public_files:
        raise ProtocolError("public behavior release file projection is malformed")
    payload_files = _content_files(root) - {"public_release.json"}
    if set(public_files) != payload_files or not payload_files <= _BEHAVIOR_PUBLIC_FILES:
        raise ProtocolError("public behavior release file projection differs from its exact allowlisted payload")
    if not {"summary.json", "category_results.csv", "report_public.html", "report_public.pdf"} <= payload_files:
        raise ProtocolError("public behavior release is missing required public reports")
    for relative, expected in public_files.items():
        if _digest(expected, f"behavior public file {relative}") != sha256_file(root / str(relative)):
            raise ProtocolError(f"public behavior release hash mismatch: {relative}")

    summary = _read_json(root / "summary.json", "behavior summary")
    if set(summary) != _BEHAVIOR_SUMMARY_FIELDS:
        raise ProtocolError("public behavior summary has an invalid top-level contract")
    if summary.get("run_id") != release["run_id"] or summary.get("status") != "passed":
        raise ProtocolError("public behavior summary differs from its release identity or status")
    if summary.get("protocol_version") != PROTOCOL_VERSION or summary.get("report_version") != REPORT_VERSION:
        raise ProtocolError("public behavior summary uses unsupported protocol or report versions")
    suite = _object(
        summary.get("suite"),
        {"name", "version", "status", "dataset_sha256", "rubric_sha256", "suite_config_sha256", "data_classification", "profile"},
        "behavior suite",
    )
    for field in ("name", "version", "status", "data_classification", "profile"):
        _text(suite.get(field), f"behavior suite {field}")
    for field in ("dataset_sha256", "rubric_sha256", "suite_config_sha256"):
        _digest(suite.get(field), f"behavior suite {field}")
    if suite.get("status") != "approved":
        raise ProtocolError("public behavior suite is not approved")
    target = _object(summary.get("target"), {"label", "revision"}, "behavior target")
    if not _usable(target.get("label")):
        raise ProtocolError("public behavior target label is missing or a placeholder")
    official_revision(target.get("revision"), "public behavior target")
    limitations = summary.get("limitations")
    if (
        not isinstance(limitations, list)
        or not limitations
        or any(not isinstance(item, str) or not item.strip() for item in limitations)
        or len(set(limitations)) != len(limitations)
    ):
        raise ProtocolError("public behavior limitations must be a non-empty unique text array")
    categories = summary.get("categories")
    _behavior_metrics(summary.get("metrics"), categories, status=summary.get("status"))
    category_rows = cast(list[dict[str, Any]], categories)
    _behavior_gates(summary.get("gates"), cast(dict[str, Any], summary["metrics"]), category_rows)
    try:
        with (root / "category_results.csv").open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
            header = tuple(reader.fieldnames or ())
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise ProtocolError("invalid public behavior category CSV") from exc
    expected_rows = [{field: "" if row.get(field) is None else str(row.get(field)) for field in _CATEGORY_FIELDS} for row in category_rows]
    if header != _CATEGORY_FIELDS or rows != expected_rows:
        raise ProtocolError("public behavior category CSV differs from summary categories")
    return "approved"


def _staged_plan(root: Path, manifest: dict[str, Any]) -> tuple[Any, list[dict[str, Any]]]:
    plan_path = root / "plan.toml"
    workload_path = root / "workload.jsonl"
    try:
        plan_config = tomllib.loads(plan_path.read_text(encoding="utf-8"))
        relative = plan_config["workload"]["path"]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ProtocolError("invalid public performance plan") from exc
    candidate = Path(str(relative))
    windows_candidate = PureWindowsPath(str(relative))
    if candidate.is_absolute() or windows_candidate.drive or windows_candidate.is_absolute():
        raise ProtocolError("public performance plan workload path is unsafe")
    with tempfile.TemporaryDirectory(prefix="cavada-public-plan-") as temporary:
        package = Path(temporary) / "performance"
        staged_plan = package / "plans" / "plan.toml"
        staged_workload = (staged_plan.parent / candidate).resolve()
        if not staged_workload.is_relative_to(package.resolve()):
            raise ProtocolError("public performance plan workload path escapes its package")
        staged_plan.parent.mkdir(parents=True)
        staged_workload.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(plan_path, staged_plan)
        shutil.copyfile(workload_path, staged_workload)
        assets = _object(manifest.get("workload"), _WORKLOAD_FIELDS, "performance workload", optional={"prefix_cache_policy"}).get("assets")
        if not isinstance(assets, dict):
            raise ProtocolError("public performance workload assets are malformed")
        for relative_asset in assets:
            destination = (staged_workload.parent / str(relative_asset)).resolve()
            if not destination.is_relative_to(package.resolve()):
                raise ProtocolError("public performance workload asset path escapes its package")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / "workload_assets" / str(relative_asset), destination)
        plan = load_performance_plan(staged_plan)
        rows = [dict(row) for row in plan.workload]
    return plan, rows


def _performance_release(value: Any, publication_version: str, *, effective_at: datetime | None = None) -> dict[str, Any]:
    release = _object(value, _PERFORMANCE_RELEASE_FIELDS, "performance release")
    if release.get("release_version") != publication_version:
        raise ProtocolError("public performance release version is unsupported")
    for field in ("release_id", "approver_id", "engagement_id"):
        _text(release.get(field), f"performance release {field}")
    _digest(release.get("approval_sha256"), "performance release approval_sha256")
    _digest(release.get("engagement_sha256"), "performance release engagement_sha256")
    if release.get("permitted_claims") != [PERMITTED_CLAIM]:
        raise ProtocolError("public performance release claim is unsupported")
    instant = effective_at or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ProtocolError("public performance release verification time must include a timezone")
    if not _time(release.get("approved_at"), "performance release approved_at") <= instant < _time(
        release.get("expires_at"), "performance release expires_at"
    ):
        raise ProtocolError("public performance release is not currently effective")
    return release


def _performance(root: Path, *, effective_at: datetime | None = None) -> str:
    manifest = _read_json(root / "public_manifest.json", "performance manifest")
    if set(manifest) != _PERFORMANCE_FIELDS or not _finite_json(manifest):
        raise ProtocolError("public performance manifest has an invalid top-level contract")
    protocol_version = str(manifest.get("performance_protocol_version"))
    publication_version = _performance_publication_version(protocol_version)
    if (
        manifest.get("publication_version") != publication_version
        or protocol_version not in SUPPORTED_PERFORMANCE_PROTOCOL_VERSIONS
        or manifest.get("status") not in {"completed", "completed-with-errors", "invalid-loadgen"}
        or not isinstance(manifest.get("official"), bool)
    ):
        raise ProtocolError("public performance publication versions or status are invalid")
    _text(manifest.get("run_id"), "performance run_id")
    evaluation_started_at = _time(manifest.get("evaluation_started_at"), "performance evaluation_started_at")
    evaluation_finished_at = _time(manifest.get("evaluation_finished_at"), "performance evaluation_finished_at")
    if evaluation_started_at > evaluation_finished_at:
        raise ProtocolError("public performance evaluation timestamps are out of order")
    for field in ("protocol_sha256", "source_manifest_sha256", "source_bundle_sha256"):
        _digest(manifest.get(field), f"performance {field}")

    plan_metadata = _object(manifest.get("plan"), _PLAN_FIELDS, "performance plan", optional=_PLAN_OPTIONAL_FIELDS)
    workload_metadata = _object(manifest.get("workload"), _WORKLOAD_FIELDS, "performance workload", optional={"prefix_cache_policy"})
    runtime = _object(manifest.get("runtime"), _RUNTIME_FIELDS, "performance runtime", optional={"container_image_digest"})
    source = _object(manifest.get("source"), {"commit", "dirty", "status_sha256"}, "performance source")
    _digest(source.get("status_sha256"), "performance source status_sha256")
    if not isinstance(source.get("commit"), str) or not isinstance(source.get("dirty"), bool):
        raise ProtocolError("public performance source identity is malformed")
    for field in ("sha256",):
        _digest(plan_metadata.get(field), f"performance plan {field}")
        _digest(workload_metadata.get(field), f"performance workload {field}")
        _digest(runtime.get(field), f"performance runtime {field}")
    _digest(workload_metadata.get("asset_set_sha256"), "performance workload asset_set_sha256")
    _digest(runtime.get("model_artifact_revision"), "performance runtime model_artifact_revision")
    if runtime.get("runtime_version") != PERFORMANCE_RUNTIME_VERSION:
        raise ProtocolError("public performance runtime version is unsupported")
    for field in (
        "id",
        "request_model",
        "expected_model",
        "model_revision",
        "engine",
        "engine_revision",
        "dtype",
        "quantization",
        "gpu_model",
        "launch_command_sanitized",
    ):
        _text(runtime.get(field), f"performance runtime {field}")
    runtime_id = cast(str, runtime["id"])
    if re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", runtime_id) is None:
        raise ProtocolError("public performance runtime id is malformed")
    if any(
        marker in cast(str, runtime[field]).casefold()
        for field in ("model_revision", "engine_revision", "gpu_model")
        for marker in ("replace-with", "todo", "unknown")
    ):
        raise ProtocolError("public performance runtime contains placeholder identity evidence")
    for field in ("gpu_count", "tensor_parallel", "max_context_tokens"):
        if _nonnegative(runtime.get(field), f"performance runtime {field}", integer=True) < 1:
            raise ProtocolError(f"public performance runtime {field} must be positive")
    if cast(int, runtime["tensor_parallel"]) > cast(int, runtime["gpu_count"]):
        raise ProtocolError("public performance runtime tensor_parallel exceeds gpu_count")
    container_digest = runtime.get("container_image_digest")
    if container_digest is not None and (not isinstance(container_digest, str) or re.fullmatch(r"sha256:[a-fA-F0-9]{64}", container_digest) is None):
        raise ProtocolError("public performance runtime container image digest is malformed")

    protocol_snapshot = root / "protocol_snapshot.md"
    canonical_protocol = canonical_performance_protocol_path(cast(str, manifest["performance_protocol_version"]))
    if not protocol_snapshot.is_file() or protocol_snapshot.is_symlink():
        raise ProtocolError("public performance protocol snapshot must be a regular file")
    try:
        protocol_matches = protocol_snapshot.read_bytes() == canonical_protocol.read_bytes()
    except OSError as exc:
        raise ProtocolError("public performance protocol snapshot is unreadable") from exc
    if not protocol_matches:
        raise ProtocolError("public performance protocol snapshot is not the canonical versioned protocol")
    if sha256_file(protocol_snapshot) != manifest["protocol_sha256"]:
        raise ProtocolError("public performance protocol snapshot hash mismatch")
    if sha256_file(root / "plan.toml") != plan_metadata["sha256"] or sha256_file(root / "workload.jsonl") != workload_metadata["sha256"]:
        raise ProtocolError("public performance plan or workload hash mismatch")
    plan, workload_rows = _staged_plan(root, manifest)
    expected_plan = {
        "name": plan.config["name"],
        "revision": plan.config["revision"],
        "sha256": plan.sha256,
        "profile": plan.config["profile"],
        "data_classification": plan.config["data_classification"],
        **(
            {
                "open_loop_arrival_distribution": plan.config["execution"]["open_loop_arrival_distribution"],
                "execution_seed": plan.config["execution"]["seed"],
            }
            if "open_loop_arrival_distribution" in plan.config["execution"]
            else {}
        ),
        **({"minimum_p99_observations": plan.config["slo"]["minimum_p99_observations"]} if "minimum_p99_observations" in plan.config["slo"] else {}),
        **({"load_generator": plan.config["load_generator"]} if "load_generator" in plan.config else {}),
    }
    expected_plan_version = _PERFORMANCE_PLAN_REPORT_VERSIONS[protocol_version][0]
    if plan_metadata != expected_plan or plan.config.get("plan_version") != expected_plan_version:
        raise ProtocolError("public performance plan metadata differs from its snapshot")
    expected_workload = {
        "id": plan.config["workload"]["id"],
        "revision": plan.config["workload"]["revision"],
        "mode": plan.config["workload"]["mode"],
        **({"prefix_cache_policy": plan.config["workload"]["prefix_cache_policy"]} if "prefix_cache_policy" in plan.config["workload"] else {}),
        "sha256": plan.workload_sha256,
        "asset_set_sha256": sha256_bytes(json.dumps(plan.workload_assets, sort_keys=True, separators=(",", ":")).encode()),
        "assets": plan.workload_assets,
        "cases": len(workload_rows),
    }
    if workload_metadata != expected_workload:
        raise ProtocolError("public performance workload metadata differs from its snapshots")

    actual_assets = {
        path.relative_to(root / "workload_assets").as_posix(): sha256_file(path)
        for path in (root / "workload_assets").rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if actual_assets != plan.workload_assets:
        raise ProtocolError("public performance workload asset set differs from its manifest")
    evidence_metadata = manifest.get("system_evidence")
    loaded_evidence: dict[str, Any] | None = None
    if evidence_metadata is None:
        if (root / "system_evidence.json").exists() or (root / "system_evidence.json").is_symlink():
            raise ProtocolError("public performance system evidence is unbound")
    else:
        evidence = _object(evidence_metadata, {"configuration_id", "sha256", "projection"}, "performance system evidence")
        if evidence.get("projection") != "public" or _digest(evidence.get("sha256"), "performance system evidence sha256") != sha256_file(
            root / "system_evidence.json"
        ):
            raise ProtocolError("public performance system evidence hash or projection mismatch")
        loaded_evidence = load_system_evidence(root / "system_evidence.json")
        if (
            loaded_evidence.get("projection") != "public"
            or public_system_evidence(loaded_evidence) != loaded_evidence
            or loaded_evidence.get("configuration_id") != evidence.get("configuration_id")
        ):
            raise ProtocolError("public performance system evidence projection or configuration_id mismatch")
        _cross_check_public_system_evidence(runtime, source, loaded_evidence)

    observations = _read_jsonl(root / "observations.jsonl", "performance observations")
    if _public_observations(observations, protocol_version) != observations:
        raise ProtocolError("public performance observations differ from the allowed projection")
    observation_keys = [(row.get("block"), row.get("cell_key"), row.get("request_index")) for row in observations]
    if len(observation_keys) != len(set(observation_keys)):
        raise ProtocolError("public performance observations contain duplicate identities")
    cells = _read_jsonl(root / "cells.jsonl", "performance cells")
    completed: dict[tuple[int, str], dict[str, Any]] = {}
    skipped: dict[tuple[int, str], str] = {}
    for row in cells:
        block, cell_key = row.get("block"), row.get("cell_key")
        if not isinstance(block, int) or isinstance(block, bool) or block < 1 or not isinstance(cell_key, str) or not cell_key:
            raise ProtocolError("public performance cell identity is malformed")
        key = (block, cell_key)
        if key in completed or key in skipped:
            raise ProtocolError("public performance cells contain duplicate identities")
        if row.get("status") == "skipped":
            skipped[key] = _text(row.get("reason"), "performance skip reason")
        elif row.get("status") in {"completed", "completed-with-errors"} | ({"invalid-loadgen"} if protocol_version == "2.0.0" else set()):
            completed[key] = row
        else:
            raise ProtocolError("public performance cells contain a non-terminal status")
    if _public_cells(completed, skipped, protocol_version) != cells:
        raise ProtocolError("public performance cells differ from the allowed projection")

    runtime_config = {**runtime, "max_context_tokens": runtime["max_context_tokens"]}
    expanded = _expand_cells(plan, PerformanceRuntime(root / "public_manifest.json", str(runtime["sha256"]), runtime_config))
    repetitions = int(plan.config["execution"]["repetitions"])
    expected_cells = {(block, str(cell["cell_key"])): cell for block in range(1, repetitions + 1) for cell in expanded}
    if set(expected_cells) != set(completed) | set(skipped):
        raise ProtocolError("public performance cells differ from the preregistered plan")
    observations_by_cell: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for row in observations:
        key = (int(row["block"]), str(row["cell_key"]))
        observations_by_cell.setdefault(key, []).append(row)
    if set(observations_by_cell) - set(completed):
        raise ProtocolError("public performance observations reference non-completed cells")
    seeds: dict[tuple[int, str], int] = {}
    execution = plan.config["execution"]
    for block in range(1, repetitions + 1):
        block_cells = list(expanded)
        if execution.get("randomize_cells", True):
            random.Random(int(execution["seed"]) + block).shuffle(block_cells)  # noqa: S311 -- frozen protocol ordering.
        for cell_index, cell in enumerate(block_cells, 1):
            seeds[(block, str(cell["cell_key"]))] = int(execution["seed"]) + block * 1000 + cell_index
    pricing_for_cells = runtime.get("pricing") if isinstance(runtime.get("pricing"), dict) else None
    workloads_by_context: dict[int, list[dict[str, Any]]] = {}
    for workload_row in workload_rows:
        workloads_by_context.setdefault(int(workload_row["context_tokens"]), []).append(workload_row)
    for key, row in completed.items():
        expected_cell = expected_cells[key]
        identity_fields = ("scenario_id", "arrival", "context_tokens", "output_tokens", "concurrency", "request_rate")
        if any(row.get(field) != expected_cell.get(field) for field in identity_fields):
            raise ProtocolError("public performance cell differs from its preregistered identity")
        cell_observations = observations_by_cell.get(key, [])
        expected_observations = _measured_request_count(plan, expected_cell, key[0])
        if len(cell_observations) != expected_observations or sorted(int(item["request_index"]) for item in cell_observations) != list(
            range(1, expected_observations + 1)
        ):
            raise ProtocolError("public performance observation count differs from its preregistered cell")
        successes = sum(item.get("status") == "success" for item in cell_observations)
        errors = len(cell_observations) - successes
        usage_observations = [item for item in cell_observations if "input_tokens" in item and "output_tokens" in item]
        expected_status = (
            "invalid-loadgen"
            if protocol_version == "2.0.0" and row.get("load_generator_valid") is False
            else "completed-with-errors"
            if errors
            else "completed"
        )
        if (
            row.get("observations") != len(cell_observations)
            or row.get("successes") != successes
            or row.get("errors") != errors
            or row.get("status") != expected_status
            or float(row.get("input_tokens_total", -1)) != sum(float(item["input_tokens"]) for item in usage_observations)
            or float(row.get("output_tokens_total", -1)) != sum(float(item["output_tokens"]) for item in usage_observations)
        ):
            raise ProtocolError("public performance cell totals differ from its observations")
        context_workloads = workloads_by_context.get(int(expected_cell["context_tokens"]), [])
        if not context_workloads:
            raise ProtocolError("public performance cell context is absent from its workload")
        for observation in cell_observations:
            request_index = int(observation["request_index"])
            expected_workload = context_workloads[(request_index - 1) % len(context_workloads)]
            tolerance = max(
                2.0,
                float(expected_cell["context_tokens"]) * float(plan.config["workload"].get("input_token_tolerance_fraction", 0.05)),
            )
            has_usage = "input_tokens" in observation and "output_tokens" in observation
            expected_input_match = (
                abs(float(observation["input_tokens"]) - float(expected_cell["context_tokens"])) <= tolerance if has_usage else None
            )
            if (
                observation.get("scenario_id") != expected_cell["scenario_id"]
                or observation.get("declared_context_tokens") != expected_cell["context_tokens"]
                or observation.get("requested_output_tokens") != expected_cell["output_tokens"]
                or observation.get("workload_id") != expected_workload["id"]
                or has_usage
                and (
                    float(observation["output_tokens"]) > float(expected_cell["output_tokens"])
                    or float(observation["input_tokens"]) + float(expected_cell["output_tokens"]) > float(runtime["max_context_tokens"])
                )
                or observation.get("status") == "success"
                and (
                    observation.get("reported_model") != runtime["expected_model"]
                    or observation.get("input_token_match") is not expected_input_match
                )
            ):
                raise ProtocolError("public performance observation differs from its cell or runtime identity")
            expected_queue = (
                round(max(0.0, (int(observation["started_monotonic_ns"]) - int(observation["scheduled_monotonic_ns"])) / 1_000_000), 3)
                if expected_cell["arrival"] == "open-loop"
                else 0.0
            )
            if observation.get("client_queue_ms") != expected_queue:
                raise ProtocolError("public performance client queue differs from monotonic timing")
        ordered = sorted(cell_observations, key=lambda item: int(item["request_index"]))
        scheduled = [int(item["scheduled_monotonic_ns"]) for item in ordered]
        if protocol_version == "2.0.0":
            if not ordered:
                offsets = []
                expected_schedule = []
            else:
                batch_starts = {item.get("batch_started_monotonic_ns") for item in ordered}
                offsets = (
                    _open_loop_offsets(plan, expected_cell, key[0], "measured")
                    if expected_cell["arrival"] == "open-loop"
                    else [0.0] * len(ordered)
                )
                if len(batch_starts) != 1 or not all(isinstance(value, int) and not isinstance(value, bool) for value in batch_starts):
                    raise ProtocolError("public performance v2 schedule has an invalid monotonic anchor")
                anchor = cast(int, next(iter(batch_starts)))
                expected_schedule = [anchor + round(offset * 1_000_000_000) for offset in offsets]
            if scheduled != expected_schedule:
                raise ProtocolError("public performance v2 schedule differs from its preregistered monotonic anchor")
        elif expected_cell["arrival"] == "closed-loop":
            if len(set(scheduled)) != 1:
                raise ProtocolError("public performance closed-loop schedule differs within a batch")
        else:
            offsets = _open_loop_offsets(plan, expected_cell, key[0], "measured")
            if len(offsets) != len(ordered) or any(
                abs((value - scheduled[0]) - round((offset - offsets[0]) * 1_000_000_000)) > 1
                for value, offset in zip(scheduled, offsets, strict=True)
            ):
                raise ProtocolError("public performance open-loop schedule differs from the preregistered arrival process")
        try:
            window = _measurement_window(cell_observations)
            recalculated = _cell_metrics_for_protocol(
                cell_observations,
                expected_cell,
                plan,
                window,
                seeds[key],
                pricing_for_cells,
                protocol_version,
            )
            recalculated["block"] = key[0]
            projected = _public_cells({key: recalculated}, {}, protocol_version)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("public performance observations cannot reconstruct cell metrics") from exc
        if projected != [row]:
            raise ProtocolError("public performance cell metrics differ from observations and plan")

    expected_counts = {
        "total": len(cells),
        "completed": sum(row.get("status") == "completed" for row in completed.values()),
        "with_errors": sum(row.get("status") == "completed-with-errors" for row in completed.values()),
        **(
            {"invalid_loadgen": sum(row.get("status") == "invalid-loadgen" for row in completed.values())}
            if protocol_version == "2.0.0"
            else {}
        ),
        "skipped": len(skipped),
        "slo_passed": sum(row.get("slo_passed") is True for row in completed.values()),
        "slo_failed": sum(row.get("slo_passed") is False for row in completed.values()),
    }
    if manifest.get("cells") != expected_counts:
        raise ProtocolError("public performance cell summary does not reconcile")
    warmups = _object(manifest.get("warmups"), {"total", "successes", "errors"}, "performance warmups")
    if any(not isinstance(warmups.get(field), int) or isinstance(warmups.get(field), bool) or warmups[field] < 0 for field in warmups):
        raise ProtocolError("public performance warm-up summary is malformed")
    warmup_total = cast(int, warmups["total"])
    warmup_successes = cast(int, warmups["successes"])
    warmup_errors = cast(int, warmups["errors"])
    if warmup_successes + warmup_errors != warmup_total:
        raise ProtocolError("public performance warm-up summary does not reconcile")
    expected_warmups = sum(int(cell["warmup_requests"]) for block in range(1, repetitions + 1) for cell in expanded if not cell.get("skip_reason"))
    expected_measured = sum(
        _measured_request_count(plan, cell, block) for block in range(1, repetitions + 1) for cell in expanded if not cell.get("skip_reason")
    )
    if warmup_total != expected_warmups or len(observations) != expected_measured:
        raise ProtocolError("public performance request counts differ from the preregistered plan")
    has_errors = warmup_errors > 0 or any(row.get("status") == "error" for row in observations)
    has_invalid_loadgen = any(row.get("status") == "invalid-loadgen" for row in completed.values())
    expected_status = "invalid-loadgen" if has_invalid_loadgen else "completed-with-errors" if has_errors else "completed"
    if manifest.get("status") != expected_status:
        raise ProtocolError("public performance status differs from its terminal outcomes")
    reconciliation = _object(manifest.get("request_reconciliation"), _RECONCILIATION_FIELDS, "performance request reconciliation")
    terminal = expected_warmups + expected_measured
    expected_reconciliation = {
        "planned": terminal,
        "scheduled": terminal,
        "accepted": terminal,
        "responses": terminal,
        "warmup_outcomes": expected_warmups,
        "measured_outcomes": expected_measured,
        "terminal_outcomes": terminal,
        "ledgers_complete": True,
        "campaign_complete": True,
    }
    if reconciliation != expected_reconciliation:
        raise ProtocolError("public performance request reconciliation differs from the plan")

    token_usage = _object(manifest.get("token_usage"), {"input", "output", "total"}, "performance token usage")
    input_tokens = _nonnegative(token_usage.get("input"), "performance input tokens")
    output_tokens = _nonnegative(token_usage.get("output"), "performance output tokens")
    if _nonnegative(token_usage.get("total"), "performance total tokens") != input_tokens + output_tokens:
        raise ProtocolError("public performance token totals do not reconcile")
    usage_observations = [row for row in observations if "input_tokens" in row and "output_tokens" in row]
    if input_tokens != sum(float(row["input_tokens"]) for row in usage_observations) or output_tokens != sum(
        float(row["output_tokens"]) for row in usage_observations
    ):
        raise ProtocolError("public performance token usage differs from measured observations")
    pricing = runtime.get("pricing")
    estimated_cost = manifest.get("estimated_cost")
    if pricing is None:
        if estimated_cost is not None:
            raise ProtocolError("public performance unpriced runtime reports estimated cost")
    else:
        pricing = _object(pricing, {"currency", "source", "effective_at", "input_per_million", "output_per_million"}, "performance pricing")
        currency = _text(pricing.get("currency"), "performance pricing currency")
        if len(currency) != 3 or not currency.isalpha() or not currency.isupper():
            raise ProtocolError("public performance pricing currency must be a three-letter uppercase code")
        _text(pricing.get("source"), "performance pricing source")
        _text(pricing.get("effective_at"), "performance pricing effective_at")
        input_rate = _nonnegative(pricing.get("input_per_million"), "performance pricing input_per_million")
        output_rate = _nonnegative(pricing.get("output_per_million"), "performance pricing output_per_million")
        cost = _object(estimated_cost, {"amount", "currency", "source", "effective_at", "includes_warmup"}, "performance estimated cost")
        expected_amount = input_tokens * input_rate / 1_000_000 + output_tokens * output_rate / 1_000_000
        if (
            _nonnegative(cost.get("amount"), "performance estimated cost amount") != expected_amount
            or cost.get("currency") != pricing.get("currency")
            or cost.get("source") != pricing.get("source")
            or cost.get("effective_at") != pricing.get("effective_at")
            or cost.get("includes_warmup") is not False
        ):
            raise ProtocolError("public performance cost does not reconcile with pricing and usage")

    summary = _read_json(root / "summary.json", "performance summary")
    expected_summary = _campaign_summary(manifest, cells, observations)
    if manifest.get("limitations") != expected_summary["limitations"]:
        raise ProtocolError("public performance limitations differ from the protocol report contract")
    if summary != expected_summary:
        raise ProtocolError("public performance summary differs from observations and cells")
    with tempfile.TemporaryDirectory(prefix="cavada-public-csv-") as temporary:
        expected_csv = Path(temporary) / "cells.csv"
        _write_cells_csv(expected_csv, cells, protocol_version=protocol_version)
        if (root / "cells.csv").read_bytes() != expected_csv.read_bytes():
            raise ProtocolError("public performance CSV differs from cells.jsonl")

    actual_presentation = {
        relative
        for relative in _content_files(root)
        if relative in _PERFORMANCE_REPORT_ROOTS or relative.startswith("figures/")
    }
    expected_presentation: set[str] = set()
    if publication_version == "2.0.0":
        with tempfile.TemporaryDirectory(prefix="cavada-public-report-") as temporary:
            expected_root = Path(temporary)
            _performance_reports(expected_root, _public_presentation_manifest(manifest), expected_summary, cells)
            expected_presentation = _content_files(expected_root)
            if actual_presentation != expected_presentation:
                raise ProtocolError("public performance presentation files differ from the verified projection")
            for relative in expected_presentation:
                if (root / relative).read_bytes() != (expected_root / relative).read_bytes():
                    raise ProtocolError(f"public performance presentation differs from the verified projection: {relative}")
    elif actual_presentation:
        raise ProtocolError("legacy public performance presentation is outside the semantic verification contract")

    official = cast(bool, manifest["official"])
    if official:
        if (
            manifest.get("status") != "completed"
            or manifest.get("assurance") != "approved"
            or manifest.get("performance_protocol_version") != PERFORMANCE_PROTOCOL_VERSION
        ):
            raise ProtocolError("official public performance assurance is incoherent")
        mutable_revisions = [field for field in ("model_revision", "engine_revision") if not _content_addressed_revision(runtime.get(field))]
        if mutable_revisions:
            raise ProtocolError(f"official public performance runtime revisions are not content-addressed: {mutable_revisions}")
        if any(row.get("status") == "invalid-loadgen" for row in completed.values()):
            raise ProtocolError("official public performance cannot contain invalid load-generator cells")
        release = _performance_release(manifest.get("release"), publication_version, effective_at=effective_at)
        if evaluation_finished_at > _time(release.get("approved_at"), "performance release approved_at"):
            raise ProtocolError("public performance release predates evaluation completion")
        _require_official_reference_inputs(
            manifest.get("protocol_sha256"),
            plan_metadata.get("sha256"),
            workload_metadata.get("sha256"),
            workload_metadata.get("assets"),
        )
        commit = source.get("commit")
        if source.get("dirty") is not False or not isinstance(commit, str) or re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", commit) is None:
            raise ProtocolError("official public performance source evidence is incomplete")
        if evidence_metadata is None or loaded_evidence is None or skipped:
            raise ProtocolError("official public performance requires complete system evidence and cells")
        collected_at = _time(loaded_evidence.get("collected_at"), "performance system evidence collected_at")
        if collected_at > evaluation_started_at or evaluation_started_at - collected_at > timedelta(hours=24):
            raise ProtocolError("official public performance system evidence is not fresh for evaluation start")
        accelerator_rows = cast(dict[str, Any], loaded_evidence["server"])["accelerators"]
        expected_unavailable = {
            "/server/host_id",
            "/load_generator/host_id",
            "/network/endpoint_host",
            "/network/endpoint_port",
            "/network/route",
            *(f"/server/accelerators/{index}/{field}" for index in range(len(cast(list[Any], accelerator_rows))) for field in ("uuid", "pci_bus_id")),
        }
        engine_evidence = cast(dict[str, Any], cast(dict[str, Any], loaded_evidence["software"])["engine"])
        if runtime.get("container_image_digest"):
            if engine_evidence.get("binary_sha256") is None:
                expected_unavailable.add("/software/engine/binary_sha256")
        else:
            expected_unavailable.add("/software/engine/container_image_digest")
        if set(cast(dict[str, Any], loaded_evidence["unavailable"])) != expected_unavailable:
            raise ProtocolError("official public performance system evidence has unexpected unavailable fields")
        client = cast(dict[str, Any], cast(dict[str, Any], loaded_evidence["load_generator"])["client"])
        if client.get("name") != "cavadalabs-evals" or client.get("revision") != source.get("commit"):
            raise ProtocolError("official public performance load-generator evidence differs from source revision")
        assurance = "approved"
    else:
        if manifest.get("assurance") != "development" or manifest.get("release") is not None:
            raise ProtocolError("development public performance assurance is incoherent")
        assurance = "development"

    expected_files = _PERFORMANCE_CORE_FILES | {f"workload_assets/{name}" for name in plan.workload_assets}
    if evidence_metadata is not None:
        expected_files.add("system_evidence.json")
    expected_files |= expected_presentation
    if _content_files(root) != expected_files:
        raise ProtocolError("public performance bundle contains missing or unknown files")
    return assurance


def verify_public_bundle(
    run_dir: Path,
    *,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    effective_at: datetime | None = None,
) -> dict[str, Any]:
    source = Path(run_dir)
    if source.is_symlink() or not source.is_dir():
        raise ProtocolError("public bundle must be a regular directory")
    with tempfile.TemporaryDirectory(prefix="cavada-public-verify-") as temporary:
        root = Path(temporary) / "bundle"
        try:
            shutil.copytree(source, root, symlinks=True)
        except OSError as exc:
            raise ProtocolError("public bundle could not be staged for verification") from exc
        verification = verify_bundle(root, signing_key_env=signing_key_env)
        if not verification["valid"]:
            raise ProtocolError("public bundle integrity verification failed: " + "; ".join(map(str, verification["failures"])))
        _reject_restricted_text(root)
        behavior = (root / "public_release.json").is_file()
        performance = (root / "public_manifest.json").is_file()
        if behavior == performance:
            raise ProtocolError("public bundle must contain exactly one recognized behavior or performance projection")
        bundle_type = "behavior" if behavior else "performance"
        assurance = _behavior(root) if behavior else _performance(root, effective_at=effective_at)
        return {
            "valid": True,
            "semantic_valid": True,
            "type": bundle_type,
            "assurance": assurance,
            "authenticity": "unverified",
            "bundle_signature": verification["signature"],
        }
