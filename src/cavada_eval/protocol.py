from __future__ import annotations

import copy
import csv
import difflib
import hashlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import tempfile
import tomllib
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import NormalDist
from typing import Any, Iterable, cast

from .assets import content_text, validate_content_parts, validate_messages
from .profiles import TASK_PROFILES

PROTOCOL_VERSION = "1.0.0"
SCHEMA_VERSION = "2.0.0"
REPORT_VERSION = "1.1.0"
BEHAVIORS = {"answer", "refuse", "abstain", "redirect", "safe_complete"}
RISK_DOMAINS = {"quality", "security", "privacy", "safety", "reliability", "performance", "fairness"}
SEVERITIES = {"low", "medium", "high", "critical"}
REVIEW_STATUSES = {"approved", "needs_review", "rejected"}
SUITE_STATUSES = {"draft", "candidate", "calibrated", "approved", "deprecated", "retired"}
DATA_CLASSES = {"public", "synthetic", "internal", "confidential", "restricted"}
SPLITS = {"public", "practice", "calibration", "holdout"}
OFFICIAL_SUITE_FIELDS = {
    "protocol_version",
    "name",
    "version",
    "status",
    "description",
    "dataset",
    "rubric",
    "data_classification",
    "dataset_sha256",
    "rubric_sha256",
    "temperature",
    "max_tokens",
    "official_min_repetitions",
    "official_min_judge_repetitions",
    "target",
    "gates",
    "governance",
    "assets",
    "metrics",
    "judge",
    "statistics",
    "report",
    "splits",
    "calibration",
    "pricing",
    "network",
    "profile",
    "dataset_integrity",
}
OFFICIAL_CASE_FIELDS = {
    "id",
    "input",
    "messages",
    "category",
    "risk_domain",
    "severity",
    "language",
    "locale",
    "split",
    "weight",
    "tags",
    "operating_condition",
    "distribution_shift_dimension",
    "distribution_shift_reference_id",
    "scenario_group_id",
    "scenario_id",
    "scenario_role",
    "scenario_reference_id",
    "performance_phase",
    "expected_behavior",
    "expected_behavior_reason",
    "expected_output",
    "expected_json",
    "expected_json_value",
    "json_schema",
    "expected_number",
    "numeric_tolerance",
    "expected_set",
    "set_f1_min",
    "token_f1_min",
    "expected_retrieval_ids",
    "retrieval_k",
    "retrieval_minimums",
    "expected_tools",
    "forbidden_tools",
    "allowed_tool_permissions",
    "expected_tool_arguments",
    "exact_tool_order",
    "max_tool_calls",
    "expected_transcript",
    "required_terms",
    "forbidden_terms",
    "required_regex",
    "forbidden_regex",
    "citation_required",
    "citation_pattern",
    "forbid_pii",
    "min_chars",
    "max_chars",
    "max_character_error_rate",
    "max_word_error_rate",
    "structured_field_accuracy_min",
    "mandatory_criteria",
    "metric_weights",
    "soft_checks",
    "judge_gold_verdict",
    "response_length",
    "response_style",
    "probe_type",
    "model_family_alias",
    "module",
    "context",
    "retrieval_context",
    "pattern",
    "source",
    "review",
}
SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"),
)


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Suite:
    root: Path
    config: dict[str, Any]
    cases: tuple[dict[str, Any], ...]
    rubric: str
    dataset_path: Path
    rubric_path: Path

    @property
    def name(self) -> str:
        return str(self.config["name"])

    @property
    def version(self) -> str:
        return str(self.config["version"])

    @property
    def status(self) -> str:
        return str(self.config["status"])


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strict_json_loads(value: str | bytes) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = item
        return result

    def reject_constant(token: str) -> Any:
        raise ValueError(f"non-finite JSON number: {token}")

    try:
        parsed = json.loads(value, object_pairs_hook=object_pairs, parse_constant=reject_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting is too deep") from exc

    def reject_overflow(item: Any) -> None:
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("non-finite JSON number")
        if isinstance(item, dict):
            for child in item.values():
                reject_overflow(child)
        elif isinstance(item, list):
            for child in item:
                reject_overflow(child)

    try:
        reject_overflow(parsed)
    except RecursionError as exc:
        raise ValueError("JSON nesting is too deep") from exc
    return parsed


def _closed_object_errors(value: Any, allowed: set[str], label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    unknown = sorted(set(value) - allowed)
    return [f"{label} has unknown fields: {unknown}"] if unknown else []


def _official_content_structure_errors(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        return []
    allowed = {
        "type",
        "text",
        "asset",
        "mime_type",
        "sha256",
        "name",
        "arguments",
        "result",
        "license",
        "origin",
        "personal_data",
    }
    return [
        error
        for index, part in enumerate(value)
        for error in _closed_object_errors(part, allowed, f"{label}[{index}]")
    ]


def _official_suite_structure_errors(suite: Suite) -> list[str]:
    config = suite.config
    errors = _closed_object_errors(config, OFFICIAL_SUITE_FIELDS, "suite")
    object_fields = {
        "governance": {
            "owner",
            "purpose",
            "intended_use",
            "prohibited_use",
            "license",
            "origin",
            "created_at",
            "retention",
            "personal_data",
            "legal_basis_reference",
            "rotation_due",
            "contamination_status",
            "canary_strategy",
            "known_leaks",
            "representativeness",
            "transfer_restrictions",
            "near_duplicate_threshold",
            "semantic_duplicate_threshold",
            "minimum_category_cases",
            "maximum_category_share",
        },
        "target": {
            "kind",
            "responses",
            "responses_sha256",
            "response_field",
            "reported_model_field",
            "retrieved_ids_field",
            "sources_field",
            "tools_field",
            "request_field",
            "request_defaults_json",
            "stream",
            "system_prompt",
            "system_prompt_sha256",
            "capabilities",
        },
        "assets": {"max_bytes", "max_image_pixels", "max_audio_seconds"},
        "metrics": {"deepeval"},
        "judge": {
            "additional_models",
            "consensus",
            "minimum_calibration_accuracy",
            "qualification_blueprint",
            "qualification_blueprint_sha256",
            "qualification_blueprint_approval",
            "qualification_blueprint_approval_sha256",
        },
        "statistics": {"confidence", "bootstrap_samples", "seed"},
        "report": {
            "include_raw",
            "public_redaction",
            "limitations",
            "assurance",
            "model_claim_allowed",
            "benchmark_claim_allowed",
        },
        "calibration": {
            "status",
            "evidence",
            "evidence_sha256",
            "independent_review",
            "independent_review_evidence",
            "independent_review_evidence_sha256",
        },
        "pricing": {
            "currency",
            "source",
            "effective_at",
            "input_per_million",
            "output_per_million",
            "judge_input_per_million",
            "judge_output_per_million",
        },
        "network": {"allowed_hosts"},
        "dataset_integrity": {
            "semantic_review_status",
            "semantic_review_evidence",
            "semantic_review_evidence_sha256",
            "semantic_detector",
            "semantic_detector_revision",
            "cross_split_reviewed",
            "cross_suite_reviewed",
        },
    }
    for field, allowed in object_fields.items():
        if field in config:
            errors.extend(_closed_object_errors(config[field], allowed, f"suite.{field}"))
    target = config.get("target")
    report = config.get("report")
    if isinstance(report, dict) and "assurance" in report:
        if report.get("assurance") != "conformance-fixture" or not isinstance(target, dict) or target.get("kind") != "recorded":
            errors.append("report.assurance=conformance-fixture is reserved for recorded official targets")
        if report.get("model_claim_allowed") is not False or report.get("benchmark_claim_allowed") is not False:
            errors.append("official conformance fixtures must prohibit model and benchmark claims")
    if "splits" in config and not isinstance(config["splits"], dict):
        errors.append("suite.splits must be an object")
    gates = config.get("gates")
    if isinstance(gates, list):
        for index, gate in enumerate(gates):
            errors.extend(_closed_object_errors(gate, {"category", "slice", "value", "metric", "min"}, f"suite.gates[{index}]"))
    metrics = config.get("metrics")
    if isinstance(metrics, dict) and isinstance(metrics.get("deepeval"), list):
        for index, metric in enumerate(metrics["deepeval"]):
            errors.extend(
                _closed_object_errors(
                    metric,
                    {"name", "threshold", "pattern", "ignore_case", "model", "hard_fail"},
                    f"suite.metrics.deepeval[{index}]",
                )
            )
    judge = config.get("judge")
    if isinstance(judge, dict) and isinstance(judge.get("additional_models"), list):
        for index, model in enumerate(judge["additional_models"]):
            errors.extend(_closed_object_errors(model, {"model", "expected_model", "revision"}, f"suite.judge.additional_models[{index}]"))
    for index, case in enumerate(suite.cases, 1):
        prefix = f"case[{index}]"
        errors.extend(_closed_object_errors(case, OFFICIAL_CASE_FIELDS, prefix))
        errors.extend(_official_content_structure_errors(case.get("input"), f"{prefix}.input"))
        source = case.get("source")
        errors.extend(
            _closed_object_errors(
                source,
                {"origin", "source_case_id", "source_run_manifest_sha256", "gold_evidence_sha256", "model_family_alias", "metadata"},
                f"{prefix}.source",
            )
        )
        errors.extend(
            _closed_object_errors(
                case.get("review"),
                {"status", "method", "reviewer_id", "reviewed_at", "evidence_sha256"},
                f"{prefix}.review",
            )
        )
        messages = case.get("messages")
        if isinstance(messages, list):
            for message_index, message in enumerate(messages):
                message_label = f"{prefix}.messages[{message_index}]"
                errors.extend(_closed_object_errors(message, {"role", "content", "name", "tool_call_id"}, message_label))
                if isinstance(message, dict):
                    errors.extend(_official_content_structure_errors(message.get("content"), f"{message_label}.content"))
    return errors


def contains_secret_like(value: Any) -> bool:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n")
    os.chmod(path, 0o600)


def _inside(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ProtocolError(f"Suite path escapes its directory: {relative}") from exc
    return path


def _read_jsonl(path: Path) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                row = _strict_json_loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                raise ProtocolError(f"Invalid JSONL line {line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise ProtocolError(f"Invalid JSONL line {line_number}: expected object")
            rows.append(row)
    return tuple(rows)


def load_suite(path: str | Path, *, official: bool = False) -> Suite:
    root = Path(path).resolve()
    config_path = root / "suite.toml"
    if not config_path.is_file():
        raise ProtocolError(f"Missing suite.toml in {root}")
    with config_path.open("rb") as handle:
        config = tomllib.load(handle)
    dataset_path = _inside(root, str(config.get("dataset", "dataset.jsonl")))
    rubric_path = _inside(root, str(config.get("rubric", "rubric.md")))
    if not dataset_path.is_file() or not rubric_path.is_file():
        raise ProtocolError("Dataset and rubric must exist inside the suite")
    suite = Suite(root, config, _read_jsonl(dataset_path), rubric_path.read_text(), dataset_path, rubric_path)
    errors = validate_suite(suite, official=official)
    if errors:
        raise ProtocolError("\n".join(errors))
    return suite


def _semantic_integrity_errors(suite: Suite, integrity: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    relative = integrity.get("semantic_review_evidence")
    if not isinstance(relative, str) or not relative.strip():
        return ["official semantic contamination evidence path is required"]
    try:
        path = _inside(suite.root, relative)
    except ProtocolError as exc:
        return [str(exc)]
    if (suite.root / relative).is_symlink() or not path.is_file():
        return ["official semantic contamination evidence file is missing"]
    expected_hash = str(integrity.get("semantic_review_evidence_sha256", ""))
    try:
        raw = path.read_bytes()
        evidence = _strict_json_loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return ["official semantic contamination evidence must be valid JSON"]
    if sha256_bytes(raw) != expected_hash:
        return ["official semantic contamination evidence hash mismatch"]
    if not isinstance(evidence, dict):
        return ["official semantic contamination evidence must be an object"]
    expected_fields = {
        "evidence_version",
        "dataset_sha256",
        "comparison_corpus",
        "comparison_corpus_sha256",
        "candidate_pairs_evidence",
        "candidate_pairs_evidence_sha256",
        "reviewer_evidence",
        "reviewer_evidence_sha256",
        "detector",
        "detector_revision",
        "detector_license",
        "similarity_metric",
        "threshold",
        "cases",
        "candidate_pairs",
        "confirmed_duplicates",
        "cross_split_reviewed",
        "cross_suite_reviewed",
        "independent_review_status",
        "performed_at",
        "passed",
    }
    if set(evidence) != expected_fields:
        errors.append(f"official semantic contamination fields must be exactly {sorted(expected_fields)}")
    hashes = ("dataset_sha256", "comparison_corpus_sha256", "candidate_pairs_evidence_sha256", "reviewer_evidence_sha256")
    if any(not isinstance(evidence.get(field), str) or not re.fullmatch(r"[a-f0-9]{64}", evidence[field]) for field in hashes):
        errors.append("official semantic contamination evidence contains invalid hashes")
    if evidence.get("evidence_version") != "2.0.0":
        errors.append("official semantic contamination evidence_version must be 2.0.0")
    if evidence.get("dataset_sha256") != sha256_file(suite.dataset_path):
        errors.append("official semantic contamination evidence dataset hash mismatch")
    if evidence.get("detector") != integrity.get("semantic_detector"):
        errors.append("official semantic contamination detector mismatch")
    if evidence.get("detector_revision") != integrity.get("semantic_detector_revision"):
        errors.append("official semantic contamination detector revision mismatch")
    for field in ("detector_license", "similarity_metric"):
        if not isinstance(evidence.get(field), str) or not str(evidence[field]).strip():
            errors.append(f"official semantic contamination {field} is required")
    threshold = evidence.get("threshold")
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not -1 <= float(threshold) <= 1:
        errors.append("official semantic contamination threshold is invalid")
    if evidence.get("cases") != len(suite.cases):
        errors.append("official semantic contamination case count mismatch")
    def support(field: str, label: str, *, parse_json: bool) -> tuple[bytes, Any] | None:
        support_relative = evidence.get(field)
        support_hash = evidence.get(f"{field}_sha256")
        if not isinstance(support_relative, str) or not support_relative.strip():
            errors.append(f"official semantic contamination {label} path is required")
            return None
        candidate = suite.root / support_relative
        try:
            support_path = _inside(suite.root, support_relative)
        except ProtocolError as exc:
            errors.append(str(exc))
            return None
        if candidate.is_symlink() or not support_path.is_file():
            errors.append(f"official semantic contamination {label} must be a regular suite-local file")
            return None
        try:
            support_raw = support_path.read_bytes()
            support_value = _strict_json_loads(support_raw) if parse_json else None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            errors.append(f"official semantic contamination {label} is unreadable or invalid")
            return None
        if not support_raw or sha256_bytes(support_raw) != support_hash:
            errors.append(f"official semantic contamination {label} hash mismatch")
            return None
        return support_raw, support_value

    comparison = support("comparison_corpus", "comparison corpus", parse_json=False)
    pairs_record = support("candidate_pairs_evidence", "candidate-pairs evidence", parse_json=True)
    reviewer_record = support("reviewer_evidence", "reviewer evidence", parse_json=True)
    if comparison is not None and sha256_bytes(comparison[0]) != evidence.get("comparison_corpus_sha256"):
        errors.append("official semantic contamination comparison corpus hash mismatch")

    pair_rows: list[Any] = []
    if pairs_record is not None:
        pairs_value = pairs_record[1]
        pair_fields = {"candidate_pairs_evidence_version", "dataset_sha256", "comparison_corpus_sha256", "pairs"}
        raw_pairs = pairs_value.get("pairs") if isinstance(pairs_value, dict) else None
        pair_rows = raw_pairs if isinstance(raw_pairs, list) else []
        suite_ids = {str(case.get("id")) for case in suite.cases}
        if (
            not isinstance(pairs_value, dict)
            or set(pairs_value) != pair_fields
            or pairs_value.get("candidate_pairs_evidence_version") != "1.0.0"
            or pairs_value.get("dataset_sha256") != evidence.get("dataset_sha256")
            or pairs_value.get("comparison_corpus_sha256") != evidence.get("comparison_corpus_sha256")
            or not isinstance(pair_rows, list)
            or any(
                not isinstance(pair, dict)
                or set(pair) != {"left_case_id", "right_corpus_id", "similarity"}
                or pair.get("left_case_id") not in suite_ids
                or not isinstance(pair.get("right_corpus_id"), str)
                or not pair["right_corpus_id"]
                or not isinstance(pair.get("similarity"), (int, float))
                or isinstance(pair.get("similarity"), bool)
                or not -1 <= float(pair["similarity"]) <= 1
                for pair in pair_rows
            )
        ):
            errors.append("official semantic contamination candidate-pairs evidence is invalid or unlinked")

    confirmed_rows: list[Any] = []
    if reviewer_record is not None:
        reviewer = reviewer_record[1]
        reviewer_fields = {
            "reviewer_evidence_version",
            "status",
            "dataset_sha256",
            "candidate_pairs_evidence_sha256",
            "independent_reviewers",
            "confirmed_duplicate_pairs",
            "completed_at",
        }
        raw_confirmed = reviewer.get("confirmed_duplicate_pairs") if isinstance(reviewer, dict) else None
        confirmed_rows = raw_confirmed if isinstance(raw_confirmed, list) else []
        reviewers = reviewer.get("independent_reviewers") if isinstance(reviewer, dict) else None
        if (
            not isinstance(reviewer, dict)
            or set(reviewer) != reviewer_fields
            or reviewer.get("reviewer_evidence_version") != "1.0.0"
            or reviewer.get("status") != "passed"
            or reviewer.get("dataset_sha256") != evidence.get("dataset_sha256")
            or reviewer.get("candidate_pairs_evidence_sha256") != evidence.get("candidate_pairs_evidence_sha256")
            or not isinstance(reviewers, list)
            or len(reviewers) < 2
            or len(set(reviewers)) != len(reviewers)
            or not all(isinstance(reviewer_id, str) and reviewer_id.strip() for reviewer_id in reviewers)
            or not isinstance(confirmed_rows, list)
            or not all(isinstance(pair_id, str) and pair_id.strip() for pair_id in confirmed_rows)
        ):
            errors.append("official semantic contamination reviewer evidence is invalid or unlinked")
        _evidence_time(reviewer.get("completed_at") if isinstance(reviewer, dict) else None, "semantic reviewer completed_at", errors)

    candidate_pairs = evidence.get("candidate_pairs")
    confirmed = evidence.get("confirmed_duplicates")
    if (
        not isinstance(candidate_pairs, int)
        or isinstance(candidate_pairs, bool)
        or candidate_pairs < 0
        or not isinstance(confirmed, int)
        or isinstance(confirmed, bool)
        or confirmed < 0
        or confirmed > candidate_pairs
        or candidate_pairs != len(pair_rows)
        or confirmed != len(confirmed_rows)
    ):
        errors.append("official semantic contamination pair counts are invalid")
    if evidence.get("cross_split_reviewed") is not True or evidence.get("cross_suite_reviewed") is not True:
        errors.append("official semantic contamination evidence requires cross-split and cross-suite review")
    if (
        evidence.get("independent_review_status") != "passed"
        or reviewer_record is None
    ):
        errors.append("official semantic contamination evidence requires independent reviewer evidence")
    if evidence.get("passed") is not True or confirmed != 0:
        errors.append("official semantic contamination evidence did not pass")
    try:
        performed_at = str(evidence.get("performed_at", "")).replace("Z", "+00:00")
        if datetime.fromisoformat(performed_at).tzinfo is None:
            raise ValueError
    except ValueError:
        errors.append("official semantic contamination performed_at must include a timezone")
    return errors


def _judge_blueprint_evidence_errors(
    suite: Suite,
    *,
    require: bool,
    now: datetime | None = None,
) -> list[str]:
    judge = suite.config.get("judge")
    fields = {
        "qualification_blueprint": "judge qualification blueprint",
        "qualification_blueprint_approval": "judge qualification blueprint approval",
    }
    configured = isinstance(judge, dict) and any(
        judge.get(field) or judge.get(f"{field}_sha256") for field in fields
    )
    if not configured:
        return ["official runs require a pinned judge qualification blueprint and independent approval"] if require else []
    if not isinstance(judge, dict):
        return ["suite.judge must be a table"]

    loaded: dict[str, tuple[Path, bytes]] = {}
    errors: list[str] = []
    for field, label in fields.items():
        relative = judge.get(field)
        expected_hash = judge.get(f"{field}_sha256")
        if (
            not isinstance(relative, str)
            or not relative.strip()
            or not isinstance(expected_hash, str)
            or not re.fullmatch(r"[a-f0-9]{64}", expected_hash)
        ):
            errors.append(f"{label} path and SHA-256 are required")
            continue
        try:
            path = _inside(suite.root, relative)
        except ProtocolError as exc:
            errors.append(str(exc))
            continue
        if (suite.root / relative).is_symlink() or not path.is_file():
            errors.append(f"{label} must be a regular suite-local file")
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            errors.append(f"cannot read {label}: {exc}")
            continue
        if sha256_bytes(raw) != expected_hash:
            errors.append(f"{label} hash mismatch")
            continue
        loaded[field] = (path, raw)
    if errors or set(loaded) != set(fields):
        return errors

    from .program import (
        validate_judge_qualification_blueprint,
        validate_judge_qualification_blueprint_approval,
    )

    blueprint_path, blueprint_raw = loaded["qualification_blueprint"]
    errors.extend(validate_judge_qualification_blueprint(blueprint_path, suite, raw=blueprint_raw))
    approval_path, approval_raw = loaded["qualification_blueprint_approval"]
    errors.extend(
        validate_judge_qualification_blueprint_approval(
            approval_path,
            suite,
            str(judge["qualification_blueprint_sha256"]),
            raw=approval_raw,
            now=now,
            require_effective=require,
        )
    )
    return errors


def _load_suite_json_evidence(
    suite: Suite,
    relative: Any,
    expected_hash: Any,
    label: str,
    errors: list[str],
) -> dict[str, Any] | None:
    if (
        not isinstance(relative, str)
        or not relative.strip()
        or not isinstance(expected_hash, str)
        or not re.fullmatch(r"[a-f0-9]{64}", expected_hash)
    ):
        errors.append(f"official {label} path and SHA-256 are required")
        return None
    candidate = suite.root / relative
    try:
        path = _inside(suite.root, relative)
    except ProtocolError as exc:
        errors.append(str(exc))
        return None
    if candidate.is_symlink() or not path.is_file():
        errors.append(f"official {label} must be a regular suite-local file")
        return None
    try:
        raw = path.read_bytes()
        value = _strict_json_loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        errors.append(f"official {label} must be valid JSON")
        return None
    if sha256_bytes(raw) != expected_hash:
        errors.append(f"official {label} hash mismatch")
        return None
    if not isinstance(value, dict):
        errors.append(f"official {label} must be a JSON object")
        return None
    return value


def _evidence_time(value: Any, label: str, errors: list[str]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
    except ValueError:
        errors.append(f"official {label} must include a timezone")
        return None
    return parsed


def _calibration_evidence_errors(
    suite: Suite,
    calibration: Any,
    *,
    require_approval: bool = True,
    now: datetime | None = None,
) -> list[str]:
    if not isinstance(calibration, dict):
        return ["official suite calibration configuration is missing"]
    errors: list[str] = []
    report = _load_suite_json_evidence(
        suite,
        calibration.get("evidence"),
        calibration.get("evidence_sha256"),
        "calibration report",
        errors,
    )
    if report is None:
        return errors
    expected_suite = {
        "name": suite.name,
        "version": suite.version,
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
    }
    support_labels = {
        "analysis_plan": "calibration analysis plan",
        "human_label_evidence": "calibration human-label evidence",
        "holdout_manifest": "calibration holdout manifest",
        "pilot_campaign": "calibration pilot campaign",
        "pilot_audit": "calibration pilot audit",
        "statistical_review": "calibration statistical review",
        "semantic_contamination_evidence": "calibration semantic-contamination evidence",
    }
    report_fields = {
        "calibration_version",
        "status",
        "protocol_version",
        "suite",
        "source_commit",
        "gates_passed",
        "results",
        "completed_at",
        "limitations",
        *(support_labels),
        *(f"{field}_sha256" for field in support_labels),
    }
    if set(report) != report_fields:
        errors.append(f"official calibration report fields must be exactly {sorted(report_fields)}")
    if (
        report.get("calibration_version") != "2.0.0"
        or report.get("status") != "passed"
        or report.get("protocol_version") != PROTOCOL_VERSION
        or report.get("suite") != expected_suite
        or not isinstance(report.get("limitations"), list)
        or not report["limitations"]
        or not all(isinstance(value, str) and value.strip() for value in report["limitations"])
        or not isinstance(report.get("source_commit"), str)
        or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", report["source_commit"])
    ):
        errors.append("official calibration report is incomplete or did not pass")

    supports: dict[str, dict[str, Any]] = {}
    for field, label in support_labels.items():
        value = _load_suite_json_evidence(suite, report.get(field), report.get(f"{field}_sha256"), label, errors)
        if value is not None:
            supports[field] = value
    if set(supports) != set(support_labels):
        return errors

    integrity = suite.config.get("dataset_integrity") or {}
    if (
        report.get("semantic_contamination_evidence") != integrity.get("semantic_review_evidence")
        or report.get("semantic_contamination_evidence_sha256") != integrity.get("semantic_review_evidence_sha256")
    ):
        errors.append("official calibration report does not match semantic contamination evidence")
    elif isinstance(integrity, dict):
        errors.extend(_semantic_integrity_errors(suite, integrity))

    analysis = supports["analysis_plan"]
    statistics = suite.config.get("statistics") or {}
    expected_statistics = {
        "confidence": statistics.get("confidence", 0.95),
        "bootstrap_samples": statistics.get("bootstrap_samples", 10_000),
        "seed": statistics.get("seed", 0),
    }
    analysis_fields = {"analysis_plan_version", "status", "suite", "gates", "statistics", "frozen_at"}
    if (
        set(analysis) != analysis_fields
        or analysis.get("analysis_plan_version") != "1.0.0"
        or analysis.get("status") != "preregistered"
        or analysis.get("suite") != expected_suite
        or analysis.get("gates") != suite.config.get("gates")
        or analysis.get("statistics") != expected_statistics
    ):
        errors.append("official calibration analysis plan does not reconstruct the pinned suite")

    case_ids = sorted(str(case.get("id")) for case in suite.cases)
    approved_ids = sorted(
        str(case.get("id")) for case in suite.cases if (case.get("review") or {}).get("status") == "approved"
    )
    human = supports["human_label_evidence"]
    human_fields = {
        "human_label_evidence_version",
        "status",
        "suite",
        "case_ids",
        "approved_case_ids",
        "independent_reviewers",
        "separate_adjudicator",
        "identity_blinded",
        "completed_at",
    }
    reviewers = human.get("independent_reviewers")
    if (
        set(human) != human_fields
        or human.get("human_label_evidence_version") != "1.0.0"
        or human.get("status") != "passed"
        or human.get("suite") != expected_suite
        or human.get("case_ids") != case_ids
        or human.get("approved_case_ids") != case_ids
        or approved_ids != case_ids
        or not isinstance(reviewers, int)
        or isinstance(reviewers, bool)
        or reviewers < 2
        or human.get("separate_adjudicator") is not True
        or human.get("identity_blinded") is not True
    ):
        errors.append("official calibration human-label evidence does not reconstruct independent approval of every case")

    split_ids = {
        split: sorted(str(case.get("id")) for case in suite.cases if case.get("split") == split)
        for split in sorted(SPLITS)
    }
    holdout = supports["holdout_manifest"]
    holdout_fields = {"holdout_manifest_version", "status", "suite", "split_case_ids", "completed_at"}
    if (
        set(holdout) != holdout_fields
        or holdout.get("holdout_manifest_version") != "1.0.0"
        or holdout.get("status") != "passed"
        or holdout.get("suite") != expected_suite
        or holdout.get("split_case_ids") != split_ids
        or not split_ids["holdout"]
        or sorted(case_id for ids in split_ids.values() for case_id in ids) != case_ids
    ):
        errors.append("official calibration holdout manifest does not reconstruct an isolated complete split partition")

    campaign = supports["pilot_campaign"]
    campaign_path = _inside(suite.root, str(report["pilot_campaign"]))
    campaign_fields = {
        "campaign_version",
        "suite",
        "requirements",
        "judge_qualification",
        "judge_independent_approval",
        "transcript_review",
        "runs",
    }
    campaign_closure_valid = isinstance(campaign, dict) and set(campaign) == campaign_fields
    campaign_root = campaign_path.parent
    if campaign_closure_valid:
        for field in ("judge_qualification", "judge_independent_approval", "transcript_review"):
            record = campaign.get(field)
            if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
                campaign_closure_valid = False
                break
            relative = record.get("path")
            expected_hash = record.get("sha256")
            if not isinstance(relative, str) or not isinstance(expected_hash, str):
                campaign_closure_valid = False
                break
            candidate = campaign_root / relative
            resolved = candidate.resolve()
            try:
                resolved.relative_to(suite.root.resolve())
                raw = resolved.read_bytes()
                _strict_json_loads(raw)
            except (ValueError, OSError, UnicodeDecodeError, json.JSONDecodeError):
                campaign_closure_valid = False
                break
            if candidate.is_symlink() or not resolved.is_file() or sha256_bytes(raw) != expected_hash:
                campaign_closure_valid = False
                break
        runs_value = campaign.get("runs")
        if not isinstance(runs_value, list):
            campaign_closure_valid = False
        else:
            for record in runs_value:
                if not isinstance(record, dict) or set(record) != {"role", "family_alias", "path"}:
                    campaign_closure_valid = False
                    break
                relative = record.get("path")
                if not isinstance(relative, str):
                    campaign_closure_valid = False
                    break
                candidate = campaign_root / relative
                resolved = candidate.resolve()
                try:
                    resolved.relative_to(suite.root.resolve())
                except ValueError:
                    campaign_closure_valid = False
                    break
                if candidate.is_symlink() or not resolved.is_dir():
                    campaign_closure_valid = False
                    break
    if not campaign_closure_valid:
        errors.append("official calibration pilot campaign is not a strict suite-local evidence closure")
    else:
        from .pilot import audit_pilot_campaign

        try:
            with tempfile.TemporaryDirectory(prefix="cavada-pilot-audit-") as temporary:
                regenerated_path = Path(temporary) / "pilot-audit.json"
                audit_pilot_campaign(campaign_path, regenerated_path)
                regenerated_raw = regenerated_path.read_bytes()
            pinned_audit_raw = (suite.root / str(report["pilot_audit"])).read_bytes()
            if regenerated_raw != pinned_audit_raw:
                errors.append("official calibration pilot audit does not match the regenerated campaign audit")
        except (OSError, ProtocolError, ValueError) as exc:
            errors.append(f"official calibration pilot campaign could not be re-audited: {exc}")

    pilot = supports["pilot_audit"]
    pilot_fields = {
        "pilot_audit_version",
        "passed",
        "campaign_sha256",
        "suite",
        "requirements",
        "runs",
        "role_counts",
        "errors",
        "limitations",
    }
    pilot_suite = pilot.get("suite")
    requirements = pilot.get("requirements")
    runs = pilot.get("runs")
    role_counts = pilot.get("role_counts")
    judge_config = suite.config.get("judge") or {}
    try:
        blueprint_config = tomllib.loads(
            _inside(suite.root, str(judge_config.get("qualification_blueprint", ""))).read_text(encoding="utf-8")
        )
    except (OSError, ProtocolError, tomllib.TOMLDecodeError):
        blueprint_config = {}
    target_families = {
        str(row.get("family_alias"))
        for row in runs or []
        if isinstance(row, dict) and row.get("role") == "target" and row.get("family_alias")
    }
    if (
        set(pilot) != pilot_fields
        or pilot.get("pilot_audit_version") != "1.0.0"
        or pilot.get("passed") is not True
        or pilot.get("errors") != []
        or not isinstance(pilot.get("campaign_sha256"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", pilot.get("campaign_sha256", ""))
        or not isinstance(pilot_suite, dict)
        or any(pilot_suite.get(field) != value for field, value in expected_suite.items())
        or not isinstance(pilot_suite.get("suite_config_sha256"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", pilot_suite.get("suite_config_sha256", ""))
        or not isinstance(requirements, dict)
        or not isinstance(requirements.get("minimum_model_families"), int)
        or isinstance(requirements.get("minimum_model_families"), bool)
        or requirements["minimum_model_families"] < 4
        or any(
            requirements.get(campaign_field) != blueprint_config.get(blueprint_field)
            for campaign_field, blueprint_field in (
                ("minimum_model_families", "minimum_model_families"),
                ("minimum_target_repetitions", "minimum_target_repetitions"),
                ("minimum_judge_repetitions", "minimum_judge_repetitions"),
            )
        )
        or not isinstance(runs, list)
        or len(runs) < 6
        or len(target_families) < requirements.get("minimum_model_families", 4)
        or not isinstance(role_counts, dict)
        or role_counts != {
            "target": sum(isinstance(row, dict) and row.get("role") == "target" for row in runs or []),
            "positive-control": sum(isinstance(row, dict) and row.get("role") == "positive-control" for row in runs or []),
            "negative-control": sum(isinstance(row, dict) and row.get("role") == "negative-control" for row in runs or []),
        }
        or role_counts.get("positive-control", 0) < 1
        or role_counts.get("negative-control", 0) < 1
        or not isinstance(pilot.get("limitations"), list)
        or not pilot["limitations"]
        or not all(isinstance(value, str) and value.strip() for value in pilot["limitations"])
    ):
        errors.append("official calibration pilot audit does not reconstruct a passing controlled campaign")

    review = supports["statistical_review"]
    review_fields = {
        "statistical_review_version",
        "status",
        "suite",
        "analysis_plan_sha256",
        "human_label_evidence_sha256",
        "holdout_manifest_sha256",
        "pilot_audit_sha256",
        "pilot_campaign_sha256",
        "semantic_contamination_evidence_sha256",
        "independent",
        "reviewer_id",
        "conflicts",
        "conflicts_resolved",
        "decision_rationale",
        "completed_at",
    }
    linked_hashes = {
        field: report.get(field)
        for field in (
            "analysis_plan_sha256",
            "human_label_evidence_sha256",
            "holdout_manifest_sha256",
            "pilot_audit_sha256",
            "pilot_campaign_sha256",
            "semantic_contamination_evidence_sha256",
        )
    }
    if (
        set(review) != review_fields
        or review.get("statistical_review_version") != "1.0.0"
        or review.get("status") != "passed"
        or review.get("suite") != expected_suite
        or any(review.get(field) != value for field, value in linked_hashes.items())
        or review.get("independent") is not True
        or review.get("conflicts_resolved") is not True
        or not all(
            isinstance(review.get(field), str) and review[field].strip()
            for field in ("reviewer_id", "conflicts", "decision_rationale", "completed_at")
        )
    ):
        errors.append("official calibration statistical review is incomplete or not linked to the reconstructed evidence")

    expected_results = {
        "analysis_plan": "preregistered",
        "human_label_cases": len(case_ids),
        "holdout_cases": len(split_ids["holdout"]),
        "pilot_runs": len(runs) if isinstance(runs, list) else 0,
        "independent_reviewers": reviewers if isinstance(reviewers, int) and not isinstance(reviewers, bool) else 0,
        "all_preregistered_gates": "passed",
    }
    if report.get("results") != expected_results or report.get("gates_passed") is not True:
        errors.append("official calibration results do not match the reconstructed evidence")

    completed_at = _evidence_time(report.get("completed_at"), "calibration completed_at", errors)
    support_times = [
        _evidence_time(analysis.get("frozen_at"), "calibration analysis frozen_at", errors),
        _evidence_time(human.get("completed_at"), "calibration human-label completed_at", errors),
        _evidence_time(holdout.get("completed_at"), "calibration holdout completed_at", errors),
        _evidence_time(review.get("completed_at"), "calibration statistical-review completed_at", errors),
    ]
    if completed_at is not None and any(value is not None and value > completed_at for value in support_times):
        errors.append("official calibration report predates its supporting evidence")

    if not require_approval:
        return errors
    approval = _load_suite_json_evidence(
        suite,
        calibration.get("independent_review_evidence"),
        calibration.get("independent_review_evidence_sha256"),
        "calibration independent approval",
        errors,
    )
    if approval is None:
        return errors
    approval_expected_fields = {
        "approval_version",
        "approval_id",
        "scope",
        "status",
        "independent",
        "calibration_sha256",
        "approver_id",
        "approver_qualification_evidence",
        "approver_qualification_evidence_sha256",
        "conflicts",
        "conflicts_resolved",
        "decision_rationale",
        "approved_at",
        "expires_at",
        "revoked_at",
        "revocation_reason",
    }
    approval_fields = (
        "approval_id",
        "approver_id",
        "approver_qualification_evidence",
        "conflicts",
        "decision_rationale",
        "approved_at",
        "expires_at",
    )
    if (
        set(approval) != approval_expected_fields
        or approval.get("approval_version") != "2.0.0"
        or approval.get("scope") != "suite-calibration"
        or approval.get("status") != "passed"
        or approval.get("independent") is not True
        or approval.get("conflicts_resolved") is not True
        or approval.get("calibration_sha256") != calibration.get("evidence_sha256")
        or not all(isinstance(approval.get(field), str) and approval[field].strip() for field in approval_fields)
    ):
        errors.append("official calibration independent approval is incomplete, unlinked, or did not pass")
        return errors
    approver_evidence = approval.get("approver_qualification_evidence")
    approver_evidence_hash = approval.get("approver_qualification_evidence_sha256")
    _load_suite_json_evidence(
        suite,
        approver_evidence,
        approver_evidence_hash,
        "calibration approver qualification evidence",
        errors,
    )
    if approval.get("revoked_at") is not None or approval.get("revocation_reason") != "":
        errors.append("official calibration independent approval has been revoked")
    try:
        approved_at = datetime.fromisoformat(approval["approved_at"].replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(approval["expires_at"].replace("Z", "+00:00"))
    except ValueError:
        errors.append("official calibration approval timestamps are invalid")
        return errors
    current = now or datetime.now(timezone.utc)
    if approved_at.tzinfo is None or expires_at.tzinfo is None or approved_at > current or expires_at <= current or expires_at <= approved_at:
        errors.append("official calibration independent approval is not currently effective")
    if completed_at is not None and approved_at < completed_at:
        errors.append("official calibration independent approval predates the calibration report")
    return errors


def validate_suite(
    suite: Suite,
    *,
    official: bool = False,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    config = suite.config
    for field in ("name", "version", "status", "description", "dataset", "rubric", "data_classification"):
        if not isinstance(config.get(field), str) or not str(config[field]).strip():
            errors.append(f"suite.{field} is required")
    if config.get("protocol_version") != PROTOCOL_VERSION:
        errors.append(f"protocol_version must be {PROTOCOL_VERSION}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(config.get("version", ""))):
        errors.append("suite.version must be semantic x.y.z")
    if config.get("status") not in SUITE_STATUSES:
        errors.append(f"suite.status must be one of {sorted(SUITE_STATUSES)}")
    if config.get("data_classification") not in DATA_CLASSES:
        errors.append(f"suite.data_classification must be one of {sorted(DATA_CLASSES)}")
    for index, gate in enumerate(config.get("gates", [])):
        if not isinstance(gate, dict):
            errors.append(f"gates[{index}] must be a table")
            continue
        category, slice_name, slice_value = gate.get("category"), gate.get("slice"), gate.get("value")
        if category and slice_name:
            errors.append(f"gates[{index}] cannot target both category and slice")
        if slice_name not in {None, "risk_domain", "severity", "language", "locale", "split", "operating_condition"}:
            errors.append(f"gates[{index}].slice is unsupported")
        if bool(slice_name) != bool(isinstance(slice_value, str) and slice_value):
            errors.append(f"gates[{index}] slice gates require both slice and value")
        if not isinstance(gate.get("metric"), str) or not gate["metric"]:
            errors.append(f"gates[{index}].metric must be a non-empty string")
        minimum = gate.get("min")
        if not isinstance(minimum, (int, float)) or isinstance(minimum, bool) or not math.isfinite(float(minimum)):
            errors.append(f"gates[{index}].min must be a finite number")
    profile = config.get("profile", "text-generation")
    if profile not in TASK_PROFILES:
        errors.append(f"suite.profile must be one of {sorted(TASK_PROFILES)}")
    elif official and not TASK_PROFILES[str(profile)]["built_in"]:
        errors.append(f"official suite profile {profile!r} requires a pinned approved external adapter")
    if official:
        errors.extend(_official_suite_structure_errors(suite))
    if not suite.cases:
        errors.append("dataset is empty")
    if contains_secret_like(config) or contains_secret_like(suite.rubric):
        errors.append("suite configuration or rubric contains secret-like material")
    pinned_dataset = config.get("dataset_sha256")
    pinned_rubric = config.get("rubric_sha256")
    if pinned_dataset and pinned_dataset != sha256_file(suite.dataset_path):
        errors.append("dataset_sha256 does not match dataset")
    if pinned_rubric and pinned_rubric != sha256_file(suite.rubric_path):
        errors.append("rubric_sha256 does not match rubric")
    for field in ("temperature",):
        if field in config and (not isinstance(config[field], (int, float)) or not 0 <= float(config[field]) <= 2):
            errors.append(f"suite.{field} must be a number from 0 to 2")
    for field in ("max_tokens", "official_min_repetitions", "official_min_judge_repetitions"):
        if field in config and (not isinstance(config[field], int) or isinstance(config[field], bool) or config[field] < 1):
            errors.append(f"suite.{field} must be a positive integer")
    statistics = config.get("statistics") or {}
    if not isinstance(statistics, dict):
        errors.append("suite.statistics must be a table")
    else:
        confidence = statistics.get("confidence", 0.95)
        samples = statistics.get("bootstrap_samples", 10_000)
        seed = statistics.get("seed", 0)
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 < float(confidence) < 1:
            errors.append("statistics.confidence must be between 0 and 1")
        if not isinstance(samples, int) or isinstance(samples, bool) or samples < 100:
            errors.append("statistics.bootstrap_samples must be an integer of at least 100")
        if not isinstance(seed, int) or isinstance(seed, bool):
            errors.append("statistics.seed must be an integer")
    target = config.get("target") or {}
    target_kind = target.get("kind", "json") if isinstance(target, dict) else None
    if target_kind not in {"json", "openai", "recorded"}:
        errors.append("target.kind must be json, openai, or recorded")
    request_defaults = target.get("request_defaults_json") if isinstance(target, dict) else None
    if request_defaults is not None:
        try:
            request_defaults_value = _strict_json_loads(request_defaults) if isinstance(request_defaults, str) else None
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            errors.append(f"target.request_defaults_json must be strict finite JSON: {exc}")
        else:
            if not isinstance(request_defaults_value, dict):
                errors.append("target.request_defaults_json must encode an object")
    if target_kind == "recorded":
        relative = target.get("responses")
        if not isinstance(relative, str):
            errors.append("recorded target requires target.responses")
        else:
            try:
                responses_path = _inside(suite.root, relative)
            except ProtocolError as exc:
                errors.append(str(exc))
            else:
                if not responses_path.is_file() or responses_path.is_symlink():
                    errors.append("recorded target responses must be a regular in-suite file")
                elif official and target.get("responses_sha256") != sha256_file(responses_path):
                    errors.append("official recorded target requires matching target.responses_sha256")
    system_prompt = target.get("system_prompt") if isinstance(target, dict) else None
    if system_prompt is not None:
        if target_kind != "openai" or not isinstance(system_prompt, str) or not system_prompt:
            errors.append("target.system_prompt requires a non-empty in-suite path and target.kind=openai")
        else:
            try:
                system_prompt_path = _inside(suite.root, system_prompt)
            except ProtocolError as exc:
                errors.append(str(exc))
            else:
                if not system_prompt_path.is_file() or system_prompt_path.is_symlink():
                    errors.append("target.system_prompt must be a regular in-suite file")
                elif official and target.get("system_prompt_sha256") != sha256_file(system_prompt_path):
                    errors.append("official target requires matching target.system_prompt_sha256")
    capabilities = target.get("capabilities", []) if isinstance(target, dict) else []
    if capabilities and (not isinstance(capabilities, list) or not all(isinstance(item, str) and item for item in capabilities)):
        errors.append("target.capabilities must be an array of non-empty strings")
    if official and profile in TASK_PROFILES:
        missing_capabilities = sorted(set(TASK_PROFILES[str(profile)]["inputs"]) - set(capabilities))
        if missing_capabilities:
            errors.append(f"target.capabilities missing profile requirements: {missing_capabilities}")
    pricing = config.get("pricing")
    if pricing is not None:
        required_pricing = {"currency", "source", "effective_at", "input_per_million", "output_per_million"}
        if not isinstance(pricing, dict) or not required_pricing <= set(pricing):
            errors.append(f"pricing is missing fields: {sorted(required_pricing - set(pricing or {}))}")
        elif not all(isinstance(pricing[field], str) and pricing[field].strip() for field in ("currency", "source", "effective_at")) or not all(
            isinstance(pricing[field], (int, float)) and not isinstance(pricing[field], bool) and float(pricing[field]) >= 0
            for field in ("input_per_million", "output_per_million")
        ):
            errors.append("pricing text fields must be non-empty and rates must be non-negative numbers")
        if isinstance(pricing, dict):
            for field in ("judge_input_per_million", "judge_output_per_million"):
                if field in pricing and (not isinstance(pricing[field], (int, float)) or isinstance(pricing[field], bool) or float(pricing[field]) < 0):
                    errors.append(f"pricing.{field} must be a non-negative number")

    errors.extend(_judge_blueprint_evidence_errors(suite, require=official, now=now))

    governance = config.get("governance")
    governance_fields = {
        "owner",
        "purpose",
        "intended_use",
        "prohibited_use",
        "license",
        "origin",
        "created_at",
        "retention",
        "personal_data",
        "legal_basis_reference",
        "rotation_due",
        "contamination_status",
        "canary_strategy",
        "known_leaks",
        "representativeness",
        "transfer_restrictions",
    }
    if official:
        if not isinstance(governance, dict):
            errors.append("official runs require a [governance] table")
        else:
            for field in governance_fields:
                value = governance.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"governance.{field} is required for official runs")
            for date_field in ("created_at", "rotation_due"):
                value = governance.get(date_field)
                if isinstance(value, str) and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                    errors.append(f"governance.{date_field} must be YYYY-MM-DD")
            threshold = governance.get("near_duplicate_threshold")
            if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not 0.8 <= float(threshold) < 1:
                errors.append("governance.near_duplicate_threshold must be a number from 0.8 (inclusive) to 1 (exclusive)")
            semantic_threshold = governance.get("semantic_duplicate_threshold")
            if (
                not isinstance(semantic_threshold, (int, float))
                or isinstance(semantic_threshold, bool)
                or not 0.8 <= float(semantic_threshold) <= 1
            ):
                errors.append("governance.semantic_duplicate_threshold must be a number from 0.8 through 1")

    seen_ids: set[str] = set()
    cases_by_id: dict[str, dict[str, Any]] = {}
    seen_inputs: set[str] = set()
    normalized_inputs: list[tuple[str, str, str | None]] = []
    for index, case in enumerate(suite.cases, 1):
        prefix = f"case[{index}]"
        case_id = case.get("id")
        prompt = case.get("input")
        if not isinstance(case_id, str) or not case_id.strip():
            errors.append(f"{prefix}.id is required")
        elif case_id in seen_ids:
            errors.append(f"duplicate case id: {case_id}")
        else:
            seen_ids.add(case_id)
            cases_by_id[case_id] = case
        part_errors = validate_content_parts(
            prompt,
            suite_root=suite.root,
            official=official,
            max_asset_bytes=int((config.get("assets") or {}).get("max_bytes", 25 * 1024 * 1024)),
            max_image_pixels=int((config.get("assets") or {}).get("max_image_pixels", 100_000_000)),
            max_audio_seconds=float((config.get("assets") or {}).get("max_audio_seconds", 3600)),
        )
        errors.extend(f"{prefix}.{message}" for message in part_errors)
        errors.extend(
            f"{prefix}.{message}"
            for message in validate_messages(
                case.get("messages"),
                suite_root=suite.root,
                official=official,
                max_asset_bytes=int((config.get("assets") or {}).get("max_bytes", 25 * 1024 * 1024)),
                max_image_pixels=int((config.get("assets") or {}).get("max_image_pixels", 100_000_000)),
                max_audio_seconds=float((config.get("assets") or {}).get("max_audio_seconds", 3600)),
            )
        )
        messages = case.get("messages")
        if isinstance(messages, list) and messages and isinstance(messages[-1], dict) and messages[-1].get("content") != prompt:
            errors.append(f"{prefix}.input must exactly match the final user message content")
        conversation_text = "\n".join(content_text(message.get("content")) for message in case.get("messages", []) if isinstance(message, dict))
        normalized_prompt = unicodedata.normalize("NFKC", content_text(prompt) + "\n" + conversation_text).casefold()
        normalized_prompt = " ".join(normalized_prompt.split())
        if normalized_prompt in seen_inputs:
            errors.append(f"duplicate case input: {case_id}")
        else:
            seen_inputs.add(normalized_prompt)
            group = case.get("scenario_group_id")
            normalized_inputs.append((str(case_id), normalized_prompt, group if isinstance(group, str) and group else None))
        if case.get("expected_behavior") not in BEHAVIORS:
            errors.append(f"{prefix}.expected_behavior is invalid")
        if case.get("risk_domain") not in RISK_DOMAINS:
            errors.append(f"{prefix}.risk_domain is invalid")
        if case.get("severity") not in SEVERITIES:
            errors.append(f"{prefix}.severity is invalid")
        if not isinstance(case.get("category"), str) or not case["category"].strip():
            errors.append(f"{prefix}.category is required")
        if not isinstance(case.get("expected_behavior_reason"), str) or not case["expected_behavior_reason"].strip():
            errors.append(f"{prefix}.expected_behavior_reason is required")
        if "mandatory_criteria" in case and (
            not isinstance(case["mandatory_criteria"], list)
            or not case["mandatory_criteria"]
            or not all(isinstance(value, str) and value.strip() for value in case["mandatory_criteria"])
        ):
            errors.append(f"{prefix}.mandatory_criteria must be a non-empty string array")
        review = case.get("review")
        if not isinstance(review, dict) or review.get("status") not in REVIEW_STATUSES:
            errors.append(f"{prefix}.review.status is invalid")
        text = json.dumps(case, ensure_ascii=False)
        if contains_secret_like(text):
            errors.append(f"{prefix} contains secret-like material")
        if "weight" in case and (not isinstance(case["weight"], (int, float)) or isinstance(case["weight"], bool) or float(case["weight"]) <= 0):
            errors.append(f"{prefix}.weight must be positive")
        metric_weights = case.get("metric_weights")
        if metric_weights is not None and (
            not isinstance(metric_weights, dict)
            or not all(
                isinstance(name, str) and isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)) and float(value) >= 0
                for name, value in metric_weights.items()
            )
        ):
            errors.append(f"{prefix}.metric_weights must map names to finite non-negative numbers")
        if "soft_checks" in case and (not isinstance(case["soft_checks"], list) or not all(isinstance(name, str) and name for name in case["soft_checks"])):
            errors.append(f"{prefix}.soft_checks must be an array of non-empty strings")
        if "exact_tool_order" in case and (
            not isinstance(case["exact_tool_order"], list)
            or not all(isinstance(name, str) and name for name in case["exact_tool_order"])
        ):
            errors.append(f"{prefix}.exact_tool_order must be an array of non-empty strings")
        if "judge_gold_verdict" in case and case["judge_gold_verdict"] not in {"pass", "fail"}:
            errors.append(f"{prefix}.judge_gold_verdict must be pass or fail")
        if "performance_phase" in case and case["performance_phase"] not in {"cold", "warmup", "steady", "soak"}:
            errors.append(f"{prefix}.performance_phase is invalid")
        if case.get("scenario_reference_id") is not None and case.get("scenario_role") != "variant":
            errors.append(f"{prefix}.scenario_reference_id is only valid for scenario variants")
        if "split" in case and case["split"] not in SPLITS:
            errors.append(f"{prefix}.split must be one of {sorted(SPLITS)}")
        for field in ("language", "locale"):
            if field in case and (not isinstance(case[field], str) or not case[field].strip()):
                errors.append(f"{prefix}.{field} must be non-empty text")

    scenario_groups: dict[str, list[dict[str, Any]]] = {}
    for case in suite.cases:
        if case.get("scenario_role") is not None:
            scenario_groups.setdefault(str(case.get("scenario_group_id", "")), []).append(case)
    for group_id, members in scenario_groups.items():
        if not group_id:
            errors.append("scenario_role requires scenario_group_id")
            continue
        all_members = [case for case in suite.cases if str(case.get("scenario_group_id", "")) == group_id]
        if len(all_members) != len(members):
            errors.append(f"scenario group {group_id}: every case must declare scenario_role")
            continue
        primaries = [case for case in members if case.get("scenario_role") == "primary"]
        if len(primaries) != 1:
            errors.append(f"scenario group {group_id}: exactly one primary case is required")
            continue
        primary_id = str(primaries[0].get("id", ""))
        for case in members:
            case_id = str(case.get("id", ""))
            role = case.get("scenario_role")
            reference_id = case.get("scenario_reference_id")
            if role not in {"primary", "variant"}:
                errors.append(f"case {case_id}: scenario_role is invalid")
            elif role == "primary" and reference_id is not None:
                errors.append(f"case {case_id}: a primary case cannot have scenario_reference_id")
            elif role == "variant" and reference_id != primary_id:
                errors.append(f"case {case_id}: variant must reference its scenario primary {primary_id}")

    for case in suite.cases:
        case_id = str(case.get("id", ""))
        reference_id = case.get("distribution_shift_reference_id")
        if case.get("operating_condition") != "distribution-shift":
            if reference_id is not None:
                errors.append(f"case {case_id}: distribution_shift_reference_id is only valid for distribution-shift cases")
            continue
        if not isinstance(case.get("distribution_shift_dimension"), str) or not case["distribution_shift_dimension"].strip():
            errors.append(f"case {case_id}: distribution_shift_dimension is required")
        if not isinstance(reference_id, str) or not reference_id.strip():
            errors.append(f"case {case_id}: distribution_shift_reference_id is required")
            continue
        reference = cases_by_id.get(reference_id)
        if reference is None:
            errors.append(f"case {case_id}: distribution-shift reference does not exist: {reference_id}")
            continue
        if reference.get("operating_condition") == "distribution-shift":
            errors.append(f"case {case_id}: distribution-shift reference must be an in-distribution case")
        for field in ("category", "language", "locale", "split", "expected_behavior"):
            if case.get(field) != reference.get(field):
                errors.append(f"case {case_id}: distribution-shift reference must match {field}")

    near_threshold = (governance or {}).get("near_duplicate_threshold") if isinstance(governance, dict) else None
    if isinstance(near_threshold, (int, float)) and not isinstance(near_threshold, bool):
        if len(normalized_inputs) > 5_000:
            errors.append("near-duplicate validation is limited to 5,000 cases; use a reviewed indexed detector for larger suites")
        else:
            # ponytail: quadratic by design for suites <=5k; replace with MinHash only when that ceiling is hit.
            for index, (left_id, left, left_group) in enumerate(normalized_inputs):
                for right_id, right, right_group in normalized_inputs[index + 1 :]:
                    if left_group is not None and left_group == right_group:
                        continue
                    ratio = difflib.SequenceMatcher(None, left, right, autojunk=False).ratio()
                    if float(near_threshold) <= ratio < 1:
                        errors.append(f"near-duplicate case inputs: {left_id}, {right_id} (similarity={ratio:.3f})")

    if official:
        if suite.status != "approved":
            errors.append("official runs require suite.status=approved")
        calibration = suite.config.get("calibration") or {}
        if calibration.get("status") != "passed" or not calibration.get("evidence"):
            errors.append("official runs require passed calibration evidence")
        if calibration.get("independent_review") != "passed":
            errors.append("official runs require passed independent calibration review")
        errors.extend(_calibration_evidence_errors(suite, calibration, now=now))
        allowed_hosts = (suite.config.get("network") or {}).get("allowed_hosts")
        if not isinstance(allowed_hosts, list) or not allowed_hosts or not all(isinstance(host, str) and host for host in allowed_hosts):
            errors.append("official runs require network.allowed_hosts")
        unresolved = [case.get("id") for case in suite.cases if (case.get("review") or {}).get("status") != "approved"]
        if unresolved:
            errors.append(f"official runs require all cases approved; unresolved={len(unresolved)}")
        if not suite.config.get("gates"):
            errors.append("official runs require at least one gate")
        if not pinned_dataset or not pinned_rubric:
            errors.append("official runs require pinned dataset_sha256 and rubric_sha256")
        integrity = suite.config.get("dataset_integrity")
        if not isinstance(integrity, dict) or integrity.get("semantic_review_status") != "passed":
            errors.append("official runs require passed semantic contamination review")
        elif (
            not isinstance(integrity.get("semantic_review_evidence_sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", integrity["semantic_review_evidence_sha256"])
            or not isinstance(integrity.get("semantic_detector"), str)
            or not integrity["semantic_detector"].strip()
            or not isinstance(integrity.get("semantic_detector_revision"), str)
            or not integrity["semantic_detector_revision"].strip()
            or integrity.get("cross_split_reviewed") is not True
            or integrity.get("cross_suite_reviewed") is not True
        ):
            errors.append("official semantic contamination evidence is incomplete or unpinned")
        else:
            errors.extend(_semantic_integrity_errors(suite, integrity))
        missing_provenance = [
            case.get("id")
            for case in suite.cases
            if not isinstance(case.get("source"), dict)
            or not isinstance((case.get("source") or {}).get("origin"), str)
            or not case["source"]["origin"].strip()
            or not isinstance((case.get("review") or {}).get("method"), str)
            or not case["review"]["method"].strip()
        ]
        if missing_provenance:
            errors.append(f"official runs require source and review method; missing={len(missing_provenance)}")
        missing_case_governance = [
            case.get("id")
            for case in suite.cases
            if not isinstance(case.get("language"), str)
            or not isinstance(case.get("locale"), str)
            or case.get("split") not in SPLITS
            or not isinstance(case.get("tags"), list)
            or not case.get("tags")
            or not all(isinstance(tag, str) and tag.strip() for tag in case.get("tags", []))
        ]
        if missing_case_governance:
            errors.append(f"official runs require language, locale, split and valid tags for every case; missing={len(missing_case_governance)}")
        for finding in dataset_quality_findings(suite):
            errors.append(f"official dataset quality gate: {finding}")
    return errors


def audit_suite(suite: Suite) -> dict[str, Any]:
    categories: dict[str, int] = {}
    behaviors: dict[str, int] = {}
    reviews: dict[str, int] = {}
    risks: dict[str, int] = {}
    severities: dict[str, int] = {}
    languages: dict[str, int] = {}
    locales: dict[str, int] = {}
    splits: dict[str, int] = {}
    for case in suite.cases:
        categories[case["category"]] = categories.get(case["category"], 0) + 1
        behaviors[case["expected_behavior"]] = behaviors.get(case["expected_behavior"], 0) + 1
        status = case["review"]["status"]
        reviews[status] = reviews.get(status, 0) + 1
        for value, destination in (
            (case.get("risk_domain", "missing"), risks),
            (case.get("severity", "missing"), severities),
            (case.get("language", "missing"), languages),
            (case.get("locale", "missing"), locales),
            (case.get("split", "missing"), splits),
        ):
            destination[str(value)] = destination.get(str(value), 0) + 1
    semantic_candidates = semantic_duplicate_candidates(suite)
    scenario_roles = {str(case.get("scenario_role")) for case in suite.cases if case.get("scenario_role") is not None}
    primary_cases = [case for case in suite.cases if case.get("scenario_role") == "primary"] if scenario_roles else []
    scenario_categories: dict[str, int] = {}
    for case in primary_cases:
        scenario_categories[str(case["category"])] = scenario_categories.get(str(case["category"]), 0) + 1
    return {
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "suite": f"{suite.name}@{suite.version}",
        "status": suite.status,
        "cases": len(suite.cases),
        "analysis_unit": "scenario" if primary_cases else "case",
        "independent_scenarios": len(primary_cases) if primary_cases else len(suite.cases),
        "scenario_variants": len(suite.cases) - len(primary_cases) if primary_cases else 0,
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
        "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
        "categories": dict(sorted(categories.items())),
        "scenario_categories": dict(sorted(scenario_categories.items())) if primary_cases else dict(sorted(categories.items())),
        "expected_behaviors": dict(sorted(behaviors.items())),
        "reviews": dict(sorted(reviews.items())),
        "risk_domains": dict(sorted(risks.items())),
        "severities": dict(sorted(severities.items())),
        "languages": dict(sorted(languages.items())),
        "locales": dict(sorted(locales.items())),
        "splits": dict(sorted(splits.items())),
        "quality_findings": dataset_quality_findings(suite),
        "semantic_duplicate_candidates": {"count": len(semantic_candidates), "sample": semantic_candidates[:20]},
        "minimum_sample_guidance": "Use suite-specific power analysis; category gates should normally have at least 30 independent cases.",
    }


def dataset_quality_findings(suite: Suite) -> list[str]:
    findings: list[str] = []
    counts: dict[str, int] = {}
    primary_cases = [case for case in suite.cases if case.get("scenario_role") == "primary"]
    analysis_cases = primary_cases if primary_cases else list(suite.cases)
    unit = "independent scenarios" if primary_cases else "cases"
    for case in analysis_cases:
        counts[str(case.get("category", "missing"))] = counts.get(str(case.get("category", "missing")), 0) + 1
    total = len(analysis_cases)
    minimum = int((suite.config.get("governance") or {}).get("minimum_category_cases", 1))
    maximum_share = float((suite.config.get("governance") or {}).get("maximum_category_share", 1.0))
    for category, count in sorted(counts.items()):
        if count < minimum:
            findings.append(f"category {category!r} has {count} {unit}; minimum is {minimum}")
        if total and count / total > maximum_share:
            findings.append(f"category {category!r} represents {count / total:.1%}; maximum is {maximum_share:.1%}")
    unresolved = sum((case.get("review") or {}).get("status") != "approved" for case in suite.cases)
    if unresolved:
        findings.append(f"{unresolved} cases have unresolved review status")
    semantic_candidates = semantic_duplicate_candidates(suite)
    if semantic_candidates:
        findings.append(f"{len(semantic_candidates)} potential token-containment duplicate pairs require review")
    return findings


def semantic_duplicate_candidates(suite: Suite) -> list[dict[str, Any]]:
    threshold = float((suite.config.get("governance") or {}).get("semantic_duplicate_threshold", 0.95))
    rows: list[tuple[str, str | None, set[str]]] = []
    for case in suite.cases:
        text = unicodedata.normalize("NFKC", content_text(case.get("input"))).casefold()
        tokens = set(re.findall(r"\w+", text))
        group = case.get("scenario_group_id")
        rows.append((str(case.get("id")), group if isinstance(group, str) and group else None, tokens))
    candidates: list[dict[str, Any]] = []
    for index, (left_id, left_group, left) in enumerate(rows):
        for right_id, right_group, right in rows[index + 1 :]:
            if left_group is not None and left_group == right_group or not left or not right:
                continue
            containment = len(left & right) / min(len(left), len(right))
            if containment >= threshold:
                candidates.append({"left": left_id, "right": right_id, "token_containment": containment})
    return candidates


def dataset_card(suite: Suite) -> str:
    audit = audit_suite(suite)
    governance = suite.config.get("governance") or {}
    sections = [
        f"# Dataset card: {suite.name}@{suite.version}",
        "",
        f"- Status: `{suite.status}`",
        f"- Cases: {audit['cases']}",
        f"- Dataset SHA-256: `{audit['dataset_sha256']}`",
        f"- Owner: {governance.get('owner', 'missing')}",
        f"- Purpose: {governance.get('purpose', 'missing')}",
        f"- Intended use: {governance.get('intended_use', 'missing')}",
        f"- Prohibited use: {governance.get('prohibited_use', 'missing')}",
        f"- License: {governance.get('license', 'missing')}",
        f"- Origin: {governance.get('origin', 'missing')}",
        f"- Personal data: {governance.get('personal_data', 'missing')}",
        f"- Retention: {governance.get('retention', 'missing')}",
        f"- Rotation due: {governance.get('rotation_due', 'missing')}",
        f"- Contamination status: {governance.get('contamination_status', 'missing')}",
        f"- Canary strategy: {governance.get('canary_strategy', 'missing')}",
        f"- Known leaks: {governance.get('known_leaks', 'missing')}",
        f"- Representativeness: {governance.get('representativeness', 'missing')}",
        f"- Transfer restrictions: {governance.get('transfer_restrictions', 'missing')}",
        "",
        "## Coverage",
        "",
    ]
    for key in ("categories", "risk_domains", "severities", "languages", "locales", "splits", "expected_behaviors", "reviews"):
        sections.append(f"- {key}: `{json.dumps(audit[key], ensure_ascii=False, sort_keys=True)}`")
    sections.extend(
        [
            "",
            "## Limitations",
            "",
            "This card describes the sampled dataset. It does not establish representativeness,",
            "absence of contamination, legal compliance, or validity outside the declared purpose.",
            "",
        ]
    )
    return "\n".join(sections)


def promotion_readiness(suite: Suite, target_status: str) -> list[str]:
    order = ["draft", "candidate", "calibrated", "approved", "deprecated", "retired"]
    if target_status not in SUITE_STATUSES:
        return [f"unknown target status: {target_status}"]
    current = order.index(suite.status)
    target = order.index(target_status)
    if target != current + 1:
        return [f"promotion must follow lifecycle order; {suite.status} -> {target_status} is not allowed"]
    if target_status in {"deprecated", "retired"}:
        return []

    errors = validate_suite(suite, official=False)
    governance = suite.config.get("governance") or {}
    for field in (
        "owner",
        "purpose",
        "intended_use",
        "prohibited_use",
        "license",
        "origin",
        "created_at",
        "retention",
        "personal_data",
        "legal_basis_reference",
        "rotation_due",
        "contamination_status",
        "canary_strategy",
        "known_leaks",
        "representativeness",
        "transfer_restrictions",
    ):
        if not isinstance(governance.get(field), str) or not governance[field].strip():
            errors.append(f"governance.{field} is required for promotion")
    if target_status in {"calibrated", "approved"}:
        if not suite.config.get("dataset_sha256") or not suite.config.get("rubric_sha256"):
            errors.append("calibrated and approved suites require pinned dataset and rubric hashes")
        unresolved = [case["id"] for case in suite.cases if case.get("review", {}).get("status") != "approved"]
        if unresolved:
            errors.append(f"all cases must be approved before calibration; unresolved={len(unresolved)}")
        calibration = suite.config.get("calibration") or {}
        if calibration.get("status") != "passed" or not calibration.get("evidence"):
            errors.append("calibration.status=passed and calibration.evidence are required")
        if target_status == "approved" and calibration.get("independent_review") != "passed":
            errors.append("calibration.independent_review=passed is required")
        errors.extend(_calibration_evidence_errors(suite, calibration, require_approval=target_status == "approved"))
    if target_status == "approved":
        calibration = suite.config.get("calibration") or {}
        if calibration.get("independent_review") != "passed":
            errors.append("approval requires calibration.independent_review=passed")
        proposed = Suite(
            suite.root,
            {**copy.deepcopy(suite.config), "status": "approved"},
            suite.cases,
            suite.rubric,
            suite.dataset_path,
            suite.rubric_path,
        )
        errors.extend(validate_suite(proposed, official=True))
    return list(dict.fromkeys(errors))


def promote_suite(suite: Suite, target_status: str, *, actor: str, evidence: str) -> dict[str, Any]:
    if not actor.strip() or not evidence.strip():
        raise ProtocolError("promotion requires non-empty actor and evidence")
    errors = promotion_readiness(suite, target_status)
    if errors:
        raise ProtocolError("\n".join(errors))
    path = suite.root / "suite.toml"
    source = path.read_text(encoding="utf-8")
    updated, replacements = re.subn(
        r'(?m)^status\s*=\s*"[^"]+"\s*$',
        f'status = "{target_status}"',
        source,
        count=1,
    )
    if replacements != 1:
        raise ProtocolError("suite.toml must contain exactly one top-level status assignment")
    atomic_text(path, updated)
    record = {
        "protocol_version": PROTOCOL_VERSION,
        "suite": suite.name,
        "version": suite.version,
        "from": suite.status,
        "to": target_status,
        "actor": actor,
        "evidence": evidence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
    }
    append_jsonl(suite.root / "promotions.jsonl", record)
    return record


def wilson_interval(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    if not 0 < confidence < 1:
        raise ProtocolError("confidence must be between 0 and 1")
    z = NormalDist().inv_cdf(0.5 + confidence / 2)
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def wilson_gate_power(total: int, gate: float, true_rate: float, confidence: float = 0.95) -> float:
    if total < 1 or total > 100_000:
        raise ProtocolError("total must be between 1 and 100,000")
    if not 0 < gate <= true_rate <= 1:
        raise ProtocolError("gate and true_rate must satisfy 0 < gate <= true_rate <= 1")
    if true_rate == 1:
        return float(wilson_interval(total, total, confidence)[0] >= gate)
    log_p = math.log(true_rate)
    log_q = math.log1p(-true_rate)
    probabilities = (
        math.exp(
            math.lgamma(total + 1)
            - math.lgamma(successes + 1)
            - math.lgamma(total - successes + 1)
            + successes * log_p
            + (total - successes) * log_q
        )
        for successes in range(total + 1)
        if wilson_interval(successes, total, confidence)[0] >= gate
    )
    return min(1.0, math.fsum(probabilities))


def deterministic_checks(case: dict[str, Any], answer: str) -> dict[str, bool]:
    from .metrics import deterministic_evaluation

    return cast(dict[str, bool], deterministic_evaluation(case, answer)["checks"])


def git_evidence(root: Path) -> dict[str, Any]:
    def command(*args: str) -> str:
        executable = shutil.which("git")
        if not executable:
            return ""
        result = subprocess.run(  # noqa: S603 -- executable is resolved from the operator-controlled PATH.
            [executable, *args], cwd=root, text=True, capture_output=True, check=False, timeout=10
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    commit = command("rev-parse", "HEAD")
    status = command("status", "--porcelain", "--untracked-files=normal")
    return {"commit": commit, "dirty": bool(status), "status_sha256": sha256_bytes(status.encode())}


def environment_evidence(root: Path) -> dict[str, Any]:
    lock = root / "uv.lock"
    hardware: dict[str, Any] = {"machine": platform.machine(), "cpu_count": os.cpu_count()}
    processor = platform.processor()
    if processor and len(processor) <= 256 and processor.isprintable() and not re.search(r"[{}\[\]]|\b(?:serial|uuid|secret|token)\b", processor, re.IGNORECASE):
        hardware["processor"] = processor
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        physical_pages = os.sysconf("SC_PHYS_PAGES")
        hardware["memory_bytes"] = int(page_size) * int(physical_pages)
    except (AttributeError, OSError, ValueError):
        pass
    try:
        executable = shutil.which("nvidia-smi")
        if not executable:
            raise FileNotFoundError
        gpu = subprocess.run(  # noqa: S603 -- fixed arguments and a resolved local executable.
            [executable, "--query-gpu=name,uuid", "--format=csv,noheader"],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
        if gpu.returncode == 0:
            hardware["gpus"] = [line.strip() for line in gpu.stdout.splitlines() if line.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    if "gpus" not in hardware:
        try:
            executable = shutil.which("amd-smi")
            if not executable:
                raise FileNotFoundError
            gpu = subprocess.run(  # noqa: S603 -- fixed arguments and a resolved local executable.
                [executable, "static", "--asic", "--vram", "--json"],
                text=True,
                capture_output=True,
                check=False,
                timeout=5,
            )
            payload = json.loads(gpu.stdout) if gpu.returncode == 0 else {}
            rows = payload.get("gpu_data", []) if isinstance(payload, dict) else []
            inventory = []
            for row in rows if isinstance(rows, list) else []:
                asic = row.get("asic", {}) if isinstance(row, dict) else {}
                vram = row.get("vram", {}) if isinstance(row, dict) else {}
                size = vram.get("size", {}) if isinstance(vram, dict) else {}
                if isinstance(asic, dict) and isinstance(size, dict):
                    inventory.append(
                        f"{asic.get('market_name', 'AMD GPU')}, {asic.get('target_graphics_version', 'unknown')}, "
                        f"{size.get('value', 'unknown')} {size.get('unit', '')}, subsystem {asic.get('subsystem_id', 'unknown')}"
                    )
            if inventory:
                hardware["gpus"] = inventory
                hardware["gpu_inventory_source"] = "amd-smi"
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "hardware": hardware,
        "uv_lock_sha256": sha256_file(lock) if lock.is_file() else "",
    }


def new_run_dir(root: Path, suite: Suite, model_label: str) -> tuple[str, Path]:
    now = datetime.now(timezone.utc)
    run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    safe_model = re.sub(r"[^A-Za-z0-9_.-]+", "-", model_label).strip("-") or "model"
    path = root / "runs" / suite.name / f"{run_id}_{safe_model}"
    path.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(path, 0o700)
    return run_id, path


def summarize(rows: Iterable[dict[str, Any]], *, confidence: float = 0.95) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    observations = list(rows)
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in observations:
        groups.setdefault(str(row.get("case_id")), []).append(row)
    items: list[dict[str, Any]] = []
    for case_id, group in groups.items():
        observed = {str(row.get("status")) for row in group}
        if "error" in observed:
            status = "error"
        elif "invalid" in observed:
            status = "invalid"
        elif "fail" in observed:
            status = "fail"
        elif observed == {"skipped"}:
            status = "skipped"
        elif observed == {"pass"}:
            status = "pass"
        else:
            status = "invalid"
        items.append(
            {
                "case_id": case_id,
                "category": group[0].get("category"),
                "status": status,
                "observations": len(group),
            }
        )
    statuses = {name: sum(row.get("status") == name for row in items) for name in ("pass", "fail", "invalid", "error", "skipped")}
    judged = statuses["pass"] + statuses["fail"]
    lower, upper = wilson_interval(statuses["pass"], judged, confidence)
    metrics = {
        "total": len(items),
        "observations": len(observations),
        **statuses,
        "pass_rate": statuses["pass"] / judged if judged else 0.0,
        "pass_rate_ci": {"lower": lower, "upper": upper, "confidence": confidence},
        "pass_rate_ci95": {"lower": lower, "upper": upper} if confidence == 0.95 else None,
        "officially_valid": statuses["invalid"] == statuses["error"] == statuses["skipped"] == 0,
    }
    categories: list[dict[str, Any]] = []
    for category in sorted({str(row.get("category")) for row in items}):
        group = [row for row in items if row.get("category") == category]
        passed = sum(row.get("status") == "pass" for row in group)
        failed = sum(row.get("status") == "fail" for row in group)
        valid = passed + failed
        low, high = wilson_interval(passed, valid, confidence)
        categories.append(
            {
                "category": category,
                "total": len(group),
                "pass": passed,
                "fail": failed,
                "invalid": sum(row.get("status") == "invalid" for row in group),
                "error": sum(row.get("status") == "error" for row in group),
                "pass_rate": passed / valid if valid else 0.0,
                "ci95_lower": low,
                "ci95_upper": high,
                "confidence": confidence,
            }
        )
    return metrics, categories


def apply_gates(suite: Suite, metrics: dict[str, Any], categories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    by_category = {row["category"]: row for row in categories}
    for gate in suite.config.get("gates", []):
        category = gate.get("category")
        slice_name = gate.get("slice")
        slice_value = gate.get("value")
        if category and slice_name:
            source: Any = {}
            scope = "invalid:category-and-slice"
        elif slice_name:
            source = ((metrics.get("slices") or {}).get(str(slice_name)) or {}).get(str(slice_value), {})
            scope = f"{slice_name}:{slice_value}"
        else:
            source = by_category.get(category, {}) if category else metrics
            scope = str(category or "overall")
        metric = str(gate.get("metric", "pass_rate_ci95.lower"))
        if isinstance(source, dict) and "ci95_lower" in source:
            source = {**source, "pass_rate_ci": {"lower": source.get("ci95_lower"), "upper": source.get("ci95_upper")}}
        value: Any = source
        for part in metric.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        minimum = float(gate.get("min", 0))
        if not isinstance(value, (int, float)) or float(value) < minimum:
            failures.append({"category": scope, "metric": metric, "minimum": minimum, "actual": value})
    return failures


def write_category_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = ["category", "total", "pass", "fail", "invalid", "error", "pass_rate", "ci95_lower", "ci95_upper", "confidence"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(path, 0o600)
