from __future__ import annotations

import copy
import csv
import difflib
import hashlib
import ipaddress
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
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import NormalDist
from typing import Any, Iterable

from .assets import content_text, validate_content_parts, validate_messages
from .profiles import TASK_PROFILES

PROTOCOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"
REPORT_VERSION = "1.0.0"
BEHAVIORS = {"answer", "refuse", "abstain", "redirect", "safe_complete"}
RISK_DOMAINS = {"quality", "security", "privacy", "safety", "reliability", "performance", "fairness"}
SEVERITIES = {"low", "medium", "high", "critical"}
REVIEW_STATUSES = {"approved", "needs_review", "rejected"}
SUITE_STATUSES = {"draft", "candidate", "calibrated", "approved", "deprecated", "retired"}
DATA_CLASSES = {"public", "synthetic", "internal", "confidential", "restricted"}
SPLITS = {"public", "practice", "calibration", "holdout"}
GATE_METRIC_PATHS = {
    "total",
    "observations",
    "pass",
    "fail",
    "invalid",
    "error",
    "skipped",
    "pass_rate",
    "pass_rate_ci.lower",
    "pass_rate_ci.upper",
    "pass_rate_ci95.lower",
    "pass_rate_ci95.upper",
}
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
SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"),
)


class ProtocolError(ValueError):
    pass


def require_matching_source_checkout(repo_root: Path, module_file: str) -> None:
    expected = (repo_root / "src" / "cavada_eval").resolve()
    if Path(module_file).resolve().parent != expected:
        raise ProtocolError("official runs require the executed cavada_eval package to match the attested source checkout")


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


def canonical_host(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or value != value.casefold():
        raise ProtocolError("host names must be non-empty canonical lowercase values")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or value.endswith(".") or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")
        ):
            raise ProtocolError("host names must be bare DNS names or IP addresses") from None
    return value


def _suite_evidence_file(
    suite: Suite, relative: Any, expected_hash: Any, label: str
) -> tuple[Path | None, bytes | None, str | None]:
    if (
        not isinstance(relative, str)
        or not relative
        or not isinstance(expected_hash, str)
        or not re.fullmatch(r"[a-f0-9]{64}", expected_hash)
    ):
        return None, None, f"official {label} path and SHA-256 are required"
    unresolved = suite.root / relative
    try:
        path = _inside(suite.root, relative)
    except ProtocolError as exc:
        return None, None, str(exc)
    if unresolved.is_symlink() or not path.is_file():
        return None, None, f"official {label} must be a regular suite-local file"
    try:
        raw = path.read_bytes()
    except OSError:
        return None, None, f"official {label} is unreadable"
    if sha256_bytes(raw) != expected_hash:
        return None, None, f"official {label} hash mismatch"
    return path, raw, None


def _read_jsonl(path: Path, raw: bytes | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = (path.read_bytes() if raw is None else raw).decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"cannot read UTF-8 JSONL: {path}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"Invalid JSONL line {line_number}: {exc.msg}") from exc
        if not isinstance(row, dict):
            raise ProtocolError(f"Invalid JSONL line {line_number}: expected object")
        rows.append(row)
    return rows


def _load_suite_snapshot(path: str | Path, *, official: bool = False) -> tuple[Suite, bytes, str, str]:
    root = Path(path).resolve()
    config_path = root / "suite.toml"
    if not config_path.is_file():
        raise ProtocolError(f"Missing suite.toml in {root}")
    config_raw = config_path.read_bytes()
    config = tomllib.loads(config_raw.decode("utf-8"))
    dataset_path = _inside(root, str(config.get("dataset", "dataset.jsonl")))
    rubric_path = _inside(root, str(config.get("rubric", "rubric.md")))
    if not dataset_path.is_file() or not rubric_path.is_file():
        raise ProtocolError("Dataset and rubric must exist inside the suite")
    dataset_raw = dataset_path.read_bytes()
    rubric_raw = rubric_path.read_bytes()
    dataset_sha256 = sha256_bytes(dataset_raw)
    rubric_sha256 = sha256_bytes(rubric_raw)
    suite = Suite(root, config, tuple(_read_jsonl(dataset_path, dataset_raw)), rubric_raw.decode("utf-8"), dataset_path, rubric_path)
    errors = validate_suite(
        suite,
        official=official,
        dataset_sha256=dataset_sha256,
        rubric_sha256=rubric_sha256,
    )
    if errors:
        raise ProtocolError("\n".join(errors))
    return suite, config_raw, dataset_sha256, rubric_sha256


def load_suite(path: str | Path, *, official: bool = False) -> Suite:
    return _load_suite_snapshot(path, official=official)[0]


def _semantic_integrity_errors(
    suite: Suite, integrity: dict[str, Any], *, dataset_sha256: str | None = None
) -> list[str]:
    path, raw, path_error = _suite_evidence_file(
        suite,
        integrity.get("semantic_review_evidence"),
        integrity.get("semantic_review_evidence_sha256"),
        "semantic contamination evidence",
    )
    if path_error or path is None or raw is None:
        return [path_error or "official semantic contamination evidence is missing"]
    try:
        evidence = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ["official semantic contamination evidence must be valid JSON"]
    if not isinstance(evidence, dict):
        return ["official semantic contamination evidence must be an object"]
    errors: list[str] = []
    hashes = ("dataset_sha256", "comparison_corpus_sha256", "candidate_pairs_evidence_sha256", "reviewer_evidence_sha256")
    if any(not isinstance(evidence.get(field), str) or not re.fullmatch(r"[a-f0-9]{64}", evidence[field]) for field in hashes):
        errors.append("official semantic contamination evidence contains invalid hashes")
    if evidence.get("evidence_version") != "2.0.0":
        errors.append("official semantic contamination evidence_version must be 2.0.0")
    if evidence.get("dataset_sha256") != (dataset_sha256 or sha256_file(suite.dataset_path)):
        errors.append("official semantic contamination evidence dataset hash mismatch")
    if evidence.get("detector") != integrity.get("semantic_detector"):
        errors.append("official semantic contamination detector mismatch")
    if evidence.get("detector_revision") != integrity.get("semantic_detector_revision"):
        errors.append("official semantic contamination detector revision mismatch")
    for field, label in (
        ("comparison_corpus", "semantic comparison corpus"),
        ("candidate_pairs_evidence", "semantic candidate-pair evidence"),
        ("reviewer_evidence", "semantic independent-review evidence"),
    ):
        _, _, error = _suite_evidence_file(suite, evidence.get(field), evidence.get(f"{field}_sha256"), label)
        if error:
            errors.append(error)
    for field in ("detector_license", "similarity_metric"):
        if not isinstance(evidence.get(field), str) or not str(evidence[field]).strip():
            errors.append(f"official semantic contamination {field} is required")
    threshold = evidence.get("threshold")
    if (
        not isinstance(threshold, (int, float))
        or isinstance(threshold, bool)
        or not math.isfinite(float(threshold))
        or not -1 <= float(threshold) <= 1
    ):
        errors.append("official semantic contamination threshold is invalid")
    if evidence.get("cases") != len(suite.cases):
        errors.append("official semantic contamination case count mismatch")
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
    ):
        errors.append("official semantic contamination pair counts are invalid")
    if evidence.get("cross_split_reviewed") is not True or evidence.get("cross_suite_reviewed") is not True:
        errors.append("official semantic contamination evidence requires cross-split and cross-suite review")
    if evidence.get("independent_review_status") != "passed":
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


def _calibration_evidence_errors(calibration: Any) -> list[str]:
    if not isinstance(calibration, dict) or not calibration:
        return ["official suite calibration configuration is missing"]
    return ["official suite calibration semantic reconstruction is unavailable"]


def _case_input_modalities(case: dict[str, Any]) -> set[str]:
    values = [case.get("input")]
    messages = case.get("messages")
    modalities: set[str] = set()
    if isinstance(messages, list):
        values.extend(message.get("content") for message in messages if isinstance(message, dict))
    for value in values:
        if isinstance(value, str):
            modalities.add("text")
        elif isinstance(value, list):
            for part in value:
                if not isinstance(part, dict):
                    continue
                kind = part.get("type")
                if kind in {"text", "image", "audio", "video", "document"}:
                    modalities.add(str(kind))
                elif kind in {"tool_call", "tool_result"}:
                    modalities.add("tools")
    return modalities


def validate_suite(
    suite: Suite,
    *,
    official: bool = False,
    dataset_sha256: str | None = None,
    rubric_sha256: str | None = None,
) -> list[str]:
    errors: list[str] = []
    config = suite.config
    for field in ("name", "version", "status", "description", "dataset", "rubric", "data_classification"):
        if not isinstance(config.get(field), str) or not str(config[field]).strip():
            errors.append(f"suite.{field} is required")
    if isinstance(config.get("name"), str) and re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", config["name"]) is None:
        errors.append("suite.name must use lowercase letters, digits, dot, underscore, or dash")
    if config.get("protocol_version") != PROTOCOL_VERSION:
        errors.append(f"protocol_version must be {PROTOCOL_VERSION}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(config.get("version", ""))):
        errors.append("suite.version must be semantic x.y.z")
    if config.get("status") not in SUITE_STATUSES:
        errors.append(f"suite.status must be one of {sorted(SUITE_STATUSES)}")
    if config.get("data_classification") not in DATA_CLASSES:
        errors.append(f"suite.data_classification must be one of {sorted(DATA_CLASSES)}")
    profile = config.get("profile", "text-generation")
    if profile not in TASK_PROFILES:
        errors.append(f"suite.profile must be one of {sorted(TASK_PROFILES)}")
    if official:
        unknown = sorted(set(config) - OFFICIAL_SUITE_FIELDS)
        if unknown:
            errors.append(f"official suite has unknown top-level fields: {unknown}")
    if not suite.cases:
        errors.append("dataset is empty")
    if contains_secret_like(config) or contains_secret_like(suite.rubric):
        errors.append("suite configuration or rubric contains secret-like material")
    gates = config.get("gates")
    if gates is not None and not isinstance(gates, list):
        errors.append("suite.gates must be an array of tables")
    elif isinstance(gates, list):
        categories = {str(case.get("category")) for case in suite.cases}
        configured_statistics = config.get("statistics")
        configured_confidence = configured_statistics.get("confidence", 0.95) if isinstance(configured_statistics, dict) else 0.95
        confidence = float(configured_confidence) if isinstance(configured_confidence, (int, float)) else 0.95
        for index, gate in enumerate(gates, 1):
            prefix = f"gate[{index}]"
            if not isinstance(gate, dict):
                errors.append(f"{prefix} must be a table")
                continue
            metric = gate.get("metric", "pass_rate_ci.lower")
            if not isinstance(metric, str) or metric not in GATE_METRIC_PATHS:
                errors.append(f"{prefix}.metric must be one of {sorted(GATE_METRIC_PATHS)}")
            elif official and metric not in {"pass_rate_ci.lower", "pass_rate_ci95.lower"}:
                errors.append(f"{prefix}.metric must be a pass-rate confidence-interval lower bound for official runs")
            elif official and gate.get("category") is None and len(categories) > 1:
                errors.append(f"{prefix} cannot aggregate multiple constructs in an official run; set category")
            elif metric.startswith("pass_rate_ci95.") and confidence != 0.95:
                errors.append(f"{prefix}.metric requires statistics.confidence=0.95")
            minimum = gate.get("min")
            if not isinstance(minimum, (int, float)) or isinstance(minimum, bool) or not math.isfinite(float(minimum)):
                errors.append(f"{prefix}.min must be a finite number")
            category = gate.get("category")
            if category is not None and (not isinstance(category, str) or not category or category not in categories):
                errors.append(f"{prefix}.category must identify a dataset category")

    if "metrics" in config:
        errors.append("suite.metrics is not supported; use versioned deterministic checks")
    pinned_dataset = config.get("dataset_sha256")
    pinned_rubric = config.get("rubric_sha256")
    actual_dataset_sha256 = dataset_sha256 or sha256_file(suite.dataset_path)
    actual_rubric_sha256 = rubric_sha256 or sha256_file(suite.rubric_path)
    if pinned_dataset and pinned_dataset != actual_dataset_sha256:
        errors.append("dataset_sha256 does not match dataset")
    if pinned_rubric and pinned_rubric != actual_rubric_sha256:
        errors.append("rubric_sha256 does not match rubric")
    for field in ("temperature",):
        if field in config and (
            not isinstance(config[field], (int, float))
            or isinstance(config[field], bool)
            or not math.isfinite(float(config[field]))
            or not 0 <= float(config[field]) <= 2
        ):
            errors.append(f"suite.{field} must be a number from 0 to 2")
    for field in ("max_tokens", "official_min_repetitions", "official_min_judge_repetitions"):
        if field in config and (not isinstance(config[field], int) or isinstance(config[field], bool) or config[field] < 1):
            errors.append(f"suite.{field} must be a positive integer")
    judge_config = config.get("judge")
    blueprint_status: str | None = None
    blueprint_configured = isinstance(judge_config, dict) and (
        "qualification_blueprint" in judge_config or "qualification_blueprint_sha256" in judge_config
    )
    if judge_config is not None and not isinstance(judge_config, dict):
        errors.append("suite.judge must be a table")
    elif isinstance(judge_config, dict) and blueprint_configured:
        relative = judge_config.get("qualification_blueprint")
        digest = judge_config.get("qualification_blueprint_sha256")
        if not isinstance(relative, str) or not relative or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            errors.append("judge qualification blueprint requires a suite-local path and SHA-256")
        else:
            try:
                blueprint_path = _inside(suite.root, relative)
            except ProtocolError as exc:
                errors.append(str(exc))
            else:
                if blueprint_path.is_symlink() or not blueprint_path.is_file():
                    errors.append("judge qualification blueprint must be a regular suite-local file")
                else:
                    try:
                        blueprint_raw = blueprint_path.read_bytes()
                        blueprint_status = tomllib.loads(blueprint_raw.decode("utf-8")).get("status")
                    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                        errors.append(f"cannot load judge qualification blueprint: {exc}")
                    else:
                        if sha256_bytes(blueprint_raw) != digest:
                            errors.append("judge qualification blueprint hash mismatch")
                        else:
                            from .program import validate_judge_qualification_blueprint

                            errors.extend(validate_judge_qualification_blueprint(blueprint_path, suite, raw=blueprint_raw))
    if official and not blueprint_configured:
        errors.append("official runs require a suite-pinned judge qualification blueprint")
    elif official and blueprint_status == "preregistration-draft":
        errors.append("official judge qualification blueprint remains preregistration-draft")
    statistics = config.get("statistics") or {}
    if not isinstance(statistics, dict):
        errors.append("suite.statistics must be a table")
    else:
        confidence = statistics.get("confidence", 0.95)
        samples = statistics.get("bootstrap_samples", 10_000)
        seed = statistics.get("seed", 0)
        if (
            not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not math.isfinite(float(confidence))
            or not 0 < float(confidence) < 1
        ):
            errors.append("statistics.confidence must be between 0 and 1")
        if not isinstance(samples, int) or isinstance(samples, bool) or samples < 100:
            errors.append("statistics.bootstrap_samples must be an integer of at least 100")
        if not isinstance(seed, int) or isinstance(seed, bool):
            errors.append("statistics.seed must be an integer")
    target = config.get("target") or {}
    target_kind = target.get("kind", "json") if isinstance(target, dict) else None
    if target_kind not in {"json", "openai", "recorded"}:
        errors.append("target.kind must be json, openai, or recorded")
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
    capabilities_declared = isinstance(target, dict) and "capabilities" in target
    capabilities_valid = isinstance(capabilities, list) and all(isinstance(item, str) and item for item in capabilities)
    if capabilities_declared and not capabilities_valid:
        errors.append("target.capabilities must be an array of non-empty strings")
    if official and profile in TASK_PROFILES:
        missing_capabilities = sorted(TASK_PROFILES[str(profile)] - (set(capabilities) if capabilities_valid else set()))
        if missing_capabilities:
            errors.append(f"target.capabilities missing profile requirements: {missing_capabilities}")
    pricing = config.get("pricing")
    if pricing is not None:
        required_pricing = {"currency", "source", "effective_at", "input_per_million", "output_per_million"}
        if not isinstance(pricing, dict) or not required_pricing <= set(pricing):
            errors.append(f"pricing is missing fields: {sorted(required_pricing - set(pricing or {}))}")
        elif not all(isinstance(pricing[field], str) and pricing[field].strip() for field in ("currency", "source", "effective_at")) or not all(
            isinstance(pricing[field], (int, float))
            and not isinstance(pricing[field], bool)
            and math.isfinite(float(pricing[field]))
            and float(pricing[field]) >= 0
            for field in ("input_per_million", "output_per_million")
        ):
            errors.append("pricing text fields must be non-empty and rates must be non-negative numbers")
        if isinstance(pricing, dict):
            for field in ("judge_input_per_million", "judge_output_per_million"):
                if field in pricing and (
                    not isinstance(pricing[field], (int, float))
                    or isinstance(pricing[field], bool)
                    or not math.isfinite(float(pricing[field]))
                    or float(pricing[field]) < 0
                ):
                    errors.append(f"pricing.{field} must be a non-negative number")

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
            if (
                not isinstance(threshold, (int, float))
                or isinstance(threshold, bool)
                or not math.isfinite(float(threshold))
                or not 0.8 <= float(threshold) < 1
            ):
                errors.append("governance.near_duplicate_threshold must be a number from 0.8 (inclusive) to 1 (exclusive)")
            semantic_threshold = governance.get("semantic_duplicate_threshold")
            if (
                not isinstance(semantic_threshold, (int, float))
                or isinstance(semantic_threshold, bool)
                or not math.isfinite(float(semantic_threshold))
                or not 0.8 <= float(semantic_threshold) <= 1
            ):
                errors.append("governance.semantic_duplicate_threshold must be a number from 0.8 through 1")

    seen_ids: set[str] = set()
    cases_by_id: dict[str, dict[str, Any]] = {}
    seen_inputs: set[str] = set()
    normalized_inputs: list[tuple[str, str, str | None]] = []
    from .metrics import metric_config_errors

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
        actual_modalities = _case_input_modalities(case)
        official_media = sorted(actual_modalities & {"image", "audio", "video", "document"})
        if official and official_media:
            errors.append(
                f"{prefix}.official media judging requires a capability-verifying, qualification-bound judge adapter: {official_media}"
            )
        if profile in TASK_PROFILES:
            unsupported = sorted(actual_modalities - TASK_PROFILES[str(profile)])
            if unsupported:
                errors.append(f"{prefix}.input modalities are not supported by suite.profile {profile!r}: {unsupported}")
        if capabilities_declared and capabilities_valid:
            missing = sorted(actual_modalities - set(capabilities))
            if missing:
                errors.append(f"{prefix}.input modalities are missing from target.capabilities: {missing}")
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
        if "weight" in case and (
            not isinstance(case["weight"], (int, float))
            or isinstance(case["weight"], bool)
            or not math.isfinite(float(case["weight"]))
            or float(case["weight"]) <= 0
        ):
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
        if "judge_gold_verdict" in case and case["judge_gold_verdict"] not in {"pass", "fail"}:
            errors.append(f"{prefix}.judge_gold_verdict must be pass or fail")
        if "performance_phase" in case and case["performance_phase"] not in {"cold", "warmup", "steady", "soak"}:
            errors.append(f"{prefix}.performance_phase is invalid")
        errors.extend(f"{prefix}.{message}" for message in metric_config_errors(case))
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
            character_counts = [Counter(text) for _, text, _ in normalized_inputs]
            # ponytail: the exact scan remains quadratic, but cheap upper bounds avoid expensive alignment for impossible matches.
            for index, (left_id, left, left_group) in enumerate(normalized_inputs):
                for right_index, (right_id, right, right_group) in enumerate(normalized_inputs[index + 1 :], index + 1):
                    if left_group is not None and left_group == right_group:
                        continue
                    length_total = len(left) + len(right)
                    if not length_total or 2 * min(len(left), len(right)) / length_total < float(near_threshold):
                        continue
                    left_chars = character_counts[index]
                    right_chars = character_counts[right_index]
                    smaller, larger = (left_chars, right_chars) if len(left_chars) <= len(right_chars) else (right_chars, left_chars)
                    if 2 * sum(min(count, larger[character]) for character, count in smaller.items()) / length_total < float(near_threshold):
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
        errors.extend(
            _calibration_evidence_errors(calibration)
        )
        allowed_hosts = (suite.config.get("network") or {}).get("allowed_hosts")
        try:
            canonical_hosts = [canonical_host(host) for host in allowed_hosts] if isinstance(allowed_hosts, list) else []
        except ProtocolError as exc:
            errors.append(str(exc))
            canonical_hosts = []
        if not canonical_hosts or len(canonical_hosts) != len(set(canonical_hosts)):
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
            errors.extend(_semantic_integrity_errors(suite, integrity, dataset_sha256=actual_dataset_sha256))
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


def promotion_readiness(
    suite: Suite,
    target_status: str,
    *,
    dataset_sha256: str | None = None,
    rubric_sha256: str | None = None,
) -> list[str]:
    order = ["draft", "candidate", "calibrated", "approved", "deprecated", "retired"]
    if target_status not in SUITE_STATUSES:
        return [f"unknown target status: {target_status}"]
    current = order.index(suite.status)
    target = order.index(target_status)
    if target != current + 1:
        return [f"promotion must follow lifecycle order; {suite.status} -> {target_status} is not allowed"]
    if target_status in {"deprecated", "retired"}:
        return []

    errors = validate_suite(
        suite,
        official=False,
        dataset_sha256=dataset_sha256,
        rubric_sha256=rubric_sha256,
    )
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
        errors.extend(
            _calibration_evidence_errors(calibration)
        )
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
        errors.extend(
            validate_suite(
                proposed,
                official=True,
                dataset_sha256=dataset_sha256,
                rubric_sha256=rubric_sha256,
            )
        )
    return list(dict.fromkeys(errors))


def promote_suite(suite: Suite, target_status: str, *, actor: str, evidence: str) -> dict[str, Any]:
    if not actor.strip() or not evidence.strip():
        raise ProtocolError("promotion requires non-empty actor and evidence")
    current, source_raw, dataset_sha256, rubric_sha256 = _load_suite_snapshot(suite.root)
    if current != suite:
        raise ProtocolError("suite changed after loading; reload it before promotion")
    errors = promotion_readiness(
        current,
        target_status,
        dataset_sha256=dataset_sha256,
        rubric_sha256=rubric_sha256,
    )
    if errors:
        raise ProtocolError("\n".join(errors))
    path = suite.root / "suite.toml"
    source = source_raw.decode("utf-8")
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
        "dataset_sha256": dataset_sha256,
        "rubric_sha256": rubric_sha256,
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
    hardware: dict[str, Any] = {"machine": platform.machine(), "processor": platform.processor(), "cpu_count": os.cpu_count()}
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
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "hardware": hardware,
        "uv_lock_sha256": sha256_file(lock) if lock.is_file() else "",
    }


def require_mutable_output_root(root: Path) -> None:
    resolved = root.resolve()
    for candidate in (resolved, *resolved.parents):
        bundle = candidate / "bundle.json"
        if bundle.exists() or bundle.is_symlink():
            raise ProtocolError("output root must be outside finalized run bundles")


def new_run_dir(root: Path, suite: Suite, model_label: str) -> tuple[str, Path]:
    require_mutable_output_root(root)
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
                "observations": sum(int(row["observations"]) for row in group),
                "pass": passed,
                "fail": failed,
                "invalid": sum(row.get("status") == "invalid" for row in group),
                "error": sum(row.get("status") == "error" for row in group),
                "skipped": sum(row.get("status") == "skipped" for row in group),
                "pass_rate": passed / valid if valid else 0.0,
                "pass_rate_ci": {"lower": low, "upper": high, "confidence": confidence},
                "pass_rate_ci95": {"lower": low, "upper": high} if confidence == 0.95 else None,
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
        source = by_category.get(category, {}) if category else metrics
        metric = str(gate.get("metric", "pass_rate_ci.lower"))
        value: Any = source
        for part in metric.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        minimum = float(gate.get("min", 0))
        if not isinstance(value, (int, float)) or float(value) < minimum:
            failures.append({"category": category or "overall", "metric": metric, "minimum": minimum, "actual": value})
    return failures


def write_category_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = ["category", "total", "pass", "fail", "invalid", "error", "pass_rate", "ci95_lower", "ci95_upper", "confidence"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(path, 0o600)
