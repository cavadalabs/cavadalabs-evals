from __future__ import annotations

import csv
import html
import ipaddress
import json
import math
import os
import random
import shutil
import stat
import tempfile
import threading
import time
import tomllib
import urllib.parse
import uuid
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from shutil import copyfile as _snapshot_copyfile
from types import MappingProxyType
from typing import Any, Mapping, cast

from .artifacts import verify_bundle, write_bundle
from .protocol import (
    ProtocolError,
    append_jsonl,
    atomic_json,
    atomic_text,
    contains_secret_like,
    environment_evidence,
    git_evidence,
    require_matching_source_checkout,
    require_mutable_output_root,
    sha256_bytes,
    sha256_file,
)
from .reporting import _pdf
from .runner import _completion_url, _manifest_endpoint, _post_openai_stream, _secure_endpoint, _stream_model_identities
from .statistics import distribution, percentile
from .system_evidence import load_system_evidence

PERFORMANCE_PROTOCOL_VERSION = "2.0.0"
PERFORMANCE_PROTOCOL_FILENAME = "PERFORMANCE_PROTOCOL_V2.md"
PERFORMANCE_PROTOCOL_FILES = {
    "1.0.0": "PERFORMANCE_PROTOCOL_V1_0.md",
    "1.1.0": "PERFORMANCE_PROTOCOL_V1_1.md",
    PERFORMANCE_PROTOCOL_VERSION: PERFORMANCE_PROTOCOL_FILENAME,
}
SUPPORTED_PERFORMANCE_PROTOCOL_VERSIONS = frozenset(PERFORMANCE_PROTOCOL_FILES)
LEGACY_PERFORMANCE_PLAN_VERSION = "1.0.0"
PERFORMANCE_PLAN_VERSION = "2.0.0"
SUPPORTED_PERFORMANCE_PLAN_VERSIONS = frozenset({LEGACY_PERFORMANCE_PLAN_VERSION, PERFORMANCE_PLAN_VERSION})
PERFORMANCE_RUNTIME_VERSION = "1.0.0"
LEGACY_PERFORMANCE_REPORT_VERSION = "1.0.0"
PERFORMANCE_REPORT_VERSION = "2.0.0"
_PERFORMANCE_COMPARISON_SOURCE_BINDING = "recorded source bundle SHA-256; source bundles are required for independent source revalidation"
MAX_WORKLOAD_BYTES = 32 * 1024 * 1024
MAX_PROMPT_BYTES = 16 * 1024 * 1024
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
_LEDGER_IDENTITY_FIELDS = (
    "request_id",
    "cell_key",
    "scenario_id",
    "block",
    "phase",
    "request_index",
    "workload_id",
    "declared_context_tokens",
    "requested_output_tokens",
    "cache_nonce",
    "client_queue_ms",
    "scheduled_monotonic_ns",
    "batch_started_monotonic_ns",
    "started_monotonic_ns",
)


def _performance_versions(plan_version: str) -> tuple[str, str]:
    if plan_version == PERFORMANCE_PLAN_VERSION:
        return PERFORMANCE_PROTOCOL_VERSION, PERFORMANCE_REPORT_VERSION
    if plan_version == LEGACY_PERFORMANCE_PLAN_VERSION:
        return "1.1.0", LEGACY_PERFORMANCE_REPORT_VERSION
    raise ProtocolError(f"unsupported performance plan version: {plan_version}")


def _v2_schedule_evidence(
    scheduled_ns: int,
    transport: dict[str, Any] | None,
    terminal_ns: int,
    *,
    success: bool,
) -> dict[str, Any]:
    transport = transport or {}
    dispatch_ns = transport.get("started_monotonic_ns")
    completed_ns = transport.get("finished_monotonic_ns", terminal_ns)
    if not isinstance(completed_ns, int) or isinstance(completed_ns, bool) or completed_ns < scheduled_ns:
        raise ProtocolError("performance completion timing is malformed")
    result: dict[str, Any] = {"completed_monotonic_ns": completed_ns}
    if isinstance(dispatch_ns, int) and not isinstance(dispatch_ns, bool):
        if not scheduled_ns <= dispatch_ns <= completed_ns:
            raise ProtocolError("performance dispatch timing is malformed")
        result.update(
            {
                "dispatch_monotonic_ns": dispatch_ns,
                "dispatch_lag_ms": round((dispatch_ns - scheduled_ns) / 1_000_000, 3),
            }
        )
    elif success:
        raise ProtocolError("successful performance response is missing dispatch timing")
    if success:
        first_ns = transport.get("first_content_monotonic_ns")
        if not isinstance(first_ns, int) or isinstance(first_ns, bool) or not cast(int, dispatch_ns) <= first_ns <= completed_ns:
            raise ProtocolError("successful performance response is missing first-token timing")
        result.update(
            {
                "first_token_monotonic_ns": first_ns,
                "scheduled_ttft_ms": round((first_ns - scheduled_ns) / 1_000_000, 3),
                "scheduled_e2e_ms": round((completed_ns - scheduled_ns) / 1_000_000, 3),
            }
        )
    return result


@dataclass(frozen=True)
class PerformancePlan:
    path: Path
    sha256: str
    config: dict[str, Any]
    workload_path: Path
    workload: tuple[dict[str, Any], ...]
    workload_sha256: str
    workload_assets: dict[str, str]


@dataclass(frozen=True)
class PerformanceRuntime:
    path: Path
    sha256: str
    config: dict[str, Any]


def canonical_performance_protocol_path(version: str, *, repo_root: Path | None = None) -> Path:
    filename = PERFORMANCE_PROTOCOL_FILES.get(version)
    if filename is None:
        raise ProtocolError(f"unsupported performance protocol version: {version}")
    root = repo_root.resolve() if repo_root is not None else Path(__file__).resolve().parents[2]
    packaged = Path(__file__).resolve().parent / "_resources"
    if repo_root is None and packaged.is_dir():
        root = packaged
    path = root / filename
    if path.is_symlink() or not path.is_file():
        raise ProtocolError(f"missing canonical performance protocol: {filename}")
    return path


class _FatalPerformanceError(ProtocolError):
    pass


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a table/object")
    return value


def _finite_json(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_finite_json(item) for item in value)
    return isinstance(value, dict) and all(isinstance(key, str) and _finite_json(item) for key, item in value.items())


def _finite_evidence(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if isinstance(value, list):
        return [_finite_evidence(item) for item in value]
    if isinstance(value, dict):
        return {key: _finite_evidence(item) for key, item in value.items()}
    return value


def _provider_usage(raw: Any) -> tuple[float, float] | None:
    usage = raw.get("usage") if isinstance(raw, dict) else None
    if not isinstance(usage, dict):
        return None
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if (
        not isinstance(prompt, int)
        or isinstance(prompt, bool)
        or prompt < 1
        or not isinstance(completion, int)
        or isinstance(completion, bool)
        or completion < 0
    ):
        return None
    return float(prompt), float(completion)


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _reject_unknown(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ProtocolError(f"{label} contains unknown fields: {unknown}")


def _semantic_version(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 3 and all(part.isdigit() and (part == "0" or not part.startswith("0")) for part in parts)


def _content_addressed_revision(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    digest = value.removeprefix("sha256:")
    expected_lengths = {64} if value.startswith("sha256:") else {40, 64}
    return len(digest) in expected_lengths and all(character in "0123456789abcdef" for character in digest)


def _read_regular_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink():
        raise ProtocolError(f"{label} must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProtocolError(f"{label} must be a regular file") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ProtocolError(f"{label} must be a regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read()
    except OSError as exc:
        raise ProtocolError(f"{label} must be a readable regular file") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_performance_governance_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_bytes(path, label)
    try:
        value = _object(json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant), label)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"invalid {label}") from exc
    if not _finite_json(value):
        raise ProtocolError(f"{label} contains non-finite evidence")
    return value, raw


def load_performance_execution_record(
    path: Path,
    *,
    protocol_sha256: str,
    plan_sha256: str,
    workload_sha256: str,
    runtime_sha256: str,
    system_evidence_sha256: str | None,
    before: datetime | None = None,
) -> tuple[dict[str, Any], bytes]:
    record, raw = _read_performance_governance_json(path, "performance execution record")
    required = {
        "record_version",
        "engagement_id",
        "execution_owner_id",
        "scope",
        "protocol_sha256",
        "plan_sha256",
        "workload_sha256",
        "runtime_sha256",
        "system_evidence_sha256",
        "recorded_at",
    }
    if set(record) != required:
        raise ProtocolError(
            f"performance execution record fields differ; missing={sorted(required - set(record))}, unknown={sorted(set(record) - required)}"
        )
    if record.get("record_version") != "1.0.0":
        raise ProtocolError("performance execution record_version must be 1.0.0")
    for field in ("engagement_id", "execution_owner_id", "scope"):
        value = record.get(field)
        if not isinstance(value, str) or not value.strip() or any(marker in value.casefold() for marker in ("replace-with", "todo", "unknown")):
            raise ProtocolError(f"performance execution record {field} is missing or a placeholder")
    expected = {
        "protocol_sha256": protocol_sha256,
        "plan_sha256": plan_sha256,
        "workload_sha256": workload_sha256,
        "runtime_sha256": runtime_sha256,
        "system_evidence_sha256": system_evidence_sha256,
    }
    mismatches = sorted(field for field, value in expected.items() if record.get(field) != value)
    if mismatches:
        raise ProtocolError(f"performance execution record does not match exact run inputs: {mismatches}")
    before = before or datetime.now(timezone.utc)
    if before.tzinfo is None:
        raise ProtocolError("performance execution record verification time must include a timezone")
    try:
        recorded_at = datetime.fromisoformat(str(record.get("recorded_at")).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("performance execution record recorded_at must be an ISO 8601 timestamp") from exc
    if recorded_at.tzinfo is None or recorded_at > before:
        raise ProtocolError("performance execution record must be recorded before execution")
    if contains_secret_like(record):
        raise ProtocolError("performance execution record contains secret-like material")
    return (
        {
            "record_version": record["record_version"],
            "engagement_id": record["engagement_id"],
            "execution_owner_id": record["execution_owner_id"],
            "sha256": sha256_bytes(raw),
            "recorded_at": record["recorded_at"],
        },
        raw,
    )


def load_performance_engagement(
    path: Path,
    *,
    protocol_sha256: str,
    plan_sha256: str,
    workload_sha256: str,
    runtime_sha256: str,
    system_evidence_sha256: str,
    configuration_id: str,
    execution_record: Mapping[str, Any],
    at: datetime | None = None,
) -> tuple[dict[str, Any], bytes]:
    engagement, raw = _read_performance_governance_json(path, "performance engagement")
    required = {
        "engagement_version",
        "engagement_id",
        "status",
        "scope",
        "execution_owner_id",
        "protocol_sha256",
        "plan_sha256",
        "workload_sha256",
        "runtime_sha256",
        "system_evidence_sha256",
        "configuration_id",
        "approved_at",
        "expires_at",
    }
    if set(engagement) != required:
        raise ProtocolError(
            f"performance engagement fields differ; missing={sorted(required - set(engagement))}, "
            f"unknown={sorted(set(engagement) - required)}"
        )
    if engagement.get("engagement_version") != "1.0.0" or engagement.get("status") != "approved":
        raise ProtocolError("performance engagement must be version 1.0.0 with approved status")
    for field in ("engagement_id", "scope", "execution_owner_id"):
        value = engagement.get(field)
        if not isinstance(value, str) or not value.strip() or any(marker in value.casefold() for marker in ("replace-with", "todo", "unknown")):
            raise ProtocolError(f"performance engagement {field} is missing or a placeholder")
    expected = {
        "engagement_id": execution_record.get("engagement_id"),
        "execution_owner_id": execution_record.get("execution_owner_id"),
        "protocol_sha256": protocol_sha256,
        "plan_sha256": plan_sha256,
        "workload_sha256": workload_sha256,
        "runtime_sha256": runtime_sha256,
        "system_evidence_sha256": system_evidence_sha256,
        "configuration_id": configuration_id,
    }
    mismatches = sorted(field for field, value in expected.items() if engagement.get(field) != value)
    if mismatches:
        raise ProtocolError(f"performance engagement does not match exact run governance and inputs: {mismatches}")
    at = at or datetime.now(timezone.utc)
    if at.tzinfo is None:
        raise ProtocolError("performance engagement verification time must include a timezone")
    try:
        approved_at = datetime.fromisoformat(str(engagement.get("approved_at")).replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(str(engagement.get("expires_at")).replace("Z", "+00:00"))
        recorded_at = datetime.fromisoformat(str(execution_record.get("recorded_at")).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("performance engagement timestamps must be ISO 8601") from exc
    if any(value.tzinfo is None for value in (approved_at, expires_at, recorded_at)) or not approved_at <= recorded_at <= at < expires_at:
        raise ProtocolError("performance engagement is not effective for the execution record and verification time")
    if contains_secret_like(engagement):
        raise ProtocolError("performance engagement contains secret-like material")
    return (
        {
            "engagement_version": engagement["engagement_version"],
            "engagement_id": engagement["engagement_id"],
            "status": engagement["status"],
            "execution_owner_id": engagement["execution_owner_id"],
            "protocol_sha256": engagement["protocol_sha256"],
            "plan_sha256": engagement["plan_sha256"],
            "workload_sha256": engagement["workload_sha256"],
            "runtime_sha256": engagement["runtime_sha256"],
            "system_evidence_sha256": engagement["system_evidence_sha256"],
            "configuration_id": engagement["configuration_id"],
            "approved_at": engagement["approved_at"],
            "expires_at": engagement["expires_at"],
            "sha256": sha256_bytes(raw),
        },
        raw,
    )


def _numbers(value: Any, label: str, *, integer: bool = False) -> list[float | int]:
    if not isinstance(value, list) or not value:
        raise ProtocolError(f"{label} must be a non-empty array")
    expected = int if integer else (int, float)
    if not all(isinstance(item, expected) and not isinstance(item, bool) for item in value):
        raise ProtocolError(f"{label} contains a non-numeric value")
    result = [int(item) if integer else float(item) for item in value]
    if any(not math.isfinite(float(item)) for item in result):
        raise ProtocolError(f"{label} values must be finite")
    if any(item <= 0 for item in result):
        raise ProtocolError(f"{label} values must be positive")
    if len(set(result)) != len(result):
        raise ProtocolError(f"{label} values must be unique")
    return result


def _safe_asset(root: Path, relative: str, expected_hash: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ProtocolError(f"unsafe workload asset path: {relative}")
    candidate = root / path
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file() or candidate.is_symlink():
        raise ProtocolError(f"workload asset must be a regular package-local file: {relative}")
    if sha256_file(resolved) != expected_hash:
        raise ProtocolError(f"workload asset hash mismatch: {relative}")
    return resolved


def _load_workload_asset_cache(root: Path, assets: Mapping[str, str]) -> Mapping[str, bytes]:
    cache: dict[str, bytes] = {}
    resolved_root = root.resolve()
    for relative, expected_hash in assets.items():
        path = Path(relative)
        candidate = root / path
        resolved = candidate.resolve()
        if path.is_absolute() or ".." in path.parts or not resolved.is_relative_to(resolved_root) or candidate.is_symlink():
            raise ProtocolError(f"unsafe workload asset path: {relative}")
        try:
            raw = _read_regular_bytes(candidate, f"workload asset {relative}")
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError(f"workload asset must be UTF-8: {relative}") from exc
        if len(raw) > MAX_PROMPT_BYTES or sha256_bytes(raw) != expected_hash:
            raise ProtocolError(f"workload asset hash or size mismatch: {relative}")
        if contains_secret_like(text):
            raise ProtocolError(f"workload asset contains secret-like material: {relative}")
        cache[relative] = raw
    return MappingProxyType(cache)


def _workload_assets_match(root: Path, cache: Mapping[str, bytes]) -> bool:
    try:
        return all(_read_regular_bytes(root / relative, f"workload asset {relative}") == raw for relative, raw in cache.items())
    except ProtocolError:
        return False


def _load_workload(path: Path, *, asset_root: Path | None = None) -> tuple[tuple[dict[str, Any], ...], dict[str, str], str]:
    source = path.read_bytes()
    if len(source) > MAX_WORKLOAD_BYTES:
        raise ProtocolError(f"performance workload exceeds {MAX_WORKLOAD_BYTES} bytes")
    rows: list[dict[str, Any]] = []
    assets: dict[str, str] = {}
    ids: set[str] = set()
    try:
        lines = source.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ProtocolError("performance workload must be UTF-8") from exc
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid performance workload line {line_number}") from exc
        if not isinstance(row, dict):
            raise ProtocolError(f"performance workload line {line_number} must be an object")
        if not _finite_json(row):
            raise ProtocolError(f"performance workload line {line_number} contains non-finite JSON")
        _reject_unknown(
            row,
            {"id", "context_tokens", "system", "prompt", "prompt_file", "prompt_sha256", "prefix", "repeat_text", "repeat_count", "suffix"},
            f"performance workload line {line_number}",
        )
        identifier = row.get("id")
        context_tokens = row.get("context_tokens")
        if not isinstance(identifier, str) or not identifier or identifier in ids:
            raise ProtocolError(f"performance workload line {line_number} has a missing or duplicate id")
        if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in identifier):
            raise ProtocolError(f"performance workload {identifier!r} has an unsafe id")
        if not isinstance(context_tokens, int) or isinstance(context_tokens, bool) or context_tokens < 1:
            raise ProtocolError(f"performance workload {identifier} has invalid context_tokens")
        prompt_forms = sum(key in row for key in ("prompt", "prompt_file", "repeat_text"))
        if prompt_forms != 1:
            raise ProtocolError(f"performance workload {identifier} requires exactly one of prompt, prompt_file, or repeat_text")
        if "prompt" in row and set(row) & {"prompt_file", "prompt_sha256", "repeat_text", "repeat_count", "prefix", "suffix"}:
            raise ProtocolError(f"performance workload {identifier} mixes incompatible prompt fields")
        if "prompt_file" in row and set(row) & {"prompt", "repeat_text", "repeat_count", "prefix", "suffix"}:
            raise ProtocolError(f"performance workload {identifier} mixes incompatible prompt fields")
        if "repeat_text" in row and set(row) & {"prompt", "prompt_file", "prompt_sha256"}:
            raise ProtocolError(f"performance workload {identifier} mixes incompatible prompt fields")
        if "prompt" in row and (not isinstance(row["prompt"], str) or not row["prompt"]):
            raise ProtocolError(f"performance workload {identifier} prompt is empty")
        if "prompt" in row and len(row["prompt"].encode()) > MAX_PROMPT_BYTES:
            raise ProtocolError(f"performance workload {identifier} prompt is too large")
        if "prompt_file" in row:
            if not isinstance(row["prompt_file"], str) or not isinstance(row.get("prompt_sha256"), str):
                raise ProtocolError(f"performance workload {identifier} prompt_file requires prompt_sha256")
            asset = _safe_asset(asset_root or path.parent, row["prompt_file"], row["prompt_sha256"])
            if asset.stat().st_size > MAX_PROMPT_BYTES:
                raise ProtocolError(f"performance workload {identifier} prompt_file is too large")
            assets[row["prompt_file"]] = row["prompt_sha256"]
        if "repeat_text" in row:
            if not isinstance(row["repeat_text"], str) or not row["repeat_text"]:
                raise ProtocolError(f"performance workload {identifier} repeat_text is empty")
            if not isinstance(row.get("repeat_count"), int) or isinstance(row["repeat_count"], bool) or row["repeat_count"] < 1:
                raise ProtocolError(f"performance workload {identifier} repeat_count is invalid")
            for field in ("prefix", "suffix"):
                if field in row and not isinstance(row[field], str):
                    raise ProtocolError(f"performance workload {identifier} {field} must be text")
            generated_bytes = (
                len(row["repeat_text"].encode()) * row["repeat_count"] + len(str(row.get("prefix", "")).encode()) + len(str(row.get("suffix", "")).encode())
            )
            if generated_bytes > MAX_PROMPT_BYTES:
                raise ProtocolError(f"performance workload {identifier} generated prompt is too large")
        if "system" in row and not isinstance(row["system"], str):
            raise ProtocolError(f"performance workload {identifier} system must be text")
        if isinstance(row.get("system"), str) and len(row["system"].encode()) > MAX_PROMPT_BYTES:
            raise ProtocolError(f"performance workload {identifier} system prompt is too large")
        if contains_secret_like(row):
            raise ProtocolError(f"performance workload {identifier} contains secret-like material")
        ids.add(identifier)
        rows.append(row)
    if not rows:
        raise ProtocolError("performance workload is empty")
    return tuple(rows), assets, sha256_bytes(source)


def load_performance_plan(path: str | Path) -> PerformancePlan:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ProtocolError("performance plan must not be a symlink")
    resolved = candidate.resolve()
    try:
        source = resolved.read_bytes()
        config = tomllib.loads(source.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot load performance plan: {exc}") from exc
    if not _finite_json(config):
        raise ProtocolError("performance plan contains non-finite values")
    plan_version = config.get("plan_version")
    expected_profile = "llm-serving-v2" if plan_version == PERFORMANCE_PLAN_VERSION else "llm-serving-v1"
    if plan_version not in SUPPORTED_PERFORMANCE_PLAN_VERSIONS or config.get("profile") != expected_profile:
        raise ProtocolError("performance plan requires a supported matching plan_version/profile")
    plan_fields = {
        "plan_version",
        "revision",
        "name",
        "description",
        "profile",
        "data_classification",
        "workload",
        "generation",
        "execution",
        "limits",
        "slo",
        "scenarios",
    }
    if plan_version == PERFORMANCE_PLAN_VERSION:
        plan_fields.add("load_generator")
    _reject_unknown(config, plan_fields, "performance plan")
    if contains_secret_like(config):
        raise ProtocolError("performance plan contains secret-like material")
    for field in ("revision", "name", "description", "data_classification"):
        if not isinstance(config.get(field), str) or not config[field].strip():
            raise ProtocolError(f"performance plan {field} is required")
    if not _semantic_version(config["revision"]):
        raise ProtocolError("performance plan revision must be a semantic version")
    if config["data_classification"] not in {"public", "synthetic"}:
        raise ProtocolError("performance protocol v1 only permits public or synthetic workloads")
    if config["name"][0] not in "abcdefghijklmnopqrstuvwxyz0123456789" or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in config["name"]
    ):
        raise ProtocolError("performance plan name must use lowercase letters, digits, dash, underscore, or dot")

    workload_config = _object(config.get("workload"), "workload")
    _reject_unknown(
        workload_config,
        {"id", "revision", "path", "sha256", "mode", "prefix_cache_policy", "input_token_tolerance_fraction"},
        "workload",
    )
    for field in ("id", "revision", "sha256"):
        if not isinstance(workload_config.get(field), str) or not workload_config[field]:
            raise ProtocolError(f"workload.{field} is required")
    if not _semantic_version(workload_config["revision"]):
        raise ProtocolError("workload.revision must be a semantic version")
    if workload_config["id"][0] not in "abcdefghijklmnopqrstuvwxyz0123456789" or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in workload_config["id"]
    ):
        raise ProtocolError("workload.id is invalid")
    if len(workload_config["sha256"]) != 64 or any(character not in "0123456789abcdef" for character in workload_config["sha256"]):
        raise ProtocolError("workload.sha256 must be a lowercase SHA-256")
    if workload_config.get("mode") not in {"iso-prompt", "iso-token"}:
        raise ProtocolError("workload.mode must be iso-prompt or iso-token")
    if workload_config.get("prefix_cache_policy", "unspecified") not in {"diverse", "shared", "unspecified"}:
        raise ProtocolError("workload.prefix_cache_policy must be diverse, shared, or unspecified")
    relative_workload = workload_config.get("path")
    if not isinstance(relative_workload, str) or Path(relative_workload).is_absolute():
        raise ProtocolError("workload.path must be relative")
    package_root = resolved.parent.parent if resolved.parent.name == "plans" else resolved.parent
    workload_candidate = resolved.parent / relative_workload
    workload_path = workload_candidate.resolve()
    if not workload_path.is_file() or workload_candidate.is_symlink() or not workload_path.is_relative_to(package_root):
        raise ProtocolError("workload.path must resolve to a regular performance-package file")
    workload, assets, workload_hash = _load_workload(workload_path)
    if workload_hash != workload_config["sha256"]:
        raise ProtocolError("performance workload hash does not match the plan")

    generation = _object(config.get("generation"), "generation")
    _reject_unknown(generation, {"stream", "temperature", "request_defaults"}, "generation")
    if generation.get("stream") is not True or generation.get("temperature") != 0:
        raise ProtocolError("performance generation requires stream=true and temperature=0")
    request_defaults = generation.get("request_defaults", {})
    if not isinstance(request_defaults, dict):
        raise ProtocolError("generation.request_defaults must be a table")
    protected = {"model", "messages", "max_tokens", "stream", "stream_options", "temperature"}
    if protected & set(request_defaults):
        raise ProtocolError(f"generation.request_defaults cannot override protected fields: {sorted(protected & set(request_defaults))}")
    if contains_secret_like(request_defaults):
        raise ProtocolError("generation.request_defaults contains secret-like material")

    execution = _object(config.get("execution"), "execution")
    _reject_unknown(
        execution,
        {
            "repetitions",
            "warmup_requests",
            "measured_requests",
            "open_loop_duration_seconds",
            "open_loop_arrival_distribution",
            "bootstrap_samples",
            "seed",
            "randomize_cells",
            "cooldown_seconds",
            "max_in_flight",
        },
        "execution",
    )
    integer_fields = {
        "repetitions": (1, 20),
        "warmup_requests": (0, 100_000),
        "measured_requests": (1, 1_000_000),
        "bootstrap_samples": (100, 100_000),
        "seed": (0, 2**31 - 1),
        "max_in_flight": (1, 4096),
    }
    for field, (minimum, maximum) in integer_fields.items():
        value = execution.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise ProtocolError(f"execution.{field} must be from {minimum} to {maximum}")
    for field in ("open_loop_duration_seconds", "cooldown_seconds"):
        value = execution.get(field)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)) or value < 0:
            raise ProtocolError(f"execution.{field} must be non-negative")
    if not isinstance(execution.get("randomize_cells"), bool):
        raise ProtocolError("execution.randomize_cells must be boolean")
    if execution.get("open_loop_arrival_distribution", "fixed") not in {"fixed", "poisson"}:
        raise ProtocolError("execution.open_loop_arrival_distribution must be fixed or poisson")

    if plan_version == PERFORMANCE_PLAN_VERSION:
        load_generator = _object(config.get("load_generator"), "load_generator")
        _reject_unknown(
            load_generator,
            {"minimum_dispatch_rate_fraction", "maximum_dispatch_lag_p95_ms", "maximum_dispatch_lag_ms"},
            "load_generator",
        )
        fidelity = load_generator.get("minimum_dispatch_rate_fraction")
        if not isinstance(fidelity, (int, float)) or isinstance(fidelity, bool) or not math.isfinite(float(fidelity)) or not 0 < float(fidelity) <= 1:
            raise ProtocolError("load_generator.minimum_dispatch_rate_fraction must be from 0 (exclusive) to 1")
        for field in ("maximum_dispatch_lag_p95_ms", "maximum_dispatch_lag_ms"):
            value = load_generator.get(field)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)) or value < 0:
                raise ProtocolError(f"load_generator.{field} must be non-negative")
        if float(load_generator["maximum_dispatch_lag_p95_ms"]) > float(load_generator["maximum_dispatch_lag_ms"]):
            raise ProtocolError("load-generator p95 dispatch lag cannot exceed its maximum lag")

    limits = _object(config.get("limits"), "limits")
    _reject_unknown(
        limits,
        {"timeout_seconds", "max_requests", "max_total_tokens", "max_campaign_seconds", "max_context_tokens", "max_output_tokens"},
        "limits",
    )
    required_limits = ("timeout_seconds", "max_requests", "max_total_tokens", "max_campaign_seconds", "max_context_tokens", "max_output_tokens")
    if any(
        not isinstance(limits.get(field), (int, float)) or isinstance(limits[field], bool) or not math.isfinite(float(limits[field])) or limits[field] <= 0
        for field in required_limits
    ):
        raise ProtocolError(f"limits requires positive values for {required_limits}")
    for field in ("max_requests", "max_total_tokens", "max_context_tokens", "max_output_tokens"):
        if not isinstance(limits[field], int):
            raise ProtocolError(f"limits.{field} must be an integer")
    scenarios = config.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ProtocolError("performance plan requires at least one [[scenarios]] table")
    scenario_ids: set[str] = set()
    workload_contexts = {int(row["context_tokens"]) for row in workload}
    for index, scenario_value in enumerate(scenarios, 1):
        scenario = _object(scenario_value, f"scenarios[{index}]")
        _reject_unknown(
            scenario,
            {"id", "arrival", "context_tokens", "output_tokens", "concurrency", "request_rates", "warmup_requests", "measured_requests", "duration_seconds"},
            f"scenarios[{index}]",
        )
        identifier = scenario.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in scenario_ids:
            raise ProtocolError(f"scenarios[{index}].id is missing or duplicate")
        if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in identifier):
            raise ProtocolError(f"scenario {identifier!r} has an unsafe id")
        scenario_ids.add(identifier)
        if scenario.get("arrival") not in {"closed-loop", "open-loop"}:
            raise ProtocolError(f"scenario {identifier} arrival must be closed-loop or open-loop")
        contexts = [int(item) for item in _numbers(scenario.get("context_tokens"), f"scenario {identifier} context_tokens", integer=True)]
        outputs = [int(item) for item in _numbers(scenario.get("output_tokens"), f"scenario {identifier} output_tokens", integer=True)]
        if not set(contexts) <= workload_contexts:
            raise ProtocolError(f"scenario {identifier} has contexts missing from the workload: {sorted(set(contexts) - workload_contexts)}")
        if max(contexts) > int(limits["max_context_tokens"]) or max(outputs) > int(limits["max_output_tokens"]):
            raise ProtocolError(f"scenario {identifier} exceeds plan token limits")
        load_field = "concurrency" if scenario["arrival"] == "closed-loop" else "request_rates"
        other_load_field = "request_rates" if load_field == "concurrency" else "concurrency"
        if other_load_field in scenario:
            raise ProtocolError(f"scenario {identifier} cannot define {other_load_field} for {scenario['arrival']}")
        values = _numbers(scenario.get(load_field), f"scenario {identifier} {load_field}", integer=scenario["arrival"] == "closed-loop")
        if scenario["arrival"] == "closed-loop" and max(values) > execution["max_in_flight"]:
            raise ProtocolError(f"scenario {identifier} concurrency exceeds execution.max_in_flight")
        if "warmup_requests" in scenario and (
            not isinstance(scenario["warmup_requests"], int) or isinstance(scenario["warmup_requests"], bool) or scenario["warmup_requests"] < 0
        ):
            raise ProtocolError(f"scenario {identifier} warmup_requests is invalid")
        if "measured_requests" in scenario and (
            not isinstance(scenario["measured_requests"], int) or isinstance(scenario["measured_requests"], bool) or scenario["measured_requests"] < 1
        ):
            raise ProtocolError(f"scenario {identifier} measured_requests is invalid")
        if "duration_seconds" in scenario and (
            not isinstance(scenario["duration_seconds"], (int, float))
            or isinstance(scenario["duration_seconds"], bool)
            or not math.isfinite(float(scenario["duration_seconds"]))
            or scenario["duration_seconds"] <= 0
        ):
            raise ProtocolError(f"scenario {identifier} duration_seconds is invalid")
        if scenario["arrival"] == "open-loop" and float(scenario.get("duration_seconds", execution["open_loop_duration_seconds"])) <= 0:
            raise ProtocolError(f"open-loop scenario {identifier} requires a positive duration")
        if scenario["arrival"] == "open-loop" and "measured_requests" in scenario:
            raise ProtocolError(f"open-loop scenario {identifier} cannot define measured_requests; use duration_seconds")
        if scenario["arrival"] == "closed-loop" and "duration_seconds" in scenario:
            raise ProtocolError(f"closed-loop scenario {identifier} cannot define duration_seconds")

    slo = _object(config.get("slo"), "slo")
    _reject_unknown(
        slo,
        {
            "ttft_p95_ms",
            "e2e_p99_ms",
            "goodput_ttft_ms",
            "goodput_e2e_ms",
            "maximum_error_rate",
            "minimum_output_tokens_fraction",
            "minimum_p99_observations",
        },
        "slo",
    )
    for field in ("ttft_p95_ms", "e2e_p99_ms", "goodput_ttft_ms", "goodput_e2e_ms"):
        if not isinstance(slo.get(field), (int, float)) or isinstance(slo[field], bool) or not math.isfinite(float(slo[field])) or slo[field] <= 0:
            raise ProtocolError(f"slo.{field} must be positive")
    for field in ("maximum_error_rate", "minimum_output_tokens_fraction"):
        if (
            not isinstance(slo.get(field), (int, float))
            or isinstance(slo[field], bool)
            or not math.isfinite(float(slo[field]))
            or not 0 <= float(slo[field]) <= 1
        ):
            raise ProtocolError(f"slo.{field} must be from 0 to 1")
    minimum_p99 = slo.get("minimum_p99_observations", 1)
    if not isinstance(minimum_p99, int) or isinstance(minimum_p99, bool) or not 1 <= minimum_p99 <= 1_000_000:
        raise ProtocolError("slo.minimum_p99_observations must be from 1 to 1000000")
    tolerance = workload_config.get("input_token_tolerance_fraction", 0.05)
    if not isinstance(tolerance, (int, float)) or isinstance(tolerance, bool) or not math.isfinite(float(tolerance)) or not 0 <= float(tolerance) <= 1:
        raise ProtocolError("workload.input_token_tolerance_fraction must be from 0 to 1")
    plan = PerformancePlan(resolved, sha256_bytes(source), config, workload_path, workload, workload_hash, assets)
    _validate_performance_plan_capacity(plan)
    return plan


def _require_official_reference_inputs(
    protocol_sha256: Any,
    plan_sha256: Any,
    workload_sha256: Any,
    workload_assets: Any,
    *,
    repo_root: Path | None = None,
) -> None:
    root = repo_root.resolve() if repo_root is not None else None
    protocol_path = canonical_performance_protocol_path(PERFORMANCE_PROTOCOL_VERSION, repo_root=root)
    resource_root = protocol_path.parent
    reference_path = resource_root / "performance" / "plans" / "llm-serving-v2.toml"
    if protocol_path.is_symlink() or not protocol_path.is_file() or reference_path.is_symlink() or not reference_path.is_file():
        raise ProtocolError("official performance requires the built-in reference protocol and plan")
    reference = load_performance_plan(reference_path)
    if (protocol_sha256, plan_sha256, workload_sha256, workload_assets) != (
        sha256_file(protocol_path),
        reference.sha256,
        reference.workload_sha256,
        reference.workload_assets,
    ):
        raise ProtocolError("official performance requires the exact reference plan, workload, and built-in protocol")


def load_performance_runtime(path: str | Path) -> PerformanceRuntime:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ProtocolError("performance runtime must not be a symlink")
    resolved = candidate.resolve()
    try:
        source = resolved.read_bytes()
        config = tomllib.loads(source.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot load performance runtime: {exc}") from exc
    if not _finite_json(config):
        raise ProtocolError("performance runtime contains non-finite values")
    if config.get("runtime_version") != PERFORMANCE_RUNTIME_VERSION:
        raise ProtocolError("performance runtime requires runtime_version=1.0.0")
    _reject_unknown(
        config,
        {
            "runtime_version",
            "id",
            "endpoint",
            "request_model",
            "expected_model",
            "model_revision",
            "api_key_env",
            "engine",
            "engine_revision",
            "model_artifact_revision",
            "dtype",
            "quantization",
            "gpu_count",
            "gpu_model",
            "tensor_parallel",
            "max_context_tokens",
            "container_image_digest",
            "launch_command_sanitized",
            "pricing",
        },
        "performance runtime",
    )
    required_text = (
        "id",
        "endpoint",
        "request_model",
        "expected_model",
        "model_revision",
        "api_key_env",
        "engine",
        "engine_revision",
        "model_artifact_revision",
        "dtype",
        "quantization",
        "gpu_model",
        "launch_command_sanitized",
    )
    if any(not isinstance(config.get(field), str) or not config[field].strip() for field in required_text):
        raise ProtocolError(f"performance runtime requires non-empty fields: {required_text}")
    if config["id"][0] not in "abcdefghijklmnopqrstuvwxyz0123456789" or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in config["id"]
    ):
        raise ProtocolError("performance runtime id must use lowercase letters, digits, dash, underscore, or dot")
    api_key_env = config["api_key_env"]
    if api_key_env[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_" or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_0123456789" for character in api_key_env
    ):
        raise ProtocolError("performance runtime api_key_env must be an environment-variable name")
    immutable_fields = ("model_revision", "engine_revision", "model_artifact_revision", "gpu_model", "launch_command_sanitized")
    if any(any(marker in config[field].casefold() for marker in ("replace-with", "todo", "unknown")) for field in immutable_fields):
        raise ProtocolError("performance runtime contains placeholder identity or launch evidence")
    artifact_digest = config["model_artifact_revision"]
    if len(artifact_digest) != 64 or any(character not in "0123456789abcdef" for character in artifact_digest):
        raise ProtocolError("performance runtime model_artifact_revision must be a lowercase SHA-256")
    parsed_endpoint = urllib.parse.urlsplit(config["endpoint"])
    if not parsed_endpoint.hostname:
        raise ProtocolError("performance runtime endpoint requires a hostname")
    safe_endpoint = _manifest_endpoint(config["endpoint"])
    if not safe_endpoint.startswith(("http://", "https://")):
        raise ProtocolError("performance runtime endpoint must use http or https")
    if safe_endpoint != config["endpoint"]:
        raise ProtocolError("performance runtime endpoint must not contain credentials, query values, or fragments")
    if contains_secret_like({key: value for key, value in config.items() if key != "api_key_env"}):
        raise ProtocolError("performance runtime contains secret-like material")
    for field in ("gpu_count", "tensor_parallel", "max_context_tokens"):
        if not isinstance(config.get(field), int) or isinstance(config[field], bool) or config[field] < 1:
            raise ProtocolError(f"performance runtime {field} must be a positive integer")
    if config["tensor_parallel"] > config["gpu_count"]:
        raise ProtocolError("performance runtime tensor_parallel cannot exceed gpu_count")
    container_digest = config.get("container_image_digest", "")
    if (
        not isinstance(container_digest, str)
        or container_digest
        and (
            not container_digest.startswith("sha256:")
            or len(container_digest) != 71
            or any(character not in "0123456789abcdefABCDEF" for character in container_digest[7:])
        )
    ):
        raise ProtocolError("container_image_digest must be empty or sha256:<64 hex characters>")
    pricing = config.get("pricing")
    if pricing is not None:
        pricing = _object(pricing, "runtime pricing")
        _reject_unknown(pricing, {"currency", "source", "effective_at", "input_per_million", "output_per_million"}, "runtime pricing")
        for field in ("currency", "source", "effective_at"):
            if not isinstance(pricing.get(field), str) or not pricing[field]:
                raise ProtocolError(f"runtime pricing {field} is required")
        if len(pricing["currency"]) != 3 or not pricing["currency"].isalpha() or pricing["currency"] != pricing["currency"].upper():
            raise ProtocolError("runtime pricing currency must be a three-letter uppercase code")
        try:
            datetime.fromisoformat(pricing["effective_at"])
        except ValueError as exc:
            raise ProtocolError("runtime pricing effective_at must be an ISO date or datetime") from exc
        for field in ("input_per_million", "output_per_million"):
            if (
                not isinstance(pricing.get(field), (int, float))
                or isinstance(pricing[field], bool)
                or not math.isfinite(float(pricing[field]))
                or pricing[field] < 0
            ):
                raise ProtocolError(f"runtime pricing {field} must be non-negative")
    return PerformanceRuntime(resolved, sha256_bytes(source), config)


def _cross_check_system_evidence(runtime: PerformanceRuntime, evidence: dict[str, Any]) -> None:
    config = runtime.config
    software = evidence["software"]
    serving = evidence["serving"]
    network = evidence["network"]
    accelerators = evidence["server"]["accelerators"]
    expected = {
        "software.engine.name": config["engine"],
        "software.engine.revision": config["engine_revision"],
        "software.model.name": config["expected_model"],
        "software.model.revision": config["model_revision"],
        "software.model.artifact_sha256": config["model_artifact_revision"],
        "serving.tensor_parallel": config["tensor_parallel"],
        "serving.max_context_tokens": config["max_context_tokens"],
        "serving.launch_command_sanitized": config["launch_command_sanitized"],
    }
    actual = {
        "software.engine.name": software["engine"]["name"],
        "software.engine.revision": software["engine"]["revision"],
        "software.model.name": software["model"]["name"],
        "software.model.revision": software["model"]["revision"],
        "software.model.artifact_sha256": software["model"]["artifact_sha256"],
        "serving.tensor_parallel": serving["tensor_parallel"],
        "serving.max_context_tokens": serving["max_context_tokens"],
        "serving.launch_command_sanitized": serving["launch_command_sanitized"],
    }
    mismatches = [path for path, value in expected.items() if actual[path] != value]
    for path, runtime_value, evidence_value in (
        ("software.model.dtype", config["dtype"], software["model"]["dtype"]),
        ("software.model.quantization", config["quantization"], software["model"]["quantization"]),
    ):
        if str(runtime_value).casefold() != str(evidence_value).casefold():
            mismatches.append(path)
    runtime_digest = config.get("container_image_digest")
    evidence_digest = software["engine"]["container_image_digest"]
    if (runtime_digest and evidence_digest != runtime_digest) or (not runtime_digest and evidence_digest is not None):
        mismatches.append("software.engine.container_image_digest")
    if isinstance(accelerators, list):
        if len(accelerators) != config["gpu_count"]:
            mismatches.append("server.accelerators count")
        if any(accelerator["model"] != config["gpu_model"] for accelerator in accelerators):
            mismatches.append("server.accelerators model")
    parsed = urllib.parse.urlsplit(str(config["endpoint"]))
    endpoint_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if network["endpoint_host"] is not None and network["endpoint_host"] != parsed.hostname:
        mismatches.append("network.endpoint_host")
    if network["endpoint_port"] is not None and network["endpoint_port"] != endpoint_port:
        mismatches.append("network.endpoint_port")
    expected_transport = "tls" if parsed.scheme == "https" else "tcp"
    if network["transport"] != expected_transport:
        mismatches.append("network.transport")
    try:
        loopback_endpoint = ipaddress.ip_address(str(parsed.hostname)).is_loopback
    except ValueError:
        loopback_endpoint = parsed.hostname == "localhost"
    if loopback_endpoint and network["relationship"] not in {"same-host", "tunnel"}:
        mismatches.append("network.relationship")
    if mismatches:
        raise ProtocolError(f"system evidence differs from performance runtime: {sorted(mismatches)}")


def _structural_unavailable(runtime: dict[str, Any], evidence: dict[str, Any]) -> set[str]:
    engine = evidence["software"]["engine"]
    if runtime.get("container_image_digest"):
        return {"/software/engine/binary_sha256"} if engine["binary_sha256"] is None else set()
    return {"/software/engine/container_image_digest"}


def performance_run_preflight(
    plan: PerformancePlan,
    runtime: PerformanceRuntime,
    *,
    repo_root: Path,
    system_evidence_path: Path | None = None,
    official: bool = False,
) -> tuple[dict[str, Any] | None, bytes | None, dict[str, Any]]:
    if official:
        require_matching_source_checkout(repo_root, __file__)
    protocol_version, _ = _performance_versions(str(plan.config["plan_version"]))
    protocol_path = canonical_performance_protocol_path(protocol_version, repo_root=repo_root)
    if not protocol_path.is_file() or protocol_path.is_symlink():
        raise ProtocolError(f"performance run requires a regular {protocol_path.name} snapshot")
    evidence: dict[str, Any] | None = None
    evidence_raw: bytes | None = None
    if system_evidence_path is not None:
        evidence = load_system_evidence(system_evidence_path)
        evidence_raw = system_evidence_path.read_bytes()
        try:
            snapshot_value = json.loads(evidence_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:  # pragma: no cover - load_system_evidence already rejected this state.
            raise ProtocolError("system evidence changed after validation") from exc
        if snapshot_value != evidence:
            raise ProtocolError("system evidence changed after validation")
        _cross_check_system_evidence(runtime, evidence)
    source = git_evidence(repo_root)
    if official:
        _require_official_reference_inputs(
            sha256_file(protocol_path),
            plan.sha256,
            plan.workload_sha256,
            plan.workload_assets,
            repo_root=repo_root,
        )
        if not source.get("commit") or source.get("dirty") is not False:
            raise ProtocolError("official performance requires a clean committed source tree")
        if evidence is None:
            raise ProtocolError("official performance requires --system-evidence")
        allowed_unavailable = _structural_unavailable(runtime.config, evidence)
        if evidence["projection"] != "restricted" or set(evidence["unavailable"]) != allowed_unavailable:
            raise ProtocolError("official performance requires complete restricted system evidence")
        collected_at = datetime.fromisoformat(str(evidence["collected_at"]).replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if collected_at > now or now - collected_at > timedelta(hours=24):
            raise ProtocolError("official performance requires system evidence collected within the previous 24 hours")
        mutable_revisions = [field for field in ("model_revision", "engine_revision") if not _content_addressed_revision(runtime.config[field])]
        if mutable_revisions:
            raise ProtocolError(
                "official performance requires content-addressed model_revision and engine_revision "
                f"(full 40/64-hex commit or sha256:<64-hex>); invalid: {mutable_revisions}"
            )
        client = evidence["load_generator"]["client"]
        if client["name"] != "cavadalabs-evals" or client["revision"] != source["commit"]:
            raise ProtocolError("official performance requires load_generator.client to identify this cavadalabs-evals source commit")
        skipped = [cell["cell_key"] for cell in _expand_cells(plan, runtime) if cell.get("skip_reason")]
        if skipped:
            raise ProtocolError(f"official performance requires every reference cell; unsupported cells: {skipped}")
    return evidence, evidence_raw, source


def performance_plan_summary(plan: PerformancePlan, runtime: PerformanceRuntime | None = None) -> dict[str, Any]:
    cells = _expand_cells(plan, runtime)
    planned_contexts = sorted({int(cell["context_tokens"]) for cell in cells})
    planned_outputs = sorted({int(cell["output_tokens"]) for cell in cells})
    result = {
        "performance_protocol_version": _performance_versions(str(plan.config["plan_version"]))[0],
        "plan": plan.config["name"],
        "plan_revision": plan.config["revision"],
        "plan_sha256": plan.sha256,
        "workload_sha256": plan.workload_sha256,
        "workload_assets": plan.workload_assets,
        "workload_cases": len(plan.workload),
        "prefix_cache_policy": plan.config["workload"].get("prefix_cache_policy", "unspecified"),
        "open_loop_arrival_distribution": plan.config["execution"].get("open_loop_arrival_distribution", "fixed"),
        "minimum_p99_observations": plan.config["slo"].get("minimum_p99_observations", 1),
        "contexts": planned_contexts,
        "output_tokens": planned_outputs,
        "available_workload_contexts": sorted({int(row["context_tokens"]) for row in plan.workload}),
        "scenarios": len(plan.config["scenarios"]),
        "cells_per_repetition": len(cells),
        "repetitions": plan.config["execution"]["repetitions"],
        "planned_requests": _planned_requests(plan, cells),
    }
    if runtime:
        result["runtime"] = {
            "id": runtime.config["id"],
            "engine": runtime.config["engine"],
            "max_context_tokens": runtime.config["max_context_tokens"],
            "compatible_cells_per_repetition": sum(not cell.get("skip_reason") for cell in cells),
            "skipped_cells_per_repetition": sum(bool(cell.get("skip_reason")) for cell in cells),
        }
    return result


def _expand_cells(plan: PerformancePlan, runtime: PerformanceRuntime | None) -> list[dict[str, Any]]:
    cells: list[dict[str, Any]] = []
    for scenario in plan.config["scenarios"]:
        load_field = "concurrency" if scenario["arrival"] == "closed-loop" else "request_rates"
        for context in scenario["context_tokens"]:
            for output in scenario["output_tokens"]:
                for load in scenario[load_field]:
                    cell = {
                        "scenario_id": scenario["id"],
                        "arrival": scenario["arrival"],
                        "context_tokens": int(context),
                        "output_tokens": int(output),
                        "concurrency": int(load) if scenario["arrival"] == "closed-loop" else None,
                        "request_rate": float(load) if scenario["arrival"] == "open-loop" else None,
                        "warmup_requests": int(scenario.get("warmup_requests", plan.config["execution"]["warmup_requests"])),
                        "measured_requests": int(scenario.get("measured_requests", plan.config["execution"]["measured_requests"])),
                        "duration_seconds": float(scenario.get("duration_seconds", plan.config["execution"]["open_loop_duration_seconds"])),
                    }
                    cell["cell_key"] = _cell_key(cell)
                    if runtime and int(context) + int(output) > int(runtime.config["max_context_tokens"]):
                        cell["skip_reason"] = "context plus requested output exceeds runtime max_context_tokens"
                    cells.append(cell)
    return cells


def _reproducible_seed(plan: PerformancePlan, cell: dict[str, Any], block: int, phase: str) -> int:
    material = f"{plan.config['execution']['seed']}\0{cell['cell_key']}\0{block}\0{phase}"
    return int(sha256_bytes(material.encode())[:16], 16)


def _open_loop_offsets(
    plan: PerformancePlan,
    cell: dict[str, Any],
    block: int,
    phase: str,
    *,
    count: int | None = None,
) -> list[float]:
    rate = float(cell["request_rate"])
    distribution_name = str(plan.config["execution"].get("open_loop_arrival_distribution", "fixed"))
    if distribution_name == "fixed":
        total = count if count is not None else max(1, math.ceil(rate * float(cell["duration_seconds"])))
        return [index / rate for index in range(total)]
    rng = random.Random(_reproducible_seed(plan, cell, block, phase))  # noqa: S311 -- frozen experimental schedule.
    offsets: list[float] = []
    elapsed = 0.0
    if count is not None:
        for _ in range(count):
            elapsed += rng.expovariate(rate)
            offsets.append(elapsed)
        return offsets
    duration = float(cell["duration_seconds"])
    while True:
        elapsed += rng.expovariate(rate)
        if elapsed >= duration:
            return offsets
        offsets.append(elapsed)


def _measured_request_count(plan: PerformancePlan, cell: dict[str, Any], block: int) -> int:
    if cell["arrival"] == "closed-loop":
        return int(cell["measured_requests"])
    return len(_open_loop_offsets(plan, cell, block, "measured"))


def _planned_requests(plan: PerformancePlan, cells: list[dict[str, Any]] | None = None) -> int:
    selected = cells if cells is not None else _expand_cells(plan, None)
    return sum(
        int(cell["warmup_requests"]) + _measured_request_count(plan, cell, block)
        for block in range(1, int(plan.config["execution"]["repetitions"]) + 1)
        for cell in selected
        if not cell.get("skip_reason")
    )


def _planned_token_upper_bound(plan: PerformancePlan) -> float:
    tolerance = float(plan.config["workload"].get("input_token_tolerance_fraction", 0.05))
    return sum(
        (float(cell["context_tokens"]) + max(2.0, float(cell["context_tokens"]) * tolerance) + float(cell["output_tokens"]))
        * (int(cell["warmup_requests"]) + _measured_request_count(plan, cell, block))
        for block in range(1, int(plan.config["execution"]["repetitions"]) + 1)
        for cell in _expand_cells(plan, None)
    )


def _validate_performance_plan_capacity(plan: PerformancePlan) -> None:
    minimum = int(plan.config["slo"].get("minimum_p99_observations", 1))
    for block in range(1, int(plan.config["execution"]["repetitions"]) + 1):
        for cell in _expand_cells(plan, None):
            observations = _measured_request_count(plan, cell, block)
            if observations < minimum:
                raise ProtocolError(
                    f"performance cell {cell['cell_key']} block {block} schedules {observations} observations; slo.minimum_p99_observations requires {minimum}"
                )
    planned = _planned_requests(plan)
    if planned > int(plan.config["limits"]["max_requests"]):
        raise ProtocolError(f"performance campaign plans {planned} requests; limit is {plan.config['limits']['max_requests']}")
    planned_tokens = _planned_token_upper_bound(plan)
    if planned_tokens > int(plan.config["limits"]["max_total_tokens"]):
        raise ProtocolError(f"performance campaign plans up to {planned_tokens:g} tokens; limit is {plan.config['limits']['max_total_tokens']}")


def _cell_key(cell: dict[str, Any]) -> str:
    load = f"c{cell['concurrency']}" if cell.get("concurrency") is not None else f"rps{cell['request_rate']:g}"
    return f"{cell['scenario_id']}__ctx{cell['context_tokens']}__out{cell['output_tokens']}__{load}"


def _prompt(row: dict[str, Any], workload_assets: Mapping[str, bytes]) -> str:
    if "prompt" in row:
        return str(row["prompt"])
    if "prompt_file" in row:
        try:
            return workload_assets[str(row["prompt_file"])].decode("utf-8")
        except KeyError as exc:
            raise ProtocolError(f"workload asset was not cached: {row['prompt_file']}") from exc
    return str(row.get("prefix", "")) + str(row["repeat_text"]) * int(row["repeat_count"]) + str(row.get("suffix", ""))


def _messages(row: dict[str, Any], workload_assets: Mapping[str, bytes], cache_nonce: str | None = None) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    if row.get("system"):
        result.append({"role": "system", "content": str(row["system"])})
    result.append({"role": "user", "content": _prompt(row, workload_assets)})
    if cache_nonce is not None:
        result[0]["content"] = f"[cache-key:{cache_nonce}]\n{result[0]['content']}"
    return result


def _cache_nonce(plan: PerformancePlan, cell: dict[str, Any], row: dict[str, Any], index: int, block: int, phase: str) -> str | None:
    if plan.config["workload"].get("prefix_cache_policy", "unspecified") != "diverse":
        return None
    material = f"{plan.config['execution']['seed']}\0{cell['cell_key']}\0{row['id']}\0{block}\0{phase}\0{index}"
    return sha256_bytes(material.encode())[:16]


def _request_material(
    plan: PerformancePlan,
    runtime: dict[str, Any],
    cell: dict[str, Any],
    row: dict[str, Any],
    index: int,
    block: int,
    phase: str,
    workload_assets: Mapping[str, bytes],
) -> tuple[str | None, dict[str, Any]]:
    cache_nonce = _cache_nonce(plan, cell, row, index, block, phase)
    return cache_nonce, {
        **plan.config["generation"].get("request_defaults", {}),
        "model": runtime["request_model"],
        "messages": _messages(row, workload_assets, cache_nonce),
        "temperature": 0,
        "max_tokens": cell["output_tokens"],
        "stream": True,
        "stream_options": {"include_usage": True},
    }


def _bootstrap_percentile(values: list[float], probability: float, samples: int, seed: int) -> dict[str, float | int]:
    if not values:
        return {"lower": 0.0, "upper": 0.0, "confidence": 0.95, "samples": samples, "seed": seed}
    rng = random.Random(seed)  # noqa: S311 -- deterministic statistical resampling, not cryptography.
    estimates = [percentile(rng.choices(values, k=len(values)), probability) for _ in range(samples)]
    return {
        "lower": percentile(estimates, 0.025),
        "upper": percentile(estimates, 0.975),
        "confidence": 0.95,
        "samples": samples,
        "seed": seed,
    }


def _metric_summary(values: list[float], bootstrap_samples: int, seed: int) -> dict[str, Any]:
    summary: dict[str, Any] = distribution(values)
    summary["p95_ci"] = _bootstrap_percentile(values, 0.95, bootstrap_samples, seed)
    summary["p99_ci"] = _bootstrap_percentile(values, 0.99, bootstrap_samples, seed + 1)
    return summary


def _line_svg(
    title: str,
    series: list[tuple[str, list[float]]],
    path: Path,
    y_label: str,
    *,
    x_labels: list[str] | None = None,
    x_label: str = "Comparable cell",
) -> None:
    longest = max([len(values) for _, values in series] + [len(x_labels or []), 1])
    labels = (x_labels or [str(index + 1) for index in range(longest)])[:longest]
    labels.extend("" for _ in range(longest - len(labels)))
    all_values = [value for _, values in series for value in values if math.isfinite(value)]
    maximum = max(all_values, default=0.0) or 1.0
    width, left, right, top, bottom = 1080, 92, 1040, 72, 414
    legend_rows = max(1, math.ceil(len(series) / 2))
    height = 522 + legend_rows * 24
    colors = ("#1769aa", "#b43c2f", "#237a3b", "#7040a0", "#886800", "#455a64")
    dashes = ("", "8 4", "3 3", "10 3 2 3", "2 3", "12 4")

    def x_position(position: int) -> float:
        return (left + right) / 2 if longest == 1 else left + position * (right - left) / (longest - 1)

    def display(value: float) -> str:
        if abs(value) >= 1000:
            return f"{value:,.0f}"
        if abs(value) >= 10:
            return f"{value:.1f}"
        return f"{value:.3g}"

    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<title id="title">{html.escape(title)}</title>',
        f'<desc id="desc">{html.escape(y_label)} by {html.escape(x_label)}. Missing values are omitted and never connected; exact values and uncertainty are tabulated in the report.</desc>',
        '<rect width="100%" height="100%" fill="#fff"/>',
        f'<text x="{left}" y="32" fill="#172033" font-family="system-ui" font-size="20" font-weight="700">{html.escape(title)}</text>',
    ]
    for tick in range(5):
        value = maximum * tick / 4
        y = bottom - (bottom - top) * tick / 4
        elements.extend(
            (
                f'<line x1="{left}" y1="{y:.1f}" x2="{right}" y2="{y:.1f}" stroke="#d7dee8" stroke-width="1"/>',
                f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" fill="#384357" font-family="system-ui" font-size="12">{html.escape(display(value))}</text>',
            )
        )
    elements.extend(
        (
            f'<line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" stroke="#172033" stroke-width="1.5"/>',
            f'<line x1="{left}" y1="{top}" x2="{left}" y2="{bottom}" stroke="#172033" stroke-width="1.5"/>',
        )
    )
    rotate = longest > 6 or any(len(label) > 10 for label in labels)
    for position, label in enumerate(labels):
        x = x_position(position)
        transform = f' transform="rotate(-35 {x:.1f} {bottom + 22})" text-anchor="end"' if rotate else ' text-anchor="middle"'
        elements.extend(
            (
                f'<line class="x-tick" x1="{x:.1f}" y1="{bottom}" x2="{x:.1f}" y2="{bottom + 6}" stroke="#172033"/>',
                f'<text class="x-tick-label" x="{x:.1f}" y="{bottom + 22}"{transform} fill="#384357" font-family="system-ui" font-size="12">{html.escape(label)}</text>',
            )
        )
    for index, (label, values) in enumerate(series):
        color = colors[index % len(colors)]
        dash = f' stroke-dasharray="{dashes[index % len(dashes)]}"' if dashes[index % len(dashes)] else ""
        segments: list[list[tuple[int, float]]] = []
        segment: list[tuple[int, float]] = []
        for position, value in enumerate(values[:longest]):
            if math.isfinite(value):
                segment.append((position, value))
            elif segment:
                segments.append(segment)
                segment = []
        if segment:
            segments.append(segment)
        for points in segments:
            if len(points) > 1:
                coordinates = " ".join(
                    f"{x_position(position):.1f},{bottom - value * (bottom - top) / maximum:.1f}" for position, value in points
                )
                elements.append(
                    f'<polyline class="data-line" points="{coordinates}" fill="none" stroke="{color}" stroke-width="2.5"{dash}/>'
                )
            for position, value in points:
                x = x_position(position)
                y = bottom - value * (bottom - top) / maximum
                elements.append(
                    f'<circle class="data-point" cx="{x:.1f}" cy="{y:.1f}" r="4" fill="#fff" stroke="{color}" stroke-width="2.5"><title>{html.escape(label)}; {html.escape(labels[position])}: {html.escape(display(value))}</title></circle>'
                )
    if not all_values:
        elements.append(
            f'<text x="{(left + right) / 2:.1f}" y="{(top + bottom) / 2:.1f}" text-anchor="middle" fill="#5d6675" font-family="system-ui" font-size="16">No successful observations available</text>'
        )
    axis_y = bottom + (67 if rotate else 48)
    elements.extend(
        (
            f'<text x="{(left + right) / 2:.1f}" y="{axis_y}" text-anchor="middle" fill="#172033" font-family="system-ui" font-size="13">{html.escape(x_label)}</text>',
            f'<text x="25" y="{(top + bottom) / 2:.1f}" transform="rotate(-90 25 {(top + bottom) / 2:.1f})" text-anchor="middle" fill="#172033" font-family="system-ui" font-size="13">{html.escape(y_label)}</text>',
        )
    )
    legend_y = 500
    for index, (label, _) in enumerate(series):
        column, row = index % 2, index // 2
        x, y = left + column * 474, legend_y + row * 24
        color = colors[index % len(colors)]
        dash = f' stroke-dasharray="{dashes[index % len(dashes)]}"' if dashes[index % len(dashes)] else ""
        elements.extend(
            (
                f'<line x1="{x}" y1="{y}" x2="{x + 28}" y2="{y}" stroke="{color}" stroke-width="2.5"{dash}/>',
                f'<circle cx="{x + 14}" cy="{y}" r="3.5" fill="#fff" stroke="{color}" stroke-width="2"/>',
                f'<text x="{x + 38}" y="{y + 4}" fill="#172033" font-family="system-ui" font-size="12">{html.escape(label)}</text>',
            )
        )
    elements.append("</svg>")
    atomic_text(path, "".join(elements) + "\n")


def _cell_metrics(
    observations: list[dict[str, Any]],
    cell: dict[str, Any],
    plan: PerformancePlan,
    window_seconds: float,
    seed: int,
    pricing: dict[str, Any] | None,
) -> dict[str, Any]:
    successes = [row for row in observations if row["status"] == "success"]
    usage_rows = [row for row in observations if "input_tokens" in row and "output_tokens" in row]
    errors = Counter(str(row.get("error_type", row["status"])) for row in observations if row["status"] != "success")
    slo = plan.config["slo"]
    good = [
        row
        for row in successes
        if float(row["ttft_ms"]) <= float(slo["goodput_ttft_ms"])
        and float(row["e2e_ms"]) <= float(slo["goodput_e2e_ms"])
        and float(row["output_tokens"]) >= float(cell["output_tokens"]) * float(slo["minimum_output_tokens_fraction"])
        and (plan.config["workload"]["mode"] == "iso-prompt" or row.get("input_token_match", True))
    ]
    bootstrap = int(plan.config["execution"]["bootstrap_samples"])
    input_tokens = sum(float(row["input_tokens"]) for row in usage_rows)
    output_tokens = sum(float(row["output_tokens"]) for row in usage_rows)
    total_cost: float | None = None
    if isinstance(pricing, dict):
        total_cost = input_tokens * float(pricing["input_per_million"]) / 1_000_000 + output_tokens * float(pricing["output_per_million"]) / 1_000_000
    error_rate = (len(observations) - len(successes)) / len(observations) if observations else 1.0
    ttft = _metric_summary([float(row["ttft_ms"]) for row in successes], bootstrap, seed)
    e2e = _metric_summary([float(row["e2e_ms"]) for row in successes], bootstrap, seed + 2)
    minimum_p99 = int(slo.get("minimum_p99_observations", 1))
    p99_resolved = len(successes) >= minimum_p99
    gates = {
        "ttft_p95": bool(successes) and float(ttft["p95"]) <= float(slo["ttft_p95_ms"]),
        "e2e_p99": p99_resolved and float(e2e["p99"]) <= float(slo["e2e_p99_ms"]),
        "error_rate": error_rate <= float(slo["maximum_error_rate"]),
    }
    return {
        **{key: cell[key] for key in ("cell_key", "scenario_id", "arrival", "context_tokens", "output_tokens", "concurrency", "request_rate")},
        "status": "completed" if len(successes) == len(observations) else "completed-with-errors",
        "observations": len(observations),
        "successes": len(successes),
        "errors": len(observations) - len(successes),
        "error_types": dict(sorted(errors.items())),
        "error_rate": error_rate,
        "slo_passed": all(gates.values()),
        "slo_gates": gates,
        "goodput_requests": len(good),
        "goodput_requests_per_second": len(good) / window_seconds if window_seconds else 0.0,
        "requests_per_second": len(successes) / window_seconds if window_seconds else 0.0,
        "input_tokens_per_second": input_tokens / window_seconds if window_seconds else 0.0,
        "output_tokens_per_second": output_tokens / window_seconds if window_seconds else 0.0,
        "input_tokens_total": input_tokens,
        "output_tokens_total": output_tokens,
        "estimated_cost": total_cost,
        "measurement_window_seconds": window_seconds,
        "ttft_ms": ttft,
        "e2e_ms": e2e,
        "p99_resolution": {"successful_observations": len(successes), "minimum": minimum_p99, "resolved": p99_resolved},
        "tpot_ms": _metric_summary([float(row["tpot_ms"]) for row in successes if row.get("tpot_ms") is not None], bootstrap, seed + 4),
        "decode_tokens_per_second": _metric_summary(
            [float(row["decode_tokens_per_second"]) for row in successes if row.get("decode_tokens_per_second") is not None], bootstrap, seed + 6
        ),
        "client_queue_ms": _metric_summary([float(row["client_queue_ms"]) for row in observations], bootstrap, seed + 8),
        "input_tokens": distribution(float(row["input_tokens"]) for row in usage_rows),
        "actual_output_tokens": distribution(float(row["output_tokens"]) for row in usage_rows),
        "warnings": (
            [f"p99 gate unresolved: {len(successes)} successful observations; {minimum_p99} required"]
            if not p99_resolved
            else (["fewer than 1000 successful observations; p99 uncertainty remains high"] if len(successes) < 1000 else [])
        ),
    }


def _cell_metrics_v2(
    observations: list[dict[str, Any]],
    cell: dict[str, Any],
    plan: PerformancePlan,
    window_seconds: float,
    seed: int,
    pricing: dict[str, Any] | None,
) -> dict[str, Any]:
    metrics = _cell_metrics(observations, cell, plan, window_seconds, seed, pricing)
    successes = [row for row in observations if row["status"] == "success"]
    bootstrap = int(plan.config["execution"]["bootstrap_samples"])
    open_loop = cell["arrival"] == "open-loop"
    if not open_loop:
        metrics.update(
            {
                "serving_slo_passed": bool(metrics["slo_passed"]),
                "throughput_window_seconds": window_seconds,
                "offered_requests": None,
                "dispatched_requests": None,
                "completed_requests": None,
                "offered_requests_per_second": None,
                "dispatched_requests_per_second": None,
                "completed_requests_per_second": None,
                "dispatch_rate_fidelity": None,
                "load_generator_valid": None,
                "load_generator_gates": {},
                "load_generator_invalid_reasons": [],
                "dispatch_lag_ms": None,
                "scheduled_ttft_ms": None,
                "scheduled_e2e_ms": None,
            }
        )
        return metrics

    schedule_window = float(cell["duration_seconds"])
    batch_starts = {row.get("batch_started_monotonic_ns") for row in observations}
    batch_started_ns = next(iter(batch_starts)) if len(batch_starts) == 1 else None
    valid_batch_start = isinstance(batch_started_ns, int) and not isinstance(batch_started_ns, bool)
    schedule_end_ns = cast(int, batch_started_ns) + round(schedule_window * 1_000_000_000) if valid_batch_start else None
    clock_monotonic = bool(observations) and valid_batch_start
    dispatch_lags: list[float] = []
    for row in observations:
        scheduled_ns = row.get("scheduled_monotonic_ns")
        dispatch_ns = row.get("dispatch_monotonic_ns")
        completed_ns = row.get("completed_monotonic_ns")
        if (
            not isinstance(scheduled_ns, int)
            or isinstance(scheduled_ns, bool)
            or valid_batch_start
            and scheduled_ns < cast(int, batch_started_ns)
            or not isinstance(completed_ns, int)
            or isinstance(completed_ns, bool)
            or completed_ns < scheduled_ns
        ):
            clock_monotonic = False
            continue
        if dispatch_ns is None:
            continue
        if not isinstance(dispatch_ns, int) or isinstance(dispatch_ns, bool) or not scheduled_ns <= dispatch_ns <= completed_ns:
            clock_monotonic = False
            continue
        lag = round((dispatch_ns - scheduled_ns) / 1_000_000, 3)
        if row.get("dispatch_lag_ms") != lag:
            raise ProtocolError("performance dispatch lag differs from monotonic timing")
        dispatch_lags.append(lag)
        if row["status"] == "success":
            first_ns = row.get("first_token_monotonic_ns")
            if not isinstance(first_ns, int) or isinstance(first_ns, bool) or not dispatch_ns <= first_ns <= completed_ns:
                clock_monotonic = False
                continue
            if row.get("scheduled_ttft_ms") != round((first_ns - scheduled_ns) / 1_000_000, 3) or row.get(
                "scheduled_e2e_ms"
            ) != round((completed_ns - scheduled_ns) / 1_000_000, 3):
                raise ProtocolError("performance scheduled latency differs from monotonic timing")

    dispatch_lag = _metric_summary(dispatch_lags, bootstrap, seed + 10)
    offered = len(observations)
    dispatched = sum(
        isinstance(row.get("dispatch_monotonic_ns"), int)
        and not isinstance(row.get("dispatch_monotonic_ns"), bool)
        and (schedule_end_ns is None or cast(int, row["dispatch_monotonic_ns"]) <= schedule_end_ns)
        for row in observations
    )
    completed = sum(
        isinstance(row.get("completed_monotonic_ns"), int)
        and not isinstance(row.get("completed_monotonic_ns"), bool)
        and (schedule_end_ns is None or cast(int, row["completed_monotonic_ns"]) <= schedule_end_ns)
        for row in observations
    )
    fidelity = dispatched / offered if offered else 0.0
    thresholds = plan.config["load_generator"]
    load_generator_gates = {
        "schedule_complete": offered == _measured_request_count(plan, cell, int(observations[0]["block"])) if observations else False,
        "clock_monotonic": clock_monotonic,
        "dispatch_rate_fidelity": fidelity >= float(thresholds["minimum_dispatch_rate_fraction"]),
        "dispatch_lag_p95": bool(dispatch_lags)
        and float(dispatch_lag["p95"]) <= float(thresholds["maximum_dispatch_lag_p95_ms"]),
        "dispatch_lag_max": bool(dispatch_lags)
        and float(dispatch_lag["max"]) <= float(thresholds["maximum_dispatch_lag_ms"]),
    }
    load_generator_valid = all(load_generator_gates.values())
    invalid_reasons: list[str] = []
    if load_generator_gates.get("schedule_complete") is False:
        invalid_reasons.append("the measured schedule is incomplete")
    if load_generator_gates.get("clock_monotonic") is False:
        invalid_reasons.append("monotonic schedule, dispatch, first-token, or completion timing is invalid")
    if load_generator_gates.get("dispatch_rate_fidelity") is False:
        invalid_reasons.append(
            f"dispatch rate fidelity {fidelity:.4f} is below preregistered minimum "
            f"{float(plan.config['load_generator']['minimum_dispatch_rate_fraction']):.4f}"
        )
    if load_generator_gates.get("dispatch_lag_p95") is False:
        invalid_reasons.append(
            (
                f"dispatch lag p95 {float(dispatch_lag['p95']):.3f} ms exceeds preregistered maximum "
                f"{float(plan.config['load_generator']['maximum_dispatch_lag_p95_ms']):.3f} ms"
            )
            if dispatch_lags
            else "dispatch lag p95 is unavailable because no measured request was dispatched"
        )
    if load_generator_gates.get("dispatch_lag_max") is False:
        invalid_reasons.append(
            (
                f"dispatch lag max {float(dispatch_lag['max']):.3f} ms exceeds preregistered maximum "
                f"{float(plan.config['load_generator']['maximum_dispatch_lag_ms']):.3f} ms"
            )
            if dispatch_lags
            else "dispatch lag maximum is unavailable because no measured request was dispatched"
        )
    serving_slo_passed = bool(metrics["slo_passed"])
    slo_passed = serving_slo_passed and load_generator_valid is not False
    slo = plan.config["slo"]
    good = [
        row
        for row in successes
        if float(row["scheduled_ttft_ms"]) <= float(slo["goodput_ttft_ms"])
        and float(row["scheduled_e2e_ms"]) <= float(slo["goodput_e2e_ms"])
        and float(row["output_tokens"]) >= float(cell["output_tokens"]) * float(slo["minimum_output_tokens_fraction"])
        and (plan.config["workload"]["mode"] == "iso-prompt" or row.get("input_token_match", True))
    ]
    if load_generator_valid is False:
        good = []
    metrics.update(
        {
            "status": "invalid-loadgen" if load_generator_valid is False else metrics["status"],
            "serving_slo_passed": serving_slo_passed,
            "slo_passed": slo_passed,
            "goodput_requests": len(good),
            "goodput_requests_per_second": len(good) / schedule_window if schedule_window else 0.0,
            "requests_per_second": len(successes) / window_seconds if window_seconds else 0.0,
            "input_tokens_per_second": metrics["input_tokens_total"] / window_seconds if window_seconds else 0.0,
            "output_tokens_per_second": metrics["output_tokens_total"] / window_seconds if window_seconds else 0.0,
            "measurement_window_seconds": schedule_window,
            "throughput_window_seconds": window_seconds,
            "offered_requests": offered,
            "dispatched_requests": dispatched,
            "completed_requests": completed,
            "offered_requests_per_second": offered / schedule_window if schedule_window else 0.0,
            "dispatched_requests_per_second": dispatched / schedule_window if schedule_window else 0.0,
            "completed_requests_per_second": completed / schedule_window if schedule_window else 0.0,
            "dispatch_rate_fidelity": fidelity,
            "load_generator_valid": load_generator_valid,
            "load_generator_gates": load_generator_gates,
            "load_generator_invalid_reasons": invalid_reasons,
            "dispatch_lag_ms": dispatch_lag,
            "scheduled_ttft_ms": _metric_summary([float(row["scheduled_ttft_ms"]) for row in successes], bootstrap, seed + 12),
            "scheduled_e2e_ms": _metric_summary([float(row["scheduled_e2e_ms"]) for row in successes], bootstrap, seed + 14),
        }
    )
    metrics["warnings"] = [*cast(list[str], metrics["warnings"]), *invalid_reasons]
    return metrics


def _cell_metrics_for_protocol(
    observations: list[dict[str, Any]],
    cell: dict[str, Any],
    plan: PerformancePlan,
    window_seconds: float,
    seed: int,
    pricing: dict[str, Any] | None,
    protocol_version: str,
) -> dict[str, Any]:
    plan_version = str(plan.config.get("plan_version"))
    if protocol_version == PERFORMANCE_PROTOCOL_VERSION and plan_version == PERFORMANCE_PLAN_VERSION:
        return _cell_metrics_v2(observations, cell, plan, window_seconds, seed, pricing)
    if protocol_version in {"1.0.0", "1.1.0"} and plan_version == LEGACY_PERFORMANCE_PLAN_VERSION:
        return _cell_metrics(observations, cell, plan, window_seconds, seed, pricing)
    raise ProtocolError("performance protocol and plan versions are incompatible")


def _performance_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        raise ProtocolError(f"missing or unsafe performance {label} ledger")

    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line, parse_constant=_reject_json_constant)
            if not isinstance(row, dict) or not _finite_json(row):
                raise ValueError
            rows.append(row)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"invalid performance {label} ledger") from exc
    return rows


def _ledger_index(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        request_id = row.get("request_id")
        if not isinstance(request_id, str) or not request_id or request_id in result:
            raise ProtocolError(f"performance {label} ledger has a missing or duplicate request id")
        result[request_id] = row
    return result


def _measurement_window(observations: list[dict[str, Any]]) -> float:
    if not observations:
        raise ProtocolError("performance observation timing cannot reconstruct the measurement window")
    start = observations[0].get("batch_started_monotonic_ns")
    if not isinstance(start, int) or isinstance(start, bool) or start < 0:
        raise ProtocolError("performance observation timing cannot reconstruct the measurement window")
    finishes: list[int] = []
    for row in observations:
        finish = row.get("finished_monotonic_ns")
        if row.get("batch_started_monotonic_ns") != start or not isinstance(finish, int) or isinstance(finish, bool) or finish <= start:
            raise ProtocolError("performance observation timing cannot reconstruct the measurement window")
        finishes.append(finish)
    return (max(finishes) - start) / 1_000_000_000


def _stream_projection(raw: dict[str, Any]) -> tuple[str, str, dict[str, Any], int]:
    events = raw.get("stream_events")
    if not isinstance(events, list) or not events:
        raise ProtocolError("performance raw response is missing streaming events")
    content: list[str] = []
    usage: dict[str, Any] = {}
    for event in events:
        if not isinstance(event, dict):
            raise ProtocolError("performance raw response has malformed streaming events")
        if isinstance(event.get("usage"), dict):
            usage = event["usage"]
        try:
            delta = event["choices"][0]["delta"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError):
            delta = None
        if isinstance(delta, str) and delta:
            content.append(delta)
    models = _stream_model_identities(raw)
    if len(models) != 1:
        raise ProtocolError("performance raw stream has missing or inconsistent model identity")
    return next(iter(models)), "".join(content), usage, len(events)


def reconcile_performance_ledgers(
    run_dir: Path,
    manifest: dict[str, Any],
    plan: PerformancePlan,
    expected_cells: dict[tuple[int, str], dict[str, Any]],
    observed_cells: dict[tuple[int, str], dict[str, Any]],
) -> dict[str, Any]:
    protocol_version = str(manifest.get("performance_protocol_version"))
    v2 = protocol_version == PERFORMANCE_PROTOCOL_VERSION
    requests = _performance_jsonl(run_dir / "requests.jsonl", "request")
    responses = _performance_jsonl(run_dir / "responses.jsonl", "response")
    warmups = _performance_jsonl(run_dir / "warmups.jsonl", "warm-up outcome")
    observations = _performance_jsonl(run_dir / "observations.jsonl", "observation")
    request_index = _ledger_index(requests, "request")
    response_index = _ledger_index(responses, "response")
    outcome_index = _ledger_index([*warmups, *observations], "outcome")
    if set(request_index) != set(response_index) or set(request_index) != set(outcome_index):
        raise ProtocolError("performance request, response, and outcome ledgers do not identify the same requests")
    for request_id, request in request_index.items():
        response = response_index[request_id]
        outcome = outcome_index[request_id]
        if any(request.get(field) != response.get(field) or request.get(field) != outcome.get(field) for field in _LEDGER_IDENTITY_FIELDS):
            raise ProtocolError("performance request, response, and outcome identities do not reconcile")
        if (
            response.get("terminal") is not True
            or any(response.get(field) != outcome.get(field) for field in ("status", "error_type", "error", "fatal", "finished_monotonic_ns"))
            or outcome.get("status") not in {"success", "error"}
        ):
            raise ProtocolError("performance response and outcome terminal states do not reconcile")
        if v2 and any(
            response.get(field) != outcome.get(field)
            for field in (
                "dispatch_monotonic_ns",
                "first_token_monotonic_ns",
                "completed_monotonic_ns",
                "dispatch_lag_ms",
                "scheduled_ttft_ms",
                "scheduled_e2e_ms",
            )
        ):
            raise ProtocolError("performance response and outcome schedule timing does not reconcile")
    if any(not isinstance(row.get("accepted"), bool) for row in requests):
        raise ProtocolError("performance request acceptance evidence is malformed")
    if any(row.get("phase") != "warmup" for row in warmups) or any(row.get("phase") != "measured" for row in observations):
        raise ProtocolError("performance outcomes are recorded in the wrong phase ledger")

    planned_identities: set[tuple[int, str, str, int]] = set()
    for (block, cell_key), cell in expected_cells.items():
        if cell.get("skip_reason"):
            continue
        counts = {
            "warmup": int(cell["warmup_requests"]),
            "measured": _measured_request_count(plan, cell, block),
        }
        for phase, count in counts.items():
            planned_identities.update((block, cell_key, phase, index) for index in range(1, count + 1))
    runtime = _object(manifest.get("runtime"), "performance runtime manifest")
    rows_by_context: dict[int, list[dict[str, Any]]] = {}
    for workload_row in plan.workload:
        rows_by_context.setdefault(int(workload_row["context_tokens"]), []).append(workload_row)
    if not rows_by_context:
        raise ProtocolError("performance workload snapshot is missing validated cases")
    workload_asset_cache = _load_workload_asset_cache(run_dir / "workload_assets", plan.workload_assets)

    actual_identities: set[tuple[int, str, str, int]] = set()
    batches: dict[tuple[int, str, str], list[dict[str, Any]]] = {}
    for row in requests:
        actual_block = row.get("block")
        actual_cell_key = row.get("cell_key")
        actual_phase = row.get("phase")
        request_index_value = row.get("request_index")
        if (
            not isinstance(actual_block, int)
            or isinstance(actual_block, bool)
            or not isinstance(actual_cell_key, str)
            or actual_phase not in {"warmup", "measured"}
            or not isinstance(request_index_value, int)
            or isinstance(request_index_value, bool)
            or request_index_value < 1
        ):
            raise ProtocolError("performance request ledger has a missing or duplicate planned identity")
        identity = (actual_block, actual_cell_key, actual_phase, request_index_value)
        if identity in actual_identities:
            raise ProtocolError("performance request ledger has a missing or duplicate planned identity")
        actual_identities.add(identity)
        expected_cell = expected_cells.get((actual_block, actual_cell_key))
        if (
            expected_cell is None
            or row.get("scenario_id") != expected_cell["scenario_id"]
            or row.get("declared_context_tokens") != expected_cell["context_tokens"]
            or row.get("requested_output_tokens") != expected_cell["output_tokens"]
        ):
            raise ProtocolError("performance request differs from its preregistered cell")
        context_rows = rows_by_context.get(int(expected_cell["context_tokens"]), [])
        if not context_rows:
            raise ProtocolError("performance request context is missing from the workload snapshot")
        workload_row = context_rows[(request_index_value - 1) % len(context_rows)]
        expected_nonce, payload = _request_material(
            plan,
            runtime,
            expected_cell,
            workload_row,
            request_index_value,
            actual_block,
            actual_phase,
            workload_asset_cache,
        )
        payload_sha256 = sha256_bytes(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode())
        if row.get("workload_id") != workload_row["id"] or row.get("cache_nonce") != expected_nonce or row.get("payload_sha256") != payload_sha256:
            raise ProtocolError("performance request payload differs from the preregistered workload")

        response = response_index[str(row["request_id"])]
        outcome = outcome_index[str(row["request_id"])]
        timing = [row.get(field) for field in ("scheduled_monotonic_ns", "batch_started_monotonic_ns", "started_monotonic_ns")]
        finish = outcome.get("finished_monotonic_ns")
        if (
            any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in timing)
            or not isinstance(finish, int)
            or isinstance(finish, bool)
        ):
            raise ProtocolError("performance request timing evidence is malformed")
        scheduled_ns, batch_started_ns, started_ns = (cast(int, value) for value in timing)
        if finish <= started_ns or started_ns < batch_started_ns:
            raise ProtocolError("performance request timing evidence is malformed")
        expected_queue = round(max(0.0, (started_ns - scheduled_ns) / 1_000_000), 3) if expected_cell["arrival"] == "open-loop" else 0.0
        if row.get("client_queue_ms") != expected_queue:
            raise ProtocolError("performance client queue timing differs from monotonic request evidence")
        accepted = row.get("accepted")
        network_contacted = response.get("network_contacted")
        if not isinstance(network_contacted, bool) or accepted is not network_contacted:
            raise ProtocolError("performance request acceptance differs from network-contact evidence")
        if accepted and started_ns < scheduled_ns:
            raise ProtocolError("performance contacted request started before its scheduled time")
        if v2:
            transport_value = response.get("transport")
            if transport_value is not None and not isinstance(transport_value, dict):
                raise ProtocolError("performance transport monotonic timing evidence is malformed")
            transport_evidence = transport_value if isinstance(transport_value, dict) else None
            if transport_evidence is not None:
                transport_times: list[int] = []
                for value in [
                    transport_evidence.get(field)
                    for field in ("started_monotonic_ns", "headers_monotonic_ns", "first_content_monotonic_ns", "finished_monotonic_ns")
                    if transport_evidence.get(field) is not None
                ]:
                    if not isinstance(value, int) or isinstance(value, bool):
                        raise ProtocolError("performance transport monotonic timing evidence is malformed")
                    transport_times.append(value)
                event_times = transport_evidence.get("event_monotonic_ns")
                normalized_event_times: list[int] | None = None
                if event_times is not None:
                    if not isinstance(event_times, list):
                        raise ProtocolError("performance transport monotonic timing evidence is malformed")
                    normalized_event_times = []
                    for value in event_times:
                        if not isinstance(value, int) or isinstance(value, bool):
                            raise ProtocolError("performance transport monotonic timing evidence is malformed")
                        normalized_event_times.append(value)
                if (
                    transport_times != sorted(transport_times)
                    or transport_times
                    and (transport_times[0] < started_ns or transport_times[-1] > finish)
                    or normalized_event_times is not None
                    and (
                        normalized_event_times != sorted(normalized_event_times)
                        or any(value < started_ns or value > finish for value in normalized_event_times)
                    )
                ):
                    raise ProtocolError("performance transport monotonic timing evidence is malformed")
            expected_schedule = _v2_schedule_evidence(
                scheduled_ns,
                transport_evidence,
                finish,
                success=outcome.get("status") == "success",
            )
            schedule_fields = {
                "dispatch_monotonic_ns",
                "first_token_monotonic_ns",
                "completed_monotonic_ns",
                "dispatch_lag_ms",
                "scheduled_ttft_ms",
                "scheduled_e2e_ms",
            }
            if {field: outcome[field] for field in schedule_fields if field in outcome} != expected_schedule:
                raise ProtocolError("performance schedule timing differs from immutable transport evidence")
        if not accepted:
            if outcome.get("status") != "error" or response.get("response") is not None or response.get("transport") is not None:
                raise ProtocolError("performance non-contacted request has invalid terminal evidence")
        elif outcome.get("status") == "success":
            raw = _object(response.get("response"), "performance raw response")
            transport = _object(response.get("transport"), "performance transport response")
            usage = _object(raw.get("usage"), "performance provider token usage")
            stream_model, stream_content, stream_usage, stream_event_count = _stream_projection(raw)
            try:
                raw_content = raw["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError) as exc:
                raise ProtocolError("performance raw response is missing reconstructed stream content") from exc
            successful_transport_times: list[int] = []
            for value in [
                transport.get(field)
                for field in ("started_monotonic_ns", "headers_monotonic_ns", "first_content_monotonic_ns", "finished_monotonic_ns")
            ]:
                if not isinstance(value, int) or isinstance(value, bool):
                    raise ProtocolError("performance transport monotonic timing evidence is malformed")
                successful_transport_times.append(value)
            events = transport.get("event_monotonic_ns")
            if not isinstance(events, list):
                raise ProtocolError("performance transport monotonic timing evidence is malformed")
            transport_started_ns, headers_ns, first_content_ns, transport_finished_ns = successful_transport_times
            if (
                not started_ns <= transport_started_ns <= headers_ns <= first_content_ns <= transport_finished_ns <= finish
                or not events
                or any(not isinstance(value, int) or isinstance(value, bool) for value in events)
                or events != sorted(events)
                or events[0] < headers_ns
                or events[-1] > transport_finished_ns
                or first_content_ns not in events
            ):
                raise ProtocolError("performance transport monotonic timing evidence is malformed")
            expected_ttft = round((first_content_ns - transport_started_ns) / 1_000_000, 3)
            expected_e2e = round((transport_finished_ns - transport_started_ns) / 1_000_000, 3)
            expected_headers = round((headers_ns - transport_started_ns) / 1_000_000, 3)
            input_tokens = usage.get("prompt_tokens")
            output_tokens = usage.get("completion_tokens")
            if (
                raw.get("model") != outcome.get("reported_model")
                or stream_model != raw.get("model")
                or stream_content != raw_content
                or stream_usage != usage
                or stream_event_count != len(events)
                or outcome.get("reported_model") != runtime.get("expected_model")
                or not isinstance(input_tokens, int)
                or isinstance(input_tokens, bool)
                or not isinstance(output_tokens, int)
                or isinstance(output_tokens, bool)
                or outcome.get("input_tokens") != float(input_tokens)
                or outcome.get("output_tokens") != float(output_tokens)
                or transport.get("request_id") != row["request_id"]
                or transport.get("attempts") != 1
                or transport.get("streaming") is not True
                or transport.get("ttft_ms") != expected_ttft
                or transport.get("total_ms") != expected_e2e
                or transport.get("headers_ms") != expected_headers
                or outcome.get("ttft_ms") != expected_ttft
                or outcome.get("e2e_ms") != expected_e2e
                or outcome.get("headers_ms") != expected_headers
            ):
                raise ProtocolError("performance outcome differs from provider response or transport evidence")
            expected_request_bytes = len(json.dumps(payload, ensure_ascii=False).encode())
            if (
                transport.get("request_bytes") != expected_request_bytes
                or outcome.get("request_bytes") != expected_request_bytes
                or not isinstance(transport.get("response_bytes"), int)
                or isinstance(transport.get("response_bytes"), bool)
                or transport["response_bytes"] < 0
                or outcome.get("response_bytes") != transport["response_bytes"]
                or outcome.get("inter_chunk_ms") != transport.get("inter_chunk_ms")
            ):
                raise ProtocolError("performance outcome byte or stream evidence differs from transport evidence")
            tolerance = max(
                2.0,
                float(workload_row["context_tokens"]) * float(plan.config["workload"].get("input_token_tolerance_fraction", 0.05)),
            )
            input_match = abs(float(input_tokens) - float(workload_row["context_tokens"])) <= tolerance
            decode_ms = max(0.0, expected_e2e - expected_ttft)
            expected_tpot = decode_ms / (output_tokens - 1) if output_tokens > 1 else None
            expected_decode_tps = (output_tokens - 1) / (decode_ms / 1000) if output_tokens > 1 and decode_ms > 0 else None
            if (
                outcome.get("input_token_match") is not input_match
                or outcome.get("tpot_ms") != expected_tpot
                or outcome.get("decode_tokens_per_second") != expected_decode_tps
            ):
                raise ProtocolError("performance derived token timing differs from immutable transport evidence")
        else:
            error_usage = _provider_usage(response.get("response"))
            outcome_has_usage = "input_tokens" in outcome or "output_tokens" in outcome
            if error_usage is None:
                if outcome_has_usage:
                    raise ProtocolError("performance error outcome has unbound provider token usage")
            elif (
                outcome.get("input_tokens") != error_usage[0]
                or outcome.get("output_tokens") != error_usage[1]
                or error_usage[1] > min(float(expected_cell["output_tokens"]), float(plan.config["limits"]["max_output_tokens"]))
                or error_usage[0] + float(expected_cell["output_tokens"]) > float(runtime["max_context_tokens"])
            ):
                raise ProtocolError("performance error outcome differs from provider usage or runtime limits")
        batches.setdefault((actual_block, actual_cell_key, actual_phase), []).append(row)
    if actual_identities != planned_identities:
        raise ProtocolError("performance request ledger differs from preregistered per-cell phase counts")

    for (block, cell_key, phase), batch in batches.items():
        cell = expected_cells[(block, cell_key)]
        ordered = sorted(batch, key=lambda item: int(item["request_index"]))
        if len({item["batch_started_monotonic_ns"] for item in ordered}) != 1:
            raise ProtocolError("performance batch timing is inconsistent")
        batch_started_ns = int(ordered[0]["batch_started_monotonic_ns"])
        scheduled = [int(item["scheduled_monotonic_ns"]) for item in ordered]
        if cell["arrival"] == "closed-loop":
            if len(set(scheduled)) != 1 or v2 and scheduled[0] != batch_started_ns:
                raise ProtocolError("performance closed-loop schedule differs within a batch")
            continue
        offsets = _open_loop_offsets(plan, cell, block, phase, count=len(ordered) if phase == "warmup" else None)
        expected_scheduled_ns = [batch_started_ns + round(offset * 1_000_000_000) for offset in offsets]
        if len(offsets) != len(ordered) or (
            scheduled != expected_scheduled_ns
            if v2
            else any(
                abs((value - scheduled[0]) - round((offset - offsets[0]) * 1_000_000_000)) > 1
                for value, offset in zip(scheduled, offsets, strict=True)
            )
        ):
            raise ProtocolError("performance open-loop schedule differs from the preregistered arrival process")

    reconciliation = manifest.get("request_reconciliation")
    if not isinstance(reconciliation, dict) or set(reconciliation) != _RECONCILIATION_FIELDS:
        raise ProtocolError("performance request reconciliation has an invalid shape")
    count_fields = _RECONCILIATION_FIELDS - {"ledgers_complete", "campaign_complete"}
    if any(not isinstance(reconciliation[field], int) or isinstance(reconciliation[field], bool) for field in count_fields):
        raise ProtocolError("performance request reconciliation counts are malformed")
    expected_reconciliation = {
        "planned": len(planned_identities),
        "scheduled": len(requests),
        "accepted": sum(row["accepted"] for row in requests),
        "responses": len(responses),
        "warmup_outcomes": len(warmups),
        "measured_outcomes": len(observations),
        "terminal_outcomes": len(warmups) + len(observations),
        "ledgers_complete": True,
        "campaign_complete": True,
    }
    if (
        reconciliation != expected_reconciliation
        or manifest.get("planned_requests") != len(planned_identities)
        or manifest.get("requests") != expected_reconciliation["accepted"]
    ):
        raise ProtocolError("performance request reconciliation differs from the immutable ledgers")
    expected_warmups = {
        "total": len(warmups),
        "successes": sum(row.get("status") == "success" for row in warmups),
        "errors": sum(row.get("status") != "success" for row in warmups),
    }
    if manifest.get("warmups") != expected_warmups:
        raise ProtocolError("performance warm-up summary differs from the immutable ledger")

    observed_counts = Counter((row.get("block"), row.get("cell_key")) for row in observations)
    expected_counts = Counter({key: _measured_request_count(plan, cell, key[0]) for key, cell in expected_cells.items() if not cell.get("skip_reason")})
    if observed_counts != expected_counts or any(observed_cells.get(key, {}).get("observations") != count for key, count in expected_counts.items()):
        raise ProtocolError("performance cell counts differ from the observation ledger")

    terminal_outcomes = [*warmups, *observations]
    if manifest.get("status") == "completed" and any(row.get("status") != "success" for row in terminal_outcomes):
        raise ProtocolError("completed performance campaign contains error outcomes")
    if manifest.get("status") == "completed-with-errors" and all(row.get("status") == "success" for row in terminal_outcomes):
        raise ProtocolError("completed-with-errors performance campaign contains no error outcomes")
    usage_rows = [row for row in terminal_outcomes if "input_tokens" in row or "output_tokens" in row]
    if any(
        not isinstance(row.get(field), (int, float)) or isinstance(row.get(field), bool) or not math.isfinite(float(row[field])) or row[field] < 0
        for row in usage_rows
        for field in ("input_tokens", "output_tokens")
    ):
        raise ProtocolError("performance token usage ledger is malformed")
    if any(
        not isinstance(row.get("requested_output_tokens"), int) or isinstance(row.get("requested_output_tokens"), bool) or row["requested_output_tokens"] < 1
        for row in usage_rows
    ):
        raise ProtocolError("performance requested output token evidence is malformed")
    if any(
        float(row["output_tokens"]) > min(float(row.get("requested_output_tokens", -1)), float(plan.config["limits"]["max_output_tokens"]))
        for row in usage_rows
    ):
        raise ProtocolError("performance completion token usage exceeds the requested or plan output limit")
    if any(float(row["input_tokens"]) + float(row["requested_output_tokens"]) > float(runtime["max_context_tokens"]) for row in usage_rows):
        raise ProtocolError("performance provider usage exceeds the runtime context limit")
    token_usage = {
        "input": sum(float(row["input_tokens"]) for row in usage_rows),
        "output": sum(float(row["output_tokens"]) for row in usage_rows),
    }
    token_usage["total"] = token_usage["input"] + token_usage["output"]
    if token_usage["total"] > float(plan.config["limits"]["max_total_tokens"]):
        raise ProtocolError("performance provider usage exceeds the campaign token budget")
    if manifest.get("status") in {"completed", "completed-with-errors", "invalid-loadgen"} and (
        manifest.get("token_usage") != token_usage or manifest.get("tokens") != token_usage["total"]
    ):
        raise ProtocolError("performance token aggregates differ from the immutable ledgers")
    pricing = manifest.get("runtime", {}).get("pricing")
    expected_cost = (
        {
            "amount": token_usage["input"] * float(pricing["input_per_million"]) / 1_000_000
            + token_usage["output"] * float(pricing["output_per_million"]) / 1_000_000,
            "currency": pricing["currency"],
            "source": pricing["source"],
            "effective_at": pricing["effective_at"],
            "includes_warmup": True,
        }
        if isinstance(pricing, dict)
        else None
    )
    if manifest.get("status") in {"completed", "completed-with-errors", "invalid-loadgen"} and manifest.get("estimated_cost") != expected_cost:
        raise ProtocolError("performance cost aggregate differs from the immutable ledgers")
    return {
        "requests": requests,
        "responses": responses,
        "warmups": warmups,
        "observations": observations,
        "errors": {str(row["error"]) for row in [*responses, *warmups, *observations] if isinstance(row.get("error"), str) and len(str(row["error"])) >= 6},
    }


def run_performance_campaign(
    plan: PerformancePlan,
    runtime: PerformanceRuntime,
    *,
    repo_root: Path,
    output_root: Path | None = None,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    signing_key_id: str = "",
    system_evidence_path: Path | None = None,
    execution_record_path: Path | None = None,
    engagement_path: Path | None = None,
    official: bool = False,
) -> Path:
    fresh_plan = load_performance_plan(plan.path)
    fresh_runtime = load_performance_runtime(runtime.path)
    if plan != fresh_plan or runtime != fresh_runtime:
        raise ProtocolError("performance plan or runtime changed after validation; no network request was sent")
    plan, runtime = fresh_plan, fresh_runtime
    config = plan.config
    runtime_config = runtime.config
    protocol_version, report_version = _performance_versions(str(config["plan_version"]))
    system_evidence, system_evidence_raw, source_evidence = performance_run_preflight(
        plan,
        runtime,
        repo_root=repo_root,
        system_evidence_path=system_evidence_path,
        official=official,
    )
    protocol_path = canonical_performance_protocol_path(protocol_version, repo_root=repo_root)
    protocol_raw = protocol_path.read_bytes()
    protocol_hash = sha256_bytes(protocol_raw)
    if official:
        _require_official_reference_inputs(
            protocol_hash,
            plan.sha256,
            plan.workload_sha256,
            plan.workload_assets,
            repo_root=repo_root,
        )
        if git_evidence(repo_root) != source_evidence:
            raise ProtocolError("performance source changed after official preflight; no network request was sent")
        if execution_record_path is None:
            raise ProtocolError("official performance requires --execution-record")
        if engagement_path is None:
            raise ProtocolError("official performance requires --engagement")
    execution_record: dict[str, Any] | None = None
    execution_record_raw: bytes | None = None
    verification_time = datetime.now(timezone.utc)
    if execution_record_path is not None:
        execution_record, execution_record_raw = load_performance_execution_record(
            execution_record_path,
            protocol_sha256=protocol_hash,
            plan_sha256=plan.sha256,
            workload_sha256=plan.workload_sha256,
            runtime_sha256=runtime.sha256,
            system_evidence_sha256=sha256_bytes(system_evidence_raw) if system_evidence_raw is not None else None,
            before=verification_time,
        )
    engagement: dict[str, Any] | None = None
    engagement_raw: bytes | None = None
    if engagement_path is not None:
        if execution_record is None or system_evidence is None or system_evidence_raw is None:
            raise ProtocolError("performance --engagement requires --execution-record and --system-evidence")
        engagement, engagement_raw = load_performance_engagement(
            engagement_path,
            protocol_sha256=protocol_hash,
            plan_sha256=plan.sha256,
            workload_sha256=plan.workload_sha256,
            runtime_sha256=runtime.sha256,
            system_evidence_sha256=sha256_bytes(system_evidence_raw),
            configuration_id=str(system_evidence["configuration_id"]),
            execution_record=execution_record,
            at=verification_time,
        )
    workload_asset_cache = _load_workload_asset_cache(plan.workload_path.parent, plan.workload_assets)
    api_key = os.getenv(str(runtime_config["api_key_env"]), "")
    if api_key and not _secure_endpoint(str(runtime_config["endpoint"])):
        raise ProtocolError("refusing to send an API key over non-local HTTP; use HTTPS or a loopback endpoint")
    cells = _expand_cells(plan, runtime)
    execution = config["execution"]
    total_planned = _planned_requests(plan, cells)
    if total_planned > int(config["limits"]["max_requests"]):
        raise ProtocolError(f"performance campaign plans {total_planned} requests; limit is {config['limits']['max_requests']}")
    root = (output_root or repo_root / "runs" / "performance" / str(config["name"])).resolve()
    require_mutable_output_root(root)
    root.mkdir(parents=True, exist_ok=True)
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{runtime_config['id']}_{uuid.uuid4().hex[:10]}"
    run_dir = root / run_id
    run_dir.mkdir(mode=0o700)
    (run_dir / "figures").mkdir(mode=0o700)
    started_at = datetime.now(timezone.utc)
    if protocol_path.read_bytes() != protocol_raw:
        raise ProtocolError("performance protocol changed after validation; no network request was sent")
    plan_hash = plan.sha256
    runtime_hash = runtime.sha256
    workload_asset_set_hash = sha256_bytes(json.dumps(plan.workload_assets, sort_keys=True, separators=(",", ":")).encode())
    manifest: dict[str, Any] = {
        "performance_protocol_version": protocol_version,
        "protocol_sha256": protocol_hash,
        "plan_version": config["plan_version"],
        "report_version": report_version,
        "run_id": run_id,
        "status": "running",
        "official_requested": official,
        "officially_valid": False,
        "started_at": started_at.isoformat(),
        "plan": {
            "name": config["name"],
            "revision": config["revision"],
            "sha256": plan_hash,
            "profile": config["profile"],
            "data_classification": config["data_classification"],
            **(
                {
                    "open_loop_arrival_distribution": execution["open_loop_arrival_distribution"],
                    "execution_seed": execution["seed"],
                }
                if "open_loop_arrival_distribution" in execution
                else {}
            ),
            **({"minimum_p99_observations": config["slo"]["minimum_p99_observations"]} if "minimum_p99_observations" in config["slo"] else {}),
            **({"load_generator": config["load_generator"]} if protocol_version == PERFORMANCE_PROTOCOL_VERSION else {}),
        },
        "workload": {
            "id": config["workload"]["id"],
            "revision": config["workload"]["revision"],
            "mode": config["workload"]["mode"],
            **({"prefix_cache_policy": config["workload"]["prefix_cache_policy"]} if "prefix_cache_policy" in config["workload"] else {}),
            "sha256": plan.workload_sha256,
            "asset_set_sha256": workload_asset_set_hash,
            "assets": plan.workload_assets,
            "cases": len(plan.workload),
        },
        "runtime": {
            **{key: value for key, value in runtime_config.items() if key not in {"endpoint", "pricing"}},
            "endpoint": _manifest_endpoint(runtime_config["endpoint"]),
            "sha256": runtime_hash,
            "pricing": runtime_config.get("pricing"),
        },
        "system_evidence": (
            {
                "configuration_id": system_evidence["configuration_id"],
                "sha256": sha256_bytes(system_evidence_raw),
                "projection": system_evidence["projection"],
                "collected_at": system_evidence["collected_at"],
            }
            if system_evidence is not None and system_evidence_raw is not None
            else None
        ),
        "execution_record": execution_record,
        "engagement": engagement,
        "source": source_evidence,
        "environment": environment_evidence(repo_root),
        "planned_requests": total_planned,
        "planned_cells": len(cells) * int(execution["repetitions"]),
    }
    atomic_json(run_dir / "manifest.json", manifest)
    (run_dir / "protocol_snapshot.md").write_bytes(protocol_raw)
    shutil.copy2(plan.path, run_dir / "plan_snapshot.toml")
    shutil.copy2(runtime.path, run_dir / "runtime_snapshot.toml")
    shutil.copy2(plan.workload_path, run_dir / "workload_snapshot.jsonl")
    if system_evidence_raw is not None:
        (run_dir / "system_evidence_snapshot.json").write_bytes(system_evidence_raw)
        os.chmod(run_dir / "system_evidence_snapshot.json", 0o600)
    if execution_record_raw is not None:
        (run_dir / "execution_record_snapshot.json").write_bytes(execution_record_raw)
        os.chmod(run_dir / "execution_record_snapshot.json", 0o600)
    if engagement_raw is not None:
        (run_dir / "engagement_snapshot.json").write_bytes(engagement_raw)
        os.chmod(run_dir / "engagement_snapshot.json", 0o600)
    for relative, raw in workload_asset_cache.items():
        destination = run_dir / "workload_assets" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    snapshots = {
        run_dir / "protocol_snapshot.md": protocol_hash,
        run_dir / "plan_snapshot.toml": plan_hash,
        run_dir / "runtime_snapshot.toml": runtime_hash,
        run_dir / "workload_snapshot.jsonl": plan.workload_sha256,
        **({run_dir / "system_evidence_snapshot.json": sha256_bytes(system_evidence_raw)} if system_evidence_raw is not None else {}),
        **({run_dir / "execution_record_snapshot.json": sha256_bytes(execution_record_raw)} if execution_record_raw is not None else {}),
        **({run_dir / "engagement_snapshot.json": sha256_bytes(engagement_raw)} if engagement_raw is not None else {}),
        **{run_dir / "workload_assets" / relative: digest for relative, digest in plan.workload_assets.items()},
    }
    if any(sha256_file(path) != digest for path, digest in snapshots.items()):
        raise ProtocolError("performance inputs changed after validation; no network request was sent")
    if not _workload_assets_match(plan.workload_path.parent, workload_asset_cache) or not _workload_assets_match(
        run_dir / "workload_assets", workload_asset_cache
    ):
        raise ProtocolError("performance workload assets changed after validation; no network request was sent")
    if official and git_evidence(repo_root) != source_evidence:
        raise ProtocolError("performance source changed after official snapshots; no network request was sent")
    for name in ("requests.jsonl", "responses.jsonl", "observations.jsonl", "warmups.jsonl", "cells.jsonl", "events.jsonl"):
        (run_dir / name).touch(mode=0o600)

    write_lock = threading.Lock()
    budget_lock = threading.Lock()
    fatal_event = threading.Event()
    request_count = 0
    total_tokens = 0.0
    total_input_tokens = 0.0
    total_output_tokens = 0.0
    token_budget_exhausted = False
    campaign_started = time.perf_counter()
    rows_by_context: dict[int, list[dict[str, Any]]] = {}
    for row in plan.workload:
        rows_by_context.setdefault(int(row["context_tokens"]), []).append(row)
    all_cell_metrics: list[dict[str, Any]] = []
    all_observations: list[dict[str, Any]] = []
    all_warmups: list[dict[str, Any]] = []

    def record(name: str, value: dict[str, Any]) -> None:
        if not _finite_json(value):
            raise ProtocolError(f"refusing to write non-finite performance evidence to {name}")
        with write_lock:
            append_jsonl(run_dir / name, value)

    def event(kind: str, **fields: Any) -> None:
        record("events.jsonl", {"timestamp": datetime.now(timezone.utc).isoformat(), "event": kind, **fields})

    def ledger_counts() -> dict[str, Any]:
        def count(name: str) -> int:
            with (run_dir / name).open(encoding="utf-8") as handle:
                return sum(bool(line.strip()) for line in handle)

        requests = count("requests.jsonl")
        responses = count("responses.jsonl")
        warmup_outcomes = count("warmups.jsonl")
        measured_outcomes = count("observations.jsonl")
        outcomes = warmup_outcomes + measured_outcomes
        ledgers_complete = requests == responses == outcomes and request_count <= requests
        return {
            "planned": total_planned,
            "scheduled": requests,
            "accepted": request_count,
            "responses": responses,
            "warmup_outcomes": warmup_outcomes,
            "measured_outcomes": measured_outcomes,
            "terminal_outcomes": outcomes,
            "ledgers_complete": ledgers_complete,
            "campaign_complete": ledgers_complete and requests == total_planned,
        }

    def preserve_abort(reason: str) -> None:
        manifest["status"] = "aborted"
        manifest["officially_valid"] = False
        manifest["abort_reason"] = reason
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        manifest["requests"] = request_count
        manifest["tokens"] = total_tokens
        manifest["token_usage"] = {"input": total_input_tokens, "output": total_output_tokens, "total": total_tokens}
        manifest["request_reconciliation"] = ledger_counts()
        manifest["artifacts"] = sorted(path.relative_to(run_dir).as_posix() for path in run_dir.rglob("*") if path.is_file())
        atomic_json(run_dir / "manifest.json", manifest)
        write_bundle(run_dir, signing_key_env=signing_key_env, key_id=signing_key_id)
        verification = verify_bundle(run_dir, signing_key_env=signing_key_env, write_result=True)
        if not verification["valid"]:
            raise ProtocolError("aborted performance bundle verification failed")

    def campaign_expired() -> bool:
        return time.perf_counter() - campaign_started > float(config["limits"]["max_campaign_seconds"])

    def require_campaign_time() -> None:
        if campaign_expired():
            raise _FatalPerformanceError("campaign time limit exceeded")

    def one_request(
        cell: dict[str, Any],
        row: dict[str, Any],
        index: int,
        block: int,
        phase: str,
        scheduled_ns: int,
        batch_started_ns: int,
    ) -> dict[str, Any]:
        nonlocal request_count, total_tokens, total_input_tokens, total_output_tokens, token_budget_exhausted
        started_ns = time.perf_counter_ns()
        request_id = uuid.uuid4().hex
        queue_ms = max(0.0, (started_ns - scheduled_ns) / 1_000_000) if cell["arrival"] == "open-loop" else 0.0
        cache_nonce, payload = _request_material(
            plan,
            runtime_config,
            cell,
            row,
            index,
            block,
            phase,
            workload_asset_cache,
        )
        base = {
            "cell_key": cell["cell_key"],
            "scenario_id": cell["scenario_id"],
            "block": block,
            "phase": phase,
            "request_index": index,
            "workload_id": row["id"],
            "declared_context_tokens": row["context_tokens"],
            "requested_output_tokens": cell["output_tokens"],
            "client_queue_ms": round(queue_ms, 3),
            "request_id": request_id,
            **({"cache_nonce": cache_nonce} if cache_nonce is not None else {}),
            "scheduled_monotonic_ns": scheduled_ns,
            "batch_started_monotonic_ns": batch_started_ns,
            "started_monotonic_ns": started_ns,
        }
        rejection: tuple[str, str] | None = None
        with budget_lock:
            if fatal_event.is_set():
                rejection = ("fatal-abort", "request was not contacted after a fatal campaign error")
            elif request_count >= int(config["limits"]["max_requests"]):
                rejection = ("request-budget", "request limit exceeded")
            elif campaign_expired():
                rejection = ("time-budget", "campaign time limit exceeded")
            elif token_budget_exhausted:
                rejection = ("token-budget", "total token limit already exceeded")
            else:
                request_count += 1
        record(
            "requests.jsonl",
            {
                **base,
                "accepted": rejection is None,
                "payload_sha256": sha256_bytes(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()),
            },
        )
        if rejection is not None:
            if rejection[0] == "time-budget":
                fatal_event.set()
            terminal_ns = time.perf_counter_ns()
            outcome = {
                **base,
                "finished_monotonic_ns": terminal_ns,
                "status": "error",
                "error_type": rejection[0],
                "error": rejection[1],
                **({"fatal": True} if rejection[0] == "time-budget" else {}),
                **(
                    _v2_schedule_evidence(scheduled_ns, None, terminal_ns, success=False)
                    if protocol_version == PERFORMANCE_PROTOCOL_VERSION
                    else {}
                ),
            }
            record("responses.jsonl", {**outcome, "terminal": True, "network_contacted": False, "response": None, "transport": None})
            return outcome
        raw: dict[str, Any] | None = None
        transport: dict[str, Any] | None = None
        usage_accounted = False
        try:
            raw, transport = _post_openai_stream(
                _completion_url(str(runtime_config["endpoint"])),
                payload,
                api_key,
                float(config["limits"]["timeout_seconds"]),
                request_id=request_id,
            )
            if not _finite_json(raw) or not _finite_json(transport):
                raise _FatalPerformanceError("streaming response contains non-finite JSON evidence")
            reported = str(raw.get("model") or "")
            reported_usage = _provider_usage(raw)
            if reported_usage is None:
                raise _FatalPerformanceError("streaming response did not report prompt_tokens and completion_tokens")
            input_tokens, output_tokens = reported_usage
            if input_tokens < 1 or output_tokens < 1:
                raise ProtocolError("streaming response reported non-positive token usage")
            with budget_lock:
                total_tokens += input_tokens + output_tokens
                total_input_tokens += input_tokens
                total_output_tokens += output_tokens
                over_token_budget = total_tokens > float(config["limits"]["max_total_tokens"])
                token_budget_exhausted = token_budget_exhausted or over_token_budget
                usage_accounted = True
            if output_tokens > min(float(cell["output_tokens"]), float(config["limits"]["max_output_tokens"])):
                raise _FatalPerformanceError(f"completion token usage {output_tokens:g} exceeds requested and plan output limit {cell['output_tokens']}")
            if reported != runtime_config["expected_model"]:
                raise _FatalPerformanceError(f"model identity mismatch: expected {runtime_config['expected_model']!r}, got {reported!r}")
            tolerance = max(2.0, float(row["context_tokens"]) * float(config["workload"].get("input_token_tolerance_fraction", 0.05)))
            input_match = abs(input_tokens - float(row["context_tokens"])) <= tolerance
            if config["workload"]["mode"] == "iso-token" and not input_match:
                raise _FatalPerformanceError(f"input token mismatch: declared {row['context_tokens']}, observed {input_tokens:g}, tolerance {tolerance:g}")
            if input_tokens + float(cell["output_tokens"]) > float(runtime_config["max_context_tokens"]):
                raise _FatalPerformanceError(
                    f"provider prompt usage {input_tokens:g} plus requested output {cell['output_tokens']} exceeds runtime context limit {runtime_config['max_context_tokens']}"
                )
            if over_token_budget:
                raise _FatalPerformanceError("total token limit exceeded")
            ttft = float(transport["ttft_ms"])
            e2e = float(transport["total_ms"])
            decode_ms = max(0.0, e2e - ttft)
            tpot = decode_ms / (output_tokens - 1) if output_tokens > 1 else None
            decode_tps = (output_tokens - 1) / (decode_ms / 1000) if output_tokens > 1 and decode_ms > 0 else None
            terminal_ns = time.perf_counter_ns()
            observation = {
                **base,
                "status": "success",
                "finished_monotonic_ns": terminal_ns,
                "reported_model": reported,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "input_token_match": input_match,
                "ttft_ms": ttft,
                "e2e_ms": e2e,
                "tpot_ms": tpot,
                "decode_tokens_per_second": decode_tps,
                "headers_ms": transport.get("headers_ms"),
                "inter_chunk_ms": transport.get("inter_chunk_ms"),
                "request_bytes": transport.get("request_bytes"),
                "response_bytes": transport.get("response_bytes"),
                **(
                    _v2_schedule_evidence(scheduled_ns, transport, terminal_ns, success=True)
                    if protocol_version == PERFORMANCE_PROTOCOL_VERSION
                    else {}
                ),
            }
            if campaign_expired():
                fatal_event.set()
                observation = {
                    **observation,
                    "status": "error",
                    "fatal": True,
                    "error_type": "time-budget",
                    "error": "campaign time limit exceeded",
                }
            record(
                "responses.jsonl",
                {
                    **base,
                    "finished_monotonic_ns": observation["finished_monotonic_ns"],
                    "terminal": True,
                    "network_contacted": True,
                    "status": observation["status"],
                    **{key: observation[key] for key in ("error_type", "error", "fatal") if key in observation},
                    **{
                        key: observation[key]
                        for key in (
                            "dispatch_monotonic_ns",
                            "first_token_monotonic_ns",
                            "completed_monotonic_ns",
                            "dispatch_lag_ms",
                            "scheduled_ttft_ms",
                            "scheduled_e2e_ms",
                        )
                        if key in observation
                    },
                    "response": raw,
                    "transport": transport,
                },
            )
            return observation
        except _FatalPerformanceError as exc:
            fatal_event.set()
            reported_usage = _provider_usage(raw)
            terminal_ns = time.perf_counter_ns()
            outcome = {
                **base,
                "finished_monotonic_ns": terminal_ns,
                "status": "error",
                "fatal": True,
                "error_type": type(exc).__name__,
                "error": str(exc),
                **(
                    {"input_tokens": reported_usage[0], "output_tokens": reported_usage[1]}
                    if reported_usage is not None and usage_accounted
                    else {}
                ),
                **(
                    _v2_schedule_evidence(scheduled_ns, transport, terminal_ns, success=False)
                    if protocol_version == PERFORMANCE_PROTOCOL_VERSION
                    else {}
                ),
            }
            record(
                "responses.jsonl",
                {
                    **outcome,
                    "terminal": True,
                    "network_contacted": True,
                    "response": _finite_evidence(raw),
                    "transport": _finite_evidence(transport),
                },
            )
            return outcome
        except Exception as exc:  # noqa: BLE001 -- transport failures are evidence, not process failures.
            raw = getattr(exc, "raw", raw)
            transport = getattr(exc, "transport", transport)
            reported_usage = _provider_usage(raw)
            over_token_budget = False
            if reported_usage is not None and not usage_accounted:
                input_tokens, output_tokens = reported_usage
                with budget_lock:
                    total_tokens += input_tokens + output_tokens
                    total_input_tokens += input_tokens
                    total_output_tokens += output_tokens
                    over_token_budget = total_tokens > float(config["limits"]["max_total_tokens"])
                    token_budget_exhausted = token_budget_exhausted or over_token_budget
                    usage_accounted = True
            identities = _stream_model_identities(raw) if isinstance(raw, dict) else set()
            identity_error = (
                f"model identity mismatch: expected {runtime_config['expected_model']!r}, got {sorted(identities)!r}"
                if identities and identities != {runtime_config["expected_model"]}
                else ""
            )
            limit_error = ""
            if reported_usage is not None:
                if reported_usage[1] > min(float(cell["output_tokens"]), float(config["limits"]["max_output_tokens"])):
                    limit_error = "completion token usage exceeds requested or plan output limit"
                elif reported_usage[0] + float(cell["output_tokens"]) > float(runtime_config["max_context_tokens"]):
                    limit_error = "provider prompt usage plus requested output exceeds runtime context limit"
                elif over_token_budget:
                    limit_error = "total token limit exceeded"
            expired = campaign_expired()
            if identity_error or limit_error or expired:
                fatal_event.set()
            terminal_ns = time.perf_counter_ns()
            outcome = {
                **base,
                "finished_monotonic_ns": terminal_ns,
                "status": "error",
                "error_type": "model-identity" if identity_error else "provider-limit" if limit_error else "time-budget" if expired else type(exc).__name__,
                "error": identity_error or limit_error or ("campaign time limit exceeded" if expired else str(exc)),
                **({"fatal": True} if identity_error or limit_error or expired else {}),
                **(
                    {"input_tokens": reported_usage[0], "output_tokens": reported_usage[1]}
                    if reported_usage is not None and usage_accounted
                    else {}
                ),
                **(
                    _v2_schedule_evidence(scheduled_ns, transport, terminal_ns, success=False)
                    if protocol_version == PERFORMANCE_PROTOCOL_VERSION
                    else {}
                ),
            }
            record(
                "responses.jsonl",
                {
                    **outcome,
                    "terminal": True,
                    "network_contacted": True,
                    "response": _finite_evidence(raw),
                    "transport": _finite_evidence(transport),
                },
            )
            return outcome

    def execute_batch(cell: dict[str, Any], count: int, block: int, phase: str, *, open_loop: bool) -> tuple[list[dict[str, Any]], float]:
        rows = rows_by_context[int(cell["context_tokens"])]
        if protocol_version == PERFORMANCE_PROTOCOL_VERSION:
            batch_started_ns = time.perf_counter_ns()
            started = batch_started_ns / 1_000_000_000
        else:
            started = time.perf_counter()
            batch_started_ns = time.perf_counter_ns()
        results: list[dict[str, Any]] = []
        offsets = _open_loop_offsets(plan, cell, block, phase, count=count if phase == "warmup" else None) if open_loop else None
        if offsets is not None:
            count = len(offsets)
        workers = int(execution["max_in_flight"] if open_loop or cell.get("concurrency") is None else cell["concurrency"])
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cavada-perf") as executor:
            pending: set[Future[dict[str, Any]]] = set()
            next_index = 0
            while next_index < count or pending:
                now = time.perf_counter()
                while next_index < count and len(pending) < workers and not fatal_event.is_set():
                    offset = offsets[next_index] if offsets is not None else 0
                    scheduled = started + offset
                    if open_loop and scheduled > now:
                        break
                    scheduled_ns = (
                        batch_started_ns + round(offset * 1_000_000_000)
                        if protocol_version == PERFORMANCE_PROTOCOL_VERSION
                        else int(scheduled * 1_000_000_000)
                    )
                    pending.add(
                        executor.submit(
                            one_request,
                            cell,
                            rows[next_index % len(rows)],
                            next_index + 1,
                            block,
                            phase,
                            scheduled_ns,
                            batch_started_ns,
                        )
                    )
                    next_index += 1
                    now = time.perf_counter()
                if not pending:
                    if fatal_event.is_set() or next_index >= count:
                        break
                    scheduled = started + (offsets[next_index] if offsets is not None else 0)
                    fatal_event.wait(max(0.0, scheduled - time.perf_counter()))
                    continue
                timeout = None
                if open_loop and offsets is not None and next_index < count and len(pending) < workers:
                    timeout = max(0.0, started + offsets[next_index] - time.perf_counter())
                done, _ = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
                for future in done:
                    pending.remove(future)
                    result = future.result()
                    results.append(result)
                    record("warmups.jsonl" if phase == "warmup" else "observations.jsonl", result)
        fatal = next((result for result in results if result.get("fatal") is True), None)
        if fatal is not None:
            raise _FatalPerformanceError(str(fatal["error"]))
        require_campaign_time()
        return results, _measurement_window(results)

    try:
        for block in range(1, int(execution["repetitions"]) + 1):
            block_cells = list(cells)
            if execution.get("randomize_cells", True):
                random.Random(int(execution["seed"]) + block).shuffle(block_cells)  # noqa: S311 -- reproducible experiment ordering.
            for cell_index, cell in enumerate(block_cells, 1):
                event("cell_started", block=block, cell_key=cell["cell_key"])
                if cell.get("skip_reason"):
                    metrics = {**cell, "block": block, "status": "skipped", "reason": cell["skip_reason"]}
                    record("cells.jsonl", metrics)
                    all_cell_metrics.append(metrics)
                    event("cell_finished", block=block, cell_key=cell["cell_key"], status="skipped")
                    continue
                if cell["warmup_requests"]:
                    warmups, _ = execute_batch(
                        cell,
                        int(cell["warmup_requests"]),
                        block,
                        "warmup",
                        open_loop=cell["arrival"] == "open-loop",
                    )
                    all_warmups.extend(warmups)
                count = _measured_request_count(plan, cell, block)
                observations, window = execute_batch(cell, count, block, "measured", open_loop=cell["arrival"] == "open-loop")
                runtime_pricing = runtime_config.get("pricing")
                metrics = _cell_metrics_for_protocol(
                    observations,
                    cell,
                    plan,
                    window,
                    int(execution["seed"]) + block * 1000 + cell_index,
                    runtime_pricing if isinstance(runtime_pricing, dict) else None,
                    protocol_version,
                )
                metrics["block"] = block
                record("cells.jsonl", metrics)
                all_cell_metrics.append(metrics)
                all_observations.extend(observations)
                event("cell_finished", block=block, cell_key=cell["cell_key"], status=metrics["status"])
                cooldown = float(execution["cooldown_seconds"])
                if cooldown and (cell_index < len(block_cells) or block < int(execution["repetitions"])):
                    time.sleep(cooldown)
                    require_campaign_time()
        require_campaign_time()
    except KeyboardInterrupt:
        preserve_abort("operator cancelled the campaign")
        raise
    except Exception as exc:
        preserve_abort(str(exc))
        raise

    completed_cells = [cell for cell in all_cell_metrics if cell.get("status") != "skipped"]
    invalid_loadgen = sum(cell.get("status") == "invalid-loadgen" for cell in all_cell_metrics)
    if protocol_version == PERFORMANCE_PROTOCOL_VERSION and invalid_loadgen:
        manifest["status"] = "invalid-loadgen"
    else:
        manifest["status"] = (
            "completed"
            if completed_cells and all(cell.get("status") == "completed" for cell in completed_cells) and all(row.get("status") == "success" for row in all_warmups)
            else "completed-with-errors"
        )
    manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
    manifest["requests"] = request_count
    manifest["tokens"] = total_tokens
    manifest["token_usage"] = {"input": total_input_tokens, "output": total_output_tokens, "total": total_tokens}
    pricing = runtime_config.get("pricing")
    manifest["estimated_cost"] = (
        {
            "amount": total_input_tokens * float(pricing["input_per_million"]) / 1_000_000
            + total_output_tokens * float(pricing["output_per_million"]) / 1_000_000,
            "currency": pricing["currency"],
            "source": pricing["source"],
            "effective_at": pricing["effective_at"],
            "includes_warmup": True,
        }
        if isinstance(pricing, dict)
        else None
    )
    manifest["cells"] = {
        "total": len(all_cell_metrics),
        "completed": sum(cell.get("status") == "completed" for cell in all_cell_metrics),
        "with_errors": sum(cell.get("status") == "completed-with-errors" for cell in all_cell_metrics),
        **({"invalid_loadgen": invalid_loadgen} if protocol_version == PERFORMANCE_PROTOCOL_VERSION else {}),
        "skipped": sum(cell.get("status") == "skipped" for cell in all_cell_metrics),
        "slo_passed": sum(cell.get("slo_passed") is True for cell in all_cell_metrics),
        "slo_failed": sum(cell.get("slo_passed") is False for cell in all_cell_metrics),
    }
    manifest["warmups"] = {
        "total": len(all_warmups),
        "successes": sum(row.get("status") == "success" for row in all_warmups),
        "errors": sum(row.get("status") != "success" for row in all_warmups),
    }
    manifest["request_reconciliation"] = ledger_counts()
    if not manifest["request_reconciliation"]["campaign_complete"]:
        preserve_abort("request/response/outcome reconciliation failed")
        raise ProtocolError("request/response/outcome reconciliation failed")
    expected_cells = {(block, str(cell["cell_key"])): cell for block in range(1, int(execution["repetitions"]) + 1) for cell in cells}
    observed_cells = {(int(cell["block"]), str(cell["cell_key"])): cell for cell in all_cell_metrics}
    try:
        reconcile_performance_ledgers(run_dir, manifest, plan, expected_cells, observed_cells)
    except Exception as exc:
        preserve_abort(str(exc))
        raise
    if not _workload_assets_match(plan.workload_path.parent, workload_asset_cache) or not _workload_assets_match(
        run_dir / "workload_assets", workload_asset_cache
    ):
        preserve_abort("performance workload assets changed during execution")
        raise ProtocolError("performance workload assets changed during execution")
    engagement_valid_through_finish = engagement is not None and datetime.fromisoformat(str(manifest["finished_at"]).replace("Z", "+00:00")) < datetime.fromisoformat(
        str(engagement["expires_at"]).replace("Z", "+00:00")
    )
    manifest["officially_valid"] = bool(official and manifest["status"] == "completed" and engagement_valid_through_finish)
    summary = _campaign_summary(manifest, all_cell_metrics, all_observations)
    atomic_json(run_dir / "summary.json", summary)
    _write_cells_csv(run_dir / "cells.csv", all_cell_metrics, protocol_version=protocol_version)
    _performance_reports(run_dir, manifest, summary, all_cell_metrics)
    manifest["artifacts"] = sorted(path.relative_to(run_dir).as_posix() for path in run_dir.rglob("*") if path.is_file())
    atomic_json(run_dir / "manifest.json", manifest)
    write_bundle(run_dir, signing_key_env=signing_key_env, key_id=signing_key_id)
    verification = verify_bundle(run_dir, signing_key_env=signing_key_env, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("performance bundle verification failed")
    return run_dir


def _campaign_summary(manifest: dict[str, Any], cells: list[dict[str, Any]], observations: list[dict[str, Any]]) -> dict[str, Any]:
    completed_statuses = {"completed"} if manifest.get("performance_protocol_version") == PERFORMANCE_PROTOCOL_VERSION else {"completed", "completed-with-errors"}
    completed = [cell for cell in cells if cell.get("status") in completed_statuses]
    best = max(completed, key=lambda row: float(row["goodput_requests_per_second"]), default=None)
    return {
        "performance_protocol_version": manifest["performance_protocol_version"],
        "run_id": manifest["run_id"],
        "runtime_id": manifest["runtime"]["id"],
        "status": manifest["status"],
        "cells": manifest["cells"],
        "observations": len(observations),
        "successes": sum(row.get("status") == "success" for row in observations),
        "errors": sum(row.get("status") != "success" for row in observations),
        "warmups": manifest["warmups"],
        "input_tokens": sum(float(row.get("input_tokens", 0)) for row in observations),
        "output_tokens": sum(float(row.get("output_tokens", 0)) for row in observations),
        "campaign_token_usage": manifest["token_usage"],
        "campaign_estimated_cost": manifest["estimated_cost"],
        "best_goodput_cell": best,
        "limitations": [
            "Client-side measurements include network transport between the load generator and endpoint.",
            "Inter-chunk timing is diagnostic and is not token-level timing.",
            "TPOT is derived from provider-reported output tokens and elapsed time after TTFT.",
            "Performance results do not establish response quality or universal deployment capacity.",
        ],
    }


def _write_cells_csv(path: Path, cells: list[dict[str, Any]], *, protocol_version: str) -> None:
    v2 = protocol_version == PERFORMANCE_PROTOCOL_VERSION
    fields = [
        "block",
        "cell_key",
        "scenario_id",
        "arrival",
        "context_tokens",
        "output_tokens",
        "concurrency",
        "request_rate",
        "status",
        *(
            [
                "reason",
                "error_types",
                "warnings",
                "goodput_requests",
                "input_tokens_total",
                "output_tokens_total",
                "load_generator_valid",
                "load_generator_invalid_reasons",
                "offered_requests",
                "dispatched_requests",
                "completed_requests",
                "offered_requests_per_second",
                "dispatched_requests_per_second",
                "completed_requests_per_second",
                "dispatch_rate_fidelity",
                "client_queue_p95_ms",
                "dispatch_lag_p95_ms",
                "dispatch_lag_max_ms",
                "scheduled_ttft_p95_ms",
                "scheduled_e2e_p99_ms",
                "serving_slo_passed",
                "measurement_window_seconds",
                "throughput_window_seconds",
            ]
            if v2
            else []
        ),
        "observations",
        "successes",
        "errors",
        "error_rate",
        "slo_passed",
        "requests_per_second",
        "goodput_requests_per_second",
        "input_tokens_per_second",
        "output_tokens_per_second",
        "ttft_p50_ms",
        "ttft_p95_ms",
        "ttft_p99_ms",
        "e2e_p50_ms",
        "e2e_p95_ms",
        "e2e_p99_ms",
        "tpot_p50_ms",
        "decode_tps_p50",
        "estimated_cost",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for cell in cells:
            error_type_values = cell.get("error_types")
            warning_values = cell.get("warnings")
            derived = {
                "error_types": (
                    json.dumps(error_type_values, sort_keys=True, separators=(",", ":")) if isinstance(error_type_values, dict) else None
                ),
                "warnings": "; ".join(str(item) for item in warning_values) if isinstance(warning_values, list) else None,
                "load_generator_invalid_reasons": "; ".join(str(item) for item in cell.get("load_generator_invalid_reasons", [])),
                "client_queue_p95_ms": (cell.get("client_queue_ms") or {}).get("p95"),
                "dispatch_lag_p95_ms": (cell.get("dispatch_lag_ms") or {}).get("p95"),
                "dispatch_lag_max_ms": (cell.get("dispatch_lag_ms") or {}).get("max"),
                "scheduled_ttft_p95_ms": (cell.get("scheduled_ttft_ms") or {}).get("p95"),
                "scheduled_e2e_p99_ms": (cell.get("scheduled_e2e_ms") or {}).get("p99"),
                "ttft_p50_ms": (cell.get("ttft_ms") or {}).get("p50"),
                "ttft_p95_ms": (cell.get("ttft_ms") or {}).get("p95"),
                "ttft_p99_ms": (cell.get("ttft_ms") or {}).get("p99"),
                "e2e_p50_ms": (cell.get("e2e_ms") or {}).get("p50"),
                "e2e_p95_ms": (cell.get("e2e_ms") or {}).get("p95"),
                "e2e_p99_ms": (cell.get("e2e_ms") or {}).get("p99"),
                "tpot_p50_ms": (cell.get("tpot_ms") or {}).get("p50"),
                "decode_tps_p50": (cell.get("decode_tokens_per_second") or {}).get("p50"),
            }
            writer.writerow(
                {field: derived.get(field, cell.get(field)) for field in fields}
            )


def _performance_reports(run_dir: Path, manifest: dict[str, Any], summary: dict[str, Any], cells: list[dict[str, Any]]) -> None:
    figures = run_dir / "figures"
    figures.mkdir(mode=0o700, parents=True, exist_ok=True)
    ordered = sorted(cells, key=lambda row: (int(row.get("block", 0)), str(row.get("scenario_id", "")), str(row.get("cell_key", ""))))
    v2 = manifest.get("performance_protocol_version") == PERFORMANCE_PROTOCOL_VERSION
    evaluated_statuses = {"completed", "completed-with-errors", *({"invalid-loadgen"} if v2 else set())}
    evaluated = [cell for cell in ordered if cell.get("status") in evaluated_statuses]
    runtime_value = manifest.get("runtime")
    runtime = runtime_value if isinstance(runtime_value, dict) else {}
    plan_value = manifest.get("plan")
    plan = plan_value if isinstance(plan_value, dict) else {}
    workload_value = manifest.get("workload")
    workload = workload_value if isinstance(workload_value, dict) else {}
    pricing = runtime.get("pricing")
    cost_heading = f"Cost ({pricing['currency']})" if isinstance(pricing, dict) else "Cost"

    def number(value: Any, digits: int) -> str:
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
            return "N/A"
        return f"{float(value):,.{digits}f}"

    def available(row: dict[str, Any]) -> bool:
        return isinstance(row.get("successes"), int) and not isinstance(row.get("successes"), bool) and int(row["successes"]) > 0

    def metric(row: dict[str, Any], key: str, percentile_key: str, digits: int) -> str:
        distribution_value = row.get(key)
        if not available(row) or not isinstance(distribution_value, dict) or int(distribution_value.get("count", 0)) < 1:
            return "N/A"
        return number(distribution_value.get(percentile_key), digits)

    def diagnostic_metric(row: dict[str, Any], key: str, percentile_key: str, digits: int) -> str:
        distribution_value = row.get(key)
        if not isinstance(distribution_value, dict) or int(distribution_value.get("count", 0)) < 1:
            return "N/A"
        return number(distribution_value.get(percentile_key), digits)

    def interval(row: dict[str, Any], key: str, interval_key: str, digits: int) -> str:
        distribution_value = row.get(key)
        if not available(row) or not isinstance(distribution_value, dict) or int(distribution_value.get("count", 0)) < 1:
            return "N/A"
        interval_value = distribution_value.get(interval_key)
        if not isinstance(interval_value, dict):
            return "N/A"
        lower, upper, confidence = interval_value.get("lower"), interval_value.get("upper"), interval_value.get("confidence")
        if not all(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)) for value in (lower, upper, confidence)):
            return "N/A"
        return f"{number(lower, digits)}–{number(upper, digits)} ({float(cast(int | float, confidence)):.0%})"

    def direct_metric(row: dict[str, Any], key: str, digits: int) -> str:
        return number(row.get(key), digits) if available(row) else "N/A"

    def verdict(value: Any) -> str:
        return "PASS" if value is True else "FAIL" if value is False else "N/A"

    def bootstrap_samples(row: dict[str, Any]) -> str:
        values: set[int] = set()
        for key, interval_key in (("ttft_ms", "p95_ci"), ("e2e_ms", "p99_ci")):
            distribution_value = row.get(key)
            interval_value = distribution_value.get(interval_key) if isinstance(distribution_value, dict) else None
            sample_value = interval_value.get("samples") if isinstance(interval_value, dict) else None
            if isinstance(sample_value, int) and not isinstance(sample_value, bool) and sample_value > 0:
                values.add(sample_value)
        return "/".join(f"{value:,}" for value in sorted(values)) if available(row) and values else "N/A"

    def p99_support(row: dict[str, Any]) -> str:
        resolution = row.get("p99_resolution")
        if not isinstance(resolution, dict):
            return "N/A"
        successes, minimum, resolved = resolution.get("successful_observations"), resolution.get("minimum"), resolution.get("resolved")
        if not isinstance(successes, int) or isinstance(successes, bool) or not isinstance(minimum, int) or isinstance(minimum, bool) or not isinstance(resolved, bool):
            return "N/A"
        return f"{successes:,}/{minimum:,} · {'resolved' if resolved else 'unresolved'}"

    def warnings(row: dict[str, Any]) -> list[str]:
        value = row.get("warnings")
        retained = [str(item) for item in value if isinstance(item, str) and item] if isinstance(value, list) else []
        reasons = row.get("load_generator_invalid_reasons")
        if isinstance(reasons, list):
            retained.extend(str(item) for item in reasons if isinstance(item, str) and item and item not in retained)
        return retained

    def load_generator_cells(row: dict[str, Any]) -> str:
        if not v2:
            return ""
        open_loop = row.get("arrival") == "open-loop"
        queue_p95 = diagnostic_metric(row, "client_queue_ms", "p95", 2) if open_loop else "N/A"
        arrival_window = number(row.get("measurement_window_seconds"), 3) if open_loop else "N/A"
        return (
            f"<td>{html.escape(number(row.get('offered_requests_per_second'), 3))}</td>"
            f"<td>{html.escape(number(row.get('dispatched_requests_per_second'), 3))}</td>"
            f"<td>{html.escape(number(row.get('completed_requests_per_second'), 3))}</td>"
            f"<td>{html.escape(number(row.get('dispatch_rate_fidelity'), 4))}</td>"
            f"<td>{html.escape(queue_p95)}</td>"
            f"<td>{html.escape(diagnostic_metric(row, 'dispatch_lag_ms', 'p95', 2))}</td>"
            f"<td>{html.escape(arrival_window)}</td>"
            f"<td>{html.escape(number(row.get('throughput_window_seconds'), 3))}</td>"
        )

    def load_label(row: dict[str, Any]) -> str:
        concurrency = row.get("concurrency")
        if concurrency is not None:
            return f"c={concurrency}"
        rate = row.get("request_rate")
        return f"{float(rate):g} req/s" if isinstance(rate, (int, float)) and not isinstance(rate, bool) else "N/A"

    def error_types(row: dict[str, Any]) -> str:
        value = row.get("error_types")
        if not isinstance(value, dict) or not value:
            return "—"
        return ", ".join(f"{key}: {count}" for key, count in sorted(value.items()))

    def outcome_detail(row: dict[str, Any]) -> str:
        parts: list[str] = []
        if row.get("status") == "skipped" and row.get("reason"):
            parts.append(str(row["reason"]))
        if error_types(row) != "—":
            parts.append(error_types(row))
        parts.extend(warnings(row))
        if row.get("status") != "skipped" and not available(row):
            parts.append("No successful observations; performance metrics are unavailable.")
        return " · ".join(parts) or "—"

    def axis_tick(field: str, value: float) -> str:
        if field in {"context_tokens", "output_tokens", "concurrency"}:
            return f"{int(value):,}"
        return f"{value:g}"

    def plot_value(row: dict[str, Any], key: str, percentile_key: str | None) -> float:
        if not available(row) or row.get("status") != "completed":
            return math.nan
        source: Any = row.get(key)
        if percentile_key is not None:
            source = source.get(percentile_key) if isinstance(source, dict) and int(source.get("count", 0)) > 0 else None
        return float(source) if isinstance(source, (int, float)) and not isinstance(source, bool) and math.isfinite(float(source)) else math.nan

    metric_specs: tuple[tuple[str, str, str, str | None, str], ...] = (
        ("ttft", "TTFT p95", "ttft_ms", "p95", "TTFT p95 (ms)"),
        ("e2e", "End-to-end p99", "e2e_ms", "p99", "E2E p99 (ms)"),
        ("throughput", "Output token throughput", "output_tokens_per_second", None, "Output tokens/s"),
        ("goodput", "SLO goodput", "goodput_requests_per_second", None, "Good requests/s"),
    )
    chart_records: dict[str, list[tuple[str, str, str]]] = {slug: [] for slug, *_ in metric_specs}
    chart_counts = {slug: 0 for slug, *_ in metric_specs}
    scenarios = sorted({(str(row.get("scenario_id", "unknown")), str(row.get("arrival", "unknown"))) for row in ordered})
    for scenario_id, arrival in scenarios:
        scenario_rows = [row for row in ordered if str(row.get("scenario_id", "unknown")) == scenario_id and str(row.get("arrival", "unknown")) == arrival]
        concurrency_values = {row.get("concurrency") for row in scenario_rows if row.get("concurrency") is not None}
        context_values = {row.get("context_tokens") for row in scenario_rows if row.get("context_tokens") is not None}
        output_values = {row.get("output_tokens") for row in scenario_rows if row.get("output_tokens") is not None}
        if arrival == "open-loop":
            axis_field, axis_name = "request_rate", "Offered request rate (requests/s)"
        elif len(concurrency_values) > 1:
            axis_field, axis_name = "concurrency", "Concurrency (users)"
        elif len(context_values) > 1:
            axis_field, axis_name = "context_tokens", "Declared context tokens"
        elif len(output_values) > 1:
            axis_field, axis_name = "output_tokens", "Requested output tokens"
        else:
            axis_field, axis_name = "concurrency", "Concurrency (users)"

        def family_key(row: dict[str, Any], field: str = axis_field) -> tuple[int, int, int, float, float]:
            concurrency = row.get("concurrency")
            request_rate = row.get("request_rate")
            return (
                int(row.get("block", 0)),
                -1 if field == "context_tokens" else int(row.get("context_tokens", -1)),
                -1 if field == "output_tokens" else int(row.get("output_tokens", -1)),
                -1.0 if field == "concurrency" or concurrency is None else float(cast(int | float, concurrency)),
                -1.0 if field == "request_rate" or request_rate is None else float(cast(int | float, request_rate)),
            )

        families: dict[tuple[int, int, int, float, float], list[dict[str, Any]]] = {}
        for row in scenario_rows:
            families.setdefault(family_key(row), []).append(row)
        for _, family_rows in sorted(families.items()):
            first = family_rows[0]
            family_parts = [f"block {first.get('block', 0)}"]
            if axis_field != "context_tokens":
                family_parts.append(f"ctx {int(first.get('context_tokens', 0)):,} tokens")
            if axis_field != "output_tokens":
                family_parts.append(f"out {int(first.get('output_tokens', 0)):,} tokens")
            if axis_field != "concurrency" and first.get("concurrency") is not None:
                family_parts.append(f"concurrency {first['concurrency']}")
            if axis_field != "request_rate" and first.get("request_rate") is not None:
                family_parts.append(f"rate {float(first['request_rate']):g} req/s")
            family_label = " · ".join(family_parts)
            by_axis = {
                float(row[axis_field]): row
                for row in family_rows
                if isinstance(row.get(axis_field), (int, float)) and not isinstance(row.get(axis_field), bool)
            }
            x_values = sorted(by_axis)
            x_labels = [axis_tick(axis_field, value) for value in x_values]
            for slug, metric_title, key, percentile_key, y_label in metric_specs:
                values = [plot_value(by_axis[value], key, percentile_key) for value in x_values]
                plotted = sum(math.isfinite(value) for value in values)
                if plotted == 0:
                    continue
                chart_counts[slug] += 1
                filename = f"{slug}.svg" if chart_counts[slug] == 1 else f"{slug}-{chart_counts[slug]:03d}.svg"
                title = f"{metric_title} — {scenario_id}"
                caption = (
                    f"Family: {family_label}; arrival: {arrival}. X-axis: {axis_name}. "
                    f"Plotted points: {plotted} of {len(values)}; non-completed, zero-success, and invalid-loadgen cells are omitted."
                )
                _line_svg(title, [(family_label, values)], figures / filename, y_label, x_labels=x_labels, x_label=axis_name)
                chart_records[slug].append((filename, title, caption))

    def badge(value: Any) -> str:
        status = str(value)
        css = {"completed": "ok", "completed-with-errors": "warn", "skipped": "muted", "invalid-loadgen": "bad"}.get(status, "bad")
        return f'<span class="badge {css}">{html.escape(status)}</span>'

    result_rows = "".join(
        f"""<tr>
<td>{row.get('block', '')}</td><th scope="row"><code>{html.escape(str(row.get('cell_key', '')))}</code></th><td>{html.escape(str(row.get('scenario_id', '')))}</td><td>{html.escape(load_label(row))}</td><td>{badge(row.get('status'))}</td>
{load_generator_cells(row)}
<td>{row.get('successes', 0):,}/{row.get('observations', 0):,}</td><td>{html.escape(metric(row, 'ttft_ms', 'p95', 2))}</td><td>{html.escape(interval(row, 'ttft_ms', 'p95_ci', 2))}</td>
<td>{html.escape(metric(row, 'e2e_ms', 'p99', 2))}</td><td>{html.escape(interval(row, 'e2e_ms', 'p99_ci', 2))}</td><td>{html.escape(metric(row, 'tpot_ms', 'p50', 3))}</td>
<td>{html.escape(bootstrap_samples(row))}</td><td>{html.escape(p99_support(row))}</td><td>{html.escape(direct_metric(row, 'output_tokens_per_second', 2))}</td>
<td>{html.escape(direct_metric(row, 'goodput_requests_per_second', 3))}</td><td>{html.escape(number(row.get('error_rate'), 4))}</td>
{f'<td>{verdict(row.get("serving_slo_passed"))}</td>' if v2 else ''}<td>{verdict(row.get('slo_passed'))}</td><td>{html.escape(number(row.get('estimated_cost'), 6))}</td><td>{html.escape(' · '.join(warnings(row)) or '—')}</td>
</tr>"""
        for row in evaluated
    ) or f'<tr><td colspan="{28 if v2 else 19}">No evaluated cells.</td></tr>'
    matrix_rows = "".join(
        f"<tr><td>{row.get('block', '')}</td><th scope=\"row\"><code>{html.escape(str(row.get('cell_key', '')))}</code></th><td>{badge(row.get('status'))}</td><td>{row.get('successes', 'N/A')}</td><td>{row.get('errors', 'N/A')}</td><td>{html.escape(error_types(row))}</td><td>{html.escape(outcome_detail(row))}</td></tr>"
        for row in ordered
    ) or '<tr><td colspan="7">No cells were recorded.</td></tr>'
    warning_items = [(str(row.get("cell_key", "")), warning) for row in evaluated for warning in warnings(row)]
    warning_section = (
        '<ul class="warnings">' + "".join(f"<li><code>{html.escape(cell_key)}</code>: {html.escape(warning)}</li>" for cell_key, warning in warning_items) + "</ul>"
        if warning_items
        else "<p>No cell-level warnings were recorded.</p>"
    )
    populated_chart_specs = [spec for spec in metric_specs if chart_records[spec[0]]]
    chart_sections = "".join(
        f"""<details{' open' if index == 0 else ''}><summary>{html.escape(metric_title)} — {len(chart_records[slug])} comparable families</summary><div class="figure-grid">{
            ''.join(
                f'<figure><img src="figures/{html.escape(filename)}" alt="{html.escape(title)}. {html.escape(caption)}" loading="lazy"><figcaption>{html.escape(caption)}</figcaption></figure>'
                for filename, title, caption in chart_records[slug]
            )
        }</div></details>"""
        for index, (slug, metric_title, _, _, _) in enumerate(populated_chart_specs)
    ) or "<p>No valid completed cells are available for serving curves.</p>"
    limitations_value = summary.get("limitations")
    limitations = [str(item) for item in limitations_value] if isinstance(limitations_value, list) else []
    limitations_html = "".join(f"<li>{html.escape(item)}</li>" for item in limitations) or "<li>No limitations were recorded.</li>"
    counts_value = manifest.get("cells")
    counts = counts_value if isinstance(counts_value, dict) else {}
    warmups_value = manifest.get("warmups")
    warmups = warmups_value if isinstance(warmups_value, dict) else {}
    system_value = manifest.get("system_evidence")
    system = system_value if isinstance(system_value, dict) else {}
    source_value = manifest.get("source")
    source = source_value if isinstance(source_value, dict) else {}
    release_value = manifest.get("release")
    release = release_value if isinstance(release_value, dict) else {}
    official_value = manifest.get("official") if isinstance(manifest.get("official"), bool) else manifest.get("officially_valid")
    official = "yes" if official_value is True else "no"
    rankable_value = manifest.get("rankable")
    rankable = "yes" if rankable_value is True else "no" if rankable_value is False else "not recorded"
    semantic_value = manifest.get("semantic_valid")
    semantic = "valid" if semantic_value is True else "invalid" if semantic_value is False else "not recorded"
    publication_version = manifest.get("publication_version")
    release_id = release.get("release_id", manifest.get("release_id", "not issued"))
    assurance = manifest.get("assurance", "not recorded")
    authenticity = manifest.get("authenticity", "not recorded")
    public_provenance = ""
    if publication_version is not None or "assurance" in manifest or "semantic_valid" in manifest:
        public_provenance = (
            f"<dt>Publication / release</dt><dd>{html.escape(str(publication_version or 'not recorded'))} / "
            f"{html.escape(str(release_id))}</dd><dt>Assurance</dt><dd>{html.escape(str(assurance))}</dd>"
            f"<dt>Official / rankable</dt><dd>{official} / {rankable}</dd>"
            f"<dt>Semantic verification / authenticity</dt><dd>{semantic} / {html.escape(str(authenticity))}</dd>"
        )
    no_success_count = sum(not available(row) for row in evaluated)
    load_generator_headers = (
        '<th scope="col">Offered req/s</th><th scope="col">Dispatched req/s</th><th scope="col">Completed req/s</th>'
        '<th scope="col">Rate fidelity</th><th scope="col">Client queue p95 ms</th><th scope="col">Dispatch lag p95 ms</th>'
        '<th scope="col">Arrival window s</th><th scope="col">Throughput window s</th>'
        if v2
        else ""
    )
    invalid_card = (
        f'<div class="card">Invalid load generator<strong>{int(counts.get("invalid_loadgen", 0)):,}</strong></div>' if v2 else ""
    )
    outcome_caption = (
        "Completed, errored, invalid-loadgen, and skipped cells remain distinct"
        if v2
        else "Completed, errored, and skipped cells remain distinct"
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>CavadaLabs LLM Performance Report</title>
<style>
:root{{--ink:#172033;--muted:#5d6675;--line:#c9d2df;--paper:#fff;--panel:#f5f8fc;--blue:#145b96;--good:#176b35;--warn:#8a5600;--bad:#9d2525}}*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:#eef2f7;color:var(--ink);font:15px/1.5 system-ui,sans-serif}}header,main,footer{{max-width:1480px;margin:auto;background:var(--paper);padding:28px clamp(18px,4vw,56px)}}header{{padding-top:42px;border-bottom:1px solid var(--line)}}h1{{font-size:clamp(2rem,5vw,3.25rem);line-height:1.05;margin:.2rem 0 1rem}}h2{{margin-top:2.5rem}}h3{{margin-top:2rem}}a{{color:var(--blue)}}a:focus-visible,summary:focus-visible{{outline:3px solid #efb100;outline-offset:3px}}code{{font:0.9em ui-monospace,monospace;background:#edf2f7;padding:.1rem .3rem;word-break:break-all}}.eyebrow{{color:var(--blue);font-weight:700;letter-spacing:.08em;text-transform:uppercase}}.skip-link{{position:absolute;left:-9999px}}.skip-link:focus{{left:1rem;top:1rem;background:#fff;padding:.7rem;z-index:2}}.notice{{border-left:5px solid var(--warn);background:#fff7df;padding:12px 16px;margin:1.5rem 0}}.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:24px 0}}.card{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}}.card strong{{display:block;font-size:1.35rem}}nav ul{{display:flex;flex-wrap:wrap;gap:8px 18px;padding:0;list-style:none}}.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:7px}}table{{border-collapse:collapse;width:100%;min-width:1150px}}caption{{text-align:left;font-weight:700;font-size:1.1rem;padding:12px}}th,td{{border:1px solid var(--line);padding:8px 10px;text-align:right;vertical-align:top}}thead th{{background:#e9f0f8;position:sticky;top:0}}tbody th,td:nth-last-child(1){{text-align:left}}tbody tr:nth-child(even){{background:#f8fafc}}.badge{{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:1px 7px;font-weight:700;white-space:nowrap}}.ok{{color:var(--good)}}.warn{{color:var(--warn)}}.bad{{color:var(--bad)}}.muted{{color:var(--muted)}}details{{border:1px solid var(--line);border-radius:8px;margin:12px 0;background:#fff}}summary{{cursor:pointer;font-weight:700;padding:14px;background:var(--panel)}}.figure-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr));gap:16px;padding:16px}}figure{{margin:0;border:1px solid var(--line);border-radius:7px;overflow:hidden}}figure img{{display:block;width:100%;height:auto;background:#fff}}figcaption{{padding:10px 12px;color:var(--muted)}}footer{{border-top:1px solid var(--line);color:var(--muted)}}@media print{{body{{background:#fff}}header,main,footer{{max-width:none;padding:10mm}}nav,.skip-link{{display:none}}details:not([open])>*{{display:block}}.table-wrap{{overflow:visible}}thead th{{position:static}}figure{{break-inside:avoid}}}}
</style></head><body><a class="skip-link" href="#main">Skip to report content</a>
<header><p class="eyebrow">CavadaLabs evaluation protocol</p><h1>LLM serving performance report</h1>
<p>Run <code>{html.escape(str(manifest.get('run_id', 'unknown')))}</code> · Runtime <code>{html.escape(str(runtime.get('id', 'unknown')))}</code> · Status <strong>{html.escape(str(manifest.get('status', 'unknown')))}</strong></p>
<nav aria-label="Report sections"><ul><li><a href="#overview">Overview</a></li><li><a href="#measurements">Measurements</a></li><li><a href="#charts">Charts</a></li><li><a href="#outcomes">Outcome matrix</a></li><li><a href="#warnings">Warnings</a></li><li><a href="#limitations">Limitations</a></li></ul></nav></header>
<main id="main"><section id="overview" aria-labelledby="overview-title"><h2 id="overview-title">Overview</h2>
<div class="summary-grid"><div class="card">Execution status<strong>{html.escape(str(manifest.get('status', 'unknown')))}</strong></div><div class="card">Evaluated cells<strong>{len(evaluated):,}</strong></div><div class="card">SLO passed<strong>{int(counts.get('slo_passed', 0)):,} / {int(counts.get('slo_passed', 0)) + int(counts.get('slo_failed', 0)):,}</strong></div>{invalid_card}<div class="card">Successful observations<strong>{int(summary.get('successes', 0)):,}</strong></div><div class="card">Error observations<strong>{int(summary.get('errors', 0)):,}</strong></div><div class="card">Officially valid evidence<strong>{official}</strong></div></div>
<div class="notice"><strong>Availability:</strong> {no_success_count:,} evaluated cells had no successful observations. Their performance metrics are reported as <strong>N/A</strong> and omitted from curves, while errors remain visible.</div>
<p>Warm-up errors: {int(warmups.get('errors', 0)):,} of {int(warmups.get('total', 0)):,}. Skipped cells: {int(counts.get('skipped', 0)):,}. Client-side measurements and protocol scope are described under <a href="#limitations">limitations</a>.</p>
<h3>Evidence identity</h3><dl><dt>Protocol / report</dt><dd>{html.escape(str(manifest.get('performance_protocol_version', 'unknown')))} / {html.escape(str(manifest.get('report_version', 'unknown')))}</dd><dt>Plan</dt><dd>{html.escape(str(plan.get('name', 'unknown')))}@{html.escape(str(plan.get('revision', 'unknown')))} · <code>{html.escape(str(plan.get('sha256', 'unknown')))}</code></dd><dt>Workload</dt><dd>{html.escape(str(workload.get('id', 'unknown')))}@{html.escape(str(workload.get('revision', 'unknown')))} · <code>{html.escape(str(workload.get('sha256', 'unknown')))}</code></dd><dt>Runtime</dt><dd>Engine {html.escape(str(runtime.get('engine', 'unknown')))}; model revision <code>{html.escape(str(runtime.get('model_revision', 'unknown')))}</code>; {html.escape(str(runtime.get('gpu_count', 'unknown')))} × {html.escape(str(runtime.get('gpu_model', 'unknown')))}; dtype {html.escape(str(runtime.get('dtype', 'unknown')))}; quantization {html.escape(str(runtime.get('quantization', 'unknown')))}</dd><dt>System evidence</dt><dd>{html.escape(str(system.get('configuration_id', 'not recorded')))}{f" · collected {html.escape(str(system.get('collected_at')))}" if system else ''}</dd><dt>Source</dt><dd>commit <code>{html.escape(str(source.get('commit', 'not recorded')))}</code>; dirty: {html.escape(str(source.get('dirty', 'not recorded')))}</dd>{public_provenance}</dl></section>
<section id="measurements" aria-labelledby="measurements-title"><h2 id="measurements-title">Measured cells</h2><p>Latency estimates show their retained 95% bootstrap intervals. “Bootstrap” is the resample count; p99 support is successful observations / required minimum. Exact machine-readable evidence remains in <a href="cells.csv">cells.csv</a> and <a href="summary.json">summary.json</a>.</p><div class="table-wrap"><table><caption>Performance measurements; N/A means the field is not applicable or its evidence is unavailable.</caption><thead><tr><th scope="col">Block</th><th scope="col">Cell</th><th scope="col">Scenario</th><th scope="col">Load</th><th scope="col">Status</th>{load_generator_headers}<th scope="col">Success / N</th><th scope="col">TTFT p95 ms</th><th scope="col">TTFT p95 CI</th><th scope="col">E2E p99 ms</th><th scope="col">E2E p99 CI</th><th scope="col">TPOT p50 ms</th><th scope="col">Bootstrap</th><th scope="col">p99 support</th><th scope="col">Output tok/s</th><th scope="col">Good req/s</th><th scope="col">Error rate</th>{'<th scope="col">Contact SLO</th>' if v2 else ''}<th scope="col">{'Final SLO' if v2 else 'SLO'}</th><th scope="col">{html.escape(cost_heading)}</th><th scope="col">Warnings</th></tr></thead><tbody>{result_rows}</tbody></table></div></section>
<section id="charts" aria-labelledby="charts-title"><h2 id="charts-title">Comparable-family charts</h2><p>Each figure holds block, scenario, arrival mode, and every non-axis dimension fixed. A single available point is shown as a marker; missing values do not create zero-valued points or connecting lines.</p>{chart_sections}</section>
<section id="outcomes" aria-labelledby="outcomes-title"><h2 id="outcomes-title">Cell outcome matrix</h2><div class="table-wrap"><table><caption>{outcome_caption}.</caption><thead><tr><th scope="col">Block</th><th scope="col">Cell</th><th scope="col">Outcome</th><th scope="col">Successes</th><th scope="col">Errors</th><th scope="col">Error types</th><th scope="col">Reason / warning</th></tr></thead><tbody>{matrix_rows}</tbody></table></div></section>
<section id="warnings" aria-labelledby="warnings-title"><h2 id="warnings-title">Warnings</h2>{warning_section}</section>
<section id="limitations" aria-labelledby="limitations-title"><h2 id="limitations-title">Limitations</h2><ul>{limitations_html}</ul></section></main>
<footer><p>Report version {html.escape(str(manifest.get('report_version', 'unknown')))} · Run {html.escape(str(manifest.get('run_id', 'unknown')))} · Finished {html.escape(str(manifest.get('finished_at', 'unknown')))}</p></footer></body></html>\n"""
    atomic_text(run_dir / "report.html", document)

    public_pdf_provenance = (
        [
            f"Publication/release: {publication_version or 'not recorded'} / {release_id}",
            f"Assurance: {assurance}; official/rankable: {official} / {rankable}",
            f"Semantic verification/authenticity: {semantic} / {authenticity}",
        ]
        if public_provenance
        else []
    )
    pdf_lines = [
        "# RUN SUMMARY",
        f"Run: {manifest.get('run_id', 'unknown')}",
        f"Runtime: {runtime.get('id', 'unknown')}",
        f"Status: {manifest.get('status', 'unknown')}; officially valid evidence: {official}",
        f"Cells evaluated: {len(evaluated)}; skipped: {counts.get('skipped', 0)}; without successes: {no_success_count}",
        f"Observations: {summary.get('observations', 0)}; successes: {summary.get('successes', 0)}; errors: {summary.get('errors', 0)}",
        f"Warm-up errors: {warmups.get('errors', 0)} / {warmups.get('total', 0)}",
        "",
        "# EVIDENCE IDENTITY",
        f"Protocol/report: {manifest.get('performance_protocol_version', 'unknown')} / {manifest.get('report_version', 'unknown')}",
        f"Plan: {plan.get('name', 'unknown')}@{plan.get('revision', 'unknown')}",
        f"Plan SHA-256: {plan.get('sha256', 'unknown')}",
        f"Workload: {workload.get('id', 'unknown')}@{workload.get('revision', 'unknown')}",
        f"Workload SHA-256: {workload.get('sha256', 'unknown')}",
        f"Engine: {runtime.get('engine', 'unknown')}; model revision: {runtime.get('model_revision', 'unknown')}",
        f"Hardware declaration: {runtime.get('gpu_count', 'unknown')} x {runtime.get('gpu_model', 'unknown')}",
        f"System configuration evidence: {system.get('configuration_id', 'not recorded')}",
        f"Source: commit {source.get('commit', 'not recorded')}; dirty: {source.get('dirty', 'not recorded')}",
        *public_pdf_provenance,
        "",
        "# TABLE 1. MEASURED CELLS (N/A = NOT APPLICABLE OR UNAVAILABLE)",
        "| Block | status | successes/N | errors | Contact SLO | Final SLO |" if v2 else "| Block | status | successes/N | errors | SLO |",
    ]
    for row in evaluated:
        slo_values = (
            f"{verdict(row.get('serving_slo_passed'))} | {verdict(row.get('slo_passed'))}"
            if v2
            else verdict(row.get("slo_passed"))
        )
        pdf_lines.extend(
            (
                f"| {row.get('block', '')} | {row.get('status', '')} | {row.get('successes', 0)}/{row.get('observations', 0)} | {row.get('errors', 0)} | {slo_values} |",
                f"  Cell: {row.get('cell_key', '')}",
                f"  TTFT p95: {metric(row, 'ttft_ms', 'p95', 2)} ms; CI: {interval(row, 'ttft_ms', 'p95_ci', 2)}",
                f"  E2E p99: {metric(row, 'e2e_ms', 'p99', 2)} ms; CI: {interval(row, 'e2e_ms', 'p99_ci', 2)}",
                f"  TPOT p50: {metric(row, 'tpot_ms', 'p50', 3)} ms; bootstrap: {bootstrap_samples(row)}; p99: {p99_support(row)}",
                f"  Output tok/s: {direct_metric(row, 'output_tokens_per_second', 2)}; good req/s: {direct_metric(row, 'goodput_requests_per_second', 3)}; error rate: {number(row.get('error_rate'), 4)}",
                f"  {cost_heading}: {number(row.get('estimated_cost'), 6)}; warnings: {'; '.join(warnings(row)) or 'none'}",
            )
        )
        if v2:
            open_loop = row.get("arrival") == "open-loop"
            queue_p95 = diagnostic_metric(row, "client_queue_ms", "p95", 2) if open_loop else "N/A"
            arrival_window = number(row.get("measurement_window_seconds"), 3) if open_loop else "N/A"
            pdf_lines.append(
                "  Load generator: "
                f"offered {number(row.get('offered_requests_per_second'), 3)} req/s; "
                f"dispatched {number(row.get('dispatched_requests_per_second'), 3)} req/s; "
                f"completed {number(row.get('completed_requests_per_second'), 3)} req/s; "
                f"fidelity {number(row.get('dispatch_rate_fidelity'), 4)}; "
                f"queue p95 {queue_p95} ms; "
                f"dispatch lag p95 {diagnostic_metric(row, 'dispatch_lag_ms', 'p95', 2)} ms; "
                f"arrival window {arrival_window} s; "
                f"throughput window {number(row.get('throughput_window_seconds'), 3)} s"
            )
    pdf_lines.extend(("", "# TABLE 2. ERROR / SKIPPED MATRIX", "| Block | outcome | successes | errors | error types / reason |"))
    for row in ordered:
        pdf_lines.extend(
            (
                f"| {row.get('block', '')} | {row.get('status', '')} | {row.get('successes', 'N/A')} | {row.get('errors', 'N/A')} | {error_types(row)} |",
                f"  Cell: {row.get('cell_key', '')}",
                f"  Detail: {outcome_detail(row)}",
            )
        )
    pdf_lines.extend(("", "# WARNINGS"))
    pdf_lines.extend(f"{cell_key}: {warning}" for cell_key, warning in warning_items)
    if not warning_items:
        pdf_lines.append("No cell-level warnings were recorded.")
    pdf_lines.extend(("", "# LIMITATIONS"))
    pdf_lines.extend(f"- {item}" for item in limitations)
    pdf_lines.extend(
        (
            "",
            "# REPORT NOTES",
            "Charts contain one comparable family each; non-completed, zero-success, and invalid-loadgen cells are omitted from curves.",
            "See cells.csv, summary.json, and report.html for retained machine-readable evidence and accessible charts.",
            f"Report version {manifest.get('report_version', 'unknown')}; run {manifest.get('run_id', 'unknown')}",
        )
    )
    _pdf(
        run_dir / "report.pdf",
        "CavadaLabs LLM Performance Report",
        pdf_lines,
        report_version=str(manifest.get("report_version", "unknown")),
    )


def verify_performance_source_bundle(
    run_dir: Path,
    *,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
) -> dict[str, Any]:
    source = Path(run_dir)
    if source.is_symlink() or not source.is_dir():
        raise ProtocolError(f"invalid performance bundle: {source}")
    with tempfile.TemporaryDirectory(prefix="cavada-performance-verify-") as temporary:
        snapshot = Path(temporary) / "run"
        shutil.copytree(source, snapshot, symlinks=True, copy_function=_snapshot_copyfile)
        verification = verify_bundle(snapshot, signing_key_env=signing_key_env)
        if not verification["valid"]:
            raise ProtocolError("performance bundle integrity verification failed: " + "; ".join(map(str, verification["failures"])))
        manifest_path = snapshot / "manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise ProtocolError("performance bundle is missing a safe manifest")
        try:
            manifest = _object(
                json.loads(manifest_path.read_text(encoding="utf-8"), parse_constant=_reject_json_constant),
                "performance manifest",
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError("performance manifest is invalid") from exc
        if not _finite_json(manifest):
            raise ProtocolError("performance manifest contains non-finite evidence")
        protocol_version = manifest.get("performance_protocol_version")
        if protocol_version == "1.0.0":
            if (manifest.get("plan_version"), manifest.get("report_version")) != ("1.0.0", "1.0.0"):
                raise ProtocolError("historical performance protocol, plan, and report versions differ")
            return {
                "valid": True,
                "semantic_valid": False,
                "type": "performance",
                "performance_protocol_version": protocol_version,
                "assurance": "legacy-hash-only",
                "official": False,
                "rankable": False,
                "authenticity": "unverified",
                "bundle_signature": verification["signature"],
            }
        if protocol_version not in SUPPORTED_PERFORMANCE_PROTOCOL_VERSIONS:
            raise ProtocolError(f"unsupported performance protocol version: {protocol_version}")
        current_manifest, *_ = _performance_comparison_input_snapshot(snapshot, signing_key_env)
        official = current_manifest.get("officially_valid") is True
        return {
            "valid": True,
            "semantic_valid": True,
            "type": "performance",
            "performance_protocol_version": protocol_version,
            "assurance": "approved" if official else "development",
            "official": official,
            "rankable": official,
            "authenticity": "unverified",
            "bundle_signature": verification["signature"],
        }


def _performance_comparison_input(
    run_dir: Path,
    signing_key_env: str,
) -> tuple[
    dict[str, Any],
    dict[tuple[int, str], dict[str, Any]],
    dict[tuple[int, str], str],
    dict[str, Any],
    dict[str, Any],
    str,
]:
    if run_dir.is_symlink() or not run_dir.is_dir():
        raise ProtocolError(f"invalid performance bundle: {run_dir}")
    with tempfile.TemporaryDirectory(prefix="cavada-performance-input-") as temporary:
        snapshot = Path(temporary) / "run"
        shutil.copytree(run_dir, snapshot, symlinks=True, copy_function=_snapshot_copyfile)
        return _performance_comparison_input_snapshot(snapshot, signing_key_env)


def _performance_comparison_input_snapshot(
    run_dir: Path,
    signing_key_env: str,
) -> tuple[
    dict[str, Any],
    dict[tuple[int, str], dict[str, Any]],
    dict[tuple[int, str], str],
    dict[str, Any],
    dict[str, Any],
    str,
]:
    verification = verify_bundle(run_dir, signing_key_env=signing_key_env)
    if not verification["valid"]:
        raise ProtocolError(f"invalid performance bundle: {run_dir}")
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ProtocolError(f"missing or unsafe performance manifest: {run_dir}")
    try:
        manifest = _object(
            json.loads(manifest_path.read_text(encoding="utf-8"), parse_constant=_reject_json_constant),
            "performance manifest",
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"invalid performance manifest: {run_dir}") from exc
    if not _finite_json(manifest):
        raise ProtocolError(f"performance manifest contains non-finite evidence: {run_dir}")
    if not isinstance(manifest.get("run_id"), str) or not manifest["run_id"]:
        raise ProtocolError(f"performance comparison requires a run id: {run_dir}")
    protocol_version = manifest.get("performance_protocol_version")
    if not isinstance(protocol_version, str) or protocol_version not in SUPPORTED_PERFORMANCE_PROTOCOL_VERSIONS:
        raise ProtocolError(f"unsupported performance protocol version: {run_dir}")
    status = manifest.get("status")
    allowed_statuses = {"completed", "completed-with-errors", *({"invalid-loadgen"} if protocol_version == PERFORMANCE_PROTOCOL_VERSION else set())}
    if status not in allowed_statuses:
        raise ProtocolError(f"performance comparison requires a finalized completed run: {run_dir}")
    if (
        not isinstance(manifest.get("official_requested"), bool)
        or not isinstance(manifest.get("officially_valid"), bool)
        or manifest["officially_valid"] and (not manifest["official_requested"] or status != "completed")
        or status == "completed" and manifest["official_requested"] != manifest["officially_valid"]
    ):
        raise ProtocolError(f"performance comparison requires coherent boolean official status: {run_dir}")
    reconciliation = _object(manifest.get("request_reconciliation"), "performance request reconciliation")
    if reconciliation.get("campaign_complete") is not True or reconciliation.get("ledgers_complete") is not True:
        raise ProtocolError(f"performance comparison requires a complete reconciled campaign: {run_dir}")

    protocol_snapshot = run_dir / "protocol_snapshot.md"
    plan_snapshot = run_dir / "plan_snapshot.toml"
    runtime_snapshot = run_dir / "runtime_snapshot.toml"
    workload_snapshot = run_dir / "workload_snapshot.jsonl"
    if not all(path.is_file() and not path.is_symlink() for path in (protocol_snapshot, plan_snapshot, runtime_snapshot, workload_snapshot)):
        raise ProtocolError(f"performance comparison requires immutable input snapshots: {run_dir}")
    if manifest.get("protocol_sha256") != sha256_file(protocol_snapshot):
        raise ProtocolError(f"performance protocol snapshot hash mismatch: {run_dir}")
    canonical_protocol = canonical_performance_protocol_path(protocol_version)
    if protocol_snapshot.read_bytes() != canonical_protocol.read_bytes():
        raise ProtocolError(f"performance protocol snapshot is not canonical for version {protocol_version}: {run_dir}")
    plan = _object(manifest.get("plan"), "performance plan manifest")
    workload = _object(manifest.get("workload"), "performance workload manifest")
    runtime_manifest = _object(manifest.get("runtime"), "performance runtime manifest")
    if plan.get("sha256") != sha256_file(plan_snapshot) or workload.get("sha256") != sha256_file(workload_snapshot):
        raise ProtocolError(f"performance input snapshot hash mismatch: {run_dir}")
    try:
        plan_config = tomllib.loads(plan_snapshot.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"invalid performance plan snapshot: {run_dir}") from exc
    if not _finite_json(plan_config):
        raise ProtocolError(f"performance plan snapshot contains non-finite evidence: {run_dir}")
    expected_plan = {
        "name": plan_config.get("name"),
        "revision": plan_config.get("revision"),
        "sha256": sha256_file(plan_snapshot),
        "profile": plan_config.get("profile"),
        "data_classification": plan_config.get("data_classification"),
        **(
            {
                "open_loop_arrival_distribution": plan_config["execution"]["open_loop_arrival_distribution"],
                "execution_seed": plan_config["execution"]["seed"],
            }
            if "open_loop_arrival_distribution" in plan_config.get("execution", {})
            else {}
        ),
        **({"minimum_p99_observations": plan_config["slo"]["minimum_p99_observations"]} if "minimum_p99_observations" in plan_config.get("slo", {}) else {}),
        **({"load_generator": plan_config["load_generator"]} if plan_config.get("plan_version") == PERFORMANCE_PLAN_VERSION else {}),
    }
    if plan != expected_plan or plan_config.get("plan_version") != manifest.get("plan_version"):
        raise ProtocolError(f"performance plan metadata differs from its snapshot: {run_dir}")
    if plan_config.get("plan_version") == PERFORMANCE_PLAN_VERSION:
        if protocol_version != PERFORMANCE_PROTOCOL_VERSION or manifest.get("report_version") != PERFORMANCE_REPORT_VERSION:
            raise ProtocolError(f"performance v2 protocol, plan, and report versions differ: {run_dir}")
    elif (
        plan_config.get("plan_version") != LEGACY_PERFORMANCE_PLAN_VERSION
        or protocol_version not in {"1.0.0", "1.1.0"}
        or manifest.get("report_version") != LEGACY_PERFORMANCE_REPORT_VERSION
    ):
        raise ProtocolError(f"performance runs require identical protocol, plan, and report versions: {run_dir}")

    runtime = load_performance_runtime(runtime_snapshot)
    expected_runtime = {
        **{key: value for key, value in runtime.config.items() if key not in {"endpoint", "pricing"}},
        "endpoint": _manifest_endpoint(runtime.config["endpoint"]),
        "sha256": runtime.sha256,
        "pricing": runtime.config.get("pricing"),
    }
    if runtime_manifest != expected_runtime:
        raise ProtocolError(f"performance runtime metadata differs from its snapshot: {run_dir}")

    assets = workload.get("assets")
    if not isinstance(assets, dict) or not all(isinstance(name, str) and isinstance(digest, str) for name, digest in assets.items()):
        raise ProtocolError(f"invalid performance workload asset manifest: {run_dir}")
    asset_root = run_dir / "workload_assets"
    if asset_root.is_symlink() or any(path.is_symlink() for path in asset_root.rglob("*")):
        raise ProtocolError(f"unsafe performance workload assets: {run_dir}")
    actual_assets = (
        {path.relative_to(asset_root).as_posix(): sha256_file(path) for path in asset_root.rglob("*") if path.is_file()} if asset_root.is_dir() else {}
    )
    asset_set_sha256 = sha256_bytes(json.dumps(assets, sort_keys=True, separators=(",", ":")).encode())
    if actual_assets != assets or workload.get("asset_set_sha256") != asset_set_sha256:
        raise ProtocolError(f"performance workload asset hash mismatch: {run_dir}")
    try:
        snapshot_workload, snapshot_assets, snapshot_workload_sha256 = _load_workload(
            workload_snapshot,
            asset_root=asset_root,
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"invalid performance workload snapshot: {run_dir}") from exc
    if snapshot_workload_sha256 != workload.get("sha256") or snapshot_assets != assets:
        raise ProtocolError(f"performance workload snapshot differs from its manifest: {run_dir}")
    plan_workload = _object(plan_config.get("workload"), "performance plan workload")
    workload_contract = [("id", "id"), ("revision", "revision"), ("mode", "mode"), ("sha256", "sha256")]
    if "prefix_cache_policy" in plan_workload:
        workload_contract.append(("prefix_cache_policy", "prefix_cache_policy"))
    if any(workload.get(manifest_field) != plan_workload.get(plan_field) for manifest_field, plan_field in workload_contract):
        raise ProtocolError(f"performance workload metadata differs from its plan: {run_dir}")
    if manifest["officially_valid"]:
        if manifest.get("performance_protocol_version") != PERFORMANCE_PROTOCOL_VERSION:
            raise ProtocolError(f"official performance comparison requires the current performance protocol: {run_dir}")
        _require_official_reference_inputs(
            manifest.get("protocol_sha256"),
            plan.get("sha256"),
            workload.get("sha256"),
            assets,
        )
    workload_cases = sum(bool(line.strip()) for line in workload_snapshot.read_text(encoding="utf-8").splitlines())
    if workload.get("cases") != workload_cases or workload_cases < 1:
        raise ProtocolError(f"performance workload case count mismatch: {run_dir}")

    try:
        repetitions = plan_config["execution"]["repetitions"]
        snapshot_plan = PerformancePlan(
            plan_snapshot,
            expected_plan["sha256"],
            plan_config,
            workload_snapshot,
            snapshot_workload,
            str(workload["sha256"]),
            assets,
        )
        expanded = _expand_cells(snapshot_plan, runtime)
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError(f"invalid preregistered performance cells: {run_dir}") from exc
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        raise ProtocolError(f"invalid preregistered performance repetitions: {run_dir}")
    expected: dict[tuple[int, str], dict[str, Any]] = {}
    for block in range(1, repetitions + 1):
        for cell in expanded:
            key = (block, str(cell["cell_key"]))
            if key in expected:
                raise ProtocolError(f"duplicate preregistered performance cell {key}: {run_dir}")
            expected[key] = cell

    rows: dict[tuple[int, str], dict[str, Any]] = {}
    cells_path = run_dir / "cells.jsonl"
    if not cells_path.is_file() or cells_path.is_symlink():
        raise ProtocolError(f"missing or unsafe performance cells: {run_dir}")
    try:
        lines = cells_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ProtocolError(f"missing performance cells: {run_dir}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = _object(
                json.loads(line, parse_constant=_reject_json_constant),
                f"performance cell line {line_number}",
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError(f"invalid performance cell line {line_number}: {run_dir}") from exc
        if not _finite_json(row):
            raise ProtocolError(f"performance cell line {line_number} contains non-finite evidence: {run_dir}")
        observed_block = row.get("block")
        cell_key = row.get("cell_key")
        if not isinstance(observed_block, int) or isinstance(observed_block, bool) or not isinstance(cell_key, str) or not cell_key:
            raise ProtocolError(f"invalid performance cell identity on line {line_number}: {run_dir}")
        key = (observed_block, cell_key)
        if key in rows:
            raise ProtocolError(f"duplicate performance cell {key}: {run_dir}")
        rows[key] = row
    missing = sorted(set(expected) - set(rows))
    extra = sorted(set(rows) - set(expected))
    if missing or extra:
        raise ProtocolError(f"partial performance cells in {run_dir}: missing={missing}, extra={extra}")

    completed: dict[tuple[int, str], dict[str, Any]] = {}
    skipped: dict[tuple[int, str], str] = {}
    identity_fields = ("scenario_id", "arrival", "context_tokens", "output_tokens", "concurrency", "request_rate")
    for key, expected_cell in expected.items():
        row = rows[key]
        if any(row.get(field) != expected_cell.get(field) for field in identity_fields):
            raise ProtocolError(f"performance cell {key} differs from its preregistered definition: {run_dir}")
        skip_reason = expected_cell.get("skip_reason")
        if skip_reason:
            expected_skip = {**expected_cell, "block": key[0], "status": "skipped", "reason": skip_reason}
            if row != expected_skip:
                raise ProtocolError(f"performance cell {key} has invalid skip evidence: {run_dir}")
            skipped[key] = str(skip_reason)
            continue
        cell_status = row.get("status")
        allowed_cell_statuses = {"completed", "completed-with-errors", *({"invalid-loadgen"} if protocol_version == PERFORMANCE_PROTOCOL_VERSION else set())}
        if cell_status not in allowed_cell_statuses:
            raise ProtocolError(f"performance cell {key} is not finalized: {cell_status!r} in {run_dir}")
        observations = row.get("observations")
        successes = row.get("successes")
        errors = row.get("errors")
        if (
            not isinstance(observations, int)
            or isinstance(observations, bool)
            or observations < 1
            or not isinstance(successes, int)
            or isinstance(successes, bool)
            or successes < 0
            or not isinstance(errors, int)
            or isinstance(errors, bool)
            or errors < 0
            or successes + errors != observations
            or (cell_status == "completed" and errors != 0)
            or (cell_status == "completed-with-errors" and errors == 0)
            or (cell_status == "invalid-loadgen" and (row.get("load_generator_valid") is not False or row.get("slo_passed") is not False))
        ):
            raise ProtocolError(f"performance cell {key} is not completed consistently or contains incomplete outcomes: {run_dir}")
        if not isinstance(row.get("slo_passed"), bool):
            raise ProtocolError(f"performance cell {key} has invalid SLO evidence: {run_dir}")
        completed[key] = row

    ledger = reconcile_performance_ledgers(run_dir, manifest, snapshot_plan, expected, rows)
    observations_by_cell: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for observation in ledger["observations"]:
        observations_by_cell.setdefault((int(observation["block"]), str(observation["cell_key"])), []).append(observation)
    seeds: dict[tuple[int, str], int] = {}
    execution = plan_config["execution"]
    for block in range(1, repetitions + 1):
        block_cells = list(expanded)
        if execution.get("randomize_cells", True):
            random.Random(int(execution["seed"]) + block).shuffle(block_cells)  # noqa: S311 -- frozen experimental ordering.
        for cell_index, cell in enumerate(block_cells, 1):
            seeds[(block, str(cell["cell_key"]))] = int(execution["seed"]) + block * 1000 + cell_index
    pricing = runtime.config.get("pricing")
    for key, row in completed.items():
        observations_for_cell = observations_by_cell.get(key, [])
        try:
            recalculated = _cell_metrics_for_protocol(
                observations_for_cell,
                expected[key],
                snapshot_plan,
                _measurement_window(observations_for_cell),
                seeds[key],
                pricing if isinstance(pricing, dict) else None,
                protocol_version,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError(f"performance cell {key} observations are malformed: {run_dir}") from exc
        recalculated["block"] = key[0]
        if row != recalculated:
            raise ProtocolError(f"performance cell {key} metrics differ from immutable observations: {run_dir}")
    expected_counts = {
        "total": len(rows),
        "completed": sum(row.get("status") == "completed" for row in completed.values()),
        "with_errors": sum(row.get("status") == "completed-with-errors" for row in completed.values()),
        **(
            {"invalid_loadgen": sum(row.get("status") == "invalid-loadgen" for row in completed.values())}
            if protocol_version == PERFORMANCE_PROTOCOL_VERSION
            else {}
        ),
        "skipped": len(skipped),
        "slo_passed": sum(row["slo_passed"] is True for row in completed.values()),
        "slo_failed": sum(row["slo_passed"] is False for row in completed.values()),
    }
    if manifest.get("planned_cells") != len(expected) or any(
        _object(manifest.get("cells"), "performance cell summary").get(field) != value for field, value in expected_counts.items()
    ):
        raise ProtocolError(f"performance cell summary does not reconcile: {run_dir}")
    expected_campaign_status = (
        "invalid-loadgen"
        if protocol_version == PERFORMANCE_PROTOCOL_VERSION and any(row.get("status") == "invalid-loadgen" for row in completed.values())
        else "completed-with-errors"
        if any(row.get("status") == "completed-with-errors" for row in completed.values()) or manifest.get("warmups", {}).get("errors", 0)
        else "completed"
    )
    if manifest.get("status") != expected_campaign_status:
        raise ProtocolError(f"performance campaign status differs from its cell outcomes: {run_dir}")
    if not completed:
        raise ProtocolError(f"performance comparison rejects an all-skipped campaign: {run_dir}")
    summary_path = run_dir / "summary.json"
    try:
        source_summary = _object(
            json.loads(summary_path.read_text(encoding="utf-8"), parse_constant=_reject_json_constant),
            "performance summary",
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError(f"invalid performance summary: {run_dir}") from exc
    if source_summary != _campaign_summary(manifest, list(rows.values()), ledger["observations"]):
        raise ProtocolError(f"performance aggregate summary differs from immutable observations: {run_dir}")

    evidence_metadata = manifest.get("system_evidence")
    evidence_snapshot = run_dir / "system_evidence_snapshot.json"
    if evidence_metadata is None:
        if evidence_snapshot.exists() or evidence_snapshot.is_symlink():
            raise ProtocolError(f"unbound performance system evidence: {run_dir}")
        if manifest["officially_valid"]:
            raise ProtocolError(f"official performance run is missing system evidence: {run_dir}")
    else:
        evidence_metadata = _object(evidence_metadata, "performance system evidence metadata")
        if not evidence_snapshot.is_file() or evidence_snapshot.is_symlink():
            raise ProtocolError(f"missing performance system evidence snapshot: {run_dir}")
        evidence = load_system_evidence(evidence_snapshot)
        _cross_check_system_evidence(runtime, evidence)
        expected_evidence_metadata = {
            "configuration_id": evidence["configuration_id"],
            "sha256": sha256_file(evidence_snapshot),
            "projection": evidence["projection"],
            "collected_at": evidence["collected_at"],
        }
        if evidence_metadata != expected_evidence_metadata:
            raise ProtocolError(f"performance system evidence metadata differs from its snapshot: {run_dir}")
        if manifest.get("officially_valid") is True:
            if evidence["projection"] != "restricted" or set(evidence["unavailable"]) != _structural_unavailable(runtime.config, evidence):
                raise ProtocolError(f"official performance run has incomplete system evidence: {run_dir}")
            try:
                collected_at = datetime.fromisoformat(str(evidence["collected_at"]).replace("Z", "+00:00"))
                started_at = datetime.fromisoformat(str(manifest["started_at"]).replace("Z", "+00:00"))
            except (KeyError, ValueError) as exc:
                raise ProtocolError(f"official performance run has invalid evidence timestamps: {run_dir}") from exc
            if collected_at.tzinfo is None or started_at.tzinfo is None or collected_at > started_at or started_at - collected_at > timedelta(hours=24):
                raise ProtocolError(f"official performance run has stale or future system evidence: {run_dir}")
            source = _object(manifest.get("source"), "performance source evidence")
            client = evidence["load_generator"]["client"]
            if client["name"] != "cavadalabs-evals" or client["revision"] != source.get("commit"):
                raise ProtocolError(f"official performance run has unbound load-generator client evidence: {run_dir}")
    execution_record_metadata = manifest.get("execution_record")
    execution_record_snapshot = run_dir / "execution_record_snapshot.json"
    if execution_record_metadata is None:
        if execution_record_snapshot.exists() or execution_record_snapshot.is_symlink():
            raise ProtocolError(f"unbound performance execution record: {run_dir}")
        if manifest["officially_valid"]:
            raise ProtocolError(f"official performance run is missing its execution record: {run_dir}")
    else:
        if not isinstance(execution_record_metadata, dict):
            raise ProtocolError(f"performance execution record metadata is malformed: {run_dir}")
        try:
            started_at = datetime.fromisoformat(str(manifest.get("started_at")).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ProtocolError(f"performance run has invalid started_at: {run_dir}") from exc
        expected_execution_record, _ = load_performance_execution_record(
            execution_record_snapshot,
            protocol_sha256=str(manifest.get("protocol_sha256")),
            plan_sha256=str(plan.get("sha256")),
            workload_sha256=str(workload.get("sha256")),
            runtime_sha256=str(runtime_manifest.get("sha256")),
            system_evidence_sha256=sha256_file(evidence_snapshot) if evidence_metadata is not None else None,
            before=started_at,
        )
        if execution_record_metadata != expected_execution_record:
            raise ProtocolError(f"performance execution record metadata differs from its snapshot: {run_dir}")
    engagement_metadata = manifest.get("engagement")
    engagement_snapshot = run_dir / "engagement_snapshot.json"
    if engagement_metadata is None:
        if engagement_snapshot.exists() or engagement_snapshot.is_symlink():
            raise ProtocolError(f"unbound performance engagement: {run_dir}")
        if manifest["officially_valid"]:
            raise ProtocolError(f"official performance run is missing its engagement: {run_dir}")
    else:
        if not isinstance(engagement_metadata, dict) or not isinstance(execution_record_metadata, dict) or evidence_metadata is None:
            raise ProtocolError(f"performance engagement metadata is malformed or unbound: {run_dir}")
        try:
            started_at = datetime.fromisoformat(str(manifest.get("started_at")).replace("Z", "+00:00"))
            finished_at = datetime.fromisoformat(str(manifest.get("finished_at")).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ProtocolError(f"performance run has invalid engagement timestamps: {run_dir}") from exc
        expected_engagement, _ = load_performance_engagement(
            engagement_snapshot,
            protocol_sha256=str(manifest.get("protocol_sha256")),
            plan_sha256=str(plan.get("sha256")),
            workload_sha256=str(workload.get("sha256")),
            runtime_sha256=str(runtime_manifest.get("sha256")),
            system_evidence_sha256=sha256_file(evidence_snapshot),
            configuration_id=str(evidence_metadata.get("configuration_id")),
            execution_record=execution_record_metadata,
            at=started_at,
        )
        if engagement_metadata != expected_engagement:
            raise ProtocolError(f"performance engagement metadata differs from its snapshot: {run_dir}")
        engagement_expiry = datetime.fromisoformat(str(expected_engagement["expires_at"]).replace("Z", "+00:00"))
        if finished_at >= engagement_expiry:
            raise ProtocolError(f"performance engagement expired before execution completed: {run_dir}")
    if manifest["officially_valid"]:
        mutable_revisions = [field for field in ("model_revision", "engine_revision") if not _content_addressed_revision(runtime.config[field])]
        source = _object(manifest.get("source"), "performance source evidence")
        source_commit = str(source.get("commit", ""))
        if (
            mutable_revisions
            or skipped
            or source.get("dirty") is not False
            or len(source_commit) not in {40, 64}
            or any(c not in "0123456789abcdef" for c in source_commit)
        ):
            raise ProtocolError(f"official performance run does not satisfy immutable source, runtime, and cell requirements: {run_dir}")
    configuration = {
        "runtime": expected_runtime,
        "system_evidence": evidence_metadata,
        "source": _object(manifest.get("source"), "performance source evidence"),
        "environment": _object(manifest.get("environment"), "performance environment evidence"),
    }
    return manifest, completed, skipped, configuration, ledger, sha256_file(run_dir / "bundle.json")


def _write_performance_comparison_reports(output: Path, result: dict[str, Any]) -> None:
    rows_value = result.get("rows")
    excluded_value = result.get("excluded_cells")
    runs_value = result.get("runs")
    differences_value = result.get("configuration_differences")
    ratios_value = result.get("observed_throughput_ratio_vs_baseline_across_blocks")
    slo_failed_value = result.get("slo_failed_cells")
    if not all(
        isinstance(value, list) and all(isinstance(item, dict) for item in value)
        for value in (rows_value, excluded_value, runs_value, differences_value, ratios_value, slo_failed_value)
    ):
        raise ProtocolError("performance comparison report projection is malformed")
    rows = cast(list[dict[str, Any]], rows_value)
    excluded = cast(list[dict[str, Any]], excluded_value)
    runs = cast(list[dict[str, Any]], runs_value)
    differences = cast(list[dict[str, Any]], differences_value)
    ratios = cast(list[dict[str, Any]], ratios_value)
    slo_failed = cast(list[dict[str, Any]], slo_failed_value)

    csv_fields = [
        "block",
        "cell_key",
        "runtime_id",
        "record_type",
        "status",
        "exclusion_reason",
        "successes",
        "observations",
        "ttft_p95_ms",
        "e2e_p99_ms",
        "tpot_p50_ms",
        "output_tokens_total",
        "throughput_window_seconds",
        "output_tokens_per_second",
        "goodput_requests",
        "measurement_window_seconds",
        "goodput_requests_per_second",
        "error_rate",
        "slo_passed",
        "estimated_cost",
        "cost_currency",
        "observed_block_throughput_ratio_vs_baseline",
        "throughput_ratio_unavailable_reason",
    ]

    def exclusion_reason(row: dict[str, Any]) -> str:
        reasons = row.get("reasons")
        details = [str(item) for item in reasons] if isinstance(reasons, list) else []
        if row.get("reason"):
            details.append(str(row["reason"]))
        return " · ".join(details)

    with (output / "comparison.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows({field: row.get(field) for field in csv_fields} for row in rows)
        writer.writerows(
            {
                **{field: row.get(field) for field in csv_fields},
                "exclusion_reason": exclusion_reason(row),
            }
            for row in excluded
        )

    labels = [str(run.get("runtime_id")) for run in runs]
    shared_keys = sorted({(int(row["block"]), str(row["cell_key"])) for row in rows})
    if shared_keys:
        series = [
            (
                label,
                [
                    float(
                        next(
                            row["output_tokens_per_second"]
                            for row in rows
                            if row["runtime_id"] == label and row["block"] == block and row["cell_key"] == cell_key
                        )
                    )
                    for block, cell_key in shared_keys
                ],
            )
            for label in labels
        ]
        _line_svg(
            "Output token throughput comparison",
            series,
            output / "throughput_comparison.svg",
            "Output tokens/s",
            x_labels=[f"B{block} · {cell_key}" for block, cell_key in shared_keys],
            x_label="Block / cell",
        )
        chart_html = '<figure><img src="throughput_comparison.svg" alt="Output token throughput by stable block and cell identifier"><figcaption>Only exact shared completed cells are plotted.</figcaption></figure>'
    else:
        chart_html = "<p>No exact shared completed cells are available for a throughput chart.</p>"

    plan = _object(result.get("plan"), "performance comparison plan")
    workload = _object(result.get("workload"), "performance comparison workload")

    def nested(run: dict[str, Any], section: str, key: str, default: str = "unknown") -> Any:
        value = run.get(section)
        return value.get(key, default) if isinstance(value, dict) else default

    def cost(row: dict[str, Any]) -> str:
        value = row.get("estimated_cost")
        return f"{float(value):.6f} {row.get('cost_currency') or ''}" if value is not None else "N/A"

    run_rows = "".join(
        "<tr>"
        f"<th scope=\"row\">{html.escape(str(run.get('runtime_id', 'unknown')))}</th>"
        f"<td>{html.escape(str(run.get('run_id', 'unknown')))}</td><td>{html.escape(str(run.get('status', 'unknown')))}</td>"
        f"<td>{html.escape(str(nested(run, 'runtime', 'engine')))}</td>"
        f"<td><code>{html.escape(str(nested(run, 'runtime', 'model_revision')))}</code></td>"
        f"<td>{html.escape(str(nested(run, 'runtime', 'gpu_model')))}</td>"
        f"<td>{html.escape(str(nested(run, 'system_evidence', 'configuration_id', 'not recorded')))}</td>"
        f"<td>{html.escape(str(run.get('officially_valid', False)))}</td><td><code>{html.escape(str(run.get('bundle_sha256', 'unknown')))}</code></td></tr>"
        for run in runs
    )
    measurement_rows = "".join(
        "<tr>"
        f"<td>{row['block']}</td><th scope=\"row\"><code>{html.escape(str(row['cell_key']))}</code></th><td>{html.escape(str(row['runtime_id']))}</td>"
        f"<td>{row['successes']}/{row['observations']}</td><td>{float(row['ttft_p95_ms']):.2f}</td><td>{float(row['e2e_p99_ms']):.2f}</td>"
        f"<td>{float(row['output_tokens_per_second']):.3f} ({float(row['output_tokens_total']):g}/{float(row['throughput_window_seconds']):g} s)</td>"
        f"<td>{float(row['goodput_requests_per_second']):.3f} ({float(row['goodput_requests']):g}/{float(row['measurement_window_seconds']):g} s)</td>"
        f"<td>{float(row['error_rate']):.4f}</td><td>{'PASS' if row['slo_passed'] is True else 'FAIL'}</td>"
        f"<td>{html.escape(cost(row))}</td>"
        f"<td>{html.escape(str(row.get('observed_block_throughput_ratio_vs_baseline') if row.get('observed_block_throughput_ratio_vs_baseline') is not None else 'N/A'))}</td></tr>"
        for row in rows
    ) or '<tr><td colspan="12">No exact shared completed cells were compared.</td></tr>'
    excluded_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(row.get('record_type', 'unknown')))}</td><td>{html.escape(str(row.get('runtime_id', 'unknown')))}</td>"
        f"<td>{html.escape(str(row.get('block', 'N/A')))}</td><th scope=\"row\"><code>{html.escape(str(row.get('cell_key', 'unknown')))}</code></th>"
        f"<td>{html.escape(str(row.get('status', 'unknown')))}</td><td>{html.escape(exclusion_reason(row))}</td></tr>"
        for row in excluded
    ) or '<tr><td colspan="6">No cells were excluded.</td></tr>'
    difference_rows = "".join(
        f"<tr><th scope=\"row\"><code>{html.escape(str(row.get('field', 'unknown')))}</code></th><td>{html.escape(json.dumps(row.get('values'), ensure_ascii=False, sort_keys=True))}</td></tr>"
        for row in differences
    ) or '<tr><td colspan="2">No material configuration differences were recorded.</td></tr>'
    slo_failed_rows = "".join(
        f"<tr><td>{html.escape(str(row.get('runtime_id', 'unknown')))}</td><td>{html.escape(str(row.get('block', 'N/A')))}</td>"
        f"<th scope=\"row\"><code>{html.escape(str(row.get('cell_key', 'unknown')))}</code></th><td>{html.escape(str(row.get('reason', 'unknown')))}</td></tr>"
        for row in slo_failed
    ) or '<tr><td colspan="4">No compared cells failed their final SLO.</td></tr>'
    ratio_rows = "".join(
        f"<tr><th scope=\"row\"><code>{html.escape(str(row.get('cell_key', 'unknown')))}</code></th><td>{html.escape(str(row.get('runtime_id', 'unknown')))}</td><td>{row.get('n', 0)}</td>"
        f"<td>{html.escape(str(row.get('median') if row.get('median') is not None else 'N/A'))}</td><td>{html.escape(str(row.get('min') if row.get('min') is not None else 'N/A'))}</td>"
        f"<td>{html.escape(str(row.get('max') if row.get('max') is not None else 'N/A'))}</td><td>{html.escape(str(row.get('unavailable_reason') or '—'))}</td></tr>"
        for row in ratios
    ) or '<tr><td colspan="7">No across-block ratios were available.</td></tr>'
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; base-uri 'none'"><title>CavadaLabs Performance Comparison</title><style>body{{font:15px/1.5 system-ui;max-width:1480px;margin:36px auto;padding:0 24px;color:#172033}}table{{border-collapse:collapse;width:100%;margin:12px 0 28px}}th,td{{border:1px solid #bbc5d2;padding:7px;text-align:left;vertical-align:top}}thead th{{background:#e9f0f8}}code{{word-break:break-all}}figure{{margin:16px 0}}img{{width:100%;height:auto}}.notice{{border-left:4px solid #8a5600;padding:10px 14px;background:#fff7df}}</style></head><body><header><h1>CavadaLabs Performance Comparison</h1><p>Baseline: <strong>{html.escape(str(result.get('baseline', 'unknown')))}</strong>. Shared compared cells: {result.get('shared_cells', 0)}. Excluded cells: {len(excluded)}. Final-SLO failures: {len(slo_failed)}. Eligible for exact-cell comparison: {'yes' if result.get('comparison_eligible') is True else 'no'}.</p></header><main><section><h2>Common evidence</h2><dl><dt>Protocol / report</dt><dd>{html.escape(str(result.get('performance_protocol_version', 'unknown')))} / {html.escape(str(result.get('report_version', 'unknown')))}</dd><dt>Protocol SHA-256</dt><dd><code>{html.escape(str(result.get('protocol_sha256', 'unknown')))}</code></dd><dt>Plan</dt><dd>{html.escape(str(plan.get('name', 'unknown')))}@{html.escape(str(plan.get('revision', 'unknown')))} · <code>{html.escape(str(plan.get('sha256', 'unknown')))}</code></dd><dt>Workload</dt><dd>{html.escape(str(workload.get('id', 'unknown')))}@{html.escape(str(workload.get('revision', 'unknown')))} · <code>{html.escape(str(workload.get('sha256', 'unknown')))}</code></dd><dt>Source binding</dt><dd>{html.escape(str(result.get('source_binding', 'not recorded')))}</dd></dl></section><section><h2>Runs and evaluated systems</h2><table><thead><tr><th>Runtime</th><th>Run</th><th>Status</th><th>Engine</th><th>Model revision</th><th>Hardware</th><th>Conditions</th><th>Official</th><th>Source bundle SHA-256</th></tr></thead><tbody>{run_rows}</tbody></table></section><section><h2>Compared cells</h2><p>N/A means the field is not applicable or its evidence is unavailable. Rates show numerator / denominator in seconds.</p><table><thead><tr><th>Block</th><th>Cell</th><th>Runtime</th><th>Success/N</th><th>TTFT p95 ms</th><th>E2E p99 ms</th><th>Output tok/s</th><th>Good req/s</th><th>Error rate</th><th>Final SLO</th><th>Cost</th><th>Observed throughput ratio</th></tr></thead><tbody>{measurement_rows}</tbody></table>{chart_html}</section><section><h2>Excluded cells ({len(excluded)})</h2><table><thead><tr><th>Category</th><th>Runtime</th><th>Block</th><th>Cell</th><th>Status</th><th>Reason</th></tr></thead><tbody>{excluded_rows}</tbody></table></section><section><h2>Final-SLO failures ({len(slo_failed)})</h2><table><thead><tr><th>Runtime</th><th>Block</th><th>Cell</th><th>Reason</th></tr></thead><tbody>{slo_failed_rows}</tbody></table></section><section><h2>Configuration differences ({len(differences)})</h2><table><thead><tr><th>Field</th><th>Values by runtime</th></tr></thead><tbody>{difference_rows}</tbody></table></section><section><h2>Across-block observed ratios</h2><table><thead><tr><th>Cell</th><th>Runtime</th><th>N</th><th>Median</th><th>Min</th><th>Max</th><th>Unavailable reason</th></tr></thead><tbody>{ratio_rows}</tbody></table></section><section><h2>Limitations</h2><p class="notice">{html.escape(str(result.get('limitations', 'No limitations recorded.')))}</p></section></main></body></html>\n"""
    atomic_text(output / "report.html", document)

    pdf_lines = [
        "# COMPARISON SUMMARY",
        f"Baseline: {result.get('baseline', 'unknown')}",
        f"Shared compared cells: {result.get('shared_cells', 0)}; excluded: {len(excluded)}; final-SLO failures: {len(slo_failed)}; eligible: {result.get('comparison_eligible')}",
        f"Protocol/report: {result.get('performance_protocol_version', 'unknown')} / {result.get('report_version', 'unknown')}",
        f"Protocol SHA-256: {result.get('protocol_sha256', 'unknown')}",
        f"Plan: {plan.get('name', 'unknown')}@{plan.get('revision', 'unknown')}; SHA-256: {plan.get('sha256', 'unknown')}",
        f"Workload: {workload.get('id', 'unknown')}@{workload.get('revision', 'unknown')}; SHA-256: {workload.get('sha256', 'unknown')}",
        f"Source binding: {result.get('source_binding', 'not recorded')}",
        "",
        "# RUNS AND EVALUATED SYSTEMS",
    ]
    pdf_lines.extend(
        f"{run.get('runtime_id')}: run {run.get('run_id')}; status {run.get('status')}; engine {nested(run, 'runtime', 'engine')}; model {nested(run, 'runtime', 'model_revision')}; hardware {nested(run, 'runtime', 'gpu_model')}; conditions {nested(run, 'system_evidence', 'configuration_id', 'not recorded')}; bundle {run.get('bundle_sha256')}"
        for run in runs
    )
    pdf_lines.extend(("", "# COMPARED CELLS", "N/A means not applicable or unavailable. Rates show numerator / denominator in seconds."))
    pdf_lines.extend(
        f"B{row['block']} {row['cell_key']} / {row['runtime_id']}: successes {row['successes']}/{row['observations']}; TTFT p95 {float(row['ttft_p95_ms']):.2f} ms; E2E p99 {float(row['e2e_p99_ms']):.2f} ms; output {float(row['output_tokens_per_second']):.3f} tok/s ({float(row['output_tokens_total']):g}/{float(row['throughput_window_seconds']):g} s); goodput {float(row['goodput_requests_per_second']):.3f} req/s ({float(row['goodput_requests']):g}/{float(row['measurement_window_seconds']):g} s); SLO {'PASS' if row['slo_passed'] is True else 'FAIL'}"
        for row in rows
    )
    if not rows:
        pdf_lines.append("No exact shared completed cells were compared.")
    pdf_lines.extend(("", "# EXCLUDED CELLS"))
    pdf_lines.extend(
        f"{row.get('record_type')} / {row.get('runtime_id')} / B{row.get('block')} {row.get('cell_key')}: {row.get('status')}; {exclusion_reason(row)}"
        for row in excluded
    )
    if not excluded:
        pdf_lines.append("No cells were excluded.")
    pdf_lines.extend(("", "# FINAL-SLO FAILURES"))
    pdf_lines.extend(
        f"{row.get('runtime_id')} / B{row.get('block')} {row.get('cell_key')}: {row.get('reason')}" for row in slo_failed
    )
    if not slo_failed:
        pdf_lines.append("No compared cells failed their final SLO.")
    pdf_lines.extend(("", "# CONFIGURATION DIFFERENCES"))
    pdf_lines.extend(f"{row.get('field')}: {json.dumps(row.get('values'), ensure_ascii=False, sort_keys=True)}" for row in differences)
    if not differences:
        pdf_lines.append("No material configuration differences were recorded.")
    pdf_lines.extend(("", "# LIMITATIONS", str(result.get("limitations", "No limitations recorded."))))
    _pdf(
        output / "report.pdf",
        "CavadaLabs Performance Comparison",
        pdf_lines,
        report_version=str(result.get("report_version", "unknown")),
    )


def verify_performance_comparison(
    comparison_dir: Path,
    *,
    source_run_dirs: list[Path] | None = None,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
) -> dict[str, Any]:
    source = Path(comparison_dir)
    if source.is_symlink() or not source.is_dir():
        raise ProtocolError("performance comparison must be a real directory")
    with tempfile.TemporaryDirectory(prefix="cavada-comparison-verify-") as temporary:
        snapshot = Path(temporary) / "comparison"
        shutil.copytree(source, snapshot, symlinks=True, copy_function=_snapshot_copyfile)
        return _verify_performance_comparison_snapshot(
            snapshot,
            source_run_dirs=source_run_dirs,
            signing_key_env=signing_key_env,
        )


def _verify_performance_comparison_snapshot(
    comparison_dir: Path,
    *,
    source_run_dirs: list[Path] | None,
    signing_key_env: str,
) -> dict[str, Any]:
    verification = verify_bundle(comparison_dir, signing_key_env=signing_key_env)
    if not verification["valid"]:
        raise ProtocolError("performance comparison bundle integrity verification failed")
    try:
        result = _object(
            json.loads((comparison_dir / "comparison.json").read_text(encoding="utf-8"), parse_constant=_reject_json_constant),
            "performance comparison",
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError("performance comparison JSON is malformed") from exc
    if not _finite_json(result):
        raise ProtocolError("performance comparison contains non-finite evidence")
    version_contract = (
        result.get("performance_protocol_version"),
        result.get("plan_version"),
        result.get("report_version"),
    )
    if version_contract not in {
        ("1.0.0", LEGACY_PERFORMANCE_PLAN_VERSION, LEGACY_PERFORMANCE_REPORT_VERSION),
        ("1.1.0", LEGACY_PERFORMANCE_PLAN_VERSION, LEGACY_PERFORMANCE_REPORT_VERSION),
        (PERFORMANCE_PROTOCOL_VERSION, PERFORMANCE_PLAN_VERSION, PERFORMANCE_REPORT_VERSION),
    }:
        raise ProtocolError("performance comparison version contract is unsupported")
    if result.get("source_binding") != _PERFORMANCE_COMPARISON_SOURCE_BINDING:
        raise ProtocolError("performance comparison source binding is malformed")

    def digest(value: Any) -> bool:
        return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)

    plan = _object(result.get("plan"), "performance comparison plan")
    workload = _object(result.get("workload"), "performance comparison workload")
    if not digest(result.get("protocol_sha256")) or not digest(plan.get("sha256")) or not digest(workload.get("sha256")):
        raise ProtocolError("performance comparison common evidence is malformed")
    runs = result.get("runs")
    rows = result.get("rows")
    excluded = result.get("excluded_cells")
    if (
        not isinstance(runs, list)
        or len(runs) < 2
        or not all(isinstance(run, dict) for run in runs)
        or not isinstance(rows, list)
        or not all(isinstance(row, dict) for row in rows)
        or not isinstance(excluded, list)
        or not all(isinstance(row, dict) for row in excluded)
    ):
        raise ProtocolError("performance comparison population is malformed")
    labels = [run.get("runtime_id") for run in runs]
    if any(not isinstance(label, str) or not label for label in labels) or len(set(labels)) != len(labels) or result.get("baseline") not in labels:
        raise ProtocolError("performance comparison run identities are malformed")
    if any(not digest(run.get("bundle_sha256")) for run in runs):
        raise ProtocolError("performance comparison source bundle binding is malformed")
    category_values = [result.get(name) for name in ("skipped_cells", "errored_cells", "invalid_loadgen_cells", "non_shared_cells")]
    if any(not isinstance(value, list) or not all(isinstance(item, dict) for item in value) for value in category_values):
        raise ProtocolError("performance comparison excluded-cell categories are malformed")
    skipped_cells, errored_cells, invalid_loadgen_cells, non_shared_cells = cast(list[list[dict[str, Any]]], category_values)
    expected_excluded = [
        *({**item, "record_type": "skipped", "status": "skipped"} for item in skipped_cells),
        *({**item, "record_type": "completed-with-errors"} for item in errored_cells),
        *({**item, "record_type": "invalid-loadgen"} for item in invalid_loadgen_cells),
        *({**item, "record_type": "non-shared"} for item in non_shared_cells),
    ]
    if excluded != expected_excluded:
        raise ProtocolError("performance comparison excluded-cell projection does not reconcile")
    compared_identities = [(row.get("runtime_id"), row.get("block"), row.get("cell_key")) for row in rows]
    excluded_identities = [(row.get("runtime_id"), row.get("block"), row.get("cell_key")) for row in excluded]
    if (
        len(set(compared_identities)) != len(compared_identities)
        or len(set(excluded_identities)) != len(excluded_identities)
        or set(compared_identities) & set(excluded_identities)
        or any(row.get("record_type") != "compared" or row.get("status") != "completed" or row.get("runtime_id") not in labels for row in rows)
        or any(row.get("runtime_id") not in labels for row in excluded)
    ):
        raise ProtocolError("performance comparison cell accounting is malformed")
    shared_keys = {(row.get("block"), row.get("cell_key")) for row in rows}
    if any({row.get("runtime_id") for row in rows if (row.get("block"), row.get("cell_key")) == key} != set(labels) for key in shared_keys):
        raise ProtocolError("performance comparison shared-cell population does not reconcile")
    if result.get("shared_cells") != len(shared_keys) or result.get("comparison_eligible") is not bool(shared_keys):
        raise ProtocolError("performance comparison eligibility does not reconcile")
    expected_counts = dict(sorted(Counter(str(row["record_type"]) for row in excluded).items()))
    if result.get("exclusion_counts") != expected_counts:
        raise ProtocolError("performance comparison exclusion counts do not reconcile")
    expected_slo_failed = [
        {"runtime_id": row["runtime_id"], "block": row["block"], "cell_key": row["cell_key"], "reason": "completed cell failed its final SLO"}
        for row in rows
        if row.get("slo_passed") is False
    ]
    if result.get("slo_failed_cells") != expected_slo_failed:
        raise ProtocolError("performance comparison SLO-failed population does not reconcile")
    differences = result.get("configuration_differences")
    if not isinstance(differences, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("values"), dict) or set(item["values"]) != set(labels) for item in differences
    ):
        raise ProtocolError("performance comparison configuration differences are malformed")

    expected_files = {
        "bundle.json",
        "checksums.txt",
        "comparison.csv",
        "comparison.json",
        "report.html",
        "report.pdf",
        *({"throughput_comparison.svg"} if rows else set()),
        *({"signature.json"} if (comparison_dir / "signature.json").is_file() else set()),
    }
    actual_files = {path.relative_to(comparison_dir).as_posix() for path in comparison_dir.rglob("*") if path.is_file()}
    if actual_files != expected_files:
        raise ProtocolError("performance comparison contains unexpected or missing artifacts")

    with tempfile.TemporaryDirectory(prefix="cavada-comparison-report-") as temporary:
        reconstructed = Path(temporary)
        try:
            _write_performance_comparison_reports(reconstructed, result)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("performance comparison report projection is malformed") from exc
        names = ["comparison.csv", "report.html", "report.pdf", *( ["throughput_comparison.svg"] if rows else [] )]
        for name in names:
            actual = comparison_dir / name
            expected = reconstructed / name
            if not actual.is_file() or actual.is_symlink() or actual.read_bytes() != expected.read_bytes():
                raise ProtocolError(f"performance comparison presentation differs from comparison.json: {name}")
        if bool(rows) != (comparison_dir / "throughput_comparison.svg").is_file():
            raise ProtocolError("performance comparison chart presence differs from comparison.json")
    if not source_run_dirs:
        return {
            "valid": True,
            "semantic_valid": False,
            "type": "performance-comparison",
            "authenticity": "recorded-source-hashes-only",
            "source_revalidation": "not performed; pass the exact source run directories in recorded order",
        }
    with tempfile.TemporaryDirectory(prefix="cavada-comparison-source-") as temporary:
        reconstructed = Path(temporary) / "comparison"
        expected_result = compare_performance_runs(
            source_run_dirs,
            reconstructed,
            signing_key_env=signing_key_env,
            _verify_semantics=False,
        )
        if result["runs"] != expected_result["runs"]:
            raise ProtocolError("performance comparison source runs do not match recorded bundle hashes or order")
        for name in ("comparison.json", "comparison.csv", "report.html", "report.pdf", "throughput_comparison.svg"):
            actual = comparison_dir / name
            expected = reconstructed / name
            if actual.is_file() != expected.is_file() or actual.is_file() and actual.read_bytes() != expected.read_bytes():
                raise ProtocolError(f"performance comparison differs from exact source runs: {name}")
    return {
        "valid": True,
        "semantic_valid": True,
        "type": "performance-comparison",
        "authenticity": "verified-source-bundles",
        "source_revalidation": "complete",
    }


def compare_performance_runs(
    run_dirs: list[Path],
    output: Path,
    *,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    _verify_semantics: bool = True,
) -> dict[str, Any]:
    require_mutable_output_root(output)
    if len(run_dirs) < 2:
        raise ProtocolError("performance comparison requires at least two runs")
    if output.exists():
        raise ProtocolError(f"refusing to overwrite performance comparison: {output}")
    if any(output.resolve().is_relative_to(run_dir.resolve()) for run_dir in run_dirs):
        raise ProtocolError("performance comparison output must be outside every input run")
    manifests: list[dict[str, Any]] = []
    cells_by_run: list[dict[tuple[int, str], dict[str, Any]]] = []
    skipped_by_run: list[dict[tuple[int, str], str]] = []
    configurations: list[dict[str, Any]] = []
    bundle_hashes: list[str] = []
    for run_dir in run_dirs:
        manifest, cells, skipped, configuration, _, bundle_sha256 = _performance_comparison_input(run_dir, signing_key_env)
        manifests.append(manifest)
        cells_by_run.append(cells)
        skipped_by_run.append(skipped)
        configurations.append(configuration)
        bundle_hashes.append(bundle_sha256)
    versions = {(item.get("performance_protocol_version"), item.get("plan_version"), item.get("report_version")) for item in manifests}
    if len(versions) != 1:
        raise ProtocolError("performance runs require identical protocol, plan, and report versions")
    version_contract = next(iter(versions))
    if version_contract not in {
        ("1.0.0", LEGACY_PERFORMANCE_PLAN_VERSION, LEGACY_PERFORMANCE_REPORT_VERSION),
        ("1.1.0", LEGACY_PERFORMANCE_PLAN_VERSION, LEGACY_PERFORMANCE_REPORT_VERSION),
        (PERFORMANCE_PROTOCOL_VERSION, PERFORMANCE_PLAN_VERSION, PERFORMANCE_REPORT_VERSION),
    }:
        raise ProtocolError(f"unsupported performance comparison versions: {version_contract}")
    if len({item["protocol_sha256"] for item in manifests}) != 1:
        raise ProtocolError("performance runs require identical performance protocol snapshots")
    compatibility = {
        (
            item["plan"]["sha256"],
            item["workload"]["sha256"],
            item["workload"]["asset_set_sha256"],
            json.dumps(item["workload"]["assets"], sort_keys=True, separators=(",", ":")),
        )
        for item in manifests
    }
    if len(compatibility) != 1:
        raise ProtocolError("performance runs require identical plan and workload hashes")
    labels = [str(manifest["runtime"]["id"]) for manifest in manifests]
    if len(set(labels)) != len(labels):
        raise ProtocolError("performance comparison requires unique runtime ids")
    comparable_by_run = [{key: row for key, row in cells.items() if row.get("status") == "completed"} for cells in cells_by_run]
    shared = sorted(set.intersection(*(set(cells) for cells in comparable_by_run)))
    skipped_cells = [
        {"runtime_id": labels[index], "block": block, "cell_key": cell_key, "reason": reason}
        for index, skipped in enumerate(skipped_by_run)
        for (block, cell_key), reason in sorted(skipped.items())
    ]
    shared_set = set(shared)

    def diagnostic(row: dict[str, Any], key: str, percentile_key: str | None = None) -> Any:
        value = row.get(key)
        return value.get(percentile_key) if percentile_key is not None and isinstance(value, dict) else value

    errored_cells = [
        {
            "runtime_id": labels[index],
            "block": block,
            "cell_key": cell_key,
            "status": "completed-with-errors",
            "successes": row["successes"],
            "errors": row["errors"],
            "error_types": row["error_types"],
            "ttft_p95_ms": diagnostic(row, "ttft_ms", "p95"),
            "e2e_p99_ms": diagnostic(row, "e2e_ms", "p99"),
            "output_tokens_per_second": diagnostic(row, "output_tokens_per_second"),
            "serving_slo_passed": row.get("serving_slo_passed"),
            "reason": "error outcomes are preserved but excluded from cross-runtime ratios",
        }
        for index, cells in enumerate(cells_by_run)
        for (block, cell_key), row in sorted(cells.items())
        if row.get("status") == "completed-with-errors"
    ]
    invalid_loadgen_cells = [
        {
            "runtime_id": labels[index],
            "block": block,
            "cell_key": cell_key,
            "status": "invalid-loadgen",
            "reasons": row["load_generator_invalid_reasons"],
            "successes": row["successes"],
            "errors": row["errors"],
            "ttft_p95_ms": diagnostic(row, "ttft_ms", "p95"),
            "e2e_p99_ms": diagnostic(row, "e2e_ms", "p99"),
            "output_tokens_per_second": diagnostic(row, "output_tokens_per_second"),
            "serving_slo_passed": row.get("serving_slo_passed"),
            "reason": "load-generator evidence is preserved but excluded from serving-system comparisons",
        }
        for index, cells in enumerate(cells_by_run)
        for (block, cell_key), row in sorted(cells.items())
        if row.get("status") == "invalid-loadgen"
    ]
    non_shared_cells = [
        {
            "runtime_id": labels[index],
            "block": block,
            "cell_key": cell_key,
            "status": row["status"],
            "reason": "not completed by every compared runtime",
        }
        for index, cells in enumerate(comparable_by_run)
        for (block, cell_key), row in sorted(cells.items())
        if (block, cell_key) not in shared_set
    ]
    excluded_cells = [
        *({**item, "record_type": "skipped", "status": "skipped"} for item in skipped_cells),
        *({**item, "record_type": "completed-with-errors"} for item in errored_cells),
        *({**item, "record_type": "invalid-loadgen"} for item in invalid_loadgen_cells),
        *({**item, "record_type": "non-shared"} for item in non_shared_cells),
    ]
    model_units_comparable = len({(manifest["runtime"]["model_artifact_revision"], manifest["runtime"]["model_revision"]) for manifest in manifests}) == 1
    ratio_unavailable_reason = (
        None if model_units_comparable else "output-token ratios require identical model artifact and revision; no verified iso-token tokenizer pin is recorded"
    )

    def number(value: Any, label: str, *, positive: bool = False, maximum: float | None = None) -> float:
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
            raise ProtocolError(f"invalid performance comparison metric {label}")
        result = float(value)
        if result < 0 or positive and result <= 0 or maximum is not None and result > maximum:
            raise ProtocolError(f"invalid performance comparison metric {label}")
        return result

    comparison_rows: list[dict[str, Any]] = []
    for key in shared:
        baseline = comparable_by_run[0][key]
        baseline_throughput = number(baseline.get("output_tokens_per_second"), f"{labels[0]} {key} output_tokens_per_second", positive=True)
        for index, cell_map in enumerate(comparable_by_run):
            row = cell_map[key]
            ttft = _object(row.get("ttft_ms"), f"{labels[index]} {key} ttft_ms")
            e2e = _object(row.get("e2e_ms"), f"{labels[index]} {key} e2e_ms")
            tpot = _object(row.get("tpot_ms"), f"{labels[index]} {key} tpot_ms")
            throughput = number(row.get("output_tokens_per_second"), f"{labels[index]} {key} output_tokens_per_second", positive=True)
            runtime_pricing = manifests[index]["runtime"].get("pricing")
            estimated_cost = row.get("estimated_cost")
            if isinstance(runtime_pricing, dict):
                estimated_cost = number(estimated_cost, f"{labels[index]} {key} estimated_cost")
            elif estimated_cost is not None:
                raise ProtocolError(f"unpriced performance cell reports a cost: {labels[index]} {key}")
            comparison_rows.append(
                {
                    "block": key[0],
                    "cell_key": key[1],
                    "runtime_id": labels[index],
                    "record_type": "compared",
                    "status": "completed",
                    "successes": row["successes"],
                    "observations": row["observations"],
                    "ttft_p95_ms": number(ttft.get("p95"), f"{labels[index]} {key} ttft_ms.p95"),
                    "e2e_p99_ms": number(e2e.get("p99"), f"{labels[index]} {key} e2e_ms.p99"),
                    "tpot_p50_ms": number(tpot.get("p50"), f"{labels[index]} {key} tpot_ms.p50"),
                    "output_tokens_per_second": throughput,
                    "output_tokens_total": number(row.get("output_tokens_total"), f"{labels[index]} {key} output_tokens_total"),
                    "throughput_window_seconds": number(
                        row.get("throughput_window_seconds", row.get("measurement_window_seconds")),
                        f"{labels[index]} {key} throughput_window_seconds",
                        positive=True,
                    ),
                    "goodput_requests_per_second": number(row.get("goodput_requests_per_second"), f"{labels[index]} {key} goodput_requests_per_second"),
                    "goodput_requests": number(row.get("goodput_requests"), f"{labels[index]} {key} goodput_requests"),
                    "measurement_window_seconds": number(
                        row.get("measurement_window_seconds"), f"{labels[index]} {key} measurement_window_seconds", positive=True
                    ),
                    "error_rate": number(row.get("error_rate"), f"{labels[index]} {key} error_rate", maximum=1),
                    "slo_passed": row["slo_passed"],
                    "estimated_cost": estimated_cost,
                    "cost_currency": runtime_pricing.get("currency") if isinstance(runtime_pricing, dict) else None,
                    "observed_block_throughput_ratio_vs_baseline": throughput / baseline_throughput if model_units_comparable else None,
                    "throughput_ratio_unavailable_reason": ratio_unavailable_reason,
                }
            )
    across_block_ratios: list[dict[str, Any]] = []
    for cell_key in sorted({key[1] for key in shared}):
        for runtime_id in labels:
            values = [
                float(row["observed_block_throughput_ratio_vs_baseline"])
                for row in comparison_rows
                if row["cell_key"] == cell_key and row["runtime_id"] == runtime_id and row["observed_block_throughput_ratio_vs_baseline"] is not None
            ]
            across_block_ratios.append(
                {
                    "cell_key": cell_key,
                    "runtime_id": runtime_id,
                    "n": len(values),
                    "median": percentile(values, 0.5) if values else None,
                    "min": min(values) if values else None,
                    "max": max(values) if values else None,
                    "unavailable_reason": ratio_unavailable_reason,
                }
            )
    material_configurations: list[dict[str, Any]] = []
    for configuration in configurations:
        runtime_configuration = {key: value for key, value in configuration["runtime"].items() if key not in {"id", "sha256", "api_key_env", "runtime_version"}}
        evidence = configuration["system_evidence"]
        material_configurations.append(
            {
                **{f"runtime.{key}": value for key, value in runtime_configuration.items()},
                "system_evidence.configuration_id": evidence.get("configuration_id") if isinstance(evidence, dict) else None,
                "source": configuration["source"],
                "environment": configuration["environment"],
            }
        )
    difference_fields = sorted(set().union(*(configuration.keys() for configuration in material_configurations)))
    configuration_differences = [
        {"field": field, "values": {label: material_configurations[index].get(field) for index, label in enumerate(labels)}}
        for field in difference_fields
        if len({json.dumps(configuration.get(field), sort_keys=True, separators=(",", ":")) for configuration in material_configurations}) > 1
    ]
    slo_failed_cells = [
        {"runtime_id": row["runtime_id"], "block": row["block"], "cell_key": row["cell_key"], "reason": "completed cell failed its final SLO"}
        for row in comparison_rows
        if row["slo_passed"] is False
    ]
    result: dict[str, Any] = {
        "performance_protocol_version": version_contract[0],
        "protocol_sha256": manifests[0]["protocol_sha256"],
        "plan_version": version_contract[1],
        "report_version": version_contract[2],
        "baseline": labels[0],
        "plan": manifests[0]["plan"],
        "workload": manifests[0]["workload"],
        "comparison_eligible": bool(shared),
        "source_binding": _PERFORMANCE_COMPARISON_SOURCE_BINDING,
        "runs": [
            {
                "run_id": manifest["run_id"],
                "runtime_id": manifest["runtime"]["id"],
                "bundle_sha256": bundle_hashes[index],
                "runtime": configurations[index]["runtime"],
                "system_evidence": configurations[index]["system_evidence"],
                "source": configurations[index]["source"],
                "environment": configurations[index]["environment"],
                "official_requested": manifest.get("official_requested"),
                "officially_valid": manifest.get("officially_valid"),
                "status": manifest.get("status"),
                "warmups": manifest.get("warmups"),
            }
            for index, manifest in enumerate(manifests)
        ],
        "shared_cells": len(shared),
        "skipped_cells": skipped_cells,
        "errored_cells": errored_cells,
        "invalid_loadgen_cells": invalid_loadgen_cells,
        "non_shared_cells": non_shared_cells,
        "excluded_cells": excluded_cells,
        "slo_failed_cells": slo_failed_cells,
        "exclusion_counts": dict(sorted(Counter(str(row["record_type"]) for row in excluded_cells).items())),
        "observed_throughput_ratio_vs_baseline_across_blocks": across_block_ratios,
        "configuration_differences": configuration_differences,
        "rows": comparison_rows,
        "limitations": "Only exact shared completed block-cells from identical plan and workload hashes are compared; every skipped and non-shared block-cell is reported, and observed ratios are not causal claims.",
    }
    output.mkdir(parents=True)
    atomic_json(output / "comparison.json", result)
    _write_performance_comparison_reports(output, result)
    write_bundle(output, signing_key_env=signing_key_env)
    if not verify_bundle(output, signing_key_env=signing_key_env)["valid"]:
        raise ProtocolError("performance comparison bundle verification failed")
    if _verify_semantics:
        verify_performance_comparison(output, source_run_dirs=run_dirs, signing_key_env=signing_key_env)
    return result
