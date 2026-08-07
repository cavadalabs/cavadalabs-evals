from __future__ import annotations

import csv
import html
import json
import math
import os
import random
import shutil
import threading
import time
import tomllib
import urllib.parse
import uuid
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .pdf_report import render_pdf, require_pdf_support
from .protocol import (
    ProtocolError,
    append_jsonl,
    atomic_json,
    atomic_text,
    contains_secret_like,
    environment_evidence,
    git_evidence,
    sha256_bytes,
    sha256_file,
)
from .runner import _completion_url, _manifest_endpoint, _post_openai_stream, _secure_endpoint
from .statistics import distribution, percentile

PERFORMANCE_PROTOCOL_VERSION = "1.0.1"
PERFORMANCE_PLAN_VERSION = "1.0.0"
PERFORMANCE_RUNTIME_VERSION = "1.0.0"
PERFORMANCE_REPORT_VERSION = "1.1.0"
MAX_WORKLOAD_BYTES = 32 * 1024 * 1024
MAX_PROMPT_BYTES = 16 * 1024 * 1024


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


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a table/object")
    return value


def _reject_unknown(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ProtocolError(f"{label} contains unknown fields: {unknown}")


def _semantic_version(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 3 and all(part.isdigit() and (part == "0" or not part.startswith("0")) for part in parts)


def _numbers(value: Any, label: str, *, integer: bool = False, positive: bool = True) -> list[float | int]:
    if not isinstance(value, list) or not value:
        raise ProtocolError(f"{label} must be a non-empty array")
    expected = int if integer else (int, float)
    if not all(isinstance(item, expected) and not isinstance(item, bool) for item in value):
        raise ProtocolError(f"{label} contains a non-numeric value")
    result = [int(item) if integer else float(item) for item in value]
    if positive and any(item <= 0 for item in result):
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


def _load_workload(path: Path) -> tuple[tuple[dict[str, Any], ...], dict[str, str], str]:
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
            asset = _safe_asset(path.parent, row["prompt_file"], row["prompt_sha256"])
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
                len(row["repeat_text"].encode()) * row["repeat_count"]
                + len(str(row.get("prefix", "")).encode())
                + len(str(row.get("suffix", "")).encode())
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
    if config.get("plan_version") != PERFORMANCE_PLAN_VERSION or config.get("profile") != "llm-serving-v1":
        raise ProtocolError("performance plan requires plan_version=1.0.0 and profile=llm-serving-v1")
    _reject_unknown(
        config,
        {"plan_version", "revision", "name", "description", "profile", "data_classification", "workload", "generation", "execution", "limits", "slo", "scenarios"},
        "performance plan",
    )
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
    _reject_unknown(workload_config, {"id", "revision", "path", "sha256", "mode", "input_token_tolerance_fraction"}, "workload")
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
        {"repetitions", "warmup_requests", "measured_requests", "open_loop_duration_seconds", "bootstrap_samples", "seed", "randomize_cells", "cooldown_seconds", "max_in_flight"},
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
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ProtocolError(f"execution.{field} must be non-negative")
    if not isinstance(execution.get("randomize_cells"), bool):
        raise ProtocolError("execution.randomize_cells must be boolean")

    limits = _object(config.get("limits"), "limits")
    _reject_unknown(
        limits,
        {"timeout_seconds", "max_requests", "max_total_tokens", "max_campaign_seconds", "max_context_tokens", "max_output_tokens"},
        "limits",
    )
    required_limits = ("timeout_seconds", "max_requests", "max_total_tokens", "max_campaign_seconds", "max_context_tokens", "max_output_tokens")
    if any(not isinstance(limits.get(field), (int, float)) or isinstance(limits[field], bool) or limits[field] <= 0 for field in required_limits):
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
            not isinstance(scenario["duration_seconds"], (int, float)) or isinstance(scenario["duration_seconds"], bool) or scenario["duration_seconds"] <= 0
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
        {"ttft_p95_ms", "e2e_p99_ms", "goodput_ttft_ms", "goodput_e2e_ms", "maximum_error_rate", "minimum_output_tokens_fraction"},
        "slo",
    )
    for field in ("ttft_p95_ms", "e2e_p99_ms", "goodput_ttft_ms", "goodput_e2e_ms"):
        if not isinstance(slo.get(field), (int, float)) or isinstance(slo[field], bool) or slo[field] <= 0:
            raise ProtocolError(f"slo.{field} must be positive")
    for field in ("maximum_error_rate", "minimum_output_tokens_fraction"):
        if not isinstance(slo.get(field), (int, float)) or isinstance(slo[field], bool) or not 0 <= float(slo[field]) <= 1:
            raise ProtocolError(f"slo.{field} must be from 0 to 1")
    tolerance = workload_config.get("input_token_tolerance_fraction", 0.05)
    if not isinstance(tolerance, (int, float)) or isinstance(tolerance, bool) or not 0 <= float(tolerance) <= 1:
        raise ProtocolError("workload.input_token_tolerance_fraction must be from 0 to 1")
    return PerformancePlan(resolved, sha256_bytes(source), config, workload_path, workload, workload_hash, assets)


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
    if config.get("runtime_version") != PERFORMANCE_RUNTIME_VERSION:
        raise ProtocolError("performance runtime requires runtime_version=1.0.0")
    _reject_unknown(
        config,
        {
            "runtime_version", "id", "endpoint", "request_model", "expected_model", "model_revision", "api_key_env", "engine",
            "engine_revision", "model_artifact_revision", "dtype", "quantization", "gpu_count", "gpu_model", "tensor_parallel",
            "max_context_tokens", "container_image_digest", "launch_command_sanitized", "pricing",
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
    if not isinstance(container_digest, str) or container_digest and (
        not container_digest.startswith("sha256:")
        or len(container_digest) != 71
        or any(character not in "0123456789abcdefABCDEF" for character in container_digest[7:])
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
            if not isinstance(pricing.get(field), (int, float)) or isinstance(pricing[field], bool) or pricing[field] < 0:
                raise ProtocolError(f"runtime pricing {field} must be non-negative")
    return PerformanceRuntime(resolved, sha256_bytes(source), config)


def performance_plan_summary(plan: PerformancePlan, runtime: PerformanceRuntime | None = None) -> dict[str, Any]:
    cells = _expand_cells(plan, runtime)
    planned_contexts = sorted({int(cell["context_tokens"]) for cell in cells})
    planned_outputs = sorted({int(cell["output_tokens"]) for cell in cells})
    requests_per_repetition = sum(
        int(cell["warmup_requests"])
        + (int(cell["measured_requests"]) if cell["arrival"] == "closed-loop" else max(1, math.ceil(cell["request_rate"] * cell["duration_seconds"])))
        for cell in cells
        if not cell.get("skip_reason")
    )
    result = {
        "performance_protocol_version": PERFORMANCE_PROTOCOL_VERSION,
        "plan": plan.config["name"],
        "plan_revision": plan.config["revision"],
        "plan_sha256": plan.sha256,
        "workload_sha256": plan.workload_sha256,
        "workload_assets": plan.workload_assets,
        "workload_cases": len(plan.workload),
        "contexts": planned_contexts,
        "output_tokens": planned_outputs,
        "available_workload_contexts": sorted({int(row["context_tokens"]) for row in plan.workload}),
        "scenarios": len(plan.config["scenarios"]),
        "cells_per_repetition": len(cells),
        "repetitions": plan.config["execution"]["repetitions"],
        "planned_requests": requests_per_repetition * int(plan.config["execution"]["repetitions"]),
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


def _cell_key(cell: dict[str, Any]) -> str:
    load = f"c{cell['concurrency']}" if cell.get("concurrency") is not None else f"rps{cell['request_rate']:g}"
    return f"{cell['scenario_id']}__ctx{cell['context_tokens']}__out{cell['output_tokens']}__{load}"


def _prompt(row: dict[str, Any], workload_root: Path) -> str:
    if "prompt" in row:
        return str(row["prompt"])
    if "prompt_file" in row:
        return (workload_root / str(row["prompt_file"])).read_text(encoding="utf-8")
    return str(row.get("prefix", "")) + str(row["repeat_text"]) * int(row["repeat_count"]) + str(row.get("suffix", ""))


def _messages(row: dict[str, Any], workload_root: Path) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    if row.get("system"):
        result.append({"role": "system", "content": str(row["system"])})
    result.append({"role": "user", "content": _prompt(row, workload_root)})
    return result


def _decode_metrics(raw: dict[str, Any], transport: dict[str, Any], output_tokens: float) -> dict[str, Any]:
    decode_ms = max(0.0, float(transport["total_ms"]) - float(transport["ttft_ms"]))
    provider: dict[str, Any] = {}
    for event in reversed(raw.get("stream_events", [])):
        if isinstance(event, dict) and isinstance(event.get("timings"), dict):
            provider = event["timings"]
            break
    value = provider.get("predicted_ms")
    provider_ms = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0 else None
    valid = provider_ms is None or decode_ms >= provider_ms * 0.5
    return {
        "tpot_ms": decode_ms / (output_tokens - 1) if valid and output_tokens > 1 else None,
        "decode_tokens_per_second": (output_tokens - 1) / (decode_ms / 1000) if valid and output_tokens > 1 and decode_ms > 0 else None,
        "stream_timing_valid": valid,
        "provider_decode_ms": provider_ms,
        "provider_decode_tokens_per_second": provider.get("predicted_per_second"),
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
    x_labels: tuple[str, ...] = (),
) -> None:
    all_values = [value for _, values in series for value in values]
    maximum = max(all_values + [1.0])
    longest = max([len(values) for _, values in series] + [1])
    left, right, bottom, plot_height = 120, 880, 350, 280
    height = 410 + 22 * max(1, len(series))
    colors = ("#1769aa", "#c23b22", "#2e7d32", "#6a1b9a", "#8d6e00", "#455a64")
    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="1000" height="{height}" viewBox="0 0 1000 {height}">',
        f"<title id=\"title\">{html.escape(title)}</title><desc id=\"desc\">{html.escape(y_label)} by comparable performance cell; exact values are tabulated.</desc>",
        f'<rect width="100%" height="100%" fill="white"/><line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" stroke="#172033"/><line x1="{left}" y1="50" x2="{left}" y2="{bottom}" stroke="#172033"/>',
    ]
    for tick in range(5):
        y = bottom - tick * 70
        value = maximum * tick / 4
        elements.append(
            f'<line x1="{left}" y1="{y}" x2="{right}" y2="{y}" stroke="#dce3ec"/>'
            f'<text x="{left - 8}" y="{y + 4}" text-anchor="end" font-family="system-ui" font-size="12">{value:.2f}</text>'
        )
    for index, (label, values) in enumerate(series):
        coordinates = [
            (500.0 if longest == 1 else left + position * (right - left) / (longest - 1), bottom - value * plot_height / maximum, value)
            for position, value in enumerate(values)
        ]
        points = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in coordinates)
        color = colors[index % len(colors)]
        elements.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2"/><text x="{left}" y="{410 + index * 22}" fill="{color}" font-family="system-ui">{html.escape(label)}</text>')
        elements.extend(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{color}"/>'
            f'<text x="{x:.1f}" y="{max(24, y - 10):.1f}" text-anchor="middle" font-family="system-ui" font-size="12">{value:.2f}</text>'
            for x, y, value in coordinates
        )
    if x_labels:
        elements.extend(
            f'<text x="{500 if len(x_labels) == 1 else left + position * (right - left) / (len(x_labels) - 1):.1f}" y="375" text-anchor="middle" font-family="system-ui" font-size="12">{html.escape(label)}</text>'
            for position, label in enumerate(x_labels)
        )
    elements.append(f'<text x="22" y="200" transform="rotate(-90 22 200)" text-anchor="middle" font-family="system-ui">{html.escape(y_label)}</text></svg>')
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
    input_tokens = sum(float(row["input_tokens"]) for row in successes)
    output_tokens = sum(float(row["output_tokens"]) for row in successes)
    total_cost: float | None = None
    if isinstance(pricing, dict):
        total_cost = input_tokens * float(pricing["input_per_million"]) / 1_000_000 + output_tokens * float(pricing["output_per_million"]) / 1_000_000
    error_rate = (len(observations) - len(successes)) / len(observations) if observations else 1.0
    ttft = _metric_summary([float(row["ttft_ms"]) for row in successes], bootstrap, seed)
    e2e = _metric_summary([float(row["e2e_ms"]) for row in successes], bootstrap, seed + 2)
    gates = {
        "ttft_p95": bool(successes) and float(ttft["p95"]) <= float(slo["ttft_p95_ms"]),
        "e2e_p99": bool(successes) and float(e2e["p99"]) <= float(slo["e2e_p99_ms"]),
        "error_rate": error_rate <= float(slo["maximum_error_rate"]),
    }
    warnings = ["fewer than 1000 observations; p99 is weakly resolved"] if len(observations) < 1000 else []
    invalid_stream_timings = sum(row.get("stream_timing_valid") is False for row in successes)
    if invalid_stream_timings:
        warnings.append(f"{invalid_stream_timings} client SSE decode timings conflicted with provider timing and were omitted")
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
        "tpot_ms": _metric_summary([float(row["tpot_ms"]) for row in successes if row.get("tpot_ms") is not None], bootstrap, seed + 4),
        "decode_tokens_per_second": _metric_summary(
            [float(row["decode_tokens_per_second"]) for row in successes if row.get("decode_tokens_per_second") is not None], bootstrap, seed + 6
        ),
        "client_queue_ms": _metric_summary([float(row["client_queue_ms"]) for row in observations], bootstrap, seed + 8),
        "input_tokens": distribution(float(row["input_tokens"]) for row in successes),
        "actual_output_tokens": distribution(float(row["output_tokens"]) for row in successes),
        "warnings": warnings,
    }


def run_performance_campaign(
    plan: PerformancePlan,
    runtime: PerformanceRuntime,
    *,
    repo_root: Path,
    output_root: Path | None = None,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    signing_key_id: str = "",
) -> Path:
    require_pdf_support()
    config = plan.config
    runtime_config = runtime.config
    api_key = os.getenv(str(runtime_config["api_key_env"]), "")
    if api_key and not _secure_endpoint(str(runtime_config["endpoint"])):
        raise ProtocolError("refusing to send an API key over non-local HTTP; use HTTPS or a loopback endpoint")
    cells = _expand_cells(plan, runtime)
    execution = config["execution"]
    total_planned = 0
    for cell in cells:
        if cell.get("skip_reason"):
            continue
        measured = cell["measured_requests"] if cell["arrival"] == "closed-loop" else math.ceil(cell["request_rate"] * cell["duration_seconds"])
        total_planned += (cell["warmup_requests"] + measured) * int(execution["repetitions"])
    if total_planned > int(config["limits"]["max_requests"]):
        raise ProtocolError(f"performance campaign plans {total_planned} requests; limit is {config['limits']['max_requests']}")
    root = (output_root or repo_root / "runs" / "performance" / str(config["name"])).resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{runtime_config['id']}_{uuid.uuid4().hex[:10]}"
    run_dir = root / run_id
    run_dir.mkdir(mode=0o700)
    (run_dir / "figures").mkdir(mode=0o700)
    started_at = datetime.now(timezone.utc)
    plan_hash = plan.sha256
    runtime_hash = runtime.sha256
    workload_asset_set_hash = sha256_bytes(json.dumps(plan.workload_assets, sort_keys=True, separators=(",", ":")).encode())
    manifest: dict[str, Any] = {
        "performance_protocol_version": PERFORMANCE_PROTOCOL_VERSION,
        "plan_version": PERFORMANCE_PLAN_VERSION,
        "report_version": PERFORMANCE_REPORT_VERSION,
        "run_id": run_id,
        "status": "running",
        "started_at": started_at.isoformat(),
        "plan": {
            "name": config["name"],
            "revision": config["revision"],
            "sha256": plan_hash,
            "profile": config["profile"],
            "data_classification": config["data_classification"],
        },
        "workload": {
            "id": config["workload"]["id"],
            "revision": config["workload"]["revision"],
            "mode": config["workload"]["mode"],
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
        "source": git_evidence(repo_root),
        "environment": environment_evidence(repo_root),
        "planned_requests": total_planned,
        "planned_cells": len(cells) * int(execution["repetitions"]),
    }
    atomic_json(run_dir / "manifest.json", manifest)
    shutil.copy2(plan.path, run_dir / "plan_snapshot.toml")
    shutil.copy2(runtime.path, run_dir / "runtime_snapshot.toml")
    shutil.copy2(plan.workload_path, run_dir / "workload_snapshot.jsonl")
    for relative in plan.workload_assets:
        destination = run_dir / "workload_assets" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(plan.workload_path.parent / relative, destination)
    snapshots = {
        run_dir / "plan_snapshot.toml": plan_hash,
        run_dir / "runtime_snapshot.toml": runtime_hash,
        run_dir / "workload_snapshot.jsonl": plan.workload_sha256,
        **{run_dir / "workload_assets" / relative: digest for relative, digest in plan.workload_assets.items()},
    }
    if any(sha256_file(path) != digest for path, digest in snapshots.items()):
        raise ProtocolError("performance inputs changed after validation; no network request was sent")
    for name in ("requests.jsonl", "responses.jsonl", "observations.jsonl", "warmups.jsonl", "cells.jsonl", "events.jsonl"):
        (run_dir / name).touch(mode=0o600)

    write_lock = threading.Lock()
    budget_lock = threading.Lock()
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
        with write_lock:
            append_jsonl(run_dir / name, value)

    def event(kind: str, **fields: Any) -> None:
        record("events.jsonl", {"timestamp": datetime.now(timezone.utc).isoformat(), "event": kind, **fields})

    def one_request(cell: dict[str, Any], row: dict[str, Any], index: int, block: int, phase: str, scheduled: float) -> dict[str, Any]:
        nonlocal request_count, total_tokens, total_input_tokens, total_output_tokens, token_budget_exhausted
        started = time.perf_counter()
        queue_ms = max(0.0, (started - scheduled) * 1000) if cell["arrival"] == "open-loop" else 0.0
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
        }
        with budget_lock:
            if request_count >= int(config["limits"]["max_requests"]):
                return {**base, "status": "error", "error_type": "request-budget", "error": "request limit exceeded"}
            if time.perf_counter() - campaign_started > float(config["limits"]["max_campaign_seconds"]):
                return {**base, "status": "error", "error_type": "time-budget", "error": "campaign time limit exceeded"}
            if token_budget_exhausted:
                return {**base, "status": "error", "error_type": "token-budget", "error": "total token limit already exceeded"}
            request_count += 1
        payload = {
            **config["generation"].get("request_defaults", {}),
            "model": runtime_config["request_model"],
            "messages": _messages(row, run_dir / "workload_assets"),
            "temperature": 0,
            "max_tokens": cell["output_tokens"],
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        request_id = uuid.uuid4().hex
        record(
            "requests.jsonl",
            {
                **base,
                "request_id": request_id,
                "payload_sha256": sha256_bytes(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()),
            },
        )
        try:
            raw, transport = _post_openai_stream(
                _completion_url(str(runtime_config["endpoint"])),
                payload,
                api_key,
                float(config["limits"]["timeout_seconds"]),
                request_id=request_id,
            )
            record("responses.jsonl", {**base, "request_id": request_id, "response": raw, "transport": transport})
            reported = str(raw.get("model") or "")
            usage = raw.get("usage")
            if not isinstance(usage, dict) or not all(
                isinstance(usage.get(field), int) and not isinstance(usage.get(field), bool)
                for field in ("prompt_tokens", "completion_tokens")
            ):
                raise ProtocolError("streaming response did not report prompt_tokens and completion_tokens")
            input_tokens = float(usage["prompt_tokens"])
            output_tokens = float(usage["completion_tokens"])
            if input_tokens < 1 or output_tokens < 1:
                raise ProtocolError("streaming response reported non-positive token usage")
            with budget_lock:
                total_tokens += input_tokens + output_tokens
                total_input_tokens += input_tokens
                total_output_tokens += output_tokens
                over_token_budget = total_tokens > float(config["limits"]["max_total_tokens"])
                token_budget_exhausted = token_budget_exhausted or over_token_budget
            if reported != runtime_config["expected_model"]:
                raise ProtocolError(f"model identity mismatch: expected {runtime_config['expected_model']!r}, got {reported!r}")
            tolerance = max(2.0, float(row["context_tokens"]) * float(config["workload"].get("input_token_tolerance_fraction", 0.05)))
            input_match = abs(input_tokens - float(row["context_tokens"])) <= tolerance
            if config["workload"]["mode"] == "iso-token" and not input_match:
                raise ProtocolError(f"input token mismatch: declared {row['context_tokens']}, observed {input_tokens:g}, tolerance {tolerance:g}")
            ttft = float(transport["ttft_ms"])
            e2e = float(transport["total_ms"])
            decode = _decode_metrics(raw, transport, output_tokens)
            observation = {
                **base,
                "status": "success",
                "request_id": request_id,
                "reported_model": reported,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "input_token_match": input_match,
                "ttft_ms": ttft,
                "e2e_ms": e2e,
                **decode,
                "headers_ms": transport.get("headers_ms"),
                "inter_chunk_ms": transport.get("inter_chunk_ms"),
                "request_bytes": transport.get("request_bytes"),
                "response_bytes": transport.get("response_bytes"),
            }
            if over_token_budget:
                observation = {**observation, "status": "error", "error_type": "token-budget", "error": "total token limit exceeded"}
            return observation
        except Exception as exc:  # noqa: BLE001 -- transport failures are evidence, not process failures.
            return {**base, "request_id": request_id, "status": "error", "error_type": type(exc).__name__, "error": str(exc)}

    def execute_batch(cell: dict[str, Any], count: int, block: int, phase: str, *, open_loop: bool) -> tuple[list[dict[str, Any]], float]:
        rows = rows_by_context[int(cell["context_tokens"])]
        started = time.perf_counter()
        results: list[dict[str, Any]] = []
        workers = int(execution["max_in_flight"] if open_loop or cell.get("concurrency") is None else cell["concurrency"])
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cavada-perf") as executor:
            futures: list[Future[dict[str, Any]]] = []
            for index in range(count):
                scheduled = started + (index / float(cell["request_rate"]) if open_loop else 0)
                if open_loop:
                    delay = scheduled - time.perf_counter()
                    if delay > 0:
                        time.sleep(delay)
                futures.append(executor.submit(one_request, cell, rows[index % len(rows)], index + 1, block, phase, scheduled))
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                record("warmups.jsonl" if phase == "warmup" else "observations.jsonl", result)
        return results, time.perf_counter() - started

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
                count = (
                    int(cell["measured_requests"])
                    if cell["arrival"] == "closed-loop"
                    else max(1, math.ceil(float(cell["request_rate"]) * float(cell["duration_seconds"])))
                )
                observations, window = execute_batch(cell, count, block, "measured", open_loop=cell["arrival"] == "open-loop")
                runtime_pricing = runtime_config.get("pricing")
                metrics = _cell_metrics(
                    observations,
                    cell,
                    plan,
                    window,
                    int(execution["seed"]) + block * 1000 + cell_index,
                    runtime_pricing if isinstance(runtime_pricing, dict) else None,
                )
                metrics["block"] = block
                record("cells.jsonl", metrics)
                all_cell_metrics.append(metrics)
                all_observations.extend(observations)
                event("cell_finished", block=block, cell_key=cell["cell_key"], status=metrics["status"])
                cooldown = float(execution["cooldown_seconds"])
                if cooldown and cell_index < len(block_cells):
                    time.sleep(cooldown)
    except KeyboardInterrupt:
        manifest["status"] = "cancelled"
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        atomic_json(run_dir / "manifest.json", manifest)
        raise

    completed_cells = [cell for cell in all_cell_metrics if cell.get("status") != "skipped"]
    manifest["status"] = "completed" if completed_cells and all(cell.get("status") == "completed" for cell in completed_cells) else "completed-with-errors"
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
        "skipped": sum(cell.get("status") == "skipped" for cell in all_cell_metrics),
        "slo_passed": sum(cell.get("slo_passed") is True for cell in all_cell_metrics),
        "slo_failed": sum(cell.get("slo_passed") is False for cell in all_cell_metrics),
    }
    manifest["warmups"] = {
        "total": len(all_warmups),
        "successes": sum(row.get("status") == "success" for row in all_warmups),
        "errors": sum(row.get("status") != "success" for row in all_warmups),
    }
    summary = _campaign_summary(manifest, all_cell_metrics, all_observations)
    atomic_json(run_dir / "summary.json", summary)
    _write_cells_csv(run_dir / "cells.csv", all_cell_metrics)
    _performance_reports(run_dir, manifest, summary, all_cell_metrics)
    manifest["artifacts"] = sorted(path.relative_to(run_dir).as_posix() for path in run_dir.rglob("*") if path.is_file())
    atomic_json(run_dir / "manifest.json", manifest)
    write_bundle(run_dir, signing_key_env=signing_key_env, key_id=signing_key_id)
    verification = verify_bundle(run_dir, signing_key_env=signing_key_env, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("performance bundle verification failed")
    return run_dir


def _campaign_summary(manifest: dict[str, Any], cells: list[dict[str, Any]], observations: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [cell for cell in cells if cell.get("status") in {"completed", "completed-with-errors"}]
    best = max(completed, key=lambda row: float(row["goodput_requests_per_second"]), default=None)
    return {
        "performance_protocol_version": PERFORMANCE_PROTOCOL_VERSION,
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


def _write_cells_csv(path: Path, cells: list[dict[str, Any]]) -> None:
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
            writer.writerow(
                {
                    **{field: cell.get(field) for field in fields},
                    "ttft_p50_ms": (cell.get("ttft_ms") or {}).get("p50"),
                    "ttft_p95_ms": (cell.get("ttft_ms") or {}).get("p95"),
                    "ttft_p99_ms": (cell.get("ttft_ms") or {}).get("p99"),
                    "e2e_p50_ms": (cell.get("e2e_ms") or {}).get("p50"),
                    "e2e_p95_ms": (cell.get("e2e_ms") or {}).get("p95"),
                    "e2e_p99_ms": (cell.get("e2e_ms") or {}).get("p99"),
                    "tpot_p50_ms": (cell.get("tpot_ms") or {}).get("p50"),
                    "decode_tps_p50": (cell.get("decode_tokens_per_second") or {}).get("p50"),
                }
            )


def _performance_reports(run_dir: Path, manifest: dict[str, Any], summary: dict[str, Any], cells: list[dict[str, Any]]) -> None:
    completed = [cell for cell in cells if cell.get("status") in {"completed", "completed-with-errors"}]
    ordered = sorted(completed, key=lambda row: (row["block"], row["cell_key"]))
    figures = run_dir / "figures"
    pricing = manifest["runtime"].get("pricing")
    cost_heading = f"Cost ({pricing['currency']})" if isinstance(pricing, dict) else "Cost"
    observations = sum(int(row.get("observations", 0)) for row in ordered)
    errors = sum(int(row.get("errors", 0)) for row in ordered)
    best = max(ordered, key=lambda row: float(row.get("goodput_requests_per_second", 0)), default={})
    distribution_keys = ("min", "p50", "p90", "p95", "max")
    for filename, title, key, label in (
        ("ttft.svg", "TTFT p95 by performance cell", "ttft_ms", "TTFT p95 (ms)"),
        ("e2e.svg", "End-to-end p99 by performance cell", "e2e_ms", "E2E p99 (ms)"),
    ):
        if len(ordered) == 1:
            values = [float((ordered[0].get(key) or {}).get(name, 0)) for name in distribution_keys]
            _line_svg(title.replace("p95 by performance cell", "distribution").replace("p99 by performance cell", "distribution"), [(manifest["runtime"]["id"], values)], figures / filename, label.replace("p95 ", "").replace("p99 ", ""), x_labels=distribution_keys)
        else:
            percentile_key = "p95" if key == "ttft_ms" else "p99"
            _line_svg(title, [(manifest["runtime"]["id"], [float(row[key][percentile_key]) for row in ordered])], figures / filename, label)
    decode_values = (
        [float((ordered[0].get("decode_tokens_per_second") or {}).get(name, 0)) for name in distribution_keys]
        if len(ordered) == 1
        else [float((row.get("decode_tokens_per_second") or {}).get("p50", 0)) for row in ordered]
    )
    _line_svg(
        "Decode rate distribution" if len(ordered) == 1 else "Decode rate p50 by performance cell",
        [(manifest["runtime"]["id"], decode_values)],
        figures / "decode.svg",
        "Decode tokens/s",
        x_labels=distribution_keys if len(ordered) == 1 else (),
    )
    _line_svg(
        "Output token throughput by performance cell",
        [(manifest["runtime"]["id"], [float(row["output_tokens_per_second"]) for row in ordered])],
        figures / "throughput.svg",
        "Output tokens/s",
    )
    _line_svg(
        "SLO goodput by performance cell",
        [(manifest["runtime"]["id"], [float(row["goodput_requests_per_second"]) for row in ordered])],
        figures / "goodput.svg",
        "Good requests/s",
    )
    table_rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(value))}</td>"
            for value in (
                row["block"],
                row["cell_key"],
                row["status"],
                row.get("slo_passed", False),
                row.get("observations", 0),
                f"{float((row.get('ttft_ms') or {}).get('p95', 0)):.2f}",
                f"{float((row.get('e2e_ms') or {}).get('p99', 0)):.2f}",
                f"{float((row.get('tpot_ms') or {}).get('p50', 0)):.3f}",
                f"{float(row.get('output_tokens_per_second', 0)):.2f}",
                f"{float(row.get('goodput_requests_per_second', 0)):.3f}",
                f"{float(row.get('error_rate', 0)):.4f}",
                f"{float(row['estimated_cost']):.6f}" if row.get("estimated_cost") is not None else "n/a",
            )
        )
        + "</tr>"
        for row in ordered
    )
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; base-uri 'none'"><title>CavadaLabs LLM Performance Report</title><style>body{{font:15px system-ui;max-width:1400px;margin:0 auto;padding:40px 24px;color:#172033;background:#f4f7fb;line-height:1.5}}header,.panel{{background:white;border:1px solid #dce3ec;border-radius:14px;padding:24px;margin-bottom:20px;box-shadow:0 6px 22px #1720330a}}h1{{margin:0 0 8px;font-size:30px}}h2{{margin-top:0}}.muted{{color:#5d697b}}.status{{display:inline-block;border-radius:999px;padding:5px 10px;background:#e8f5eb;color:#176b35;font-weight:700}}.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:22px}}.kpi{{border:1px solid #dce3ec;border-radius:10px;padding:14px}}.kpi strong{{display:block;font-size:24px}}.charts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px}}figure{{margin:0;border:1px solid #e1e6ee;border-radius:10px;padding:10px}}figcaption{{font-weight:700;padding:4px 8px}}img{{width:100%;height:auto;display:block}}table{{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}}.table-wrap{{overflow:auto}}th,td{{border-bottom:1px solid #dce3ec;padding:9px;text-align:right;white-space:nowrap}}th{{background:#eef3f8}}th:nth-child(2),td:nth-child(2){{text-align:left}}code{{background:#eef2f6;padding:2px 4px;overflow-wrap:anywhere}}.notice{{border-left:5px solid #1769aa;background:#eef6ff;padding:12px 16px}}@media(max-width:700px){{body{{padding:16px 10px}}.charts{{grid-template-columns:1fr}}}}@media print{{body{{background:white;padding:0}}header,.panel{{box-shadow:none}}}}</style></head><body><header><span class="status">{html.escape(manifest['status']).upper()}</span><h1>LLM serving performance</h1><p class="muted">{html.escape(str(manifest['runtime']['id']))}<br>Run <code>{html.escape(manifest['run_id'])}</code></p><div class="kpis"><div class="kpi"><span>Measured requests</span><strong>{observations}</strong><small>{errors} errors</small></div><div class="kpi"><span>TTFT p95</span><strong>{float((best.get('ttft_ms') or {}).get('p95', 0)) / 1000:.2f} s</strong><small>lower is better</small></div><div class="kpi"><span>Decode p50</span><strong>{float((best.get('decode_tokens_per_second') or {}).get('p50', 0)):.2f}</strong><small>tokens/s · higher is better</small></div><div class="kpi"><span>Output throughput</span><strong>{float(best.get('output_tokens_per_second', 0)):.3f}</strong><small>tokens/s · prefill included</small></div><div class="kpi"><span>SLO cells</span><strong>{manifest['cells']['slo_passed']}/{manifest['cells']['slo_passed'] + manifest['cells']['slo_failed']}</strong><small>passing / evaluated</small></div></div></header><section class="panel"><h2>How to read this run</h2><p class="notice"><strong>Decode tokens/s</strong> measures generation after the first token. <strong>Output throughput</strong> includes prompt processing and is the campaign-level rate. Compare only runs with identical plan, workload and host mode.</p></section><section class="panel"><h2>Measured distributions</h2><div class="charts"><figure><figcaption>Time to first token · lower is better</figcaption><img src="figures/ttft.svg" alt="Time to first token chart"></figure><figure><figcaption>End-to-end latency · lower is better</figcaption><img src="figures/e2e.svg" alt="End-to-end latency chart"></figure><figure><figcaption>Decode rate · higher is better</figcaption><img src="figures/decode.svg" alt="Decode rate chart"></figure><figure><figcaption>Campaign output throughput · higher is better</figcaption><img src="figures/throughput.svg" alt="Output token throughput chart"></figure><figure><figcaption>SLO goodput · higher is better</figcaption><img src="figures/goodput.svg" alt="SLO goodput chart"></figure></div></section><section class="panel"><h2>Comparable cells</h2><div class="table-wrap"><table><thead><tr><th>Block</th><th>Cell</th><th>Status</th><th>SLO</th><th>N</th><th>TTFT p95 ms</th><th>E2E p99 ms</th><th>TPOT p50 ms</th><th>Output tok/s</th><th>Good req/s</th><th>Error rate</th><th>{html.escape(cost_heading)}</th></tr></thead><tbody>{table_rows}</tbody></table></div></section><section class="panel"><h2>Reproducibility and limits</h2><p>Plan SHA-256: <code>{manifest['plan']['sha256']}</code><br>Workload SHA-256: <code>{manifest['workload']['sha256']}</code><br>Warm-up errors: {manifest['warmups']['errors']} of {manifest['warmups']['total']}.</p><ul>{''.join(f'<li>{html.escape(item)}</li>' for item in summary['limitations'])}</ul><p class="muted">Performance evidence does not establish response quality, safety, compliance, energy use or universal deployment capacity.</p></section></body></html>\n'''
    atomic_text(run_dir / "report.html", document)
    _performance_pdf(run_dir / "report.pdf", manifest, summary, cells)


def _performance_pdf(path: Path, manifest: dict[str, Any], summary: dict[str, Any], cells: list[dict[str, Any]]) -> None:
    runtime = manifest.get("runtime") or {}
    plan = manifest.get("plan") or {}
    workload = manifest.get("workload") or {}
    completed = [cell for cell in cells if cell.get("status") in {"completed", "completed-with-errors"}]
    observations = int(summary.get("observations", 0))
    errors = int(summary.get("errors", 0))
    evaluated = int((manifest.get("cells") or {}).get("slo_passed", 0)) + int((manifest.get("cells") or {}).get("slo_failed", 0))
    best = summary.get("best_goodput_cell") or {}

    def percentile(row: dict[str, Any], metric: str, name: str) -> float:
        value = (row.get(metric) or {}).get(name, 0)
        return float(value) if isinstance(value, (int, float)) else 0.0

    cell_rows = [
        [
            cell.get("cell_key", ""),
            f"{int(cell.get('context_tokens', 0)):,}",
            cell.get("output_tokens", 0),
            cell.get("concurrency", "-"),
            cell.get("observations", 0),
            cell.get("status", "unknown"),
            f"{float(cell.get('error_rate', 0)):.1%}",
            f"{percentile(cell, 'ttft_ms', 'p95') / 1000:,.2f}",
            f"{percentile(cell, 'decode_tokens_per_second', 'p50'):,.2f}",
            f"{float(cell.get('output_tokens_per_second', 0)):,.3f}",
        ]
        for cell in cells
    ]
    if len(completed) == 1:
        cell = completed[0]
        performance_charts = [
            {
                "title": "Time to first token distribution - lower is better",
                "rows": [(label, percentile(cell, "ttft_ms", key) / 1000) for label, key in (("minimum", "min"), ("p50", "p50"), ("p90", "p90"), ("p95", "p95"), ("maximum", "max"))],
                "unit": "s",
            },
            {
                "title": "End-to-end latency distribution - lower is better",
                "rows": [(label, percentile(cell, "e2e_ms", key) / 1000) for label, key in (("minimum", "min"), ("p50", "p50"), ("p90", "p90"), ("p95", "p95"), ("maximum", "max"))],
                "unit": "s",
            },
            {
                "title": "Decode rate distribution - higher is better",
                "rows": [(label, percentile(cell, "decode_tokens_per_second", key)) for label, key in (("minimum", "min"), ("p50", "p50"), ("p90", "p90"), ("p95", "p95"), ("maximum", "max"))],
                "unit": "tok/s",
            },
        ]
    else:
        performance_charts = [
            {"title": "Campaign output throughput - higher is better", "rows": [(str(cell.get("cell_key", "cell")), float(cell.get("output_tokens_per_second", 0))) for cell in completed], "unit": "tok/s"},
            {"title": "Decode rate after first token - higher is better", "rows": [(str(cell.get("cell_key", "cell")), percentile(cell, "decode_tokens_per_second", "p50")) for cell in completed], "unit": "tok/s"},
            {"title": "Time to first token p95 - lower is better", "rows": [(str(cell.get("cell_key", "cell")), percentile(cell, "ttft_ms", "p95") / 1000) for cell in completed], "unit": "s"},
        ]
    warnings = [str(item) for cell in cells for item in cell.get("warnings", [])]
    error_rows = [
        [cell.get("cell_key", ""), cell.get("status", ""), f"{float(cell.get('error_rate', 0)):.1%}", json.dumps(cell.get("error_types") or {}, sort_keys=True)]
        for cell in cells
        if cell.get("status") == "completed-with-errors" or cell.get("error_types")
    ]
    if errors:
        interpretation = "RUN CONTAINS ERRORS. Treat this bundle as failure evidence; do not include it in successful model averages or rankings."
    elif observations < 30:
        interpretation = f"Small measured sample: {observations} observations. This is a smoke or capacity check, not statistically strong reference evidence."
    else:
        interpretation = "The run completed without measured request errors. Interpret every result within the exact plan, workload, runtime, and hardware scope recorded below."
    cost = manifest.get("estimated_cost") or {}
    cost_text = f"{float(cost.get('amount', 0)):,.4f} {cost.get('currency', '')}" if isinstance(cost, dict) else "not configured"
    sections: list[dict[str, Any]] = [
        {
            "title": "Executive interpretation",
            "paragraphs": [interpretation],
            "warning": "Performance evidence does not establish response quality, safety, compliance, energy use, or universal deployment capacity.",
            "key_values": [
                ("Plan", f"{plan.get('name', 'unknown')}@{plan.get('revision', 'unknown')}"),
                ("Workload", f"{workload.get('id', 'unknown')}@{workload.get('revision', 'unknown')}"),
                ("Arrival", best.get("arrival", "mixed")),
                ("Warm-up", f"{(manifest.get('warmups') or {}).get('successes', 0)} success / {(manifest.get('warmups') or {}).get('errors', 0)} errors"),
                ("Measured requests", observations),
                ("Estimated cost", cost_text),
            ],
        },
        {
            "title": "Measured performance cells",
            "table": {
                "headers": ["Cell", "Context", "Output", "C", "N", "Status", "Errors", "TTFT p95 s", "Decode tok/s", "Output tok/s"],
                "rows": cell_rows,
                "widths": [34, 17, 14, 10, 10, 29, 15, 20, 15, 15],
            },
            "charts": performance_charts,
        },
        {
            "title": "System under test",
            "key_values": [
                ("Runtime ID", runtime.get("id", "unknown")),
                ("Expected model", runtime.get("expected_model", "unknown")),
                ("Model revision", runtime.get("model_revision", "unknown")),
                ("Model artifact", runtime.get("model_artifact_revision", "unknown")),
                ("Engine", f"{runtime.get('engine', 'unknown')} / {runtime.get('engine_revision', 'unknown')}"),
                ("Quantization / dtype", f"{runtime.get('quantization', 'unknown')} / {runtime.get('dtype', 'unknown')}"),
                ("GPU", f"{runtime.get('gpu_count', 'unknown')} x {runtime.get('gpu_model', 'unknown')}"),
                ("Tensor parallel", runtime.get("tensor_parallel", "unknown")),
                ("Maximum context", f"{int(runtime.get('max_context_tokens', 0)):,} tokens"),
                ("Endpoint", runtime.get("endpoint", "redacted")),
                ("Launch command", runtime.get("launch_command_sanitized", "not recorded")),
            ],
        },
        {
            "title": "Protocol and reproducibility",
            "paragraphs": [
                "Warm-up observations are separate from measured observations. Measured requests are not silently retried. Provider-reported token usage is used for official performance evidence.",
                "Only runs with identical plan, workload, and asset-set hashes have exact comparable cells. Differences remain observational and cannot be attributed to one component without controlled experiments.",
            ],
            "key_values": [
                ("Performance protocol", manifest.get("performance_protocol_version", "unknown")),
                ("Plan SHA-256", plan.get("sha256", "unknown")),
                ("Workload SHA-256", workload.get("sha256", "unknown")),
                ("Asset-set SHA-256", workload.get("asset_set_sha256", "unknown")),
                ("Source commit", (manifest.get("source") or {}).get("commit", "unknown")),
                ("Source dirty", (manifest.get("source") or {}).get("dirty", "unknown")),
            ],
        },
    ]
    if error_rows or warnings:
        sections.append(
            {
                "title": "Errors and warnings",
                "keep_together": True,
                "warning": interpretation if errors else "Warnings affect interpretation and remain part of the evidence bundle.",
                "paragraphs": warnings or ["No cell warning was recorded."],
                "table": {"headers": ["Cell", "Status", "Error rate", "Error types"], "rows": error_rows or [["All", "completed", "0.0%", "none"]], "widths": [60, 35, 25, 59]},
            }
        )
    sections.append(
        {
            "title": "Limitations",
            "paragraphs": [str(item) for item in summary.get("limitations", [])]
            + ["High-percentile estimates are weakly resolved when observation counts are small. Repeat reference campaigns with sufficient duration and observations before publishing rankings."],
        }
    )
    render_pdf(
        path,
        title="LLM Serving Performance Report",
        subtitle=f"{runtime.get('expected_model', 'unknown')} / {int(best.get('context_tokens', runtime.get('max_context_tokens', 0))):,} measured context / {runtime.get('gpu_count', 'unknown')} GPU",
        status=str(manifest.get("status", "unknown")),
        report_id=str(manifest.get("run_id", "unknown")),
        classification=str(plan.get("data_classification", "restricted")),
        scope="Client-side serving performance for the exact runtime and workload; response quality and universal capacity are outside scope.",
        kpis=[
            ("Observations", f"{observations:,}", f"{summary.get('successes', 0)} success / {errors} errors"),
            ("SLO cells", f"{(manifest.get('cells') or {}).get('slo_passed', 0)}/{evaluated}", "evaluated cells"),
            ("Input tokens", f"{float((summary.get('campaign_token_usage') or {}).get('input', 0)):,.0f}", "warm-up included"),
            ("Decode p50", f"{percentile(best, 'decode_tokens_per_second', 'p50'):,.2f} tok/s", "best-goodput cell"),
            ("TTFT p95", f"{percentile(best, 'ttft_ms', 'p95') / 1000:,.2f} s", "best-goodput cell"),
            ("Output throughput", f"{float(best.get('output_tokens_per_second', 0)):,.3f} tok/s", "prefill included"),
        ],
        sections=sections,
        metadata={
            "Run ID": str(manifest.get("run_id", "unknown")),
            "Status": str(manifest.get("status", "unknown")),
            "Started": str(manifest.get("started_at", "unknown")),
            "Finished": str(manifest.get("finished_at", "unknown")),
            "Runtime": str(runtime.get("id", "unknown")),
            "Plan SHA-256": str(plan.get("sha256", "unknown")),
            "Workload SHA-256": str(workload.get("sha256", "unknown")),
        },
    )


def compare_performance_runs(run_dirs: list[Path], output: Path, *, signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY") -> dict[str, Any]:
    require_pdf_support()
    if len(run_dirs) < 2:
        raise ProtocolError("performance comparison requires at least two runs")
    if output.exists():
        raise ProtocolError(f"refusing to overwrite performance comparison: {output}")
    manifests: list[dict[str, Any]] = []
    cells_by_run: list[dict[tuple[int, str], dict[str, Any]]] = []
    for run_dir in run_dirs:
        verification = verify_bundle(run_dir, signing_key_env=signing_key_env)
        if not verification["valid"]:
            raise ProtocolError(f"invalid performance bundle: {run_dir}")
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("performance_protocol_version") != PERFORMANCE_PROTOCOL_VERSION:
            raise ProtocolError(f"incompatible performance protocol: {run_dir}")
        manifests.append(manifest)
        rows = [json.loads(line) for line in (run_dir / "cells.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        cells_by_run.append({(int(row["block"]), str(row["cell_key"])): row for row in rows if row.get("status") != "skipped"})
    compatibility = {(item["plan"]["sha256"], item["workload"]["sha256"], item["workload"]["asset_set_sha256"]) for item in manifests}
    if len(compatibility) != 1:
        raise ProtocolError("performance runs require identical plan and workload hashes")
    shared = sorted(set.intersection(*(set(rows) for rows in cells_by_run)))
    if not shared:
        raise ProtocolError("performance runs have no shared completed cells")
    labels = [str(manifest["runtime"]["id"]) for manifest in manifests]
    if len(set(labels)) != len(labels):
        raise ProtocolError("performance comparison requires unique runtime ids")
    output.mkdir(parents=True)
    comparison_rows: list[dict[str, Any]] = []
    for key in shared:
        baseline = cells_by_run[0][key]
        for index, cell_map in enumerate(cells_by_run):
            row = cell_map[key]
            runtime = manifests[index]["runtime"]
            throughput = float(row.get("output_tokens_per_second", 0))
            baseline_throughput = float(baseline.get("output_tokens_per_second", 0))
            runtime_pricing = runtime.get("pricing")
            ttft = row.get("ttft_ms") or {}
            e2e = row.get("e2e_ms") or {}
            tpot = row.get("tpot_ms") or {}
            decode = row.get("decode_tokens_per_second") or {}

            comparison_rows.append(
                {
                    "block": key[0],
                    "cell_key": key[1],
                    "runtime_id": labels[index],
                    "model": str(runtime["expected_model"]),
                    "quantization": str(runtime["quantization"]),
                    "gpu_count": int(runtime["gpu_count"]),
                    "gpu_model": str(runtime["gpu_model"]),
                    "tensor_parallel": int(runtime["tensor_parallel"]),
                    "arrival": str(row.get("arrival", "unknown")),
                    "context_tokens": int(row.get("context_tokens", 0)),
                    "output_tokens": int(row.get("output_tokens", 0)),
                    "concurrency": int(row.get("concurrency") or 0),
                    "request_rate": float(row["request_rate"]) if row.get("request_rate") is not None else None,
                    "observations": int(row.get("observations", 0)),
                    "successes": int(row.get("successes", 0)),
                    "errors": int(row.get("errors", 0)),
                    "ttft_p50_ms": float(ttft.get("p50", 0)),
                    "ttft_p95_ms": float(ttft.get("p95", 0)),
                    "e2e_p50_ms": float(e2e.get("p50", 0)),
                    "e2e_p95_ms": float(e2e.get("p95", 0)),
                    "e2e_p99_ms": float(e2e.get("p99", 0)),
                    "tpot_p50_ms": float(tpot.get("p50", 0)),
                    "decode_tps_mean": float(decode.get("mean", 0)),
                    "decode_tps_p50": float(decode.get("p50", 0)),
                    "decode_tps_p95": float(decode.get("p95", 0)),
                    "requests_per_second": float(row.get("requests_per_second", 0)),
                    "input_tokens_per_second": float(row.get("input_tokens_per_second", 0)),
                    "output_tokens_per_second": throughput,
                    "goodput_requests_per_second": float(row.get("goodput_requests_per_second", 0)),
                    "error_rate": float(row.get("error_rate", 0)),
                    "slo_passed": bool(row.get("slo_passed")),
                    "estimated_cost": float(row["estimated_cost"]) if row.get("estimated_cost") is not None else None,
                    "cost_currency": runtime_pricing.get("currency") if isinstance(runtime_pricing, dict) else None,
                    "throughput_speedup_vs_baseline": throughput / baseline_throughput if baseline_throughput else None,
                }
            )
    result: dict[str, Any] = {
        "performance_protocol_version": PERFORMANCE_PROTOCOL_VERSION,
        "baseline": labels[0],
        "runs": [
            {
                "run_id": manifest["run_id"],
                "runtime_id": manifest["runtime"]["id"],
                "model": manifest["runtime"]["expected_model"],
                "quantization": manifest["runtime"]["quantization"],
                "gpu_count": manifest["runtime"]["gpu_count"],
                "gpu_model": manifest["runtime"]["gpu_model"],
                "bundle_sha256": sha256_file(run_dirs[index] / "bundle.json"),
            }
            for index, manifest in enumerate(manifests)
        ],
        "shared_cells": len(shared),
        "rows": comparison_rows,
        "limitations": "Only exact shared cells from identical plan and workload hashes are compared; differences are observational, not causal.",
    }
    atomic_json(output / "comparison.json", result)
    with (output / "comparison.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(comparison_rows[0]))
        writer.writeheader()
        writer.writerows(comparison_rows)
    series = [
        (label, [next(float(row["output_tokens_per_second"]) for row in comparison_rows if row["runtime_id"] == label and row["block"] == key[0] and row["cell_key"] == key[1]) for key in shared])
        for label in labels
    ]
    _line_svg("Output token throughput comparison", series, output / "throughput_comparison.svg", "Output tokens/s")

    def format_value(value: float, digits: int, percent: bool = False) -> str:
        return f"{value:.{digits}%}" if percent else f"{value:,.{digits}f}"

    matrix_specs = (
        ("TTFT p50", "ttft_p50_ms", "ms", 1, False, False),
        ("TTFT p95", "ttft_p95_ms", "ms", 1, False, False),
        ("End-to-end p95", "e2e_p95_ms", "ms", 1, False, False),
        ("Decode p50", "decode_tps_p50", "tok/s", 2, False, True),
        ("Decode p95", "decode_tps_p95", "tok/s", 2, False, True),
        ("Output throughput", "output_tokens_per_second", "tok/s", 3, False, True),
        ("Input throughput", "input_tokens_per_second", "tok/s", 2, False, True),
        ("Error rate", "error_rate", "%", 2, True, False),
    )
    row_lookup = {(str(row["runtime_id"]), int(row["block"]), str(row["cell_key"])): row for row in comparison_rows}
    cell_labels = {
        key: f"{int(cells_by_run[0][key].get('context_tokens', 0)):,} ctx · {int(cells_by_run[0][key].get('output_tokens', 0))} out · "
        + (f"c{int(cells_by_run[0][key]['concurrency'])}" if cells_by_run[0][key].get("concurrency") is not None else f"r{float(cells_by_run[0][key]['request_rate']):g}")
        for key in shared
    }
    matrices: list[str] = []
    for title, field, unit, digits, percent, higher_is_better in matrix_specs:
        best_by_cell = {
            key: (max if higher_is_better else min)(float(row_lookup[(label, key[0], key[1])][field]) for label in labels)
            for key in shared
        }
        matrix_rows = "".join(
            "<tr><th scope=\"row\"><strong>"
            + html.escape(str(row_lookup[(label, shared[0][0], shared[0][1])]["model"]))
            + "</strong><small>"
            + html.escape(label)
            + "</small></th>"
            + "".join(
                f'<td class="{"best" if float(row_lookup[(label, key[0], key[1])][field]) == best_by_cell[key] else ""}">{format_value(float(row_lookup[(label, key[0], key[1])][field]), digits, percent)}</td>'
                for key in shared
            )
            + "</tr>"
            for label in labels
        )
        matrices.append(
            f'<article class="matrix"><h3>{html.escape(title)} <small>{html.escape(unit)} · {"higher" if higher_is_better else "lower"} is better</small></h3><div class="table-wrap"><table><thead><tr><th>Model / runtime</th>{"".join(f"<th>{html.escape(cell_labels[key])}</th>" for key in shared)}</tr></thead><tbody>{matrix_rows}</tbody></table></div></article>'
        )

    exact_rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(value))}</td>"
            for value in (
                row["model"],
                f"{row['context_tokens']:,}",
                row["output_tokens"],
                f"c{row['concurrency']}" if row["concurrency"] else f"r{float(row['request_rate'] or 0):g}",
                f"{row['gpu_count']} / tp{row['tensor_parallel']}",
                row["observations"],
                f"{row['ttft_p50_ms']:,.1f}",
                f"{row['ttft_p95_ms']:,.1f}",
                f"{row['e2e_p95_ms']:,.1f}",
                f"{row['e2e_p99_ms']:,.1f}",
                f"{row['decode_tps_p50']:,.2f}",
                f"{row['decode_tps_p95']:,.2f}",
                f"{row['input_tokens_per_second']:,.2f}",
                f"{row['output_tokens_per_second']:,.3f}",
                f"{row['requests_per_second']:,.4f}",
                f"{row['goodput_requests_per_second']:,.4f}",
                f"{row['error_rate']:.2%}",
                row["slo_passed"],
                f"{float(row['throughput_speedup_vs_baseline'] or 0):.2f}x",
                row["quantization"],
                row["runtime_id"],
                row["gpu_model"],
            )
        )
        + "</tr>"
        for row in comparison_rows
    )
    fastest = max(comparison_rows, key=lambda row: float(row.get("output_tokens_per_second", 0)))
    error_free = sum(float(row.get("error_rate", 0)) == 0 for row in comparison_rows)
    atomic_text(
        output / "report.html",
        f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; base-uri 'none'"><title>CavadaLabs Performance Comparison</title><style>body{{font:15px system-ui;max-width:1600px;margin:0 auto;padding:40px 24px;color:#172033;background:#f4f7fb;line-height:1.5}}header,.panel{{background:white;border:1px solid #dce3ec;border-radius:14px;padding:24px;margin-bottom:20px;box-shadow:0 6px 22px #1720330a}}h1{{margin:0 0 8px;font-size:30px}}h2{{margin-top:0}}h3{{margin:0 0 10px;font-size:16px}}h3 small,.matrix th small{{display:block;color:#5d697b;font-weight:400}}.muted{{color:#5d697b}}.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:22px}}.kpi{{border:1px solid #dce3ec;border-radius:10px;padding:14px}}.kpi strong{{display:block;font-size:23px;overflow-wrap:anywhere}}figure{{margin:0;border:1px solid #e1e6ee;border-radius:10px;padding:10px}}img{{width:100%;height:auto;display:block}}.table-wrap{{overflow:auto;max-height:72vh;border:1px solid #dce3ec;border-radius:8px}}table{{border-collapse:separate;border-spacing:0;width:100%;font-variant-numeric:tabular-nums}}th,td{{border-bottom:1px solid #dce3ec;padding:8px 10px;text-align:right;white-space:nowrap}}thead th{{position:sticky;top:0;z-index:2;background:#eef3f8}}tbody tr:nth-child(even){{background:#f8fafc}}tbody tr:hover{{background:#eef6ff}}th:first-child,td:first-child{{position:sticky;left:0;z-index:1;background:inherit;text-align:left}}thead th:first-child{{z-index:3;background:#eef3f8}}.matrices{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr));gap:16px}}.matrix{{min-width:0;border:1px solid #dce3ec;border-radius:10px;padding:14px}}.matrix .table-wrap{{max-height:none}}.matrix th:first-child{{min-width:240px}}.best{{background:#e4f5e9!important;color:#0d5f2a;font-weight:750}}.notice{{border-left:5px solid #b26a00;background:#fff6df;padding:12px 16px}}@media(max-width:700px){{body{{padding:16px 10px}}.matrix th:first-child{{min-width:190px}}}}@media print{{body{{background:white;padding:0}}header,.panel{{box-shadow:none}}.table-wrap{{overflow:visible;max-height:none}}}}</style></head><body><header><h1>LLM serving comparison</h1><p class="muted">Dense, exact shared-cell comparison from verified evidence bundles</p><div class="kpis"><div class="kpi"><span>Runtimes</span><strong>{len(labels)}</strong><small>verified bundles</small></div><div class="kpi"><span>Shared cells</span><strong>{len(shared)}</strong><small>same plan and workload</small></div><div class="kpi"><span>Highest output rate</span><strong>{float(fastest['output_tokens_per_second']):.3f} tok/s</strong><small>{html.escape(str(fastest['runtime_id']))}</small></div><div class="kpi"><span>Observed speedup</span><strong>{float(fastest.get('throughput_speedup_vs_baseline') or 0):.2f}x</strong><small>versus baseline</small></div><div class="kpi"><span>Error-free rows</span><strong>{error_free}/{len(comparison_rows)}</strong><small>zero measured errors</small></div></div></header><section class="panel"><h2>Metric matrices</h2><p class="muted">Models are rows; exact context, requested output and concurrency cells are columns. Green marks the best observed value in each column.</p><div class="matrices">{"".join(matrices)}</div></section><section class="panel"><h2>Complete results grid</h2><p class="muted">Performance columns come first; full runtime and hardware identity remain available at the right. All values are preserved in comparison.csv and comparison.json.</p><div class="table-wrap"><table><thead><tr><th>Model</th><th>Context</th><th>Output</th><th>Load</th><th>GPUs / TP</th><th>N</th><th>TTFT p50 ms</th><th>TTFT p95 ms</th><th>E2E p95 ms</th><th>E2E p99 ms</th><th>Decode p50</th><th>Decode p95</th><th>Input tok/s</th><th>Output tok/s</th><th>Req/s</th><th>Good req/s</th><th>Error rate</th><th>SLO</th><th>Speedup</th><th>Quant</th><th>Runtime</th><th>GPU model</th></tr></thead><tbody>{exact_rows}</tbody></table></div></section><section class="panel"><h2>Throughput chart</h2><figure><img src="throughput_comparison.svg" alt="Output token throughput comparison"></figure><p class="notice"><strong>Baseline:</strong> {html.escape(labels[0])}. Output tokens/s includes prompt prefill; decode rate starts after the first token.</p></section><section class="panel"><h2>Limits</h2><p>{html.escape(str(result['limitations']))}</p><p class="muted">Observed differences are not causal and do not establish response quality, safety or universal capacity.</p></section></body></html>\n''',
    )
    _comparison_pdf(output / "report.pdf", result, comparison_rows)
    write_bundle(output, signing_key_env=signing_key_env)
    if not verify_bundle(output, signing_key_env=signing_key_env)["valid"]:
        raise ProtocolError("performance comparison bundle verification failed")
    return result


def _comparison_pdf(path: Path, result: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    baseline = str(result["baseline"])
    best = max(rows, key=lambda row: float(row.get("output_tokens_per_second", 0)))
    error_free = sum(float(row.get("error_rate", 0)) == 0 for row in rows)
    table_rows = [
        [
            f"{row.get('model', '')}\n{row.get('runtime_id', '')}",
            f"{int(row.get('context_tokens', 0)):,}",
            row.get("observations", 0),
            f"{float(row.get('ttft_p50_ms', 0)) / 1000:,.2f}",
            f"{float(row.get('ttft_p95_ms', 0)) / 1000:,.2f}",
            f"{float(row.get('e2e_p95_ms', 0)) / 1000:,.2f}",
            f"{float(row.get('e2e_p99_ms', 0)) / 1000:,.2f}",
            f"{float(row.get('decode_tps_p50', 0)):,.2f}",
            f"{float(row.get('decode_tps_p95', 0)):,.2f}",
            f"{float(row.get('input_tokens_per_second', 0)):,.2f}",
            f"{float(row.get('output_tokens_per_second', 0)):,.3f}",
            f"{float(row.get('error_rate', 0)):.1%}",
        ]
        for row in rows
    ]
    runtime_ids = [str(run["runtime_id"]) for run in result.get("runs", [])]
    cell_keys = list(dict.fromkeys(str(row["cell_key"]) for row in rows))
    cell_labels = {
        key: f"{int(row['context_tokens']):,}/{int(row['output_tokens'])}/"
        + (f"c{int(row['concurrency'])}" if row["concurrency"] else f"r{float(row['request_rate'] or 0):g}")
        for key in cell_keys
        for row in rows
        if row["cell_key"] == key
    }

    def matrix(field: str, digits: int, *, percent: bool = False) -> dict[str, Any]:
        values = {(str(row["runtime_id"]), str(row["cell_key"])): float(row[field]) for row in rows}
        matrix_rows = [
            [
                next(str(run.get("model", runtime_id)) for run in result.get("runs", []) if run["runtime_id"] == runtime_id),
                *(f"{values[(runtime_id, key)]:.{digits}%}" if percent else f"{values[(runtime_id, key)]:,.{digits}f}" for key in cell_keys),
            ]
            for runtime_id in runtime_ids
        ]
        cell_width = 134 / len(cell_keys)
        return {"headers": ["Model", *(cell_labels[key] for key in cell_keys)], "rows": matrix_rows, "widths": [45, *(cell_width for _ in cell_keys)]}

    run_rows = [[run.get("runtime_id", "unknown"), run.get("run_id", "unknown"), run.get("bundle_sha256", "unknown")] for run in result.get("runs", [])]
    render_pdf(
        path,
        title="LLM Serving Performance Comparison",
        subtitle=f"{len(result.get('runs', []))} runtimes / {result.get('shared_cells', 0)} exact shared cells",
        status="observational comparison",
        report_id=f"comparison / {baseline}",
        classification="RESTRICTED",
        scope="Exact shared-cell comparison of verified bundles. Observed differences are not causal and do not establish quality, safety, or universal capacity.",
        kpis=[
            ("Runtimes", f"{len(result.get('runs', [])):,}", "verified bundles"),
            ("Shared cells", f"{int(result.get('shared_cells', 0)):,}", "identical plan and workload"),
            ("Error-free rows", f"{error_free}/{len(rows)}", "zero measured errors"),
            ("Highest output rate", f"{float(best.get('output_tokens_per_second', 0)):,.3f} tok/s", str(best.get("runtime_id", "unknown"))),
            ("Observed speedup", f"{float(best.get('throughput_speedup_vs_baseline') or 0):,.2f}x", "versus declared baseline"),
            ("Baseline", "1.00x", baseline),
        ],
        sections=[
            {
                "title": "Executive interpretation",
                "paragraphs": [
                    f"The highest observed campaign output rate is {float(best.get('output_tokens_per_second', 0)):,.3f} tok/s for {best.get('runtime_id', 'unknown')}, or {float(best.get('throughput_speedup_vs_baseline') or 0):,.2f}x the declared baseline.",
                    "Campaign output tokens/s includes prompt prefill and differs from decode tokens/s measured after the first token. Use the detailed run reports when interpreting model generation speed.",
                ],
                "warning": "Only exact shared cells are shown. Hardware, runtime, model, engine, and host differences remain confounded unless the experiment controls them independently.",
            },
            {
                "title": "Observed comparison",
                "table": {
                    "headers": ["Model / runtime", "Context", "N", "TTFT p50 s", "TTFT p95 s", "E2E p95 s", "E2E p99 s", "Decode p50", "Decode p95", "Input tok/s", "Output tok/s", "Errors"],
                    "rows": table_rows,
                    "widths": [32, 13, 8, 14, 14, 14, 14, 14, 14, 14, 14, 14],
                },
                "charts": [
                    {"title": "Campaign output throughput - higher is better", "rows": [(str(row.get("runtime_id", "runtime")), float(row.get("output_tokens_per_second", 0))) for row in rows], "unit": "tok/s"},
                    {"title": "Time to first token p95 - lower is better", "rows": [(str(row.get("runtime_id", "runtime")), float(row.get("ttft_p95_ms", 0)) / 1000) for row in rows], "unit": "s"},
                ],
            },
            {"title": "TTFT p95 matrix - milliseconds - lower is better", "table": matrix("ttft_p95_ms", 1)},
            {"title": "Decode p50 matrix - tokens/s - higher is better", "table": matrix("decode_tps_p50", 2)},
            {"title": "Output throughput matrix - tokens/s - higher is better", "table": matrix("output_tokens_per_second", 3)},
            {"title": "Error rate matrix - lower is better", "page_break": True, "table": matrix("error_rate", 2, percent=True)},
            {
                "title": "Methodology and limitations",
                "paragraphs": [str(result.get("limitations", "Only exact shared cells are compared.")), "This comparison is observational, not causal. Repeat a reference campaign with sufficient observations before publishing model or hardware rankings."],
                "key_values": [("Baseline", baseline), ("Performance protocol", result.get("performance_protocol_version", "unknown")), ("Shared cells", result.get("shared_cells", 0))],
            },
            {
                "title": "Source bundles",
                "table": {"headers": ["Runtime", "Run ID", "Bundle SHA-256"], "rows": run_rows, "widths": [50, 70, 59]},
            },
        ],
        metadata={
            "Baseline": baseline,
            "Runtimes": str(len(result.get("runs", []))),
            "Shared cells": str(result.get("shared_cells", 0)),
            "Protocol": str(result.get("performance_protocol_version", "unknown")),
        },
    )
