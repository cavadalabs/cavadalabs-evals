from __future__ import annotations

import json
import math
import os
import tempfile
import tomllib
import unicodedata
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, cast

from .artifacts import _read_regular
from .evaluation import _load_factory as _load_trusted_factory
from .evaluation import _write_once
from .performance import (
    MAX_WORKLOAD_BYTES,
    PerformancePlan,
    PerformanceRuntime,
    load_performance_plan,
    load_performance_runtime,
    run_performance_campaign,
)
from .protocol import ProtocolError, _strict_json_loads, contains_secret_like, sha256_bytes

CLIENT_BENCHMARK_VERSION = "1.0.0"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_FACTORY_ROWS = 100_000


@dataclass(frozen=True)
class ClientBenchmark:
    path: Path
    sha256: str
    config: dict[str, Any]
    workload_bytes: bytes
    contexts: tuple[int, ...]


@dataclass(frozen=True)
class PlannedClientBenchmark:
    directory: Path
    plan: PerformancePlan
    runtime: PerformanceRuntime


def _reject_unknown(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ProtocolError(f"{label} contains unknown fields: {unknown}")


def _safe_relative(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or value != unicodedata.normalize("NFC", value) or "\\" in value:
        raise ProtocolError(f"{label} must be a canonical relative path")
    path = Path(value)
    if path.is_absolute() or PureWindowsPath(value).is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ProtocolError(f"{label} must be a canonical relative path")
    return path


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ProtocolError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _number(value: Any, label: str, *, minimum: float, maximum: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)) or not minimum <= float(value) <= maximum:
        raise ProtocolError(f"{label} must be a finite number from {minimum:g} to {maximum:g}")
    return float(value)


def _load_factory(reference: str, *, trusted: bool, root: Path) -> list[dict[str, Any]]:
    parts = reference.split(":")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ProtocolError("factory must use trusted module:callable syntax")
    module_name, callable_name = parts
    if any(not component.isidentifier() for component in module_name.split(".")) or not callable_name.isidentifier():
        raise ProtocolError("factory must use trusted module:callable syntax")
    if not trusted:
        raise ProtocolError("dataset factory execution requires explicit trust_factory=True")
    factory = _load_trusted_factory(reference, root, "benchmark dataset factory")
    try:
        produced = factory()
    except Exception as exc:  # noqa: BLE001 -- a trusted client factory may raise any application exception.
        raise ProtocolError(f"trusted dataset factory {reference!r} failed ({type(exc).__name__})") from exc
    if isinstance(produced, (str, bytes, dict)) or not isinstance(produced, Iterable):
        raise ProtocolError("trusted dataset factory must return an iterable of workload objects")
    rows: list[dict[str, Any]] = []
    for index, value in enumerate(produced, 1):
        if index > MAX_FACTORY_ROWS:
            raise ProtocolError(f"trusted dataset factory exceeds {MAX_FACTORY_ROWS} rows")
        if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
            raise ProtocolError(f"trusted dataset factory row {index} must be an object with string keys")
        if "prompt_file" in value:
            raise ProtocolError("trusted dataset factory rows must materialize prompt text, not prompt_file")
        rows.append(cast(dict[str, Any], value))
    if not rows:
        raise ProtocolError("trusted dataset factory returned no rows")
    return rows


def _materialize_rows(rows: list[dict[str, Any]]) -> tuple[bytes, tuple[int, ...]]:
    canonical: list[bytes] = []
    contexts: set[int] = set()
    for index, original in enumerate(rows, 1):
        row = dict(original)
        context = row.get("context_tokens")
        if not isinstance(context, int) or isinstance(context, bool) or context < 1:
            raise ProtocolError(f"dataset row {index} has invalid context_tokens")
        contexts.add(context)
        if "prompt_file" in row:
            raise ProtocolError(f"dataset row {index} must materialize prompt text, not prompt_file")
        try:
            canonical.append(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
            raise ProtocolError(f"dataset row {index} is not strict JSON") from exc
    workload = b"\n".join(canonical) + b"\n"
    if len(workload) > MAX_WORKLOAD_BYTES:
        raise ProtocolError(f"materialized workload exceeds {MAX_WORKLOAD_BYTES} bytes")
    return workload, tuple(sorted(contexts))


def load_client_benchmark(path: str | Path, *, trust_factory: bool = False) -> ClientBenchmark:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ProtocolError("client benchmark config must not be a symlink")
    resolved = candidate.resolve()
    try:
        source = _read_regular(resolved.parent, Path(resolved.name))
        if len(source) > MAX_CONFIG_BYTES:
            raise ProtocolError(f"client benchmark config exceeds {MAX_CONFIG_BYTES} bytes")
        config = tomllib.loads(source.decode("utf-8"))
    except ProtocolError:
        raise
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot load client benchmark config: {exc}") from exc
    if contains_secret_like(config):
        raise ProtocolError("client benchmark config appears to contain a secret; use target.api_key_env")
    _reject_unknown(
        config,
        {
            "benchmark_version",
            "name",
            "dataset",
            "factory",
            "concurrency",
            "warmup_requests",
            "duration_seconds",
            "repetitions",
            "timeout",
            "max_requests",
            "output_tokens",
            "data_classification",
            "target",
        },
        "client benchmark",
    )
    if config.get("benchmark_version") != CLIENT_BENCHMARK_VERSION:
        raise ProtocolError(f"client benchmark requires benchmark_version={CLIENT_BENCHMARK_VERSION}")
    name = config.get("name")
    if not isinstance(name, str) or not name or name[0] not in "abcdefghijklmnopqrstuvwxyz0123456789" or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in name
    ):
        raise ProtocolError("client benchmark name must use lowercase letters, digits, dash, underscore, or dot")
    if ("dataset" in config) == ("factory" in config):
        raise ProtocolError("client benchmark requires exactly one of dataset or trusted factory")
    concurrency_value = config.get("concurrency")
    if not isinstance(concurrency_value, list) or not concurrency_value:
        raise ProtocolError("client benchmark concurrency must be a non-empty array")
    concurrency = [_integer(value, "client benchmark concurrency", 1, 4096) for value in concurrency_value]
    if len(set(concurrency)) != len(concurrency):
        raise ProtocolError("client benchmark concurrency values must be unique")
    config["concurrency"] = concurrency
    config["warmup_requests"] = _integer(config.get("warmup_requests"), "client benchmark warmup_requests", 0, 100_000)
    config["repetitions"] = _integer(config.get("repetitions"), "client benchmark repetitions", 1, 20)
    config["duration_seconds"] = _number(config.get("duration_seconds"), "client benchmark duration_seconds", minimum=0.001, maximum=86_400)
    config["timeout"] = _number(config.get("timeout"), "client benchmark timeout", minimum=0.001, maximum=86_400)
    config["max_requests"] = _integer(config.get("max_requests", 1_000_000), "client benchmark max_requests", 1, 1_000_000)
    config["output_tokens"] = _integer(config.get("output_tokens", 128), "client benchmark output_tokens", 1, 1_000_000)
    data_classification = config.get("data_classification", "synthetic")
    if data_classification not in {"public", "synthetic"}:
        raise ProtocolError("client benchmark data_classification must be public or synthetic")
    config["data_classification"] = data_classification

    target = config.get("target")
    if not isinstance(target, dict):
        raise ProtocolError("client benchmark target must be a table")
    _reject_unknown(
        target,
        {
            "endpoint",
            "model",
            "expected_model",
            "model_revision",
            "api_key_env",
            "max_context_tokens",
            "pricing",
        },
        "client benchmark target",
    )
    required_target = ("endpoint", "model", "model_revision", "api_key_env")
    if any(not isinstance(target.get(field), str) or not target[field] for field in required_target):
        raise ProtocolError(f"client benchmark target requires non-empty fields: {required_target}")
    if not str(target["api_key_env"]).isidentifier():
        raise ProtocolError("client benchmark target.api_key_env must be an environment-variable name")
    endpoint = urllib.parse.urlsplit(str(target["endpoint"]))
    if (
        endpoint.scheme not in {"http", "https"}
        or not endpoint.hostname
        or endpoint.username
        or endpoint.password
        or endpoint.query
        or endpoint.fragment
        or (endpoint.scheme != "https" and endpoint.hostname not in {"127.0.0.1", "localhost", "::1"})
    ):
        raise ProtocolError("client benchmark target.endpoint requires HTTPS or loopback and no credentials, query, or fragment")
    if "expected_model" in target and (not isinstance(target["expected_model"], str) or not target["expected_model"]):
        raise ProtocolError("client benchmark target.expected_model must be non-empty text")
    if "max_context_tokens" in target:
        _integer(target["max_context_tokens"], "client benchmark target.max_context_tokens", 1, 2**31 - 1)
    pricing = target.get("pricing")
    if pricing is not None:
        if not isinstance(pricing, dict) or set(pricing) != {"currency", "source", "effective_at", "input_per_million", "output_per_million"}:
            raise ProtocolError("client benchmark target.pricing requires currency, source, effective_at, input_per_million, and output_per_million")
        if any(not isinstance(pricing[field], str) or not pricing[field] for field in ("currency", "source", "effective_at")):
            raise ProtocolError("client benchmark target.pricing text fields must be non-empty")
        for field in ("input_per_million", "output_per_million"):
            _number(pricing[field], f"client benchmark target.pricing.{field}", minimum=0, maximum=1_000_000)

    if "dataset" in config:
        relative = _safe_relative(config["dataset"], "client benchmark dataset")
        try:
            dataset_source = _read_regular(resolved.parent, relative)
        except OSError as exc:
            raise ProtocolError("cannot read client benchmark dataset") from exc
        if len(dataset_source) > MAX_WORKLOAD_BYTES:
            raise ProtocolError(f"client benchmark dataset exceeds {MAX_WORKLOAD_BYTES} bytes")
        rows: list[dict[str, Any]] = []
        try:
            for index, line in enumerate(dataset_source.decode("utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                value = _strict_json_loads(line)
                if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
                    raise ProtocolError(f"client benchmark dataset line {index} must be an object")
                rows.append(cast(dict[str, Any], value))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ProtocolError("client benchmark dataset must be strict UTF-8 JSONL") from exc
        workload, contexts = _materialize_rows(rows)
    else:
        factory = config["factory"]
        if not isinstance(factory, str):
            raise ProtocolError("factory must use trusted module:callable syntax")
        workload, contexts = _materialize_rows(_load_factory(factory, trusted=trust_factory, root=resolved.parent))
    if not contexts:
        raise ProtocolError("client benchmark dataset is empty")
    minimum_requests = len(contexts) * len(concurrency) * int(config["repetitions"]) * (int(config["warmup_requests"]) + 1)
    if int(config["max_requests"]) < minimum_requests:
        raise ProtocolError("client benchmark max_requests must leave room for at least one measured request")
    return ClientBenchmark(resolved, sha256_bytes(source), config, workload, contexts)


def _quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def plan_client_benchmark(
    benchmark: ClientBenchmark | str | Path, directory: str | Path, *, trust_factory: bool = False
) -> PlannedClientBenchmark:
    loaded = load_client_benchmark(benchmark, trust_factory=trust_factory) if isinstance(benchmark, (str, Path)) else benchmark
    root = Path(directory)
    try:
        root.mkdir(mode=0o700)
    except OSError as exc:
        raise ProtocolError("client benchmark planning directory must not already exist") from exc
    workload_path = root / "workload.jsonl"
    _write_once(workload_path, loaded.workload_bytes)
    config = loaded.config
    target = cast(dict[str, Any], config["target"])
    pricing = target.get("pricing")
    maximum_context = max(loaded.contexts)
    output_tokens = int(config["output_tokens"])
    timeout = float(config["timeout"])
    cells = len(loaded.contexts) * len(cast(list[int], config["concurrency"])) * int(config["repetitions"])
    maximum_campaign = max(
        30.0,
        float(config["duration_seconds"]) * cells
        + timeout * (int(config["warmup_requests"]) + 1) * cells
        + 30.0,
    )
    workload_sha256 = sha256_bytes(loaded.workload_bytes)
    contexts = ", ".join(str(value) for value in loaded.contexts)
    concurrency = ", ".join(str(value) for value in cast(list[int], config["concurrency"]))
    dataset_source = str(config.get("factory", config.get("dataset", "materialized")))
    plan_source = f'''# client_config_sha256 = {loaded.sha256}
# client_dataset_source = {_quoted(dataset_source)}
plan_version = "1.0.0"
revision = "1.0.0"
name = {_quoted(str(config["name"]))}
description = "Materialized client benchmark using the Cavada performance core."
profile = "client-benchmark-v1"
data_classification = {_quoted(str(config["data_classification"]))}
[workload]
id = {_quoted(str(config["name"]) + "-workload")}
revision = "1.0.0"
path = "workload.jsonl"
sha256 = "{workload_sha256}"
mode = "iso-prompt"
input_token_tolerance_fraction = 1
[generation]
stream = true
temperature = 0
[execution]
repetitions = {config["repetitions"]}
warmup_requests = {config["warmup_requests"]}
measured_requests = 1
open_loop_duration_seconds = 0
bootstrap_samples = 100
seed = 0
randomize_cells = false
cooldown_seconds = 0
max_in_flight = {max(cast(list[int], config["concurrency"]))}
[limits]
timeout_seconds = {timeout}
max_requests = {config["max_requests"]}
max_total_tokens = {int(config["max_requests"]) * (maximum_context + output_tokens)}
max_campaign_seconds = {maximum_campaign}
max_context_tokens = {maximum_context}
max_output_tokens = {output_tokens}
[slo]
ttft_p95_ms = {timeout * 1000}
e2e_p99_ms = {timeout * 1000}
goodput_ttft_ms = {timeout * 1000}
goodput_e2e_ms = {timeout * 1000}
maximum_error_rate = 1
minimum_output_tokens_fraction = 0
[[scenarios]]
id = "client-concurrency-sweep"
arrival = "closed-loop"
context_tokens = [{contexts}]
output_tokens = [{output_tokens}]
concurrency = [{concurrency}]
duration_seconds = {config["duration_seconds"]}
'''
    plan_path = root / "plan.toml"
    _write_once(plan_path, plan_source.encode("utf-8"))

    expected_model = str(target.get("expected_model", target["model"]))
    model_revision = str(target["model_revision"])
    runtime_max_context = _integer(
        target.get("max_context_tokens", maximum_context + output_tokens),
        "client benchmark target.max_context_tokens",
        maximum_context + output_tokens,
        2**31 - 1,
    )
    runtime_source = f'''runtime_version = "1.0.0"
runtime_profile = "client-benchmark-v1"
hardware_observed = false
id = {_quoted(str(config["name"]) + "-target")}
endpoint = {_quoted(str(target["endpoint"]))}
request_model = {_quoted(str(target["model"]))}
expected_model = {_quoted(expected_model)}
model_revision = {_quoted(model_revision)}
api_key_env = {_quoted(str(target["api_key_env"]))}
engine = "not-observed"
engine_revision = "not-observed"
model_artifact_revision = "not-observed"
dtype = "not-reported"
quantization = "not-reported"
gpu_count = 0
gpu_model = "not-observed"
tensor_parallel = 0
max_context_tokens = {runtime_max_context}
container_image_digest = ""
launch_command_sanitized = "externally-managed-openai-compatible-endpoint"
'''
    if isinstance(pricing, dict):
        runtime_source += f'''[pricing]
currency = {_quoted(str(pricing["currency"]))}
source = {_quoted(str(pricing["source"]))}
effective_at = {_quoted(str(pricing["effective_at"]))}
input_per_million = {float(pricing["input_per_million"])}
output_per_million = {float(pricing["output_per_million"])}
'''
    runtime_path = root / "runtime.toml"
    _write_once(runtime_path, runtime_source.encode("utf-8"))
    plan = load_performance_plan(plan_path)
    runtime = load_performance_runtime(runtime_path)
    return PlannedClientBenchmark(root.resolve(), plan, runtime)


def run_client_benchmark(
    benchmark: ClientBenchmark | str | Path,
    *,
    repo_root: Path,
    output_root: Path | None = None,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    signing_key_id: str = "",
    trust_factory: bool = False,
) -> Path:
    loaded = load_client_benchmark(benchmark, trust_factory=trust_factory) if isinstance(benchmark, (str, Path)) else benchmark
    api_key_env = str(cast(dict[str, Any], loaded.config["target"])["api_key_env"])
    if not os.getenv(api_key_env):
        raise ProtocolError(f"environment variable {api_key_env} is not set; no network request was sent")
    client_output = output_root or loaded.path.parent / "runs" / "performance" / str(loaded.config["name"])
    with tempfile.TemporaryDirectory(prefix="cavada-client-benchmark-") as temporary:
        planned = plan_client_benchmark(loaded, Path(temporary) / "inputs")
        return run_performance_campaign(
            planned.plan,
            planned.runtime,
            repo_root=repo_root,
            output_root=client_output,
            signing_key_env=signing_key_env,
            signing_key_id=signing_key_id,
        )
