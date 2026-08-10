from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .protocol import ProtocolError, atomic_json, contains_secret_like, require_mutable_output_root, sha256_bytes

SHA256 = re.compile(r"^[a-f0-9]{64}$")
STATUSES = {"pass", "fail", "invalid", "error", "skipped"}
LM_EVAL_ADAPTER = "lm-evaluation-harness-results/1.0.0"
VLLM_BENCH_ADAPTER = "vllm-bench-serve/1.0.0"
VLLM_SUMMARY_FIELDS = (
    "duration",
    "completed",
    "failed",
    "total_input_tokens",
    "total_output_tokens",
    "request_throughput",
    "request_goodput",
    "input_throughput",
    "output_throughput",
    "total_token_throughput",
    "max_output_tokens_per_s",
    "max_concurrent_requests",
    "rtfx",
    "mean_ttft_ms",
    "median_ttft_ms",
    "std_ttft_ms",
    "percentiles_ttft_ms",
    "mean_tpot_ms",
    "median_tpot_ms",
    "std_tpot_ms",
    "percentiles_tpot_ms",
    "mean_itl_ms",
    "median_itl_ms",
    "std_itl_ms",
    "percentiles_itl_ms",
    "mean_e2el_ms",
    "median_e2el_ms",
    "std_e2el_ms",
    "percentiles_e2el_ms",
    "steady_state",
)
VLLM_PERCENTILE = re.compile(r"^p\d+(?:\.\d+)?_(?:ttft|tpot|itl|e2el)_ms$")


def _load_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise ProtocolError(f"{label} must be a regular file")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"{label} must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a JSON object")
    if not _finite_json(value):
        raise ProtocolError(f"{label} contains non-finite JSON values")
    return value, raw


def _non_empty_strings(value: Any, fields: set[str], label: str, allowed: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be an object")
    missing = fields - set(value)
    if missing:
        raise ProtocolError(f"{label} is missing fields: {sorted(missing)}")
    unknown = set(value) - (allowed or fields)
    if unknown:
        raise ProtocolError(f"{label} has unsupported fields: {sorted(unknown)}")
    if any(not isinstance(value[field], str) or not value[field].strip() for field in fields):
        raise ProtocolError(f"{label} fields must be non-empty strings")
    return value


def _source_metadata(value: Any, expected_name: str | None = None) -> dict[str, Any]:
    required = {"name", "version", "commit", "license", "dataset_sha256", "evaluator_sha256", "invocation"}
    allowed = required if expected_name is not None else required | {"artifact_sha256", "adapter", "evaluation_repository_commit"}
    metadata = _non_empty_strings(value, required, "external source metadata", allowed)
    if expected_name is not None and metadata["name"] != expected_name:
        raise ProtocolError(f"adapter requires source.name={expected_name!r}")
    if not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", metadata["commit"]):
        raise ProtocolError("external source commit must be an immutable Git SHA")
    if not SHA256.fullmatch(metadata["dataset_sha256"]) or not SHA256.fullmatch(metadata["evaluator_sha256"]):
        raise ProtocolError("external dataset and evaluator hashes must be SHA-256")
    return metadata


def _identity(value: Any) -> dict[str, Any]:
    identity = _non_empty_strings(
        value,
        {"model_id", "model_revision", "model_sha", "runtime_name", "runtime_version", "runtime_revision"},
        "adapter identity",
    )
    if not SHA256.fullmatch(identity["model_sha"]):
        raise ProtocolError("adapter identity model_sha must be a lowercase SHA-256")
    return identity


def _suite(value: Any, *, normalized: bool = False) -> dict[str, Any]:
    required = {"id", "version", "sha256"}
    suite = _non_empty_strings(value, required, "adapter suite", required | ({"identity", "upstream_format"} if normalized else set()))
    if not SHA256.fullmatch(suite["sha256"]):
        raise ProtocolError("adapter suite sha256 must be SHA-256")
    return suite


def _outcome(value: Any, unit: str) -> tuple[str, dict[str, Any]]:
    if value is None:
        return "invalid", {"status": "invalid", "reason": f"no explicit outcome mapping for {unit}"}
    outcome = _non_empty_strings(value, {"status", "reason"}, f"outcome for {unit}")
    if outcome["status"] not in STATUSES:
        raise ProtocolError(f"outcome for {unit} has unsupported status")
    return str(outcome["status"]), dict(outcome)


def _adapter_artifact(descriptor_path: Path, descriptor: dict[str, Any]) -> tuple[Path, dict[str, Any], str, bytes]:
    relative = descriptor.get("artifact")
    expected_hash = descriptor.get("artifact_sha256")
    if not isinstance(relative, str) or not relative.strip() or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ProtocolError("adapter artifact must be a safe relative path")
    if not isinstance(expected_hash, str) or not SHA256.fullmatch(expected_hash):
        raise ProtocolError("adapter artifact_sha256 must be SHA-256")
    unresolved = descriptor_path.parent / relative
    if unresolved.is_symlink():
        raise ProtocolError("adapter artifact must not be a symlink")
    artifact_path = unresolved.resolve()
    try:
        artifact_path.relative_to(descriptor_path.parent.resolve())
    except ValueError as exc:
        raise ProtocolError("adapter artifact escapes the descriptor directory") from exc
    artifact, raw = _load_object(artifact_path, "upstream artifact")
    actual_hash = sha256_bytes(raw)
    if actual_hash != expected_hash:
        raise ProtocolError("upstream artifact hash does not match adapter descriptor")
    return artifact_path, artifact, actual_hash, raw


def _lm_eval_contract(descriptor: dict[str, Any], artifact: dict[str, Any], artifact_hash: str) -> dict[str, Any]:
    metadata = _source_metadata(descriptor.get("source"), "lm-evaluation-harness")
    identity = _identity(descriptor.get("identity"))
    suite = _suite(descriptor.get("suite"))
    evaluation_commit = descriptor.get("evaluation_repository_commit")
    if not isinstance(evaluation_commit, str) or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", evaluation_commit):
        raise ProtocolError("lm-eval descriptor requires a full evaluation repository commit")
    upstream_commit = artifact.get("git_hash")
    abbreviated = (
        re.fullmatch(r"[a-f0-9]{7,64}", upstream_commit or "")
        or re.search(r"-g([a-f0-9]{7,64})$", upstream_commit or "")
    )
    if abbreviated is None or not evaluation_commit.startswith(abbreviated.group(1 if abbreviated.lastindex else 0)):
        raise ProtocolError("lm-eval artifact commit differs from the pinned evaluation repository")
    if artifact.get("lm_eval_version") != metadata["version"]:
        raise ProtocolError("lm-eval artifact version differs from pinned source")
    if artifact.get("model_name") != identity["model_id"] or artifact.get("model_source") != identity["runtime_name"]:
        raise ProtocolError("lm-eval artifact model/runtime identity differs from adapter identity")
    config = artifact.get("config")
    if not isinstance(config, dict):
        raise ProtocolError("lm-eval artifact lacks model configuration")
    for field in ("model_revision", "model_sha"):
        if field in config and config[field] != identity[field]:
            raise ProtocolError("lm-eval artifact model revision/SHA differs from adapter identity")

    mappings = descriptor.get("outcomes", {})
    if not isinstance(mappings, dict):
        raise ProtocolError("lm-eval outcomes must be an object keyed by task")
    results = artifact.get("results")
    supporting: dict[str, dict[str, Any]] = {}
    for name in ("configs", "versions", "n-shot", "higher_is_better", "n-samples", "task_hashes"):
        value = artifact.get(name)
        if isinstance(value, dict):
            supporting[name] = value
    if not isinstance(results, dict) or not results or len(supporting) != 6:
        raise ProtocolError("unsupported or incomplete lm-eval aggregate result format")
    unknown_mappings = set(mappings) - set(results)
    if unknown_mappings:
        raise ProtocolError(f"lm-eval outcomes reference unknown tasks: {sorted(unknown_mappings)}")

    imported: list[dict[str, Any]] = []
    for task_id, metrics in results.items():
        if not isinstance(task_id, str) or not task_id.strip() or not isinstance(metrics, dict):
            raise ProtocolError("lm-eval results require non-empty task IDs and metric objects")
        if any(task_id not in supporting[name] for name in supporting):
            raise ProtocolError(f"lm-eval task {task_id!r} lacks configuration or sample identity")
        if not SHA256.fullmatch(str(supporting["task_hashes"][task_id])):
            raise ProtocolError(f"lm-eval task {task_id!r} lacks a SHA-256 task hash")
        sample_count = supporting["n-samples"][task_id]
        if not isinstance(sample_count, dict) or not isinstance(sample_count.get("effective"), int) or isinstance(sample_count.get("effective"), bool):
            raise ProtocolError(f"lm-eval task {task_id!r} has invalid sample counts")
        status, outcome = _outcome(mappings.get(task_id), task_id)
        if sample_count["effective"] <= 0 and status in {"pass", "fail"}:
            status = "invalid"
            outcome = {"status": status, "reason": "task has no effective samples", "declared_outcome": outcome}
        imported.append(
            {
                "case_id": task_id,
                "status": status,
                "status_evidence": outcome,
                "identity": identity,
                "task": {
                    "id": task_id,
                    "sha256": supporting["task_hashes"][task_id],
                    "config": supporting["configs"][task_id],
                    "version": supporting["versions"][task_id],
                    "n_shot": supporting["n-shot"][task_id],
                    "higher_is_better": supporting["higher_is_better"][task_id],
                    "n_samples": sample_count,
                },
                "metrics": metrics,
            }
        )
    return {
        "adapter_version": "1.0.0",
        "source": {
            **metadata,
            "artifact_sha256": artifact_hash,
            "adapter": LM_EVAL_ADAPTER,
            "evaluation_repository_commit": evaluation_commit,
        },
        "suite": {**suite, "identity": identity, "upstream_format": "lm-evaluation-harness aggregate results"},
        "results": imported,
    }


def _integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProtocolError(f"vLLM benchmark {label} must be a non-negative integer")
    return value


def _vllm_bench_contract(descriptor: dict[str, Any], artifact: dict[str, Any], artifact_hash: str) -> dict[str, Any]:
    metadata = _source_metadata(descriptor.get("source"), "vllm")
    identity = _identity(descriptor.get("identity"))
    suite = _suite(descriptor.get("suite"))
    cell_id = descriptor.get("cell_id")
    cell_sha256 = descriptor.get("cell_sha256")
    if not isinstance(cell_id, str) or not cell_id.strip():
        raise ProtocolError("vLLM benchmark descriptor requires a non-empty cell_id")
    if not isinstance(cell_sha256, str) or not SHA256.fullmatch(cell_sha256):
        raise ProtocolError("vLLM benchmark descriptor requires a cell_sha256")
    required = {"date", "backend", "model_id", "num_prompts", "request_rate", "duration", "completed", "failed", "total_input_tokens", "request_throughput"}
    if required - set(artifact):
        raise ProtocolError(f"unsupported vLLM bench result; missing fields: {sorted(required - set(artifact))}")
    if artifact["model_id"] != identity["model_id"]:
        raise ProtocolError("vLLM bench model_id differs from adapter identity")
    endpoint_backend = descriptor.get("endpoint_backend")
    if endpoint_backend not in {"vllm", "openai", "openai-chat"} or endpoint_backend != artifact["backend"]:
        raise ProtocolError("vLLM bench endpoint_backend differs from upstream artifact")
    if artifact.get("endpoint_type", endpoint_backend) != endpoint_backend:
        raise ProtocolError("vLLM bench endpoint_type and backend disagree")
    if not isinstance(artifact["date"], str) or not artifact["date"].strip():
        raise ProtocolError("vLLM benchmark date must be a non-empty string")
    for field in ("duration", "request_throughput"):
        value = artifact[field]
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)) or float(value) < 0:
            raise ProtocolError(f"vLLM benchmark {field} must be a finite non-negative number")
    num_prompts = _integer(artifact["num_prompts"], "num_prompts")
    completed = _integer(artifact["completed"], "completed")
    failed = _integer(artifact["failed"], "failed")
    _integer(artifact["total_input_tokens"], "total_input_tokens")
    request_rate = artifact["request_rate"]
    if request_rate != "inf" and (
        not isinstance(request_rate, (int, float))
        or isinstance(request_rate, bool)
        or not math.isfinite(float(request_rate))
        or float(request_rate) <= 0
    ):
        raise ProtocolError("vLLM benchmark request_rate must be 'inf' or a finite positive number")
    max_concurrency = artifact.get("max_concurrency")
    if max_concurrency is not None and (not isinstance(max_concurrency, int) or isinstance(max_concurrency, bool) or max_concurrency <= 0):
        raise ProtocolError("vLLM benchmark max_concurrency must be a positive integer or null")
    if num_prompts == 0:
        raise ProtocolError("vLLM benchmark num_prompts must be positive")

    status, outcome = _outcome(descriptor.get("outcome"), cell_id)
    if completed + failed != num_prompts:
        status = "invalid"
        outcome = {"status": status, "reason": "completed + failed does not equal num_prompts", "declared_outcome": outcome}
    elif failed:
        errors = artifact.get("errors")
        if not isinstance(errors, list) or len(errors) != num_prompts or sum(bool(error) for error in errors) != failed:
            status = "invalid"
            outcome = {"status": status, "reason": "failure count lacks matching detailed error evidence", "declared_outcome": outcome}
        else:
            status = "error"
            outcome = {"status": status, "reason": "one or more upstream requests failed", "declared_outcome": outcome}
    elif completed == 0:
        status = "invalid"
        outcome = {"status": status, "reason": "cell has no successful observations", "declared_outcome": outcome}
    elif status == "skipped":
        raise ProtocolError("a vLLM artifact containing completed requests cannot be mapped to skipped")

    return {
        "adapter_version": "1.0.0",
        "source": {**metadata, "artifact_sha256": artifact_hash, "adapter": VLLM_BENCH_ADAPTER},
        "suite": {**suite, "identity": identity, "upstream_format": "vllm bench serve single-run JSON"},
        "results": [
            {
                "case_id": cell_id,
                "status": status,
                "status_evidence": outcome,
                "identity": identity,
                "cell": {
                    "id": cell_id,
                    "sha256": cell_sha256,
                    "backend": endpoint_backend,
                    "request_rate": artifact["request_rate"],
                    "max_concurrency": artifact.get("max_concurrency"),
                    "num_prompts": num_prompts,
                },
                "metrics": {
                    key: artifact[key]
                    for key in sorted(artifact)
                    if key in VLLM_SUMMARY_FIELDS or VLLM_PERCENTILE.fullmatch(key)
                },
            }
        ],
    }


def _validate_contract(source: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    if source.get("adapter_version") != "1.0.0":
        raise ProtocolError("unsupported external adapter contract")
    metadata = _source_metadata(source.get("source"))
    suite = _suite(source.get("suite"), normalized=True)
    identity = _identity(suite.get("identity"))
    results = source.get("results")
    if not isinstance(results, list) or not results:
        raise ProtocolError("external import requires non-empty results")
    seen: set[str] = set()
    for index, result in enumerate(results):
        if not isinstance(result, dict) or not isinstance(result.get("case_id"), str) or not result["case_id"].strip() or result.get("status") not in STATUSES:
            raise ProtocolError(f"external result {index} requires a non-empty case_id and a valid status")
        if result["case_id"] in seen:
            raise ProtocolError(f"duplicate external result case_id: {result['case_id']}")
        status_evidence = result.get("status_evidence")
        if (
            result.get("identity") != identity
            or not isinstance(status_evidence, dict)
            or status_evidence.get("status") != result["status"]
            or not isinstance(status_evidence.get("reason"), str)
            or not status_evidence["reason"].strip()
            or not isinstance(result.get("metrics"), dict)
        ):
            raise ProtocolError(f"external result {index} lacks exact identity, outcome, or metric evidence")
        if not _finite_json(result):
            raise ProtocolError(f"external result {index} contains non-finite JSON values")
        seen.add(result["case_id"])
    return metadata, suite, results


def _finite_json(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_finite_json(item) for item in value)
    return isinstance(value, dict) and all(isinstance(key, str) and _finite_json(item) for key, item in value.items())


def import_external_results(source_path: Path, output_dir: Path) -> dict[str, Any]:
    require_mutable_output_root(output_dir)
    if output_dir.exists():
        raise ProtocolError("external import output directory already exists")
    descriptor, descriptor_raw = _load_object(source_path, "external import source")
    adapter = descriptor.get("adapter_version")
    if adapter not in {LM_EVAL_ADAPTER, VLLM_BENCH_ADAPTER}:
        raise ProtocolError(f"unsupported external adapter: {adapter!r}")
    common = {"adapter_version", "artifact", "artifact_sha256", "source", "identity", "suite"}
    allowed = common | (
        {"outcomes", "evaluation_repository_commit"}
        if adapter == LM_EVAL_ADAPTER
        else {"cell_id", "cell_sha256", "endpoint_backend", "outcome"}
    )
    if unknown := set(descriptor) - allowed:
        raise ProtocolError(f"external adapter descriptor has unsupported fields: {sorted(unknown)}")
    upstream_path, upstream, upstream_hash, upstream_raw = _adapter_artifact(source_path, descriptor)
    source = _lm_eval_contract(descriptor, upstream, upstream_hash) if adapter == LM_EVAL_ADAPTER else _vllm_bench_contract(descriptor, upstream, upstream_hash)
    metadata, suite, results = _validate_contract(source)
    if contains_secret_like(descriptor) or contains_secret_like(source) or contains_secret_like(upstream):
        raise ProtocolError("external import contains secret-like material")

    status_counts = Counter(str(result["status"]) for result in results)
    manifest = {
        "external_import_version": "1.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_artifact": str(source_path.name),
        "source_artifact_sha256": sha256_bytes(descriptor_raw),
        "upstream_artifact": {"name": upstream_path.name, "sha256": sha256_bytes(upstream_raw), "bundle_path": "upstream_artifact.json"},
        "adapter": str(adapter),
        "source": metadata,
        "suite": suite,
        "result_count": len(results),
        "status_counts": {status: status_counts.get(status, 0) for status in sorted(STATUSES)},
        "official": False,
        "assurance": "development-import",
        "limitations": [
            "Imported evidence retains upstream methodology and license limitations",
            "External imports are never CavadaLabs official results",
            "Adapter-recorded identities remain subject to their upstream evidence",
        ],
    }
    output_dir.mkdir(parents=True, mode=0o700)
    atomic_json(output_dir / "manifest.json", manifest)
    atomic_json(output_dir / "imported_results.json", results)
    (output_dir / "source_artifact.json").write_bytes(descriptor_raw)
    os.chmod(output_dir / "source_artifact.json", 0o600)
    (output_dir / "upstream_artifact.json").write_bytes(upstream_raw)
    os.chmod(output_dir / "upstream_artifact.json", 0o600)
    write_bundle(output_dir)
    verification = verify_bundle(output_dir, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("external import bundle verification failed")
    return manifest
