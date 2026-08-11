from __future__ import annotations

import gzip
import json
import re
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from shutil import copyfile as _snapshot_copyfile
from typing import Any, cast
from urllib.parse import urlsplit

from .artifacts import verify_bundle, write_bundle
from .performance import (
    PERFORMANCE_PLAN_VERSION,
    PERFORMANCE_PROTOCOL_VERSION,
    PERFORMANCE_REPORT_VERSION,
    _campaign_summary,
    _finite_json,
    _performance_comparison_input_snapshot,
    _performance_reports,
    _read_performance_governance_json,
    _require_official_reference_inputs,
    _structural_unavailable,
    _write_cells_csv,
)
from .protocol import ProtocolError, atomic_json, atomic_text, contains_secret_like, require_mutable_output_root, sha256_bytes, sha256_file
from .release import _evidence_error, _read_object, _time, _usable
from .system_evidence import load_system_evidence, public_system_evidence

PERFORMANCE_PUBLICATION_VERSION = "2.0.0"
PERMITTED_CLAIM = "Bounded LLM serving performance under the named protocol, plan, workload, runtime, hardware configuration, and network conditions."
_RUNTIME_FIELDS = (
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
    "container_image_digest",
    "launch_command_sanitized",
    "pricing",
    "sha256",
)
_OBSERVATION_FIELDS = (
    "cell_key",
    "scenario_id",
    "block",
    "phase",
    "request_index",
    "workload_id",
    "declared_context_tokens",
    "requested_output_tokens",
    "client_queue_ms",
    "scheduled_monotonic_ns",
    "batch_started_monotonic_ns",
    "started_monotonic_ns",
    "finished_monotonic_ns",
    "status",
    "reported_model",
    "input_tokens",
    "output_tokens",
    "input_token_match",
    "ttft_ms",
    "e2e_ms",
    "tpot_ms",
    "decode_tokens_per_second",
    "headers_ms",
    "inter_chunk_ms",
    "request_bytes",
    "response_bytes",
    "error_type",
    "fatal",
)
_OBSERVATION_FIELDS_V2 = (
    *_OBSERVATION_FIELDS,
    "dispatch_monotonic_ns",
    "first_token_monotonic_ns",
    "completed_monotonic_ns",
    "dispatch_lag_ms",
    "scheduled_ttft_ms",
    "scheduled_e2e_ms",
)
_CELL_FIELDS = (
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
    "error_types",
    "error_rate",
    "slo_passed",
    "slo_gates",
    "goodput_requests",
    "goodput_requests_per_second",
    "requests_per_second",
    "input_tokens_per_second",
    "output_tokens_per_second",
    "input_tokens_total",
    "output_tokens_total",
    "estimated_cost",
    "measurement_window_seconds",
    "ttft_ms",
    "e2e_ms",
    "p99_resolution",
    "tpot_ms",
    "decode_tokens_per_second",
    "client_queue_ms",
    "input_tokens",
    "actual_output_tokens",
    "warnings",
    "block",
    "reason",
)
_CELL_FIELDS_V2 = (
    *_CELL_FIELDS,
    "throughput_window_seconds",
    "offered_requests",
    "dispatched_requests",
    "completed_requests",
    "offered_requests_per_second",
    "dispatched_requests_per_second",
    "completed_requests_per_second",
    "dispatch_rate_fidelity",
    "dispatch_lag_ms",
    "scheduled_ttft_ms",
    "scheduled_e2e_ms",
    "load_generator_valid",
    "load_generator_gates",
    "load_generator_invalid_reasons",
    "serving_slo_passed",
)
_USER_PATH = re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\Users\\)")
_DISTRIBUTION_FIELDS = ("count", "min", "max", "mean", "median", "stdev", "p50", "p90", "p95", "p99")
_INTERVAL_FIELDS = ("lower", "upper", "confidence", "samples", "seed")


def _public_presentation_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("performance_protocol_version") != PERFORMANCE_PROTOCOL_VERSION:
        raise ProtocolError("public performance presentation requires protocol 2.0.0")
    return {
        **manifest,
        "report_version": PERFORMANCE_REPORT_VERSION,
        "finished_at": manifest["evaluation_finished_at"],
        "officially_valid": manifest["official"],
        "rankable": manifest["official"],
        "semantic_valid": True,
        "authenticity": "unverified",
    }


def _release_approval(run_dir: Path, manifest: dict[str, Any], path: Path, now: datetime) -> dict[str, Any]:
    if now.tzinfo is None:
        raise ProtocolError("performance release approval verification time must include a timezone")
    approval, approval_raw = _read_performance_governance_json(path, "performance release approval")
    required = {
        "release_version",
        "release_id",
        "status",
        "run_id",
        "bundle_sha256",
        "manifest_sha256",
        "configuration_id",
        "engagement_id",
        "engagement_sha256",
        "execution_owner_id",
        "approver_id",
        "independent",
        "conflicts",
        "conflict_mitigation",
        "permitted_claims",
        "limitations_acknowledged",
        "review_evidence",
        "review_evidence_sha256",
        "qualification_evidence",
        "qualification_evidence_sha256",
        "approved_at",
        "expires_at",
    }
    errors: list[str] = []
    if set(approval) != required:
        errors.append(f"release approval fields differ; missing={sorted(required - set(approval))}, unknown={sorted(set(approval) - required)}")
    evidence = manifest.get("system_evidence") or {}
    execution_record_value = manifest.get("execution_record")
    execution_record = execution_record_value if isinstance(execution_record_value, dict) else {}
    engagement_value = manifest.get("engagement")
    engagement = engagement_value if isinstance(engagement_value, dict) else {}
    if manifest.get("performance_protocol_version") != PERFORMANCE_PROTOCOL_VERSION:
        raise ProtocolError("performance release approval requires protocol 2.0.0")
    publication_version = PERFORMANCE_PUBLICATION_VERSION
    expected = {
        "release_version": publication_version,
        "status": "approved",
        "run_id": manifest.get("run_id"),
        "bundle_sha256": sha256_file(run_dir / "bundle.json"),
        "manifest_sha256": sha256_file(run_dir / "manifest.json"),
        "configuration_id": evidence.get("configuration_id"),
        "engagement_id": engagement.get("engagement_id"),
        "engagement_sha256": engagement.get("sha256"),
        "execution_owner_id": execution_record.get("execution_owner_id"),
    }
    errors.extend(f"release approval {field} does not match" for field, value in expected.items() if approval.get(field) != value)
    if not _usable(execution_record.get("execution_owner_id")):
        errors.append("performance run execution owner is missing or a placeholder")
    if engagement.get("status") != "approved" or engagement.get("execution_owner_id") != execution_record.get("execution_owner_id"):
        errors.append("performance run engagement is missing or differs from execution ownership")
    for field in ("release_id", "engagement_id", "execution_owner_id", "approver_id"):
        if not _usable(approval.get(field)):
            errors.append(f"release approval {field} is missing or a placeholder")
    if approval.get("independent") is not True or approval.get("execution_owner_id") == approval.get("approver_id"):
        errors.append("release approval must be independent of execution ownership")
    conflicts = approval.get("conflicts")
    if not isinstance(conflicts, list) or any(not _usable(item) for item in conflicts):
        errors.append("release approval conflicts must be a reviewed text array")
    elif conflicts and not _usable(approval.get("conflict_mitigation")):
        errors.append("release approval conflicts require mitigation")
    claims = approval.get("permitted_claims")
    if claims != [PERMITTED_CLAIM]:
        errors.append("release approval may permit only the bounded performance claim")
    if approval.get("limitations_acknowledged") is not True:
        errors.append("release approval must acknowledge report limitations")
    for name in ("review", "qualification"):
        error = _evidence_error(path, approval.get(f"{name}_evidence"), approval.get(f"{name}_evidence_sha256"), f"performance release {name} evidence")
        if error:
            errors.append(error)
    approved_at = _time(approval.get("approved_at"), "performance release approved_at")
    expires_at = _time(approval.get("expires_at"), "performance release expires_at")
    finished_at = _time(manifest.get("finished_at"), "performance run finished_at")
    engagement_approved_at = _time(engagement.get("approved_at"), "performance engagement approved_at")
    engagement_expires_at = _time(engagement.get("expires_at"), "performance engagement expires_at")
    if not engagement_approved_at <= finished_at <= approved_at <= now < expires_at <= engagement_expires_at:
        errors.append("performance release approval timing is invalid or outside the engagement validity period")
    if errors:
        raise ProtocolError("invalid performance release approval:\n" + "\n".join(errors))
    return {
        "release_version": publication_version,
        "release_id": approval["release_id"],
        "engagement_id": approval["engagement_id"],
        "engagement_sha256": approval["engagement_sha256"],
        "approval_sha256": sha256_bytes(approval_raw),
        "approver_id": approval["approver_id"],
        "permitted_claims": claims,
        "approved_at": approval["approved_at"],
        "expires_at": approval["expires_at"],
    }


def _copy_checked(source: Path, destination: Path, expected_hash: str | None = None, *, source_root: Path) -> None:
    try:
        relative = source.relative_to(source_root)
    except ValueError as exc:
        raise ProtocolError(f"performance publication artifact escapes its source run: {source}") from exc
    if ".." in relative.parts or not source.resolve().is_relative_to(source_root.resolve()):
        raise ProtocolError(f"performance publication artifact escapes its source run: {relative}")
    if any((source_root / Path(*relative.parts[:index])).is_symlink() for index in range(1, len(relative.parts) + 1)):
        raise ProtocolError(f"unsafe symlink in performance publication artifact: {relative}")
    if not source.is_file() or source.is_symlink():
        raise ProtocolError(f"missing or unsafe performance publication artifact: {source.name}")
    source_hash = sha256_file(source)
    if expected_hash is not None and source_hash != expected_hash:
        raise ProtocolError(f"performance publication artifact hash mismatch: {source.name}")
    if source != destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        if sha256_file(destination) != (expected_hash or source_hash):
            raise ProtocolError(f"performance publication artifact changed while copied: {source.name}")


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and _finite_json(float(value)) and value >= 0


def _contains_nested_text(value: Any) -> bool:
    if isinstance(value, str):
        return True
    if isinstance(value, list):
        return any(_contains_nested_text(item) for item in value)
    return isinstance(value, dict) and any(_contains_nested_text(item) for item in value.values())


def _project_object(value: Any, fields: tuple[str, ...], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ProtocolError(f"public performance {label} has an invalid shape")
    return {field: value[field] for field in fields}


def _project_distribution(value: Any, label: str, *, intervals: bool) -> dict[str, Any]:
    fields = (*_DISTRIBUTION_FIELDS, "p95_ci", "p99_ci") if intervals else _DISTRIBUTION_FIELDS
    projected = _project_object(value, fields, label)
    if intervals:
        for field in ("p95_ci", "p99_ci"):
            projected[field] = _project_object(projected[field], _INTERVAL_FIELDS, f"{label}.{field}")
    return projected


def _public_observations(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    public: list[dict[str, Any]] = []
    for row in rows:
        item = {field: row[field] for field in _OBSERVATION_FIELDS_V2 if field in row}
        status = item.get("status")
        if (
            status not in {"success", "error"}
            or item.get("phase") != "measured"
            or any(
                not isinstance(item.get(field), int) or isinstance(item.get(field), bool) or item[field] < 1
                for field in ("block", "request_index", "declared_context_tokens", "requested_output_tokens")
            )
            or any(
                not isinstance(item.get(field), int) or isinstance(item.get(field), bool) or item[field] < 0
                for field in ("scheduled_monotonic_ns", "batch_started_monotonic_ns", "started_monotonic_ns", "finished_monotonic_ns")
            )
            or item["finished_monotonic_ns"] <= item["started_monotonic_ns"]
            or item["started_monotonic_ns"] < item["batch_started_monotonic_ns"]
            or item["started_monotonic_ns"] < item["scheduled_monotonic_ns"]
            or not _number(item.get("client_queue_ms"))
            or not _finite_json(item)
        ):
            raise ProtocolError("public performance observations require finite terminal measurements with monotonic timing")
        dispatch = item.get("dispatch_monotonic_ns")
        if (
            not isinstance(item.get("completed_monotonic_ns"), int)
            or isinstance(item.get("completed_monotonic_ns"), bool)
            or item["completed_monotonic_ns"] < item["started_monotonic_ns"]
            or item["finished_monotonic_ns"] < item["completed_monotonic_ns"]
        ):
            raise ProtocolError("public performance observations require reconstructible v2 dispatch timing")
        if dispatch is None:
            if status == "success" or "dispatch_monotonic_ns" in item or "dispatch_lag_ms" in item:
                raise ProtocolError("public performance observations have incomplete v2 dispatch timing")
        elif (
            not isinstance(dispatch, int)
            or isinstance(dispatch, bool)
            or not item["started_monotonic_ns"] <= dispatch <= item["completed_monotonic_ns"]
            or item.get("dispatch_lag_ms") != round((dispatch - item["scheduled_monotonic_ns"]) / 1_000_000, 3)
        ):
            raise ProtocolError("public performance observations require reconstructible v2 dispatch timing")
        if status == "success":
            dispatch_ns = cast(int, dispatch)
            if (
                "error_type" in item
                or item.get("fatal") is not None
                or not isinstance(item.get("reported_model"), str)
                or not item["reported_model"]
                or not isinstance(item.get("input_token_match"), bool)
                or any(not _number(item.get(field)) for field in ("input_tokens", "output_tokens", "ttft_ms", "e2e_ms"))
                or any(float(item[field]) < 1 or not float(item[field]).is_integer() for field in ("input_tokens", "output_tokens"))
                or any(
                    item.get(field) is not None and not _number(item[field])
                    for field in ("tpot_ms", "decode_tokens_per_second", "headers_ms", "request_bytes", "response_bytes")
                )
                or _contains_nested_text(item.get("inter_chunk_ms"))
            ):
                raise ProtocolError("public successful performance observation is malformed")
            decode_ms = float(item["e2e_ms"]) - float(item["ttft_ms"])
            output_tokens = float(item["output_tokens"])
            expected_tpot = decode_ms / (output_tokens - 1) if output_tokens > 1 else None
            expected_decode = (output_tokens - 1) / (decode_ms / 1000) if output_tokens > 1 and decode_ms > 0 else None
            if (
                decode_ms < 0
                or item.get("headers_ms") is not None
                and float(item["headers_ms"]) > float(item["ttft_ms"])
                or item.get("tpot_ms") != expected_tpot
                or item.get("decode_tokens_per_second") != expected_decode
            ):
                raise ProtocolError("public performance token timing differs from latency and provider usage")
            first_token = item.get("first_token_monotonic_ns")
            if (
                not isinstance(first_token, int)
                or isinstance(first_token, bool)
                or not dispatch_ns <= first_token <= item["completed_monotonic_ns"]
                or item.get("scheduled_ttft_ms") != round((first_token - item["scheduled_monotonic_ns"]) / 1_000_000, 3)
                or item.get("scheduled_e2e_ms")
                != round((item["completed_monotonic_ns"] - item["scheduled_monotonic_ns"]) / 1_000_000, 3)
                or item.get("ttft_ms") != round((first_token - dispatch_ns) / 1_000_000, 3)
                or item.get("e2e_ms") != round((item["completed_monotonic_ns"] - dispatch_ns) / 1_000_000, 3)
            ):
                raise ProtocolError("public successful performance observation has unreconstructible scheduled timing")
        else:
            has_input = "input_tokens" in item
            has_output = "output_tokens" in item
            success_only = {
                "reported_model",
                "input_token_match",
                "ttft_ms",
                "e2e_ms",
                "tpot_ms",
                "decode_tokens_per_second",
                "headers_ms",
                "first_token_monotonic_ns",
                "scheduled_ttft_ms",
                "scheduled_e2e_ms",
            }
            if (
                not isinstance(item.get("error_type"), str)
                or not item["error_type"]
                or item.get("fatal") is True
                or item.get("fatal") is not None
                and not isinstance(item.get("fatal"), bool)
                or has_input != has_output
                or has_input
                and (
                    not _number(item["input_tokens"])
                    or float(item["input_tokens"]) < 1
                    or not float(item["input_tokens"]).is_integer()
                    or not _number(item["output_tokens"])
                    or not float(item["output_tokens"]).is_integer()
                )
                or any(field in item for field in success_only)
            ):
                raise ProtocolError("public error performance observation is malformed")
        public.append(item)
    return public


def _public_cells(
    rows: dict[tuple[int, str], dict[str, Any]],
    skipped: dict[tuple[int, str], str],
) -> list[dict[str, Any]]:
    public: list[dict[str, Any]] = []
    for _, row in sorted(rows.items()):
        item = {field: row[field] for field in _CELL_FIELDS_V2 if field in row}
        item["slo_gates"] = _project_object(item.get("slo_gates"), ("ttft_p95", "e2e_p99", "error_rate"), "SLO gates")
        item["p99_resolution"] = _project_object(
            item.get("p99_resolution"),
            ("successful_observations", "minimum", "resolved"),
            "p99 resolution",
        )
        interval_distributions = [
            "ttft_ms",
            "e2e_ms",
            "tpot_ms",
            "decode_tokens_per_second",
            "client_queue_ms",
            "dispatch_lag_ms",
            "scheduled_ttft_ms",
            "scheduled_e2e_ms",
        ]
        for field in interval_distributions:
            if field in {"dispatch_lag_ms", "scheduled_ttft_ms", "scheduled_e2e_ms"} and item.get(field) is None:
                item[field] = None
            else:
                item[field] = _project_distribution(item.get(field), field, intervals=True)
        for field in ("input_tokens", "actual_output_tokens"):
            item[field] = _project_distribution(item.get(field), field, intervals=False)
        required = {
            "offered_requests",
            "dispatched_requests",
            "completed_requests",
            "offered_requests_per_second",
            "dispatched_requests_per_second",
            "completed_requests_per_second",
            "dispatch_rate_fidelity",
            "load_generator_valid",
            "load_generator_gates",
            "load_generator_invalid_reasons",
            "serving_slo_passed",
            "throughput_window_seconds",
        }
        if not required <= item.keys():
            raise ProtocolError("public performance v2 cell is missing load-generator evidence")
        gates = item["load_generator_gates"]
        reasons = item["load_generator_invalid_reasons"]
        open_loop = item.get("arrival") == "open-loop"
        gate_fields = {
            "schedule_complete",
            "clock_monotonic",
            "dispatch_rate_fidelity",
            "dispatch_lag_p95",
            "dispatch_lag_max",
        }
        if open_loop:
            if (
                not isinstance(gates, dict)
                or set(gates) != gate_fields
                or any(not isinstance(value, bool) for value in gates.values())
                or not isinstance(item["load_generator_valid"], bool)
                or item["load_generator_valid"] is not all(gates.values())
                or not isinstance(reasons, list)
                or any(not isinstance(reason, str) or not reason for reason in reasons)
                or bool(reasons) is item["load_generator_valid"]
                or not _number(item["throughput_window_seconds"])
                or float(item["throughput_window_seconds"]) <= 0
            ):
                raise ProtocolError("public performance v2 load-generator gates are malformed")
        elif (
            item["load_generator_valid"] is not None
            or gates != {}
            or reasons != []
            or any(
                item.get(field) is not None
                for field in (
                    "offered_requests",
                    "dispatched_requests",
                    "completed_requests",
                    "offered_requests_per_second",
                    "dispatched_requests_per_second",
                    "completed_requests_per_second",
                    "dispatch_rate_fidelity",
                    "dispatch_lag_ms",
                    "scheduled_ttft_ms",
                    "scheduled_e2e_ms",
                )
            )
        ):
            raise ProtocolError("public performance closed-loop cell cannot report load-generator evidence")
        if not isinstance(item["serving_slo_passed"], bool):
            raise ProtocolError("public performance v2 serving SLO evidence is malformed")
        if item["load_generator_valid"] is False and (
            item.get("status") != "invalid-loadgen"
            or item.get("slo_passed") is not False
            or item.get("goodput_requests") != 0
            or item.get("goodput_requests_per_second") != 0
        ):
            raise ProtocolError("invalid load-generator evidence cannot pass SLO or contribute goodput")
        public.append(item)
    public.extend({"block": key[0], "cell_key": key[1], "status": "skipped", "reason": reason} for key, reason in sorted(skipped.items()))
    public.sort(key=lambda row: (int(row["block"]), str(row["cell_key"])))
    if any(not _finite_json(row) for row in public):
        raise ProtocolError("public performance cells contain non-finite metrics")
    return public


def _private_tokens(manifest: dict[str, Any], evidence: dict[str, Any] | None, run_dir: Path, errors: set[str]) -> set[str]:
    runtime = manifest["runtime"]
    endpoint = str(runtime.get("endpoint", ""))
    parsed = urlsplit(endpoint)
    tokens = {endpoint, str(runtime.get("api_key_env", "")), str(run_dir), str(Path.home()), *errors}
    if parsed.hostname:
        tokens.add(parsed.hostname)
    execution_record_value = manifest.get("execution_record")
    execution_record = execution_record_value if isinstance(execution_record_value, dict) else {}
    tokens.add(str(execution_record.get("execution_owner_id", "")))
    if evidence:
        server = evidence.get("server") or {}
        load_generator = evidence.get("load_generator") or {}
        network = evidence.get("network") or {}
        tokens.update(
            str(value) for value in (server.get("host_id"), load_generator.get("host_id"), network.get("endpoint_host"), network.get("route")) if value
        )
        for accelerator in server.get("accelerators") or []:
            tokens.update(str(accelerator.get(field)) for field in ("uuid", "pci_bus_id") if accelerator.get(field))
    return {token for token in tokens if len(token) >= 6}


def _reject_private_text(root: Path, tokens: set[str]) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".html", ".json", ".jsonl", ".csv", ".svg", ".toml", ".md", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in tokens) or _USER_PATH.search(text) or contains_secret_like(text):
            raise ProtocolError(f"public performance artifact repeats restricted evidence: {path.relative_to(root)}")


def _portable_tarinfo(member: tarfile.TarInfo) -> tarfile.TarInfo:
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    member.mtime = 0
    return member


def export_public_performance(
    run_dir: Path,
    output: Path,
    *,
    approval_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    source = run_dir.resolve()
    output = output.resolve()
    require_mutable_output_root(output.parent)
    if run_dir.is_symlink() or not source.is_dir():
        raise ProtocolError("performance export requires a regular source run")
    if output.exists():
        raise ProtocolError(f"refusing to overwrite performance export: {output}")
    if output.is_relative_to(source):
        raise ProtocolError("performance export must be outside its immutable source run")
    with tempfile.TemporaryDirectory(prefix="cavada-performance-export-") as temporary:
        snapshot = Path(temporary) / "run"
        shutil.copytree(source, snapshot, symlinks=True, copy_function=_snapshot_copyfile)
        return _export_public_performance_snapshot(snapshot, output, approval_path=approval_path, now=now)


def _export_public_performance_snapshot(
    run_dir: Path,
    output: Path,
    *,
    approval_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    output = output.resolve()
    require_mutable_output_root(output.parent)
    if output.exists():
        raise ProtocolError(f"refusing to overwrite performance export: {output}")
    if output.is_relative_to(run_dir):
        raise ProtocolError("performance export must be outside its immutable source run")
    manifest, completed_cells, skipped_cells, _, ledger, _ = _performance_comparison_input_snapshot(
        run_dir, "CAVADA_EVAL_SIGNING_KEY"
    )
    protocol_version = str(manifest.get("performance_protocol_version"))
    if protocol_version != PERFORMANCE_PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported performance protocol version: {protocol_version}")
    publication_version = PERFORMANCE_PUBLICATION_VERSION
    versions = (protocol_version, manifest.get("plan_version"), manifest.get("report_version"))
    if versions != (PERFORMANCE_PROTOCOL_VERSION, PERFORMANCE_PLAN_VERSION, PERFORMANCE_REPORT_VERSION):
        raise ProtocolError(f"unsupported performance publication versions: {versions}")
    observations = ledger["observations"]
    error_strings = ledger["errors"]
    public_observations = _public_observations(observations)
    public_cells = _public_cells(completed_cells, skipped_cells)
    source_summary_projection = _campaign_summary(manifest, public_cells, public_observations)
    source_summary = _read_object(run_dir / "summary.json", "performance summary")
    summary_contract = (
        "run_id",
        "runtime_id",
        "status",
        "cells",
        "observations",
        "successes",
        "errors",
        "warmups",
        "input_tokens",
        "output_tokens",
        "campaign_token_usage",
        "campaign_estimated_cost",
        "limitations",
    )
    if any(source_summary.get(field) != source_summary_projection.get(field) for field in summary_contract):
        raise ProtocolError("performance summary differs from its immutable ledgers")

    if not isinstance(manifest.get("official_requested"), bool) or not isinstance(manifest.get("officially_valid"), bool):
        raise ProtocolError("performance official status evidence is malformed")
    official = manifest.get("officially_valid") is True
    if official and manifest.get("official_requested") is not True:
        raise ProtocolError("official performance evidence must record an official request")
    if manifest.get("official_requested") is True and not official and manifest.get("status") not in {"completed-with-errors", "invalid-loadgen"}:
        raise ProtocolError("an invalid official campaign cannot be public-exported")
    if official != (approval_path is not None):
        raise ProtocolError("official public performance export requires exactly one release approval")

    plan = manifest.get("plan") or {}
    workload = manifest.get("workload") or {}
    runtime = manifest.get("runtime") or {}
    measured_input_tokens = sum(float(row["input_tokens"]) for row in public_observations if "input_tokens" in row)
    measured_output_tokens = sum(float(row["output_tokens"]) for row in public_observations if "output_tokens" in row)
    public_token_usage = {
        "input": measured_input_tokens,
        "output": measured_output_tokens,
        "total": measured_input_tokens + measured_output_tokens,
    }
    pricing = runtime.get("pricing") if isinstance(runtime, dict) else None
    public_estimated_cost = (
        {
            "amount": measured_input_tokens * float(pricing["input_per_million"]) / 1_000_000
            + measured_output_tokens * float(pricing["output_per_million"]) / 1_000_000,
            "currency": pricing["currency"],
            "source": pricing["source"],
            "effective_at": pricing["effective_at"],
            "includes_warmup": False,
        }
        if isinstance(pricing, dict)
        else None
    )
    public_summary = _campaign_summary(
        {**manifest, "token_usage": public_token_usage, "estimated_cost": public_estimated_cost},
        public_cells,
        public_observations,
    )
    if official:
        _require_official_reference_inputs(
            manifest.get("protocol_sha256"),
            plan.get("sha256"),
            workload.get("sha256"),
            workload.get("assets"),
        )

    restricted_evidence: dict[str, Any] | None = None
    public_evidence: dict[str, Any] | None = None
    evidence_record = manifest.get("system_evidence")
    if evidence_record is not None:
        evidence_path = run_dir / "system_evidence_snapshot.json"
        if sha256_file(evidence_path) != evidence_record.get("sha256"):
            raise ProtocolError("performance system evidence snapshot hash mismatch")
        restricted_evidence = load_system_evidence(evidence_path)
        public_evidence = public_system_evidence(restricted_evidence)
    if official:
        source = manifest.get("source") or {}
        if (
            public_evidence is None
            or restricted_evidence is None
            or restricted_evidence.get("projection") != "restricted"
            or set(restricted_evidence.get("unavailable", {})) != _structural_unavailable(runtime, restricted_evidence)
            or skipped_cells
            or any(cell.get("status") == "invalid-loadgen" for cell in completed_cells.values())
            or source.get("dirty") is not False
            or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", str(source.get("commit", "")))
        ):
            raise ProtocolError("official public performance export requires complete official source, cell, and system evidence")
    release = _release_approval(run_dir, manifest, approval_path, now or datetime.now(timezone.utc)) if approval_path else None

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cavada-perf-public-", dir=output.parent) as temporary:
        publication = Path(temporary)
        atomic_json(publication / "summary.json", public_summary)
        atomic_text(
            publication / "cells.jsonl",
            "".join(f"{json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':'))}\n" for row in public_cells),
        )
        _write_cells_csv(publication / "cells.csv", public_cells)
        _copy_checked(
            run_dir / "protocol_snapshot.md",
            publication / "protocol_snapshot.md",
            str(manifest["protocol_sha256"]),
            source_root=run_dir,
        )
        _copy_checked(run_dir / "plan_snapshot.toml", publication / "plan.toml", str(plan["sha256"]), source_root=run_dir)
        _copy_checked(run_dir / "workload_snapshot.jsonl", publication / "workload.jsonl", str(workload["sha256"]), source_root=run_dir)
        atomic_text(
            publication / "observations.jsonl",
            "".join(f"{json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':'))}\n" for row in public_observations),
        )
        for relative, digest in (workload.get("assets") or {}).items():
            _copy_checked(
                run_dir / "workload_assets" / relative,
                publication / "workload_assets" / relative,
                str(digest),
                source_root=run_dir,
            )
        if public_evidence is not None:
            atomic_json(publication / "system_evidence.json", public_evidence)
        public_manifest = {
            "publication_version": publication_version,
            "performance_protocol_version": manifest["performance_protocol_version"],
            "protocol_sha256": manifest["protocol_sha256"],
            "run_id": manifest["run_id"],
            "evaluation_started_at": manifest["started_at"],
            "evaluation_finished_at": manifest["finished_at"],
            "status": manifest["status"],
            "assurance": "approved" if official else "development",
            "official": official,
            "source_manifest_sha256": sha256_file(run_dir / "manifest.json"),
            "source_bundle_sha256": sha256_file(run_dir / "bundle.json"),
            "plan": plan,
            "workload": workload,
            "runtime": {field: runtime.get(field) for field in _RUNTIME_FIELDS if field in runtime},
            "system_evidence": (
                {
                    "configuration_id": public_evidence["configuration_id"],
                    "sha256": sha256_file(publication / "system_evidence.json"),
                    "projection": "public",
                }
                if public_evidence is not None
                else None
            ),
            "source": {field: (manifest.get("source") or {}).get(field) for field in ("commit", "dirty", "status_sha256")},
            "cells": manifest.get("cells"),
            "warmups": manifest.get("warmups"),
            "request_reconciliation": manifest.get("request_reconciliation"),
            "token_usage": public_token_usage,
            "estimated_cost": public_estimated_cost,
            "release": release,
            "limitations": public_summary["limitations"],
        }
        if not _finite_json(public_manifest):
            raise ProtocolError("public performance manifest contains non-finite values")
        atomic_json(publication / "public_manifest.json", public_manifest)
        _performance_reports(publication, _public_presentation_manifest(public_manifest), public_summary, public_cells)
        _reject_private_text(publication, _private_tokens(manifest, restricted_evidence, run_dir, error_strings))
        write_bundle(publication)
        if not verify_bundle(publication)["valid"]:
            raise ProtocolError("public performance bundle verification failed")
        from .public_verify import verify_public_bundle

        verify_public_bundle(publication)
        try:
            with output.open("xb") as handle, gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    for path in sorted(publication.rglob("*")):
                        if path.is_file() and not path.is_symlink():
                            archive.add(path, arcname=path.relative_to(publication).as_posix(), recursive=False, filter=_portable_tarinfo)
        except Exception:
            output.unlink(missing_ok=True)
            raise
    return public_manifest
