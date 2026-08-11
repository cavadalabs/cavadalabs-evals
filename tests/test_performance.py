from __future__ import annotations

import json
import tarfile
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.cli import main, parser
from cavada_eval.performance import (
    _cache_nonce,
    _cell_metrics,
    _cell_metrics_v2,
    _expand_cells,
    _messages,
    _open_loop_offsets,
    _performance_comparison_input,
    _planned_token_upper_bound,
    _write_cells_csv,
    compare_performance_runs,
    load_performance_engagement,
    load_performance_execution_record,
    load_performance_plan,
    load_performance_runtime,
    performance_plan_summary,
    performance_run_preflight,
    run_performance_campaign,
)
from cavada_eval.performance_release import export_public_performance
from cavada_eval.protocol import ProtocolError, sha256_file
from cavada_eval.public_verify import verify_public_bundle
from cavada_eval.runner import _ResponseError
from cavada_eval.system_evidence import system_configuration_id


def _files(root: Path, endpoint: str, runtime_id: str) -> tuple[Path, Path]:
    (root / "PERFORMANCE_PROTOCOL_V2.md").write_bytes((Path(__file__).parents[1] / "PERFORMANCE_PROTOCOL_V2.md").read_bytes())
    workload = root / "workload.jsonl"
    workload.write_text(
        json.dumps({"id": "ctx-8", "context_tokens": 8, "repeat_text": " datum", "repeat_count": 8}) + "\n",
        encoding="utf-8",
    )
    plan = root / "plan.toml"
    workload_hash = sha256_file(workload)
    plan.write_text(
        f"""plan_version = "2.0.0"
revision = "2.0.0"
name = "test-serving-v2"
description = "Bounded test campaign."
profile = "llm-serving-v2"
data_classification = "synthetic"
[load_generator]
minimum_dispatch_rate_fraction = 0.98
maximum_dispatch_lag_p95_ms = 100
maximum_dispatch_lag_ms = 1000
[workload]
id = "test-workload-v2"
revision = "1.0.0"
path = "workload.jsonl"
sha256 = "{workload_hash}"
mode = "iso-token"
prefix_cache_policy = "diverse"
input_token_tolerance_fraction = 0
[generation]
stream = true
temperature = 0
[execution]
repetitions = 1
warmup_requests = 1
measured_requests = 2
open_loop_duration_seconds = 0.05
open_loop_arrival_distribution = "fixed"
bootstrap_samples = 100
seed = 7
randomize_cells = false
cooldown_seconds = 0
max_in_flight = 4
[limits]
timeout_seconds = 5
max_requests = 20
max_total_tokens = 1000
max_campaign_seconds = 10
max_context_tokens = 8
max_output_tokens = 2
[slo]
ttft_p95_ms = 5000
e2e_p99_ms = 5000
goodput_ttft_ms = 5000
goodput_e2e_ms = 5000
maximum_error_rate = 0
minimum_output_tokens_fraction = 1
minimum_p99_observations = 1
[[scenarios]]
id = "closed"
arrival = "closed-loop"
context_tokens = [8]
output_tokens = [2]
concurrency = [1, 2]
[[scenarios]]
id = "open"
arrival = "open-loop"
context_tokens = [8]
output_tokens = [2]
request_rates = [20]
""",
        encoding="utf-8",
    )
    runtime = root / f"{runtime_id}.toml"
    runtime.write_text(
        f'''runtime_version = "1.0.0"
id = "{runtime_id}"
endpoint = "{endpoint}"
request_model = "test-model"
expected_model = "test-model"
model_revision = "model-revision"
api_key_env = "MISSING_TEST_KEY"
engine = "test-engine"
engine_revision = "dddddddddddddddddddddddddddddddddddddddd"
model_artifact_revision = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
dtype = "fp16"
quantization = "none"
gpu_count = 1
gpu_model = "test-gpu"
tensor_parallel = 1
max_context_tokens = 10
launch_command_sanitized = "test-server"
''',
        encoding="utf-8",
    )
    return plan, runtime


def _system_evidence(endpoint: str) -> dict[str, object]:
    parsed = urlsplit(endpoint)
    evidence: dict[str, object] = {
        "evidence_version": "1.0.0",
        "configuration_id": "",
        "projection": "restricted",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collection_method": "automated",
        "server": {
            "host_id": "test-server",
            "os": {"name": "Test Linux", "version": "1", "kernel": "1.0"},
            "cpu": {"model": "Test CPU", "architecture": "x86_64", "sockets": 1, "physical_cores": 4, "logical_cores": 8},
            "memory": {"total_bytes": 16_000_000_000},
            "numa": {"nodes": 1, "policy": "local"},
            "accelerators": [
                {
                    "index": 0,
                    "vendor": "Test",
                    "model": "test-gpu",
                    "uuid": "test-gpu-0",
                    "vram_bytes": 8_000_000_000,
                    "pci_bus_id": "0000:01:00.0",
                    "power_limit_watts": 100,
                    "graphics_clock_limit_mhz": 1000,
                    "memory_clock_limit_mhz": 1000,
                }
            ],
            "accelerator_topology": "one local accelerator",
        },
        "software": {
            "driver": {"name": "test-driver", "version": "1"},
            "compute_runtime": {"name": "test-compute", "version": "1"},
            "engine": {
                "name": "test-engine",
                "revision": "d" * 40,
                "binary_sha256": "e" * 64,
                "container_image_digest": None,
            },
            "model": {
                "name": "test-model",
                "revision": "model-revision",
                "artifact_sha256": "c" * 64,
                "dtype": "fp16",
                "quantization": "none",
            },
        },
        "serving": {
            "launch_command_sanitized": "test-server",
            "max_context_tokens": 10,
            "max_batch_size": 4,
            "max_batch_tokens": 40,
            "continuous_batching": True,
            "prefix_cache": False,
            "kv_cache_dtype": "fp16",
            "tensor_parallel": 1,
            "pipeline_parallel": 1,
            "data_parallel": 1,
            "parallel_slots": 4,
        },
        "load_generator": {
            "host_id": "test-loadgen",
            "os": {"name": "Test OS", "version": "1", "kernel": "1.0"},
            "cpu": {"model": "Test CPU", "architecture": "x86_64", "logical_cores": 8},
            "memory": {"total_bytes": 16_000_000_000},
            "client": {"name": "cavadalabs-evals", "revision": "test-revision"},
            "colocated_with_server": True,
        },
        "network": {
            "relationship": "same-host",
            "transport": "tls" if parsed.scheme == "https" else "tcp",
            "endpoint_host": parsed.hostname,
            "endpoint_port": parsed.port,
            "route": "loopback",
            "rtt_ms": {"method": "TCP connect", "samples": 10, "median": 0.1, "p95": 0.2, "measured_at": datetime.now(timezone.utc).isoformat()},
        },
        "artifacts": [],
        "unavailable": {"/software/engine/container_image_digest": "not applicable: engine was not containerized"},
    }
    evidence["configuration_id"] = system_configuration_id(evidence)
    return evidence


def test_generation_only_campaign_and_exact_comparison(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert payload["stream"] is True and payload["stream_options"] == {"include_usage": True}
            events = (
                {"model": "test-model", "choices": [{"delta": {"content": "one "}}]},
                {"model": "test-model", "choices": [{"delta": {"content": "two"}}]},
                {"model": "test-model", "choices": [], "usage": {"prompt_tokens": 8, "completion_tokens": 2}},
            )
            body = b"".join(f"data: {json.dumps(event)}\n\n".encode() for event in events) + b"data: [DONE]\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/v1"
        left_root = tmp_path / "left"
        right_root = tmp_path / "right"
        left_root.mkdir()
        right_root.mkdir()
        left_plan, left_runtime = _files(left_root, endpoint, "runtime-a")
        right_plan, right_runtime = _files(right_root, endpoint, "runtime-b")
        left_evidence = left_root / "system-evidence.json"
        left_evidence.write_text(json.dumps(_system_evidence(endpoint)), encoding="utf-8")
        left_plan_object = load_performance_plan(left_plan)
        left_runtime_object = load_performance_runtime(left_runtime)
        execution_record = left_root / "execution-record.json"
        execution_record.write_text(
            json.dumps(
                {
                    "record_version": "1.0.0",
                    "engagement_id": "local-performance-engagement-1",
                    "execution_owner_id": "executor-1",
                    "scope": "Execute the exact hash-bound test performance campaign.",
                    "protocol_sha256": sha256_file(left_root / "PERFORMANCE_PROTOCOL_V2.md"),
                    "plan_sha256": left_plan_object.sha256,
                    "workload_sha256": left_plan_object.workload_sha256,
                    "runtime_sha256": left_runtime_object.sha256,
                    "system_evidence_sha256": sha256_file(left_evidence),
                    "recorded_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                }
            ),
            encoding="utf-8",
        )
        left_run = run_performance_campaign(
            left_plan_object,
            left_runtime_object,
            repo_root=left_root,
            output_root=tmp_path / "runs-a",
            system_evidence_path=left_evidence,
            execution_record_path=execution_record,
        )
        right_run = run_performance_campaign(
            load_performance_plan(right_plan),
            load_performance_runtime(right_runtime),
            repo_root=right_root,
            output_root=tmp_path / "runs-b",
        )
    finally:
        server.shutdown()
        thread.join()

    assert verify_bundle(left_run)["valid"] and verify_bundle(right_run)["valid"]
    manifest = json.loads((left_run / "manifest.json").read_text(encoding="utf-8"))
    cells = [json.loads(line) for line in (left_run / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    assert manifest["status"] == "completed" and len(cells) == 3
    assert manifest["protocol_sha256"] == sha256_file(left_run / "protocol_snapshot.md")
    assert manifest["system_evidence"]["configuration_id"]
    assert (left_run / "system_evidence_snapshot.json").read_bytes() == left_evidence.read_bytes()
    assert manifest["execution_record"]["execution_owner_id"] == "executor-1"
    assert (left_run / "execution_record_snapshot.json").read_bytes() == execution_record.read_bytes()
    assert manifest["request_reconciliation"]["campaign_complete"] is True
    assert all(cell["slo_passed"] for cell in cells)
    assert all(cell["ttft_ms"]["count"] > 0 and cell["output_tokens_per_second"] > 0 for cell in cells)
    observations = [json.loads(line) for line in (left_run / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(row["client_queue_ms"] == 0 for row in observations if row["scenario_id"] == "closed")
    assert not (left_run / "judgments.jsonl").exists()
    output = tmp_path / "comparison"
    comparison = compare_performance_runs([left_run, right_run], output)
    assert comparison["shared_cells"] == 3 and verify_bundle(output)["valid"]


def test_v2_scheduler_transport_reports_export_and_verifiers_end_to_end(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        requests = 0
        lock = threading.Lock()

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            with self.lock:
                type(self).requests += 1
                request_number = type(self).requests
            if 2 <= request_number <= 5:
                time.sleep(0.3)
            if request_number == 6:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            events = (
                {"model": "test-model", "choices": [{"delta": {"content": "one "}}]},
                {"model": "test-model", "choices": [{"delta": {"content": "two"}}]},
                {"model": "test-model", "choices": [], "usage": {"prompt_tokens": 8, "completion_tokens": 2}},
            )
            body = b"".join(f"data: {json.dumps(event)}\n\n".encode() for event in events) + b"data: [DONE]\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        (tmp_path / "PERFORMANCE_PROTOCOL_V2.md").write_bytes((Path(__file__).parents[1] / "PERFORMANCE_PROTOCOL_V2.md").read_bytes())
        workload = tmp_path / "workload.jsonl"
        workload.write_text(json.dumps({"id": "ctx-8", "context_tokens": 8, "repeat_text": " datum", "repeat_count": 8}) + "\n")
        plan_path = tmp_path / "plan-v2.toml"
        plan_path.write_text(
            f'''plan_version = "2.0.0"
revision = "2.0.0"
name = "v2-e2e"
description = "Deterministic local v2 end-to-end proof."
profile = "llm-serving-v2"
data_classification = "synthetic"
[workload]
id = "v2-e2e"
revision = "2.0.0"
path = "workload.jsonl"
sha256 = "{sha256_file(workload)}"
mode = "iso-token"
prefix_cache_policy = "diverse"
input_token_tolerance_fraction = 0
[generation]
stream = true
temperature = 0
[execution]
repetitions = 1
warmup_requests = 0
measured_requests = 1
open_loop_duration_seconds = 0.2
open_loop_arrival_distribution = "fixed"
bootstrap_samples = 100
seed = 1
randomize_cells = false
cooldown_seconds = 0
max_in_flight = 1
[load_generator]
minimum_dispatch_rate_fraction = 0.9
maximum_dispatch_lag_p95_ms = 100
maximum_dispatch_lag_ms = 1000
[limits]
timeout_seconds = 2
max_requests = 6
max_total_tokens = 100
max_campaign_seconds = 10
max_context_tokens = 8
max_output_tokens = 2
[slo]
ttft_p95_ms = 1000
e2e_p99_ms = 1000
goodput_ttft_ms = 1000
goodput_e2e_ms = 2000
maximum_error_rate = 0
minimum_output_tokens_fraction = 1
minimum_p99_observations = 1
[[scenarios]]
id = "healthy"
arrival = "open-loop"
context_tokens = [8]
output_tokens = [2]
request_rates = [5]
duration_seconds = 0.2
[[scenarios]]
id = "saturated"
arrival = "open-loop"
context_tokens = [8]
output_tokens = [2]
request_rates = [20]
duration_seconds = 0.2
[[scenarios]]
id = "transport-error"
arrival = "open-loop"
context_tokens = [8]
output_tokens = [2]
request_rates = [5]
duration_seconds = 0.2
''',
            encoding="utf-8",
        )
        runtime_path = tmp_path / "runtime.toml"
        runtime_path.write_text(
            f'''runtime_version = "1.0.0"
id = "v2-e2e-runtime"
endpoint = "http://127.0.0.1:{server.server_port}/v1"
request_model = "test-model"
expected_model = "test-model"
model_revision = "{'a' * 40}"
api_key_env = "MISSING_V2_E2E_KEY"
engine = "test-engine"
engine_revision = "{'b' * 40}"
model_artifact_revision = "{'c' * 64}"
dtype = "fp16"
quantization = "none"
gpu_count = 1
gpu_model = "test-gpu"
tensor_parallel = 1
max_context_tokens = 10
launch_command_sanitized = "test-server"
''',
            encoding="utf-8",
        )
        run_dir = run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=tmp_path / "runs",
        )
    finally:
        server.shutdown()
        thread.join()

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    cells = [json.loads(line) for line in (run_dir / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    responses = [json.loads(line) for line in (run_dir / "responses.jsonl").read_text(encoding="utf-8").splitlines()]
    assert verify_bundle(run_dir)["valid"] is True
    assert _performance_comparison_input(run_dir, "")[0]["status"] == "invalid-loadgen"
    assert manifest["status"] == "invalid-loadgen"
    assert manifest["cells"] == {
        "total": 3,
        "completed": 1,
        "with_errors": 1,
        "invalid_loadgen": 1,
        "skipped": 0,
        "slo_passed": 1,
        "slo_failed": 2,
    }
    assert manifest["request_reconciliation"] == {
        "planned": 6,
        "scheduled": 6,
        "accepted": 6,
        "responses": 6,
        "warmup_outcomes": 0,
        "measured_outcomes": 6,
        "terminal_outcomes": 6,
        "ledgers_complete": True,
        "campaign_complete": True,
    }
    assert {cell["scenario_id"]: cell["status"] for cell in cells} == {
        "healthy": "completed",
        "saturated": "invalid-loadgen",
        "transport-error": "completed-with-errors",
    }
    assert sum(response["status"] == "error" for response in responses) == 1
    report = (run_dir / "report.html").read_text(encoding="utf-8")
    assert "invalid-loadgen cells are omitted" in report and "Throughput window s" in report

    archive = tmp_path / "public-v2-e2e.tar.gz"
    export_public_performance(run_dir, archive)
    public = tmp_path / "public-v2-e2e"
    public.mkdir()
    with tarfile.open(archive) as package:
        package.extractall(public, filter="data")
    assert verify_public_bundle(public)["semantic_valid"] is True

    response_path = run_dir / "responses.jsonl"
    observation_path = run_dir / "observations.jsonl"
    response_rows = [json.loads(line) for line in response_path.read_text(encoding="utf-8").splitlines()]
    observation_rows = [json.loads(line) for line in observation_path.read_text(encoding="utf-8").splitlines()]
    error_response = next(row for row in response_rows if row["status"] == "error")
    error_observation = next(row for row in observation_rows if row["request_id"] == error_response["request_id"])
    impossible_completion = error_response["finished_monotonic_ns"] + 1
    error_response["transport"]["finished_monotonic_ns"] = impossible_completion
    error_response["completed_monotonic_ns"] = impossible_completion
    error_observation["completed_monotonic_ns"] = impossible_completion
    response_path.write_text("".join(json.dumps(row) + "\n" for row in response_rows), encoding="utf-8")
    observation_path.write_text("".join(json.dumps(row) + "\n" for row in observation_rows), encoding="utf-8")
    write_bundle(run_dir)

    with pytest.raises(ProtocolError, match="transport monotonic timing evidence is malformed"):
        _performance_comparison_input(run_dir, "")
    with pytest.raises(ProtocolError, match="transport monotonic timing evidence is malformed"):
        export_public_performance(run_dir, tmp_path / "impossible-error-timing.tar.gz")


def test_performance_plan_fails_closed_before_network(tmp_path: Path) -> None:
    plan, runtime = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-a")
    assert main(["perf", "validate", str(plan), "--runtime", str(runtime)]) == 0
    source = plan.read_text(encoding="utf-8")
    plan.write_text(source.replace("minimum_p99_observations = 1", "minimum_p99_observations = 2"), encoding="utf-8")
    with pytest.raises(ProtocolError, match="minimum_p99_observations requires 2"):
        load_performance_plan(plan)
    plan.write_text(source.replace('data_classification = "synthetic"', 'data_classification = "confidential"'), encoding="utf-8")
    with pytest.raises(ProtocolError, match="only permits public or synthetic"):
        load_performance_plan(plan)
    plan.write_text(source.replace("max_total_tokens = 1000", "max_total_tokens = 95"), encoding="utf-8")
    with pytest.raises(ProtocolError, match="plans up to 96 tokens; limit is 95"):
        load_performance_plan(plan)
    assert load_performance_runtime(runtime).config["id"] == "runtime-a"


def test_performance_execution_record_binds_exact_inputs(tmp_path: Path) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-owner-binding")
    plan = load_performance_plan(plan_path)
    runtime = load_performance_runtime(runtime_path)
    record_path = tmp_path / "execution-record.json"
    record = {
        "record_version": "1.0.0",
        "engagement_id": "local-performance-engagement-1",
        "execution_owner_id": "executor-1",
        "scope": "Execute the exact hash-bound test performance campaign.",
        "protocol_sha256": sha256_file(tmp_path / "PERFORMANCE_PROTOCOL_V2.md"),
        "plan_sha256": plan.sha256,
        "workload_sha256": plan.workload_sha256,
        "runtime_sha256": runtime.sha256,
        "system_evidence_sha256": None,
        "recorded_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")

    projection, raw = load_performance_execution_record(
        record_path,
        protocol_sha256=record["protocol_sha256"],
        plan_sha256=plan.sha256,
        workload_sha256=plan.workload_sha256,
        runtime_sha256=runtime.sha256,
        system_evidence_sha256=None,
    )

    assert projection["execution_owner_id"] == "executor-1"
    assert projection["sha256"] == sha256_file(record_path) and raw == record_path.read_bytes()
    record["runtime_sha256"] = "0" * 64
    record_path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ProtocolError, match="exact run inputs.*runtime_sha256"):
        load_performance_execution_record(
            record_path,
            protocol_sha256=record["protocol_sha256"],
            plan_sha256=plan.sha256,
            workload_sha256=plan.workload_sha256,
            runtime_sha256=runtime.sha256,
            system_evidence_sha256=None,
        )


def test_performance_engagement_binds_exact_inputs_owner_and_validity(tmp_path: Path) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-engagement")
    plan = load_performance_plan(plan_path)
    runtime = load_performance_runtime(runtime_path)
    now = datetime.now(timezone.utc)
    execution_record = {
        "engagement_id": "performance-engagement-1",
        "execution_owner_id": "executor-1",
        "recorded_at": (now - timedelta(minutes=1)).isoformat(),
    }
    engagement_path = tmp_path / "engagement.json"
    engagement: dict[str, object] = {
        "engagement_version": "1.0.0",
        "engagement_id": execution_record["engagement_id"],
        "status": "approved",
        "scope": "Run and release this exact hash-bound performance campaign.",
        "execution_owner_id": execution_record["execution_owner_id"],
        "protocol_sha256": sha256_file(tmp_path / "PERFORMANCE_PROTOCOL_V2.md"),
        "plan_sha256": plan.sha256,
        "workload_sha256": plan.workload_sha256,
        "runtime_sha256": runtime.sha256,
        "system_evidence_sha256": "1" * 64,
        "configuration_id": "cfg-sha256:" + "2" * 64,
        "approved_at": (now - timedelta(minutes=2)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")

    projection, raw = load_performance_engagement(
        engagement_path,
        protocol_sha256=str(engagement["protocol_sha256"]),
        plan_sha256=plan.sha256,
        workload_sha256=plan.workload_sha256,
        runtime_sha256=runtime.sha256,
        system_evidence_sha256="1" * 64,
        configuration_id=str(engagement["configuration_id"]),
        execution_record=execution_record,
        at=now,
    )

    assert projection["engagement_id"] == execution_record["engagement_id"]
    assert projection["sha256"] == sha256_file(engagement_path) and raw == engagement_path.read_bytes()
    engagement_symlink = tmp_path / "engagement-link.json"
    engagement_symlink.symlink_to(engagement_path)
    with pytest.raises(ProtocolError, match="regular file"):
        load_performance_engagement(
            engagement_symlink,
            protocol_sha256=str(engagement["protocol_sha256"]),
            plan_sha256=plan.sha256,
            workload_sha256=plan.workload_sha256,
            runtime_sha256=runtime.sha256,
            system_evidence_sha256="1" * 64,
            configuration_id=str(engagement["configuration_id"]),
            execution_record=execution_record,
            at=now,
        )
    engagement["execution_owner_id"] = "different-owner"
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    with pytest.raises(ProtocolError, match="exact run governance.*execution_owner_id"):
        load_performance_engagement(
            engagement_path,
            protocol_sha256=str(engagement["protocol_sha256"]),
            plan_sha256=plan.sha256,
            workload_sha256=plan.workload_sha256,
            runtime_sha256=runtime.sha256,
            system_evidence_sha256="1" * 64,
            configuration_id=str(engagement["configuration_id"]),
            execution_record=execution_record,
            at=now,
        )
    engagement["execution_owner_id"] = execution_record["execution_owner_id"]
    engagement["expires_at"] = (now - timedelta(seconds=1)).isoformat()
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    with pytest.raises(ProtocolError, match="not effective"):
        load_performance_engagement(
            engagement_path,
            protocol_sha256=str(engagement["protocol_sha256"]),
            plan_sha256=plan.sha256,
            workload_sha256=plan.workload_sha256,
            runtime_sha256=runtime.sha256,
            system_evidence_sha256="1" * 64,
            configuration_id=str(engagement["configuration_id"]),
            execution_record=execution_record,
            at=now,
        )


def test_run_reloads_validated_inputs_before_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-reload")
    plan = load_performance_plan(plan_path)
    plan.config["limits"]["max_requests"] += 1
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: pytest.fail("network must not be contacted for a mutated in-memory plan"),
    )

    with pytest.raises(ProtocolError, match="changed after validation; no network request"):
        run_performance_campaign(plan, load_performance_runtime(runtime_path), repo_root=tmp_path, output_root=tmp_path / "runs")

    runtime = load_performance_runtime(runtime_path)
    runtime.config["expected_model"] = "mutated-model"
    with pytest.raises(ProtocolError, match="changed after validation; no network request"):
        run_performance_campaign(load_performance_plan(plan_path), runtime, repo_root=tmp_path, output_root=tmp_path / "runs")


def test_prompt_asset_mutation_after_preflight_sends_no_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-asset-cache")
    asset = tmp_path / "prompt.txt"
    asset.write_text("immutable prompt", encoding="utf-8")
    workload = tmp_path / "workload.jsonl"
    workload.write_text(
        json.dumps(
            {
                "id": "ctx-8",
                "context_tokens": 8,
                "prompt_file": asset.name,
                "prompt_sha256": sha256_file(asset),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    plan_text = plan_path.read_text(encoding="utf-8")
    old_hash_line = next(line for line in plan_text.splitlines() if line.startswith("sha256 = "))
    plan_path.write_text(plan_text.replace(old_hash_line, f'sha256 = "{sha256_file(workload)}"'), encoding="utf-8")

    def mutate_after_cache(_root: Path) -> None:
        asset.write_text("changed after preflight", encoding="utf-8")

    monkeypatch.setattr("cavada_eval.performance.require_mutable_output_root", mutate_after_cache)
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: pytest.fail("network must not be contacted after prompt asset drift"),
    )
    output = tmp_path / "runs"

    with pytest.raises(ProtocolError, match="workload assets changed after validation"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=output,
        )

    run_dir = next(output.iterdir())
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["officially_valid"] is False
    assert not (run_dir / "requests.jsonl").exists()


def test_performance_run_rejects_output_inside_finalized_bundle_before_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-output-root")
    finalized = tmp_path / "finalized"
    finalized.mkdir()
    (finalized / "bundle.json").write_text("{}\n", encoding="utf-8")
    output = finalized / "nested" / "runs"
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: pytest.fail("network must not be contacted for an immutable output root"),
    )

    with pytest.raises(ProtocolError, match="outside finalized run bundles"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=output,
        )

    assert not output.exists()


def test_official_run_rechecks_reference_protocol_before_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-protocol-recheck")

    def changed_reference(*_args: object, **_kwargs: object) -> None:
        raise ProtocolError("reference protocol changed before snapshot")

    monkeypatch.setattr(
        "cavada_eval.performance.performance_run_preflight",
        lambda *_args, **_kwargs: (None, None, {"commit": "a" * 40, "dirty": False}),
    )
    monkeypatch.setattr("cavada_eval.performance._require_official_reference_inputs", changed_reference)
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: pytest.fail("network must not be contacted after protocol drift"),
    )

    with pytest.raises(ProtocolError, match="reference protocol changed before snapshot"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=tmp_path / "runs",
            official=True,
        )


def test_official_run_rechecks_source_after_protocol_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-source-recheck")
    source = {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64}
    monkeypatch.setattr("cavada_eval.performance.performance_run_preflight", lambda *_args, **_kwargs: (None, None, source))
    monkeypatch.setattr("cavada_eval.performance._require_official_reference_inputs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "cavada_eval.performance.git_evidence",
        lambda _root: {**source, "dirty": True, "status_sha256": "c" * 64},
    )
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: pytest.fail("network must not be contacted after source drift"),
    )

    with pytest.raises(ProtocolError, match="source changed after official preflight"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=tmp_path / "runs",
            official=True,
        )


def test_official_run_rechecks_source_after_all_snapshots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-source-snapshot-recheck")
    source = {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64}
    calls = 0

    def source_evidence(_root: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return source if calls == 1 else {**source, "dirty": True, "status_sha256": "c" * 64}

    evidence = {
        "configuration_id": "cfg-sha256:" + "a" * 64,
        "projection": "restricted",
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
    monkeypatch.setattr("cavada_eval.performance.performance_run_preflight", lambda *_args, **_kwargs: (evidence, b"{}", source))
    monkeypatch.setattr("cavada_eval.performance._require_official_reference_inputs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("cavada_eval.performance.git_evidence", source_evidence)
    monkeypatch.setattr(
        "cavada_eval.performance.load_performance_execution_record",
        lambda *_args, **_kwargs: (
            {
                "record_version": "1.0.0",
                "engagement_id": "engagement-1",
                "execution_owner_id": "executor-1",
                "recorded_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            },
            b"{}",
        ),
    )
    monkeypatch.setattr(
        "cavada_eval.performance.load_performance_engagement",
        lambda *_args, **_kwargs: (
            {
                "engagement_version": "1.0.0",
                "engagement_id": "engagement-1",
                "status": "approved",
                "execution_owner_id": "executor-1",
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            },
            b"{}",
        ),
    )
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: pytest.fail("network must not be contacted after snapshot source drift"),
    )

    with pytest.raises(ProtocolError, match="source changed after official snapshots"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=tmp_path / "runs",
            official=True,
            execution_record_path=tmp_path / "execution-record.json",
            engagement_path=tmp_path / "engagement.json",
        )


def test_official_run_requires_execution_record_before_output_or_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-owner-required")
    source = {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64}
    monkeypatch.setattr("cavada_eval.performance.performance_run_preflight", lambda *_args, **_kwargs: (None, None, source))
    monkeypatch.setattr("cavada_eval.performance._require_official_reference_inputs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("cavada_eval.performance.git_evidence", lambda _root: source)
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: pytest.fail("network must not be contacted without an execution record"),
    )
    output = tmp_path / "runs"

    with pytest.raises(ProtocolError, match="requires --execution-record"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=output,
            official=True,
        )

    assert not output.exists()


def test_official_run_requires_engagement_before_output_or_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-engagement-required")
    source = {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64}
    monkeypatch.setattr("cavada_eval.performance.performance_run_preflight", lambda *_args, **_kwargs: ({}, b"{}", source))
    monkeypatch.setattr("cavada_eval.performance._require_official_reference_inputs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("cavada_eval.performance.git_evidence", lambda _root: source)
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: pytest.fail("network must not be contacted without an engagement"),
    )
    output = tmp_path / "runs"

    with pytest.raises(ProtocolError, match="requires --engagement"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=output,
            official=True,
            execution_record_path=tmp_path / "execution-record.json",
        )

    assert not output.exists()


def test_non_finite_plan_numbers_fail_validation(tmp_path: Path) -> None:
    plan_path, _ = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-finite")
    plan_path.write_text(plan_path.read_text(encoding="utf-8").replace("cooldown_seconds = 0", "cooldown_seconds = nan"), encoding="utf-8")

    with pytest.raises(ProtocolError, match="performance plan contains non-finite values"):
        load_performance_plan(plan_path)


def test_warmup_error_prevents_completed_and_officially_valid_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-warmup")
    calls = 0

    def response(
        _url: str,
        payload: dict[str, object],
        _key: str,
        _timeout: float,
        *,
        request_id: str,
    ) -> tuple[dict[str, object], dict[str, object]]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic warm-up failure")
        started_ns = time.perf_counter_ns()
        finished_ns = time.perf_counter_ns()
        total_ms = round((finished_ns - started_ns) / 1_000_000, 3)
        return (
            {
                "model": "test-model",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                "stream_events": [
                    {
                        "model": "test-model",
                        "choices": [{"delta": {"content": "ok"}}],
                        "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                    }
                ],
            },
            {
                "request_id": request_id,
                "attempts": 1,
                "request_bytes": len(json.dumps(payload, ensure_ascii=False).encode()),
                "response_bytes": 1,
                "headers_ms": 0.0,
                "ttft_ms": 0.0,
                "total_ms": total_ms,
                "streaming": True,
                "started_monotonic_ns": started_ns,
                "headers_monotonic_ns": started_ns,
                "first_content_monotonic_ns": started_ns,
                "finished_monotonic_ns": finished_ns,
                "event_monotonic_ns": [started_ns],
                "inter_chunk_ms": {},
                "attempt_errors": [],
            },
        )

    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", response)
    run_dir = run_performance_campaign(
        load_performance_plan(plan_path),
        load_performance_runtime(runtime_path),
        repo_root=tmp_path,
        output_root=tmp_path / "runs",
    )
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed-with-errors"
    assert manifest["warmups"]["errors"] == 1
    assert manifest["officially_valid"] is False


def test_over_output_usage_aborts_with_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-over-output")
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: (
            {"model": "test-model", "usage": {"prompt_tokens": 8, "completion_tokens": 3}},
            {"ttft_ms": 1.0, "total_ms": 2.0},
        ),
    )
    output = tmp_path / "runs"

    with pytest.raises(ProtocolError, match="exceeds requested and plan output limit"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=output,
        )
    run_dir = next(output.iterdir())
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "aborted" and verify_bundle(run_dir)["valid"] is True


def test_campaign_duration_is_checked_after_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-duration")
    plan_path.write_text(
        plan_path.read_text(encoding="utf-8").replace("max_campaign_seconds = 10", "max_campaign_seconds = 0.05"),
        encoding="utf-8",
    )
    calls = 0

    def slow_response(*_args: object, **_kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        nonlocal calls
        calls += 1
        threading.Event().wait(0.06)
        return (
            {"model": "test-model", "usage": {"prompt_tokens": 8, "completion_tokens": 2}},
            {"ttft_ms": 1.0, "total_ms": 2.0},
        )

    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", slow_response)
    output = tmp_path / "runs"
    with pytest.raises(ProtocolError, match="campaign time limit exceeded"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=output,
        )
    assert calls == 1
    assert json.loads((next(output.iterdir()) / "manifest.json").read_text(encoding="utf-8"))["status"] == "aborted"


def test_campaign_cools_down_between_repetition_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-cooldown")
    plan_path.write_text(
        plan_path.read_text(encoding="utf-8").replace("repetitions = 1", "repetitions = 2").replace("cooldown_seconds = 0", "cooldown_seconds = 1"),
        encoding="utf-8",
    )

    def response(_url: str, payload: dict[str, object], _key: str, _timeout: float, *, request_id: str) -> tuple[dict[str, object], dict[str, object]]:
        started = time.perf_counter_ns()
        threading.Event().wait(0.002)
        finished = time.perf_counter_ns()
        first_content = started + (finished - started) // 2
        ttft_ms = round((first_content - started) / 1_000_000, 3)
        total_ms = round((finished - started) / 1_000_000, 3)
        return (
            {
                "model": "test-model",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                "stream_events": [
                    {
                        "model": "test-model",
                        "choices": [{"delta": {"content": "ok"}}],
                        "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                    }
                ],
            },
            {
                "request_id": request_id,
                "attempts": 1,
                "request_bytes": len(json.dumps(payload, ensure_ascii=False).encode()),
                "response_bytes": 20,
                "headers_ms": 0.0,
                "ttft_ms": ttft_ms,
                "total_ms": total_ms,
                "streaming": True,
                "started_monotonic_ns": started,
                "headers_monotonic_ns": started,
                "first_content_monotonic_ns": first_content,
                "finished_monotonic_ns": finished,
                "event_monotonic_ns": [first_content],
                "inter_chunk_ms": {},
                "attempt_errors": [],
            },
        )

    cooldowns: list[float] = []
    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", response)
    monkeypatch.setattr("cavada_eval.performance.time.sleep", cooldowns.append)

    run_performance_campaign(
        load_performance_plan(plan_path),
        load_performance_runtime(runtime_path),
        repo_root=tmp_path,
        output_root=tmp_path / "runs",
    )

    assert cooldowns == [1.0] * 5


def test_performance_preset_accepts_runtime_without_explicit_plan() -> None:
    args = parser().parse_args(["perf", "run", "runtime.toml", "--preset", "reference"])
    assert args.plan is None and args.runtime == "runtime.toml" and args.preset == "reference"
    for retired in ("smoke", "quick", "standard", "full"):
        with pytest.raises(SystemExit):
            parser().parse_args(["perf", "run", "runtime.toml", "--preset", retired])


def test_performance_cli_accepts_explicit_integrity_inputs() -> None:
    args = parser().parse_args(
        [
            "perf",
            "run",
            "runtime.toml",
            "--preset",
            "reference",
            "--system-evidence",
            "system-evidence.json",
            "--execution-record",
            "execution-record.json",
            "--engagement",
            "engagement.json",
            "--official",
        ]
    )
    assert (
        args.official is True
        and args.system_evidence == "system-evidence.json"
        and args.execution_record == "execution-record.json"
        and args.engagement == "engagement.json"
    )


def test_runtime_requires_exact_model_artifact_digest(tmp_path: Path) -> None:
    _, runtime = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-invalid-digest")
    runtime.write_text(runtime.read_text(encoding="utf-8").replace("c" * 64, "mutable-tag"), encoding="utf-8")
    with pytest.raises(ProtocolError, match="model_artifact_revision must be a lowercase SHA-256"):
        load_performance_runtime(runtime)


@pytest.mark.parametrize("name", ("llm-serving-smoke-v1.toml", "llm-serving-quick-v1.toml", "llm-serving-standard-v1.toml", "llm-serving-v1.toml"))
def test_released_v1_plans_are_preserved_but_not_executable(name: str) -> None:
    root = Path(__file__).parents[1] / "performance" / "plans"
    with pytest.raises(ProtocolError, match="plan_version 2.0.0"):
        load_performance_plan(root / name)


def test_reference_v2_preregisters_cache_arrivals_and_p99_resolution(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    plan = load_performance_plan(root / "performance" / "plans" / "llm-serving-v2.toml")
    summary = performance_plan_summary(plan)
    assert summary["performance_protocol_version"] == "2.0.0"
    assert sha256_file(root / "PERFORMANCE_PROTOCOL_V2.md") != sha256_file(root / "PERFORMANCE_PROTOCOL_V1_0.md")
    assert summary["prefix_cache_policy"] == "diverse"
    assert summary["open_loop_arrival_distribution"] == "poisson"
    assert summary["minimum_p99_observations"] == 100
    assert summary["planned_requests"] == 78_911
    assert plan.config["limits"]["max_requests"] == 80_000
    planned_token_upper_bound = _planned_token_upper_bound(plan)
    assert planned_token_upper_bound == pytest.approx(3_922_193_766.4)
    assert planned_token_upper_bound < plan.config["limits"]["max_total_tokens"] == 4_000_000_000
    scenarios = {scenario["id"]: scenario for scenario in plan.config["scenarios"]}
    assert scenarios["multi-user-throughput"]["warmup_requests"] == 64
    assert scenarios["multi-user-throughput"]["measured_requests"] == 640
    assert scenarios["long-context-concurrency"]["warmup_requests"] == 4
    assert plan.config["limits"]["max_context_tokens"] == 270336
    _, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-reference-capacity")
    runtime_path.write_text(runtime_path.read_text(encoding="utf-8").replace("max_context_tokens = 10", "max_context_tokens = 270336"), encoding="utf-8")
    assert not [cell for cell in _expand_cells(plan, load_performance_runtime(runtime_path)) if cell.get("skip_reason")]

    cell = next(cell for cell in _expand_cells(plan, None) if cell["arrival"] == "open-loop")
    assert _open_loop_offsets(plan, cell, 1, "measured") == _open_loop_offsets(plan, cell, 1, "measured")
    assert len(_open_loop_offsets(plan, cell, 1, "measured")) >= 100
    row = plan.workload[0]
    nonce = _cache_nonce(plan, cell, row, 1, 1, "measured")
    assert nonce == _cache_nonce(plan, cell, row, 1, 1, "measured")
    assert nonce != _cache_nonce(plan, cell, row, 2, 1, "measured")
    assert _messages(row, {}, nonce)[0]["content"].startswith(f"[cache-key:{nonce}]")

    observation = {
        "status": "success",
        "ttft_ms": 1.0,
        "e2e_ms": 2.0,
        "output_tokens": float(cell["output_tokens"]),
        "input_tokens": float(cell["context_tokens"]),
        "tpot_ms": 1.0,
        "decode_tokens_per_second": 1.0,
        "client_queue_ms": 0.0,
    }
    metrics = _cell_metrics([observation], cell, plan, 1.0, 1, None)
    assert metrics["p99_resolution"] == {"successful_observations": 1, "minimum": 100, "resolved": False}
    assert metrics["slo_gates"]["e2e_p99"] is False and metrics["slo_passed"] is False


def test_open_loop_saturation_cannot_pass_slo_or_goodput() -> None:
    plan = load_performance_plan(Path(__file__).parents[1] / "performance" / "plans" / "llm-serving-v2.toml")
    plan = replace(
        plan,
        config={
            **plan.config,
            "execution": {**plan.config["execution"], "bootstrap_samples": 100, "open_loop_arrival_distribution": "fixed"},
        },
    )
    cell = {
        "cell_key": "open-loop-100",
        "scenario_id": "open-loop-100",
        "arrival": "open-loop",
        "context_tokens": 2048,
        "output_tokens": 512,
        "concurrency": None,
        "request_rate": 1.0,
        "duration_seconds": 100.0,
    }

    def observations(dispatch_lag_ms: int) -> list[dict[str, object]]:
        batch_started_ns = 1_000_000_000
        rows = []
        for index in range(100):
            scheduled_ns = batch_started_ns + index * 1_000_000_000
            dispatch_ns = scheduled_ns + dispatch_lag_ms * 1_000_000
            first_ns = dispatch_ns + 100_000_000
            completed_ns = dispatch_ns + 1_000_000_000
            rows.append(
                {
                    "block": 1,
                    "status": "success",
                    "ttft_ms": 100.0,
                    "e2e_ms": 1000.0,
                    "output_tokens": 512.0,
                    "input_tokens": 2048.0,
                    "input_token_match": True,
                    "tpot_ms": 900.0 / 511,
                    "decode_tokens_per_second": 511 / 0.9,
                    "client_queue_ms": float(dispatch_lag_ms),
                    "batch_started_monotonic_ns": batch_started_ns,
                    "scheduled_monotonic_ns": scheduled_ns,
                    "dispatch_monotonic_ns": dispatch_ns,
                    "first_token_monotonic_ns": first_ns,
                    "completed_monotonic_ns": completed_ns,
                    "dispatch_lag_ms": float(dispatch_lag_ms),
                    "scheduled_ttft_ms": float(dispatch_lag_ms + 100),
                    "scheduled_e2e_ms": float(dispatch_lag_ms + 1000),
                }
            )
        return rows

    legacy = _cell_metrics(observations(60_000), cell, plan, 100.0, 1, None)
    assert legacy["status"] == "completed"
    assert legacy["slo_passed"] is True
    assert legacy["goodput_requests"] == 100
    assert legacy["goodput_requests_per_second"] == 1

    saturated = _cell_metrics_v2(observations(60_000), cell, plan, 100.0, 1, None)
    assert saturated["status"] == "invalid-loadgen"
    assert saturated["client_queue_ms"]["p95"] == 60_000
    assert saturated["dispatch_lag_ms"]["p95"] == 60_000
    assert saturated["offered_requests_per_second"] == 1
    assert saturated["dispatched_requests_per_second"] == 0.41
    assert saturated["completed_requests_per_second"] == 0.4
    assert saturated["dispatch_rate_fidelity"] == 0.41
    assert saturated["serving_slo_passed"] is True
    assert saturated["load_generator_valid"] is False
    assert saturated["slo_passed"] is False
    assert saturated["goodput_requests"] == 0
    assert saturated["goodput_requests_per_second"] == 0

    healthy = _cell_metrics_v2(observations(0), cell, plan, 100.0, 1, None)
    assert healthy["status"] == "completed"
    assert healthy["load_generator_valid"] is True
    assert healthy["dispatch_rate_fidelity"] == 1
    assert healthy["slo_passed"] is True
    assert healthy["goodput_requests"] == 100
    assert healthy["goodput_requests_per_second"] == 1


def test_v2_closed_loop_uses_contact_latency_and_has_no_open_loop_metrics() -> None:
    plan = load_performance_plan(Path(__file__).parents[1] / "performance" / "plans" / "llm-serving-v2.toml")
    plan = replace(plan, config={**plan.config, "execution": {**plan.config["execution"], "bootstrap_samples": 100}})
    cell = {
        "cell_key": "closed-loop-100",
        "scenario_id": "closed-loop-100",
        "arrival": "closed-loop",
        "context_tokens": 2048,
        "output_tokens": 512,
        "concurrency": 1,
        "request_rate": None,
    }
    batch_started_ns = 1_000_000_000
    observations = [
        {
            "block": 1,
            "status": "success",
            "ttft_ms": 100.0,
            "e2e_ms": 1000.0,
            "output_tokens": 512.0,
            "input_tokens": 2048.0,
            "input_token_match": True,
            "tpot_ms": 900.0 / 511,
            "decode_tokens_per_second": 511 / 0.9,
            "client_queue_ms": 0.0,
            "batch_started_monotonic_ns": batch_started_ns,
            "scheduled_monotonic_ns": batch_started_ns,
            "dispatch_monotonic_ns": batch_started_ns + index * 1_000_000_000,
            "first_token_monotonic_ns": batch_started_ns + index * 1_000_000_000 + 100_000_000,
            "completed_monotonic_ns": batch_started_ns + index * 1_000_000_000 + 1_000_000_000,
            "dispatch_lag_ms": float(index * 1000),
            "scheduled_ttft_ms": float(index * 1000 + 100),
            "scheduled_e2e_ms": float(index * 1000 + 1000),
        }
        for index in range(100)
    ]

    metrics = _cell_metrics_v2(observations, cell, plan, 101.0, 1, None)

    assert metrics["status"] == "completed"
    assert metrics["serving_slo_passed"] is True
    assert metrics["load_generator_valid"] is None
    assert metrics["load_generator_gates"] == {}
    assert metrics["successes"] == 100
    assert metrics["goodput_requests"] == 100
    assert metrics["offered_requests"] is None
    assert metrics["dispatch_rate_fidelity"] is None
    assert metrics["dispatch_lag_ms"] is None
    assert metrics["scheduled_ttft_ms"] is None
    assert metrics["scheduled_e2e_ms"] is None


def test_v2_open_loop_drain_uses_distinct_measurement_and_throughput_windows() -> None:
    plan = load_performance_plan(Path(__file__).parents[1] / "performance" / "plans" / "llm-serving-v2.toml")
    plan = replace(
        plan,
        config={
            **plan.config,
            "execution": {**plan.config["execution"], "bootstrap_samples": 100, "open_loop_arrival_distribution": "fixed"},
        },
    )
    cell = {
        "cell_key": "open-loop-drain-100",
        "scenario_id": "open-loop-drain-100",
        "arrival": "open-loop",
        "context_tokens": 2048,
        "output_tokens": 512,
        "concurrency": None,
        "request_rate": 1.0,
        "duration_seconds": 100.0,
    }
    batch_started_ns = 1_000_000_000
    observations = []
    for index in range(100):
        scheduled_ns = batch_started_ns + index * 1_000_000_000
        observations.append(
            {
                "block": 1,
                "status": "success",
                "ttft_ms": 100.0,
                "e2e_ms": 2000.0,
                "output_tokens": 512.0,
                "input_tokens": 2048.0,
                "input_token_match": True,
                "tpot_ms": 1900.0 / 511,
                "decode_tokens_per_second": 511 / 1.9,
                "client_queue_ms": 0.0,
                "batch_started_monotonic_ns": batch_started_ns,
                "scheduled_monotonic_ns": scheduled_ns,
                "dispatch_monotonic_ns": scheduled_ns,
                "first_token_monotonic_ns": scheduled_ns + 100_000_000,
                "completed_monotonic_ns": scheduled_ns + 2_000_000_000,
                "dispatch_lag_ms": 0.0,
                "scheduled_ttft_ms": 100.0,
                "scheduled_e2e_ms": 2000.0,
            }
        )

    metrics = _cell_metrics_v2(observations, cell, plan, 101.0, 1, None)

    assert metrics["offered_requests"] == 100
    assert metrics["dispatched_requests"] == 100
    assert metrics["dispatch_rate_fidelity"] == 1
    assert metrics["load_generator_valid"] is True
    assert metrics["completed_requests"] == 99
    assert metrics["completed_requests_per_second"] == 0.99
    assert metrics["goodput_requests"] == 100
    assert metrics["goodput_requests_per_second"] == 1.0
    assert metrics["measurement_window_seconds"] == 100
    assert metrics["throughput_window_seconds"] == 101
    assert metrics["requests_per_second"] == pytest.approx(100 / 101)
    assert metrics["output_tokens_per_second"] == pytest.approx(51_200 / 101)


def test_v2_all_skipped_csv_keeps_stable_v2_columns(tmp_path: Path) -> None:
    path = tmp_path / "cells.csv"
    _write_cells_csv(
        path,
        [
            {
                "block": 1,
                "cell_key": "skipped-v2",
                "scenario_id": "skipped-v2",
                "arrival": "open-loop",
                "context_tokens": 128,
                "output_tokens": 64,
                "concurrency": None,
                "request_rate": 1.0,
                "status": "skipped",
                "reason": "unsupported context",
            }
        ],
    )

    header, row = path.read_text(encoding="utf-8").splitlines()
    assert "dispatch_rate_fidelity" in header
    assert "measurement_window_seconds" in header
    assert "throughput_window_seconds" in header
    assert "skipped-v2" in row
    values = dict(zip(header.split(","), row.split(","), strict=True))
    assert values["dispatch_rate_fidelity"] == values["measurement_window_seconds"] == values["throughput_window_seconds"] == ""
    assert values["reason"] == "unsupported context"
    assert {"goodput_requests", "input_tokens_total", "output_tokens_total", "error_types", "warnings"} <= values.keys()


def test_v2_open_loop_window_boundary_is_inclusive_to_the_nanosecond() -> None:
    plan = load_performance_plan(Path(__file__).parents[1] / "performance" / "plans" / "llm-serving-v2.toml")
    plan = replace(
        plan,
        config={
            **plan.config,
            "execution": {**plan.config["execution"], "bootstrap_samples": 100},
            "load_generator": {
                "minimum_dispatch_rate_fraction": 0.5,
                "maximum_dispatch_lag_p95_ms": 200_000,
                "maximum_dispatch_lag_ms": 200_000,
            },
        },
    )
    cell = {
        "cell_key": "open-loop-boundary",
        "scenario_id": "open-loop-boundary",
        "arrival": "open-loop",
        "context_tokens": 2048,
        "output_tokens": 512,
        "concurrency": None,
        "request_rate": 0.02,
        "duration_seconds": 100.0,
    }
    batch_started_ns = 1_000_000_000
    window_end_ns = 101_000_000_000
    observations = [
        {
            "block": 1,
            "status": "error",
            "error_type": "boundary",
            "client_queue_ms": 0.0,
            "batch_started_monotonic_ns": batch_started_ns,
            "scheduled_monotonic_ns": batch_started_ns,
            "dispatch_monotonic_ns": boundary,
            "completed_monotonic_ns": boundary,
            "dispatch_lag_ms": round((boundary - batch_started_ns) / 1_000_000, 3),
        }
        for boundary in (window_end_ns, window_end_ns + 1)
    ]

    metrics = _cell_metrics_v2(observations, cell, plan, 100.000000001, 1, None)

    assert metrics["offered_requests"] == 2
    assert metrics["dispatched_requests"] == 1
    assert metrics["completed_requests"] == 1
    assert metrics["dispatched_requests_per_second"] == 0.01
    assert metrics["completed_requests_per_second"] == 0.01


def test_transport_failures_have_one_terminal_response_and_outcome(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        plan_path, runtime_path = _files(tmp_path, f"http://127.0.0.1:{server.server_port}/v1", "runtime-errors")
        run_dir = run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=tmp_path / "runs",
        )
    finally:
        server.shutdown()
        thread.join()

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    reconciliation = manifest["request_reconciliation"]
    assert reconciliation["campaign_complete"] is True
    assert reconciliation["scheduled"] == reconciliation["responses"] == reconciliation["terminal_outcomes"] == manifest["planned_requests"]
    responses = [json.loads(line) for line in (run_dir / "responses.jsonl").read_text(encoding="utf-8").splitlines()]
    assert responses and all(row["terminal"] and row["status"] == "error" for row in responses)


def test_response_error_usage_is_counted_and_costed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-error-usage")
    runtime_path.write_text(
        runtime_path.read_text(encoding="utf-8")
        + '''
[pricing]
currency = "USD"
source = "test-rate-card"
effective_at = "2026-01-01"
input_per_million = 1
output_per_million = 2
''',
        encoding="utf-8",
    )
    calls = 0

    def response_error(*_args: object, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        nonlocal calls
        calls += 1
        started_ns = time.perf_counter_ns()
        finished_ns = time.perf_counter_ns()
        raise _ResponseError(
            "provider returned an error after reporting usage",
            request={"model": "test-model"},
            raw={"model": "test-model", "usage": {"prompt_tokens": 8, "completion_tokens": 2}},
            transport={
                "request_id": kwargs["request_id"],
                "attempts": 1,
                "started_monotonic_ns": started_ns,
                "finished_monotonic_ns": finished_ns,
            },
        )

    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", response_error)
    run_dir = run_performance_campaign(
        load_performance_plan(plan_path),
        load_performance_runtime(runtime_path),
        repo_root=tmp_path,
        output_root=tmp_path / "runs",
    )

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed-with-errors"
    assert manifest["token_usage"] == {"input": calls * 8.0, "output": calls * 2.0, "total": calls * 10.0}
    assert manifest["estimated_cost"]["amount"] == pytest.approx(calls * 12 / 1_000_000)
    outcomes = [
        json.loads(line)
        for name in ("warmups.jsonl", "observations.jsonl")
        for line in (run_dir / name).read_text(encoding="utf-8").splitlines()
    ]
    assert all((row["input_tokens"], row["output_tokens"]) == (8.0, 2.0) for row in outcomes)


def test_response_error_usage_enforces_campaign_token_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-error-budget")
    plan_path.write_text(
        plan_path.read_text(encoding="utf-8").replace('mode = "iso-token"', 'mode = "iso-prompt"').replace("max_total_tokens = 1000", "max_total_tokens = 100"),
        encoding="utf-8",
    )
    runtime_path.write_text(runtime_path.read_text(encoding="utf-8").replace("max_context_tokens = 10", "max_context_tokens = 100"), encoding="utf-8")

    def response_error(*_args: object, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        raise _ResponseError(
            "provider returned an error after reporting usage",
            request={"model": "test-model"},
            raw={"model": "test-model", "usage": {"prompt_tokens": 20, "completion_tokens": 2}},
            transport={"request_id": kwargs["request_id"], "attempts": 1},
        )

    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", response_error)
    output = tmp_path / "runs"
    with pytest.raises(ProtocolError, match="total token limit exceeded"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=output,
        )

    manifest = json.loads((next(output.iterdir()) / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "aborted" and manifest["tokens"] > 100


def test_provider_usage_enforces_runtime_context_capacity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-context-usage")
    plan_path.write_text(plan_path.read_text(encoding="utf-8").replace('mode = "iso-token"', 'mode = "iso-prompt"'), encoding="utf-8")
    monkeypatch.setattr(
        "cavada_eval.performance._post_openai_stream",
        lambda *_args, **_kwargs: (
            {"model": "test-model", "usage": {"prompt_tokens": 9, "completion_tokens": 1}},
            {"ttft_ms": 1.0, "total_ms": 2.0},
        ),
    )
    output = tmp_path / "runs"
    with pytest.raises(ProtocolError, match="provider prompt usage 9 plus requested output 2 exceeds runtime context limit 10"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=output,
        )

    manifest = json.loads((next(output.iterdir()) / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "aborted" and manifest["token_usage"] == {"input": 9.0, "output": 1.0, "total": 10.0}


@pytest.mark.parametrize(
    ("reported_model", "usage", "message"),
    [
        ("test-model", None, "did not report prompt_tokens"),
        ("wrong-model", {"prompt_tokens": 8, "completion_tokens": 2}, "model identity mismatch"),
        ("test-model", {"prompt_tokens": 12, "completion_tokens": 2}, "input token mismatch"),
    ],
)
def test_identity_usage_and_iso_token_mismatch_abort_with_verified_evidence(
    tmp_path: Path,
    reported_model: str,
    usage: dict[str, int] | None,
    message: str,
) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            events: list[dict[str, object]] = [
                {"model": reported_model, "choices": [{"delta": {"content": "one "}}]},
                {"model": reported_model, "choices": [{"delta": {"content": "two"}}]},
            ]
            if usage is not None:
                events.append({"model": reported_model, "choices": [], "usage": usage})
            body = b"".join(f"data: {json.dumps(event)}\n\n".encode() for event in events) + b"data: [DONE]\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output_root = tmp_path / "runs"
    try:
        plan_path, runtime_path = _files(tmp_path, f"http://127.0.0.1:{server.server_port}/v1", "runtime-fatal")
        with pytest.raises(ProtocolError, match=message):
            run_performance_campaign(
                load_performance_plan(plan_path),
                load_performance_runtime(runtime_path),
                repo_root=tmp_path,
                output_root=output_root,
            )
    finally:
        server.shutdown()
        thread.join()

    run_dir = next(output_root.iterdir())
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "aborted" and message in manifest["abort_reason"]
    assert manifest["request_reconciliation"]["ledgers_complete"] is True
    assert verify_bundle(run_dir)["valid"] is True
    responses = [json.loads(line) for line in (run_dir / "responses.jsonl").read_text(encoding="utf-8").splitlines()]
    assert responses[-1]["fatal"] is True and responses[-1]["response"] is not None


@pytest.mark.parametrize("partial_stream_error", [False, True])
def test_fatal_identity_mismatch_stops_before_the_next_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, partial_stream_error: bool
) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-stop")
    plan_path.write_text(
        plan_path.read_text(encoding="utf-8").replace("warmup_requests = 1", "warmup_requests = 0").replace("measured_requests = 2", "measured_requests = 5"),
        encoding="utf-8",
    )
    calls = 0

    def wrong_model(*_args: object, **_kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        nonlocal calls
        calls += 1
        if partial_stream_error:
            raise _ResponseError(
                "stream failed after conflicting identities",
                request={"model": "test-model"},
                raw={"model": "test-model", "stream_events": [{"model": "wrong-model"}, {"model": "test-model"}]},
                transport={"request_id": str(_kwargs["request_id"]), "attempts": 1},
            )
        return (
            {"model": "wrong-model", "usage": {"prompt_tokens": 8, "completion_tokens": 2}},
            {"ttft_ms": 1.0, "total_ms": 2.0},
        )

    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", wrong_model)
    output = tmp_path / "runs"
    with pytest.raises(ProtocolError, match="model identity mismatch"):
        run_performance_campaign(
            load_performance_plan(plan_path),
            load_performance_runtime(runtime_path),
            repo_root=tmp_path,
            output_root=output,
        )

    manifest = json.loads((next(output.iterdir()) / "manifest.json").read_text(encoding="utf-8"))
    assert calls == 1
    assert manifest["request_reconciliation"]["ledgers_complete"] is True
    assert manifest["request_reconciliation"]["scheduled"] == 1 < manifest["request_reconciliation"]["planned"]


def test_official_performance_requires_content_addressed_runtime_revisions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Path(__file__).parents[1]
    plan = load_performance_plan(repo / "performance" / "plans" / "llm-serving-v2.toml")
    _, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-mutable")
    evidence_path = tmp_path / "system-evidence.json"
    evidence_path.write_text(json.dumps(_system_evidence("http://127.0.0.1:1/v1")), encoding="utf-8")
    monkeypatch.setattr(
        "cavada_eval.performance.git_evidence",
        lambda _root: {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64},
    )

    with pytest.raises(ProtocolError, match="content-addressed model_revision and engine_revision"):
        performance_run_preflight(
            plan,
            load_performance_runtime(runtime_path),
            repo_root=repo,
            system_evidence_path=evidence_path,
            official=True,
        )


def test_system_evidence_mismatch_and_non_reference_official_fail_before_network(tmp_path: Path) -> None:
    plan_path, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-preflight")
    plan = load_performance_plan(plan_path)
    runtime = load_performance_runtime(runtime_path)
    evidence = _system_evidence("http://127.0.0.1:1/v1")
    evidence["software"]["engine"]["name"] = "different-engine"  # type: ignore[index]
    evidence["configuration_id"] = system_configuration_id(evidence)
    evidence_path = tmp_path / "system-evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ProtocolError, match="differs from performance runtime"):
        performance_run_preflight(plan, runtime, repo_root=Path(__file__).parents[1], system_evidence_path=evidence_path)

    evidence = _system_evidence("http://127.0.0.1:1/v1")
    evidence["network"]["transport"] = "tls"  # type: ignore[index]
    evidence["configuration_id"] = system_configuration_id(evidence)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(ProtocolError, match="network.transport"):
        performance_run_preflight(plan, runtime, repo_root=Path(__file__).parents[1], system_evidence_path=evidence_path)

    evidence = _system_evidence("http://127.0.0.1:1/v1")
    evidence["network"]["relationship"] = "direct-lan"  # type: ignore[index]
    evidence["load_generator"]["colocated_with_server"] = False  # type: ignore[index]
    evidence["configuration_id"] = system_configuration_id(evidence)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(ProtocolError, match="network.relationship"):
        performance_run_preflight(plan, runtime, repo_root=Path(__file__).parents[1], system_evidence_path=evidence_path)

    evidence = _system_evidence("http://127.0.0.1:1/v1")
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(ProtocolError, match="exact reference plan"):
        performance_run_preflight(plan, runtime, repo_root=Path(__file__).parents[1], system_evidence_path=evidence_path, official=True)


def test_official_preflight_requires_clean_source_and_complete_restricted_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Path(__file__).parents[1]
    plan = load_performance_plan(repo / "performance" / "plans" / "llm-serving-v2.toml")
    _, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-official")
    runtime_path.write_text(runtime_path.read_text(encoding="utf-8").replace("model-revision", "a" * 40), encoding="utf-8")
    runtime = load_performance_runtime(runtime_path)
    monkeypatch.setattr("cavada_eval.performance.git_evidence", lambda _root: {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64})

    with pytest.raises(ProtocolError, match="requires --system-evidence"):
        performance_run_preflight(plan, runtime, repo_root=repo, official=True)

    evidence = _system_evidence("http://127.0.0.1:1/v1")
    evidence["software"]["model"]["revision"] = "a" * 40
    evidence["load_generator"]["client"]["revision"] = "a" * 40  # type: ignore[index]
    evidence["projection"] = "public"
    evidence["configuration_id"] = system_configuration_id(evidence)
    evidence_path = tmp_path / "system-evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(ProtocolError, match="complete restricted|must redact"):
        performance_run_preflight(plan, runtime, repo_root=repo, system_evidence_path=evidence_path, official=True)

    evidence["projection"] = "restricted"
    evidence["configuration_id"] = system_configuration_id(evidence)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    monkeypatch.setattr("cavada_eval.performance.git_evidence", lambda _root: {"commit": "a" * 40, "dirty": True, "status_sha256": "b" * 64})
    with pytest.raises(ProtocolError, match="clean committed source tree"):
        performance_run_preflight(plan, runtime, repo_root=repo, system_evidence_path=evidence_path, official=True)

    monkeypatch.setattr("cavada_eval.performance.git_evidence", lambda _root: {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64})
    evidence["load_generator"]["client"]["revision"] = "wrong-client-revision"  # type: ignore[index]
    evidence["configuration_id"] = system_configuration_id(evidence)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(ProtocolError, match="load_generator.client"):
        performance_run_preflight(plan, runtime, repo_root=repo, system_evidence_path=evidence_path, official=True)

    evidence["load_generator"]["client"]["revision"] = "a" * 40  # type: ignore[index]
    evidence["configuration_id"] = system_configuration_id(evidence)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(ProtocolError, match="requires every reference cell"):
        performance_run_preflight(plan, runtime, repo_root=repo, system_evidence_path=evidence_path, official=True)


@pytest.mark.parametrize("age", [timedelta(hours=25), timedelta(minutes=-1)])
def test_official_preflight_rejects_stale_or_future_system_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    age: timedelta,
) -> None:
    repo = Path(__file__).parents[1]
    plan = load_performance_plan(repo / "performance" / "plans" / "llm-serving-v2.toml")
    _, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-evidence-age")
    runtime_path.write_text(runtime_path.read_text(encoding="utf-8").replace("model-revision", "a" * 40), encoding="utf-8")
    evidence = _system_evidence("http://127.0.0.1:1/v1")
    evidence["software"]["model"]["revision"] = "a" * 40  # type: ignore[index]
    evidence["load_generator"]["client"]["revision"] = "a" * 40  # type: ignore[index]
    evidence["collected_at"] = (datetime.now(timezone.utc) - age).isoformat()
    evidence["configuration_id"] = system_configuration_id(evidence)
    evidence_path = tmp_path / "system-evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    monkeypatch.setattr("cavada_eval.performance.git_evidence", lambda _root: {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64})

    with pytest.raises(ProtocolError, match="collected within the previous 24 hours"):
        performance_run_preflight(
            plan,
            load_performance_runtime(runtime_path),
            repo_root=repo,
            system_evidence_path=evidence_path,
            official=True,
        )


def test_official_performance_rejects_code_from_a_different_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Path(__file__).parents[1]
    plan = load_performance_plan(repo / "performance" / "plans" / "llm-serving-v2.toml")
    _, runtime_path = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-wheel")
    monkeypatch.setattr("cavada_eval.performance.__file__", str(tmp_path / "wheel" / "cavada_eval" / "performance.py"))

    with pytest.raises(ProtocolError, match="executed cavada_eval package"):
        performance_run_preflight(plan, load_performance_runtime(runtime_path), repo_root=repo, official=True)
