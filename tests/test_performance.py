from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from pypdf import PdfReader

from cavada_eval.artifacts import verify_bundle
from cavada_eval.cli import main, parser
from cavada_eval.performance import (
    _decode_metrics,
    _performance_pdf,
    compare_performance_runs,
    load_performance_plan,
    load_performance_runtime,
    performance_plan_summary,
    run_performance_campaign,
)
from cavada_eval.protocol import ProtocolError, sha256_file


def test_collapsed_sse_decode_timing_is_omitted() -> None:
    raw = {"stream_events": [{"timings": {"predicted_ms": 4000, "predicted_per_second": 32.0}}]}
    collapsed = _decode_metrics(raw, {"ttft_ms": 69000, "total_ms": 69006}, 128)
    streamed = _decode_metrics(raw, {"ttft_ms": 69000, "total_ms": 73000}, 128)

    assert collapsed["stream_timing_valid"] is False and collapsed["decode_tokens_per_second"] is None
    assert streamed["stream_timing_valid"] is True and streamed["decode_tokens_per_second"] == 31.75


def _files(root: Path, endpoint: str, runtime_id: str) -> tuple[Path, Path]:
    workload = root / "workload.jsonl"
    workload.write_text(
        json.dumps({"id": "ctx-8", "context_tokens": 8, "repeat_text": " datum", "repeat_count": 8}) + "\n",
        encoding="utf-8",
    )
    plan = root / "plan.toml"
    workload_hash = sha256_file(workload)
    plan.write_text(
        f"""plan_version = "1.0.0"
revision = "1.0.0"
name = "test-serving-v1"
description = "Bounded test campaign."
profile = "llm-serving-v1"
data_classification = "synthetic"
[workload]
id = "test-workload-v1"
revision = "1.0.0"
path = "workload.jsonl"
sha256 = "{workload_hash}"
mode = "iso-token"
input_token_tolerance_fraction = 0
[generation]
stream = true
temperature = 0
[execution]
repetitions = 1
warmup_requests = 1
measured_requests = 2
open_loop_duration_seconds = 0.05
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
model_revision = "model-sha"
api_key_env = "MISSING_TEST_KEY"
engine = "test-engine"
engine_revision = "engine-sha"
model_artifact_revision = "artifact-sha"
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
        left_run = run_performance_campaign(
            load_performance_plan(left_plan),
            load_performance_runtime(left_runtime),
            repo_root=tmp_path,
            output_root=tmp_path / "runs-a",
        )
        right_run = run_performance_campaign(
            load_performance_plan(right_plan),
            load_performance_runtime(right_runtime),
            repo_root=tmp_path,
            output_root=tmp_path / "runs-b",
        )
    finally:
        server.shutdown()
        thread.join()

    assert verify_bundle(left_run)["valid"] and verify_bundle(right_run)["valid"]
    manifest = json.loads((left_run / "manifest.json").read_text(encoding="utf-8"))
    cells = [json.loads(line) for line in (left_run / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    assert manifest["status"] == "completed" and len(cells) == 3
    assert all(cell["slo_passed"] for cell in cells)
    assert all(cell["ttft_ms"]["count"] > 0 and cell["output_tokens_per_second"] > 0 for cell in cells)
    assert "<circle" in (left_run / "figures" / "ttft.svg").read_text(encoding="utf-8")
    assert (left_run / "figures" / "decode.svg").is_file()
    assert "How to read this run" in (left_run / "report.html").read_text(encoding="utf-8")
    observations = [json.loads(line) for line in (left_run / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(row["client_queue_ms"] == 0 for row in observations if row["scenario_id"] == "closed")
    assert not (left_run / "judgments.jsonl").exists()
    output = tmp_path / "comparison"
    comparison = compare_performance_runs([left_run, right_run], output)
    assert comparison["shared_cells"] == 3 and verify_bundle(output)["valid"]
    assert "Highest output rate" in (output / "report.html").read_text(encoding="utf-8")
    run_pdf = PdfReader(left_run / "report.pdf")
    comparison_pdf = PdfReader(output / "report.pdf")
    assert len(run_pdf.pages) >= 2 and "Measured performance cells" in "".join(page.extract_text() or "" for page in run_pdf.pages)
    assert len(comparison_pdf.pages) >= 2 and "Observed comparison" in "".join(page.extract_text() or "" for page in comparison_pdf.pages)


def test_performance_failure_pdf_is_explicit_and_auditable(tmp_path: Path) -> None:
    cell = {
        "cell_key": "capacity-128k__ctx129024__out128__c1",
        "context_tokens": 129024,
        "output_tokens": 128,
        "concurrency": 1,
        "observations": 3,
        "status": "completed-with-errors",
        "error_rate": 1.0,
        "error_types": {"ProtocolError": 3},
        "warnings": ["no successful observations"],
        "ttft_ms": {"p95": 0},
        "decode_tokens_per_second": {"p50": 0},
        "output_tokens_per_second": 0,
    }
    manifest = {
        "run_id": "failure-run-with-a-long-auditable-identifier",
        "status": "completed-with-errors",
        "started_at": "2026-08-06T10:00:00+00:00",
        "finished_at": "2026-08-06T10:01:00+00:00",
        "performance_protocol_version": "1.0.1",
        "plan": {"name": "capacity-128k", "revision": "1.0.0", "sha256": "a" * 64, "data_classification": "synthetic"},
        "workload": {"id": "long-context", "revision": "1.0.0", "sha256": "b" * 64, "asset_set_sha256": "c" * 64},
        "runtime": {
            "id": "model-gpu0-128k",
            "expected_model": "model",
            "model_revision": "d" * 64,
            "model_artifact_revision": "e" * 64,
            "engine": "engine",
            "engine_revision": "f" * 64,
            "quantization": "Q4",
            "dtype": "f16",
            "gpu_count": 1,
            "gpu_model": "test GPU",
            "tensor_parallel": 1,
            "max_context_tokens": 131072,
            "endpoint": "http://127.0.0.1:8000/v1",
            "launch_command_sanitized": "engine --api-key REDACTED",
        },
        "cells": {"slo_passed": 0, "slo_failed": 1},
        "warmups": {"successes": 0, "errors": 1},
        "source": {"commit": "1" * 40, "dirty": False},
    }
    summary = {
        "observations": 3,
        "successes": 0,
        "errors": 3,
        "best_goodput_cell": cell,
        "campaign_token_usage": {"input": 0},
        "limitations": ["Small sample."],
    }
    output = tmp_path / "failure.pdf"
    _performance_pdf(output, manifest, summary, [cell])
    reader = PdfReader(output)
    text = "".join(page.extract_text() or "" for page in reader.pages)
    assert len(reader.pages) >= 2 and "RUN CONTAINS ERRORS" in text and "ProtocolError" in text


def test_performance_plan_fails_closed_before_network(tmp_path: Path) -> None:
    plan, runtime = _files(tmp_path, "http://127.0.0.1:1/v1", "runtime-a")
    assert main(["perf", "validate", str(plan), "--runtime", str(runtime)]) == 0
    plan.write_text(plan.read_text(encoding="utf-8").replace('data_classification = "synthetic"', 'data_classification = "confidential"'))
    with pytest.raises(ProtocolError, match="only permits public or synthetic"):
        load_performance_plan(plan)
    assert load_performance_runtime(runtime).config["id"] == "runtime-a"


def test_performance_preset_accepts_runtime_without_explicit_plan() -> None:
    args = parser().parse_args(["perf", "run", "runtime.toml", "--preset", "quick"])
    assert args.plan is None and args.runtime == "runtime.toml" and args.preset == "quick"


def test_builtin_quick_and_standard_plans_keep_declared_request_budgets() -> None:
    root = Path(__file__).parents[1] / "performance" / "plans"
    quick = performance_plan_summary(load_performance_plan(root / "llm-serving-quick-v1.toml"))
    standard = performance_plan_summary(load_performance_plan(root / "llm-serving-standard-v1.toml"))
    assert (quick["planned_requests"], quick["cells_per_repetition"]) == (98, 12)
    assert (standard["planned_requests"], standard["cells_per_repetition"]) == (825, 34)
