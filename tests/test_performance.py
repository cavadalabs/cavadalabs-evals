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
    _performance_telemetry,
    build_performance_matrix,
    compare_performance_runs,
    load_performance_plan,
    load_performance_runtime,
    performance_plan_summary,
    run_performance_campaign,
)
from cavada_eval.protocol import ProtocolError, sha256_file


def test_collapsed_sse_decode_timing_is_omitted() -> None:
    raw = {
        "stream_events": [
            {
                "timings": {
                    "predicted_ms": 4000,
                    "predicted_n": 128,
                    "predicted_per_second": 999.0,
                    "prompt_ms": 2000,
                    "prompt_n": 1000,
                    "prompt_per_second": 1.0,
                }
            }
        ]
    }
    collapsed = _decode_metrics(raw, {"ttft_ms": 69000, "total_ms": 69006}, 128, 1000)
    streamed = _decode_metrics(raw, {"ttft_ms": 69000, "total_ms": 73000}, 128, 1000)

    assert collapsed["stream_timing_valid"] is False and collapsed["decode_tokens_per_second"] is None
    assert streamed["stream_timing_valid"] is True and streamed["decode_tokens_per_second"] == 31.75
    assert collapsed["server_decode_tokens_per_second"] == streamed["server_decode_tokens_per_second"] == 32.0
    assert streamed["server_prompt_tokens_per_second"] == 500.0
    assert streamed["provider_decode_tokens_per_second"] == 999.0
    assert streamed["decode_rate_relative_difference"] == pytest.approx(0.0078125)


def test_hardware_telemetry_is_validated_summarized_and_copied(tmp_path: Path) -> None:
    telemetry = tmp_path / "gpu.csv"
    telemetry.write_text(
        "timestamp,device,edge_c,junction_c,memory_c,power_w,gpu_use_percent,vram_allocated_percent,vram_activity_percent,memory_activity,average_memory_bandwidth\n"
        "2026-08-08T10:00:00+02:00,card0,40,50,60,100,90,70,20,N/A,0\n"
        "2026-08-08T10:00:05+02:00,card0,42,53,62,110,100,72,30,N/A,0\n",
        encoding="utf-8",
    )
    links = tmp_path / "links.tsv"
    links.write_text("run-a\tgpu.csv\t5\trocm-smi\n", encoding="utf-8")
    result = _performance_telemetry(links, {"run-a"}, tmp_path / "output")

    assert result["run-a"]["average_board_power_w"] == 105
    assert result["run-a"]["lifecycle_energy_wh"] == pytest.approx(105 * 5 / 3600)
    assert result["run-a"]["vram_allocated_percent"]["max"] == 72
    assert len(list((tmp_path / "output" / "telemetry").iterdir())) == 1


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
[measurement]
require_server_generation_timing = true
require_server_prompt_timing = true
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
gpu_model = "test-gpu-{runtime_id}"
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
                {
                    "model": "test-model",
                    "choices": [],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                    "timings": {"prompt_n": 8, "prompt_ms": 8, "predicted_n": 2, "predicted_ms": 2},
                },
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
    assert all(cell["timing_coverage"]["server_generation"] == 1 for cell in cells)
    assert all(cell["ttft_ms"]["count"] > 0 and cell["output_tokens_per_second"] > 0 for cell in cells)
    assert "<circle" in (left_run / "figures" / "ttft.svg").read_text(encoding="utf-8")
    assert (left_run / "figures" / "decode.svg").is_file()
    assert "Metric contract" in (left_run / "report.html").read_text(encoding="utf-8")
    observations = [json.loads(line) for line in (left_run / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(row["client_queue_ms"] == 0 for row in observations if row["scenario_id"] == "closed")
    assert not (left_run / "judgments.jsonl").exists()
    output = tmp_path / "comparison"
    comparison = compare_performance_runs([left_run, right_run], output)
    assert comparison["shared_cells"] == 3 and verify_bundle(output)["valid"]
    assert {
        "model",
        "context_tokens",
        "ttft_p50_ms",
        "generation_tps_p50",
        "server_generation_tps_p50",
        "server_prefill_tps_p50",
    } <= set(comparison["rows"][0])
    comparison_html = (output / "report.html").read_text(encoding="utf-8")
    assert "Metric matrices" in comparison_html and "Complete results grid" in comparison_html
    assert "Server gen p50" in comparison_html and "position:sticky" in comparison_html
    run_pdf = PdfReader(left_run / "report.pdf")
    comparison_pdf = PdfReader(output / "report.pdf")
    assert len(run_pdf.pages) >= 2 and "Measured performance cells" in "".join(page.extract_text() or "" for page in run_pdf.pages)
    comparison_text = "".join(page.extract_text() or "" for page in comparison_pdf.pages)
    assert len(comparison_pdf.pages) >= 2 and "Observed comparison" in comparison_text
    assert "TTFT p95 matrix" in comparison_text and "End-to-end output throughput matrix" in comparison_text

    matrix_output = tmp_path / "matrix"
    matrix_result = build_performance_matrix([left_run, right_run], matrix_output)
    assert matrix_result["status"] == "completed" and matrix_result["eligible_cells"] == 6
    assert all(row["server_context_tokens"] == 10 for row in matrix_result["rows"])
    assert verify_bundle(matrix_output)["valid"]
    matrix_html = (matrix_output / "report.html").read_text(encoding="utf-8")
    assert "Server generation p50" in matrix_html and "Complete exact results" in matrix_html
    assert "Server context" in matrix_html and "Prompt input" in matrix_html
    assert "Performance curves" in matrix_html and (matrix_output / "figures" / "generation-1gpu.svg").is_file()
    assert "<circle" in (matrix_output / "figures" / "generation-1gpu.svg").read_text(encoding="utf-8")
    matrix_pdf = PdfReader(matrix_output / "report.pdf")
    matrix_text = "".join(page.extract_text() or "" for page in matrix_pdf.pages)
    assert "LLM Serving Campaign Matrix" in matrix_text and "Server generation p50 matrix" in matrix_text
    assert "Server generation p50 charts" in matrix_text and "Time to first token p95 charts" in matrix_text


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
        "performance_protocol_version": "1.1.0",
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
