from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.performance import (
    _campaign_summary,
    _cell_metrics,
    _expand_cells,
    _request_material,
    _write_performance_comparison_reports,
    compare_performance_runs,
    load_performance_plan,
    load_performance_runtime,
    verify_performance_comparison,
)
from cavada_eval.protocol import ProtocolError, atomic_json, sha256_bytes, sha256_file


def _run(
    root: Path,
    runtime_id: str,
    *,
    gpu_model: str = "gpu-a",
    max_context_tokens: int = 10,
    plan_name: str = "comparison-test-v1",
    evidence_id: str | None = None,
    model_revision: str = "model-revision",
    error_block: int | None = None,
) -> Path:
    root.mkdir(parents=True)
    protocol = root / "protocol_snapshot.md"
    protocol.write_bytes((Path(__file__).parents[1] / "PERFORMANCE_PROTOCOL_V1_0.md").read_bytes())
    workload = root / "workload_snapshot.jsonl"
    workload.write_text(
        "".join(json.dumps({"id": f"ctx-{context}", "context_tokens": context, "prompt": "test"}) + "\n" for context in (8, 16)),
        encoding="utf-8",
    )
    workload_hash = sha256_file(workload)
    plan = root / "plan_snapshot.toml"
    plan.write_text(
        f'''plan_version = "1.0.0"
revision = "1.0.0"
name = "{plan_name}"
description = "Comparison test."
profile = "llm-serving-v1"
data_classification = "synthetic"
[workload]
id = "comparison-workload-v1"
revision = "1.0.0"
path = "workload_snapshot.jsonl"
sha256 = "{workload_hash}"
mode = "iso-prompt"
[execution]
repetitions = 2
warmup_requests = 0
measured_requests = 2
open_loop_duration_seconds = 1
open_loop_arrival_distribution = "fixed"
bootstrap_samples = 100
seed = 1
randomize_cells = false
cooldown_seconds = 0
max_in_flight = 1
[generation]
stream = true
temperature = 0
[limits]
timeout_seconds = 5
max_requests = 8
max_total_tokens = 1000
max_campaign_seconds = 10
max_context_tokens = 16
max_output_tokens = 2
[slo]
ttft_p95_ms = 100
e2e_p99_ms = 100
goodput_ttft_ms = 100
goodput_e2e_ms = 100
maximum_error_rate = 0
minimum_output_tokens_fraction = 1
[[scenarios]]
id = "closed"
arrival = "closed-loop"
context_tokens = [8, 16]
output_tokens = [2]
concurrency = [1]
''',
        encoding="utf-8",
    )
    runtime_path = root / "runtime_snapshot.toml"
    runtime_path.write_text(
        f'''runtime_version = "1.0.0"
id = "{runtime_id}"
endpoint = "http://127.0.0.1:8000/v1"
request_model = "test-model"
expected_model = "test-model"
model_revision = "{model_revision}"
api_key_env = "MISSING_TEST_KEY"
engine = "test-engine"
engine_revision = "dddddddddddddddddddddddddddddddddddddddd"
model_artifact_revision = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
dtype = "fp16"
quantization = "none"
gpu_count = 1
gpu_model = "{gpu_model}"
tensor_parallel = 1
max_context_tokens = {max_context_tokens}
launch_command_sanitized = "test-server"
''',
        encoding="utf-8",
    )
    plan_object = load_performance_plan(plan)
    runtime = load_performance_runtime(runtime_path)
    runtime_manifest = {
        **{key: value for key, value in runtime.config.items() if key not in {"endpoint", "pricing"}},
        "endpoint": runtime.config["endpoint"],
        "sha256": runtime.sha256,
        "pricing": None,
    }
    rows: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    expanded = _expand_cells(plan_object, runtime)
    for block in (1, 2):
        for cell_index, cell in enumerate(expanded, 1):
            if cell.get("skip_reason"):
                rows.append({**cell, "block": block, "status": "skipped", "reason": cell["skip_reason"]})
            else:
                batch_started_ns = (block * 10 + cell_index) * 1_000_000_000
                cell_observations: list[dict[str, Any]] = []
                for request_index in (1, 2):
                    request_id = f"{runtime_id}-{block}-{cell['cell_key']}-{request_index}"
                    finished_ns = batch_started_ns + request_index * 500_000_000
                    e2e_ms = 20.0 if block == 1 else 200.0
                    transport_started_ns = batch_started_ns
                    headers_ns = transport_started_ns + 1_000_000
                    first_content_ns = transport_started_ns + 10_000_000
                    transport_finished_ns = transport_started_ns + int(e2e_ms * 1_000_000)
                    base = {
                        "request_id": request_id,
                        "cell_key": cell["cell_key"],
                        "scenario_id": cell["scenario_id"],
                        "block": block,
                        "phase": "measured",
                        "request_index": request_index,
                        "workload_id": f"ctx-{cell['context_tokens']}",
                        "declared_context_tokens": cell["context_tokens"],
                        "requested_output_tokens": cell["output_tokens"],
                        "client_queue_ms": 0.0,
                        "scheduled_monotonic_ns": batch_started_ns,
                        "batch_started_monotonic_ns": batch_started_ns,
                        "started_monotonic_ns": batch_started_ns,
                    }
                    observation = {
                        **base,
                        "finished_monotonic_ns": finished_ns,
                        "status": "success",
                        "reported_model": "test-model",
                        "input_tokens": float(cell["context_tokens"]),
                        "output_tokens": float(cell["output_tokens"]),
                        "input_token_match": True,
                        "ttft_ms": 10.0,
                        "e2e_ms": e2e_ms,
                        "tpot_ms": e2e_ms - 10.0,
                        "decode_tokens_per_second": 1000 / (e2e_ms - 10.0),
                        "headers_ms": 1.0,
                        "inter_chunk_ms": {},
                        "request_bytes": 10,
                        "response_bytes": 20,
                    }
                    if block == error_block and cell_index == 1 and request_index == 1:
                        for field in (
                            "reported_model",
                            "input_token_match",
                            "ttft_ms",
                            "e2e_ms",
                            "tpot_ms",
                            "decode_tokens_per_second",
                            "headers_ms",
                            "inter_chunk_ms",
                            "request_bytes",
                            "response_bytes",
                        ):
                            observation.pop(field)
                        observation.update(status="error", error_type="TimeoutError", error="timed out after provider usage")
                    _, payload = _request_material(
                        plan_object,
                        runtime.config,
                        cell,
                        next(row for row in plan_object.workload if row["context_tokens"] == cell["context_tokens"]),
                        request_index,
                        block,
                        "measured",
                        {},
                    )
                    request_bytes = len(json.dumps(payload, ensure_ascii=False).encode())
                    observation["request_bytes"] = request_bytes
                    requests.append(
                        {
                            **base,
                            "accepted": True,
                            "payload_sha256": sha256_bytes(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()),
                        }
                    )
                    responses.append(
                        {
                            **base,
                            "finished_monotonic_ns": finished_ns,
                            "terminal": True,
                            "network_contacted": True,
                            "status": observation["status"],
                            **({"error_type": observation["error_type"], "error": observation["error"]} if observation["status"] == "error" else {}),
                            "response": {
                                "model": "test-model",
                                "choices": [{"message": {"content": "ok"}}],
                                "usage": {"prompt_tokens": cell["context_tokens"], "completion_tokens": cell["output_tokens"]},
                                "stream_events": [
                                    {"model": "test-model", "choices": [{"delta": {"content": "ok"}}]},
                                    {
                                        "model": "test-model",
                                        "choices": [{"delta": {}}],
                                        "usage": {"prompt_tokens": cell["context_tokens"], "completion_tokens": cell["output_tokens"]},
                                    },
                                ],
                            },
                            "transport": {
                                "request_id": request_id,
                                "attempts": 1,
                                "request_bytes": request_bytes,
                                "response_bytes": 20,
                                "headers_ms": 1.0,
                                "ttft_ms": 10.0,
                                "total_ms": e2e_ms,
                                "streaming": True,
                                "started_monotonic_ns": transport_started_ns,
                                "headers_monotonic_ns": headers_ns,
                                "first_content_monotonic_ns": first_content_ns,
                                "finished_monotonic_ns": transport_finished_ns,
                                "event_monotonic_ns": [first_content_ns, transport_finished_ns],
                                "inter_chunk_ms": {},
                                "attempt_errors": [],
                            },
                        }
                    )
                    observations.append(observation)
                    cell_observations.append(observation)
                metric = _cell_metrics(
                    cell_observations,
                    cell,
                    plan_object,
                    1.0,
                    1 + block * 1000 + cell_index,
                    None,
                )
                metric["block"] = block
                rows.append(metric)
    cells = root / "cells.jsonl"
    cells.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    for name, ledger_rows in (
        ("requests.jsonl", requests),
        ("responses.jsonl", responses),
        ("observations.jsonl", observations),
    ):
        (root / name).write_text("".join(json.dumps(row) + "\n" for row in ledger_rows), encoding="utf-8")
    (root / "warmups.jsonl").write_text("", encoding="utf-8")
    completed = [row for row in rows if row["status"] == "completed"]
    with_errors = [row for row in rows if row["status"] == "completed-with-errors"]
    evaluated = [*completed, *with_errors]
    skipped = [row for row in rows if row["status"] == "skipped"]
    system_evidence: dict[str, Any] | None = None
    if evidence_id is not None:
        evidence = {
            "configuration_id": evidence_id,
            "projection": "restricted",
            "collected_at": "2026-08-07T00:00:00+00:00",
        }
        evidence_path = root / "system_evidence_snapshot.json"
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        system_evidence = {**evidence, "sha256": sha256_file(evidence_path)}
    asset_set_hash = sha256_bytes(b"{}")
    manifest = {
        "performance_protocol_version": "1.0.0",
        "protocol_sha256": sha256_file(protocol),
        "plan_version": "1.0.0",
        "report_version": "1.0.0",
        "run_id": f"run-{runtime_id}",
        "status": "completed-with-errors" if with_errors else "completed",
        "official_requested": False,
        "officially_valid": False,
        "plan": {
            "name": plan_name,
            "revision": "1.0.0",
            "sha256": sha256_file(plan),
            "profile": "llm-serving-v1",
            "data_classification": "synthetic",
            "open_loop_arrival_distribution": "fixed",
            "execution_seed": 1,
        },
        "workload": {
            "id": "comparison-workload-v1",
            "revision": "1.0.0",
            "mode": "iso-prompt",
            "sha256": workload_hash,
            "asset_set_sha256": asset_set_hash,
            "assets": {},
            "cases": 2,
        },
        "runtime": runtime_manifest,
        "system_evidence": system_evidence,
        "source": {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64},
        "environment": {"python": "3.13", "platform": "test", "hardware": {"cpu_count": 8}, "uv_lock_sha256": "c" * 64},
        "started_at": "2026-08-07T00:00:00+00:00",
        "finished_at": "2026-08-07T00:01:00+00:00",
        "planned_requests": len(requests),
        "planned_cells": len(rows),
        "requests": len(requests),
        "tokens": sum(row["input_tokens"] + row["output_tokens"] for row in observations),
        "token_usage": {
            "input": sum(row["input_tokens"] for row in observations),
            "output": sum(row["output_tokens"] for row in observations),
            "total": sum(row["input_tokens"] + row["output_tokens"] for row in observations),
        },
        "estimated_cost": None,
        "cells": {
            "total": len(rows),
            "completed": len(completed),
            "with_errors": len(with_errors),
            "skipped": len(skipped),
            "slo_passed": sum(row["slo_passed"] is True for row in evaluated),
            "slo_failed": sum(row["slo_passed"] is False for row in evaluated),
        },
        "warmups": {"total": 0, "successes": 0, "errors": 0},
        "request_reconciliation": {
            "planned": len(requests),
            "scheduled": len(requests),
            "accepted": len(requests),
            "responses": len(responses),
            "warmup_outcomes": 0,
            "measured_outcomes": len(observations),
            "terminal_outcomes": len(observations),
            "ledgers_complete": True,
            "campaign_complete": True,
        },
    }
    (root / "summary.json").write_text(json.dumps(_campaign_summary(manifest, rows, observations)), encoding="utf-8")
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    write_bundle(root)
    return root


def _manifest(run: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((run / "manifest.json").read_text(encoding="utf-8")))


def _write_manifest(run: Path, manifest: dict[str, Any]) -> None:
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    write_bundle(run)


def test_performance_comparison_accounts_for_cells_and_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cavada_eval.performance.load_system_evidence", lambda path: json.loads(Path(path).read_text(encoding="utf-8")))
    monkeypatch.setattr("cavada_eval.performance._cross_check_system_evidence", lambda *_args: None)
    left = _run(tmp_path / "left", "runtime-a", gpu_model="gpu-a", evidence_id="cfg-a")
    right = _run(tmp_path / "right", "runtime-b", gpu_model="gpu-b", evidence_id="cfg-b")

    result = compare_performance_runs([left, right], tmp_path / "comparison")

    assert result["shared_cells"] == 2
    assert len(result["skipped_cells"]) == 4
    assert result["non_shared_cells"] == []
    assert len(result["rows"]) == 4 and any(row["slo_passed"] is False for row in result["rows"])
    assert all(row["observed_block_throughput_ratio_vs_baseline"] is not None for row in result["rows"])
    assert all(summary["n"] == 2 for summary in result["observed_throughput_ratio_vs_baseline_across_blocks"])
    assert [run["system_evidence"]["configuration_id"] for run in result["runs"]] == ["cfg-a", "cfg-b"]
    differences = {item["field"] for item in result["configuration_differences"]}
    assert {"runtime.gpu_model", "system_evidence.configuration_id"} <= differences
    assert "not causal" in result["limitations"]
    assert verify_bundle(tmp_path / "comparison")["valid"] is True
    assert verify_performance_comparison(tmp_path / "comparison")["semantic_valid"] is False
    assert verify_performance_comparison(tmp_path / "comparison", source_run_dirs=[left, right])["semantic_valid"] is True
    with pytest.raises(ProtocolError, match="source runs do not match recorded bundle hashes or order"):
        verify_performance_comparison(tmp_path / "comparison", source_run_dirs=[right, left])


def test_performance_comparison_reports_every_included_and_excluded_cell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def completed(cell_key: str, *, status: str = "completed", slo_passed: bool = True) -> dict[str, Any]:
        return {
            "block": 1,
            "cell_key": cell_key,
            "status": status,
            "successes": 1 if status == "completed" else 0,
            "observations": 1,
            "errors": 0 if status == "completed" else 1,
            "error_types": {} if status == "completed" else {"TimeoutError": 1},
            "ttft_ms": {"p95": 10.0},
            "e2e_ms": {"p99": 20.0},
            "tpot_ms": {"p50": 5.0},
            "output_tokens_per_second": 20.0,
            "output_tokens_total": 20.0,
            "throughput_window_seconds": 1.0,
            "goodput_requests_per_second": 1.0 if slo_passed else 0.0,
            "goodput_requests": 1.0 if slo_passed else 0.0,
            "measurement_window_seconds": 1.0,
            "error_rate": 0.0 if status == "completed" else 1.0,
            "slo_passed": slo_passed,
            "estimated_cost": None,
        }

    invalid = {
        **completed("invalid", status="invalid-loadgen", slo_passed=False),
        "successes": 1,
        "errors": 0,
        "error_types": {},
        "serving_slo_passed": True,
        "load_generator_invalid_reasons": ["dispatch lag p95 exceeds its preregistered maximum"],
    }
    common_manifest = {
        "performance_protocol_version": "2.0.0",
        "protocol_sha256": "a" * 64,
        "plan_version": "2.0.0",
        "report_version": "2.0.0",
        "plan": {"name": "comparison-v2", "revision": "2.0.0", "sha256": "b" * 64},
        "workload": {"id": "comparison-workload-v2", "revision": "2.0.0", "sha256": "c" * 64, "asset_set_sha256": "d" * 64, "assets": {}},
    }

    def input_record(
        runtime_id: str,
        cells: dict[tuple[int, str], dict[str, Any]],
        skipped: dict[tuple[int, str], str],
        gpu_model: str,
    ) -> tuple[dict[str, Any], dict[tuple[int, str], dict[str, Any]], dict[tuple[int, str], str], dict[str, Any], dict[str, Any], str]:
        runtime = {
            "id": runtime_id,
            "engine": "test-engine",
            "model_revision": "e" * 40,
            "model_artifact_revision": "f" * 64,
            "gpu_model": gpu_model,
            "pricing": None,
        }
        manifest = {
            **common_manifest,
            "run_id": f"run-{runtime_id}",
            "status": "invalid-loadgen" if runtime_id == "runtime-a" else "completed",
            "official_requested": False,
            "officially_valid": False,
            "runtime": runtime,
            "warmups": {"total": 0, "successes": 0, "errors": 0},
        }
        configuration = {
            "runtime": runtime,
            "system_evidence": {"configuration_id": f"cfg-{runtime_id}"},
            "source": {"commit": "1" * 40, "dirty": False},
            "environment": {"platform": "test"},
        }
        return manifest, cells, skipped, configuration, {}, "9" * 64

    left = tmp_path / "left"
    right = tmp_path / "right"
    records = {
        left: input_record(
                "runtime-a",
                {
                    (1, "shared"): completed("shared"),
                    (1, "errored"): completed("errored", status="completed-with-errors", slo_passed=False),
                    (1, "invalid"): invalid,
                    (1, "left-only"): completed("left-only"),
                },
                {(1, "skipped"): "context exceeds the runtime limit"},
                "gpu-a",
            ),
        right: input_record(
                "runtime-b",
                {
                    (1, "shared"): completed("shared", slo_passed=False),
                    (1, "errored"): completed("errored"),
                    (1, "invalid"): completed("invalid"),
                    (1, "skipped"): completed("skipped"),
                    (1, "right-only"): completed("right-only"),
                },
                {},
                "gpu-b",
            ),
    }
    monkeypatch.setattr("cavada_eval.performance._performance_comparison_input", lambda path, *_args, **_kwargs: records[Path(path)])

    output = tmp_path / "comparison"
    result = compare_performance_runs([left, right], output)

    assert result["shared_cells"] == 1
    assert len(result["excluded_cells"]) == 8
    assert len(result["configuration_differences"]) == 2
    report = (output / "report.html").read_text(encoding="utf-8")
    for evidence in (
        "comparison-v2",
        "comparison-workload-v2",
        "runtime.gpu_model",
        "completed-with-errors",
        "invalid-loadgen",
        "context exceeds the runtime limit",
        "non-shared",
        "dispatch lag p95 exceeds its preregistered maximum",
        "left-only",
        "right-only",
    ):
        assert evidence in report
    csv_report = (output / "comparison.csv").read_text(encoding="utf-8")
    assert all(record_type in csv_report for record_type in ("compared", "skipped", "completed-with-errors", "invalid-loadgen", "non-shared"))
    svg = (output / "throughput_comparison.svg").read_text(encoding="utf-8")
    assert "B1 · shared" in svg and "Comparable cell" not in svg
    pdf = (output / "report.pdf").read_bytes()
    assert b"CONFIGURATION DIFFERENCES" in pdf and b"EXCLUDED CELLS" in pdf
    assert verify_performance_comparison(output)["semantic_valid"] is False
    assert verify_performance_comparison(output, source_run_dirs=[left, right])["semantic_valid"] is True

    report_path = output / "report.html"
    original_report = report_path.read_bytes()
    report_path.write_bytes(original_report + b"false presentation")
    write_bundle(output)
    with pytest.raises(ProtocolError, match="presentation differs from comparison.json"):
        verify_performance_comparison(output)
    report_path.write_bytes(original_report)
    write_bundle(output)

    comparison_path = output / "comparison.json"
    altered = json.loads(comparison_path.read_text(encoding="utf-8"))
    altered["excluded_cells"] = altered["excluded_cells"][:-1]
    comparison_path.write_text(json.dumps(altered), encoding="utf-8")
    write_bundle(output)
    with pytest.raises(ProtocolError, match="excluded-cell projection does not reconcile"):
        verify_performance_comparison(output)


@pytest.mark.parametrize("corruption", ("metric", "removed-rows"))
def test_performance_comparison_rejects_resealed_source_semantic_forgery(tmp_path: Path, corruption: str) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    output = tmp_path / "comparison"
    compare_performance_runs([left, right], output)
    comparison_path = output / "comparison.json"
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    if corruption == "metric":
        comparison["rows"][0]["output_tokens_per_second"] += 1.0
    else:
        comparison["rows"] = []
        comparison["shared_cells"] = 0
        comparison["comparison_eligible"] = False
        comparison["slo_failed_cells"] = []
        comparison["observed_throughput_ratio_vs_baseline_across_blocks"] = []
        (output / "throughput_comparison.svg").unlink()
    atomic_json(comparison_path, comparison)
    _write_performance_comparison_reports(output, comparison)
    write_bundle(output)

    assert verify_performance_comparison(output)["semantic_valid"] is False
    with pytest.raises(ProtocolError, match="differs from exact source runs"):
        verify_performance_comparison(output, source_run_dirs=[left, right])


def test_performance_comparison_rejects_resealed_extra_claim_file(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    output = tmp_path / "comparison"
    compare_performance_runs([left, right], output)
    (output / "false-claims.html").write_text("<p>false comparison claim</p>", encoding="utf-8")
    write_bundle(output)

    with pytest.raises(ProtocolError, match="unexpected or missing artifacts"):
        verify_performance_comparison(output, source_run_dirs=[left, right])


def test_performance_comparison_verifier_reads_only_its_verified_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    output = tmp_path / "comparison"
    compare_performance_runs([left, right], output)
    swapped = False

    def verify_then_swap(path: Path, **kwargs: Any) -> dict[str, Any]:
        nonlocal swapped
        result = verify_bundle(path, **kwargs)
        if not swapped and path.resolve() != output.resolve():
            swapped = True
            (output / "comparison.json").write_text("{}", encoding="utf-8")
        return result

    monkeypatch.setattr("cavada_eval.performance.verify_bundle", verify_then_swap)

    assert verify_performance_comparison(output, source_run_dirs=[left, right])["semantic_valid"] is True
    assert swapped is True and verify_bundle(output)["valid"] is False


def test_performance_comparison_declares_errors_without_false_comparability(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a", error_block=1)
    right = _run(tmp_path / "right", "runtime-b", error_block=2)

    result = compare_performance_runs([left, right], tmp_path / "comparison")

    assert result["shared_cells"] == 0 and result["rows"] == []
    assert {item["runtime_id"] for item in result["errored_cells"]} == {"runtime-a", "runtime-b"}
    assert len(result["non_shared_cells"]) == 2
    assert all(run["status"] == "completed-with-errors" and run["officially_valid"] is False for run in result["runs"])
    assert (tmp_path / "comparison" / "comparison.csv").read_text(encoding="utf-8").startswith("block,cell_key,runtime_id")
    assert not (tmp_path / "comparison" / "throughput_comparison.svg").exists()
    assert "No exact shared completed cells are available for a throughput chart." in (tmp_path / "comparison" / "report.html").read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize(
    ("corruption", "message"),
    [
        ("partial", "partial performance cells"),
        ("duplicate", "duplicate performance cell"),
        ("error", "is not completed"),
        ("metric", "metrics differ from immutable observations"),
    ],
)
def test_performance_comparison_rejects_incomplete_or_invalid_cells_before_output(
    tmp_path: Path,
    corruption: str,
    message: str,
) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    rows = [json.loads(line) for line in (left / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    if corruption == "partial":
        rows.pop()
    elif corruption == "duplicate":
        rows.append(rows[0])
    elif corruption == "error":
        next(row for row in rows if row["status"] == "completed")["status"] = "completed-with-errors"
    else:
        next(row for row in rows if row["status"] == "completed")["output_tokens_per_second"] += 1
    (left / "cells.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    write_bundle(left)

    output = tmp_path / "comparison"
    with pytest.raises(ProtocolError, match=message):
        compare_performance_runs([left, right], output)
    assert not output.exists()


@pytest.mark.parametrize(
    ("corruption", "message"),
    [
        ("status", "finalized completed"),
        ("reconciliation", "complete reconciled"),
        ("version", "identical protocol, plan, and report versions"),
        ("official", "coherent boolean official status"),
    ],
)
def test_performance_comparison_rejects_nonfinalized_or_version_mismatched_runs(
    tmp_path: Path,
    corruption: str,
    message: str,
) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    manifest = _manifest(right)
    if corruption == "status":
        manifest["status"] = "aborted"
    elif corruption == "reconciliation":
        manifest["request_reconciliation"]["campaign_complete"] = False
    elif corruption == "version":
        manifest["report_version"] = "2.0.0"
    else:
        manifest["officially_valid"] = True
    _write_manifest(right, manifest)

    output = tmp_path / "comparison"
    with pytest.raises(ProtocolError, match=message):
        compare_performance_runs([left, right], output)
    assert not output.exists()


def test_performance_comparison_rejects_forged_historical_official_status(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    manifest = _manifest(right)
    manifest["official_requested"] = manifest["officially_valid"] = True
    _write_manifest(right, manifest)

    output = tmp_path / "comparison"
    with pytest.raises(ProtocolError, match="official performance comparison requires the current performance protocol"):
        compare_performance_runs([left, right], output)
    assert not output.exists()


def test_performance_comparison_requires_exact_plan_assets_and_skip_contract(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    different_plan = _run(tmp_path / "different-plan", "runtime-b", plan_name="different-plan-v1")
    with pytest.raises(ProtocolError, match="identical plan and workload hashes"):
        compare_performance_runs([left, different_plan], tmp_path / "plan-comparison")
    assert not (tmp_path / "plan-comparison").exists()

    right = _run(tmp_path / "right", "runtime-b")
    asset = right / "workload_assets" / "asset.txt"
    asset.parent.mkdir()
    asset.write_text("asset", encoding="utf-8")
    manifest = _manifest(right)
    manifest["workload"]["assets"] = {"asset.txt": sha256_file(asset)}
    manifest["workload"]["asset_set_sha256"] = sha256_bytes(json.dumps(manifest["workload"]["assets"], sort_keys=True, separators=(",", ":")).encode())
    _write_manifest(right, manifest)
    with pytest.raises(ProtocolError, match="workload snapshot differs from its manifest"):
        compare_performance_runs([left, right], tmp_path / "asset-comparison")
    assert not (tmp_path / "asset-comparison").exists()

    wider = _run(tmp_path / "wider", "runtime-c", max_context_tokens=20)
    comparison = compare_performance_runs([left, wider], tmp_path / "skip-comparison")
    assert comparison["shared_cells"] == 2
    assert len(comparison["skipped_cells"]) == 2
    assert len(comparison["non_shared_cells"]) == 2
    assert {item["runtime_id"] for item in comparison["skipped_cells"]} == {"runtime-a"}
    assert {item["runtime_id"] for item in comparison["non_shared_cells"]} == {"runtime-c"}


def test_performance_comparison_withholds_ratios_across_model_revisions(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a", model_revision="model-revision-a")
    right = _run(tmp_path / "right", "runtime-b", model_revision="model-revision-b")

    result = compare_performance_runs([left, right], tmp_path / "comparison")

    assert all(row["observed_block_throughput_ratio_vs_baseline"] is None for row in result["rows"])
    assert all(row["throughput_ratio_unavailable_reason"] for row in result["rows"])
    assert all(item["n"] == 0 and item["median"] is None for item in result["observed_throughput_ratio_vs_baseline_across_blocks"])


def test_performance_comparison_rejects_protocol_snapshot_drift_before_output(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    (right / "protocol_snapshot.md").write_text("different protocol\n", encoding="utf-8")
    _write_manifest(right, _manifest(right))

    output = tmp_path / "comparison"
    with pytest.raises(ProtocolError, match="protocol snapshot hash mismatch"):
        compare_performance_runs([left, right], output)
    assert not output.exists()


def test_performance_comparison_rejects_self_consistent_noncanonical_protocol(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    snapshot = left / "protocol_snapshot.md"
    snapshot.write_bytes(snapshot.read_bytes() + b"\nforged")
    manifest = _manifest(left)
    manifest["protocol_sha256"] = sha256_file(snapshot)
    _write_manifest(left, manifest)

    output = tmp_path / "comparison"
    with pytest.raises(ProtocolError, match="not canonical for version 1.0.0"):
        compare_performance_runs([left, right], output)
    assert not output.exists()


def test_performance_comparison_rejects_ledger_tampering_before_output(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    observations = (left / "observations.jsonl").read_text(encoding="utf-8").splitlines()
    (left / "observations.jsonl").write_text("\n".join(observations[:-1]) + "\n", encoding="utf-8")
    write_bundle(left)

    output = tmp_path / "comparison"
    with pytest.raises(ProtocolError, match="do not identify the same requests"):
        compare_performance_runs([left, right], output)
    assert not output.exists()


def test_performance_comparison_rejects_aggregate_tampering_before_output(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    manifest = _manifest(left)
    manifest["token_usage"]["total"] += 1
    _write_manifest(left, manifest)

    output = tmp_path / "comparison"
    with pytest.raises(ProtocolError, match="token aggregates differ from the immutable ledgers"):
        compare_performance_runs([left, right], output)
    assert not output.exists()


@pytest.mark.parametrize(
    ("ledger", "mutation", "message"),
    [
        ("requests.jsonl", "payload", "payload differs from the preregistered workload"),
        ("responses.jsonl", "usage", "outcome differs from provider response or transport evidence"),
    ],
)
def test_performance_comparison_binds_requests_and_outcomes_to_raw_evidence(
    tmp_path: Path,
    ledger: str,
    mutation: str,
    message: str,
) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    path = left / ledger
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    if mutation == "payload":
        rows[0]["payload_sha256"] = "f" * 64
    else:
        rows[0]["response"]["usage"]["prompt_tokens"] += 1
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    write_bundle(left)

    output = tmp_path / "comparison"
    with pytest.raises(ProtocolError, match=message):
        compare_performance_runs([left, right], output)


def test_performance_comparison_rejects_resealed_contradictory_stream_identity(tmp_path: Path) -> None:
    left = _run(tmp_path / "left", "runtime-a")
    right = _run(tmp_path / "right", "runtime-b")
    path = left / "responses.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["response"]["stream_events"][0]["model"] = "wrong-model"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    write_bundle(left)

    output = tmp_path / "comparison"
    with pytest.raises(ProtocolError, match="inconsistent model identity"):
        compare_performance_runs([left, right], output)
    assert not output.exists()
    assert not output.exists()
