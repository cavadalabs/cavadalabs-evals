from __future__ import annotations

import json
import shutil
import tarfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.performance import (
    PerformanceRuntime,
    _campaign_summary,
    _cell_metrics_v2,
    _expand_cells,
    _measurement_window,
    _performance_reports,
    _require_official_reference_inputs,
    _write_cells_csv,
    load_performance_plan,
    load_performance_runtime,
    run_performance_campaign,
    verify_performance_source_bundle,
)
from cavada_eval.performance_release import (
    PERFORMANCE_PUBLICATION_VERSION,
    PERMITTED_CLAIM,
    _copy_checked,
    _public_cells,
    _public_presentation_manifest,
    _release_approval,
    export_public_performance,
)
from cavada_eval.protocol import ProtocolError, sha256_bytes, sha256_file
from cavada_eval.public_verify import verify_public_bundle
from cavada_eval.runner import _ResponseError

ROOT = Path(__file__).parents[1]


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_publication_copy_rejects_source_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "artifact.txt"
    source.write_text("original", encoding="utf-8")
    destination = tmp_path / "destination.txt"
    real_copy = shutil.copy2

    def drift_then_copy(src: Path, dst: Path) -> str:
        Path(src).write_text("changed", encoding="utf-8")
        return str(real_copy(src, dst))

    monkeypatch.setattr("cavada_eval.performance_release.shutil.copy2", drift_then_copy)
    with pytest.raises(ProtocolError, match="changed while copied"):
        _copy_checked(source, destination, source_root=source_root)


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    response_error: bool = False,
    open_loop: bool = False,
) -> Path:
    protocol_name = "PERFORMANCE_PROTOCOL_V2.md"
    (tmp_path / protocol_name).write_bytes((ROOT / protocol_name).read_bytes())
    workload = tmp_path / "workload.jsonl"
    workload.write_text(json.dumps({"id": "case", "context_tokens": 8, "repeat_text": " datum", "repeat_count": 8}) + "\n")
    plan = tmp_path / "plan.toml"
    load_generator = """[load_generator]
minimum_dispatch_rate_fraction = 0.98
maximum_dispatch_lag_p95_ms = 100
maximum_dispatch_lag_ms = 1000
"""
    scenario = (
        """id = "open"
arrival = "open-loop"
context_tokens = [8]
output_tokens = [2]
request_rates = [1]
warmup_requests = 0
duration_seconds = 1
"""
        if open_loop
        else """id = "closed"
arrival = "closed-loop"
context_tokens = [8]
output_tokens = [2]
concurrency = [1]
"""
    )
    plan.write_text(
        f'''plan_version = "2.0.0"
revision = "2.0.0"
name = "publication-test"
description = "Publication test."
profile = "llm-serving-v2"
data_classification = "synthetic"
[workload]
id = "publication-test"
revision = "1.0.0"
path = "workload.jsonl"
sha256 = "{sha256_file(workload)}"
mode = "iso-token"
input_token_tolerance_fraction = 0
[generation]
stream = true
temperature = 0
[execution]
repetitions = 1
warmup_requests = 0
measured_requests = 1
open_loop_duration_seconds = 1
bootstrap_samples = 100
seed = 1
randomize_cells = false
cooldown_seconds = 0
max_in_flight = 1
{load_generator}
[limits]
timeout_seconds = 5
max_requests = 1
max_total_tokens = 20
max_campaign_seconds = 10
max_context_tokens = 8
max_output_tokens = 2
[slo]
ttft_p95_ms = 100
e2e_p99_ms = 100
goodput_ttft_ms = 100
goodput_e2e_ms = 100
maximum_error_rate = 0
minimum_output_tokens_fraction = 1
[[scenarios]]
{scenario}
'''
    )
    runtime = tmp_path / "runtime.toml"
    runtime.write_text(
        """runtime_version = "1.0.0"
id = "runtime-a"
endpoint = "http://127.0.0.1:1/v1"
request_model = "test-model"
expected_model = "test-model"
model_revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
api_key_env = "PRIVATE_TEST_API_ENV"
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
"""
    )

    def response(_url: str, payload: dict[str, Any], _key: str, _timeout: float, *, request_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if response_error:
            raise _ResponseError(
                "private provider error after usage",
                request=payload,
                raw={"model": "test-model", "usage": {"prompt_tokens": 8, "completion_tokens": 2}},
                transport={"request_id": request_id, "attempts": 1},
            )
        started_ns = time.perf_counter_ns()
        time.sleep(0.002)
        finished_ns = time.perf_counter_ns()
        first_content_ns = started_ns + (finished_ns - started_ns) // 2
        ttft_ms = round((first_content_ns - started_ns) / 1_000_000, 3)
        total_ms = round((finished_ns - started_ns) / 1_000_000, 3)
        return (
            {
                "model": "test-model",
                "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                "choices": [{"message": {"content": "RAW_PRIVATE_COMPLETION_42"}}],
                "stream_events": [
                    {
                        "model": "test-model",
                        "choices": [{"delta": {"content": "RAW_PRIVATE_COMPLETION_42"}}],
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
                "started_monotonic_ns": started_ns,
                "headers_monotonic_ns": started_ns,
                "first_content_monotonic_ns": first_content_ns,
                "finished_monotonic_ns": finished_ns,
                "event_monotonic_ns": [first_content_ns],
                "inter_chunk_ms": {},
                "attempt_errors": [],
                "raw_body_b64": "PRIVATE_RAW_BODY",
            },
        )

    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", response)
    return run_performance_campaign(
        load_performance_plan(plan),
        load_performance_runtime(runtime),
        repo_root=tmp_path,
        output_root=tmp_path / "runs",
    )


def _export_v2_public(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, open_loop: bool = True) -> Path:
    run = _run(tmp_path, monkeypatch, open_loop=open_loop)
    suffix = "open" if open_loop else "closed"
    archive = tmp_path / f"public-v2-{suffix}.tar.gz"
    export_public_performance(run, archive)
    public = tmp_path / f"public-v2-{suffix}"
    public.mkdir()
    with tarfile.open(archive) as package:
        package.extractall(public, filter="data")
    return public


def _add_test_evidence(run: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    manifest = json.loads((run / "manifest.json").read_text())
    restricted: dict[str, Any] = {
        "configuration_id": "cfg-sha256:" + "a" * 64,
        "projection": "restricted",
        "collected_at": (datetime.fromisoformat(manifest["started_at"]) - timedelta(minutes=1)).isoformat(),
        "unavailable": {"/software/engine/container_image_digest": "not applicable: engine was not containerized"},
        "software": {"engine": {"binary_sha256": "e" * 64}},
        "server": {"host_id": "private-server", "accelerators": []},
        "load_generator": {"host_id": "private-loadgen", "client": {"name": "cavadalabs-evals", "revision": "a" * 40}},
        "network": {"endpoint_host": "private-endpoint", "route": "private-route"},
    }
    public = {
        **restricted,
        "projection": "public",
        "server": {"host_id": None, "accelerators": []},
        "load_generator": {"host_id": None},
        "network": {"endpoint_host": None, "route": None},
    }
    evidence_path = run / "system_evidence_snapshot.json"
    evidence_path.write_text(json.dumps(restricted))
    manifest["system_evidence"] = {
        "configuration_id": restricted["configuration_id"],
        "sha256": sha256_file(evidence_path),
        "projection": "restricted",
        "collected_at": restricted["collected_at"],
    }
    (run / "manifest.json").write_text(json.dumps(manifest))
    _performance_reports(
        run,
        manifest,
        json.loads((run / "summary.json").read_text(encoding="utf-8")),
        [json.loads(line) for line in (run / "cells.jsonl").read_text(encoding="utf-8").splitlines()],
    )
    write_bundle(run)
    monkeypatch.setattr("cavada_eval.performance.load_system_evidence", lambda _path: restricted)
    monkeypatch.setattr("cavada_eval.performance._cross_check_system_evidence", lambda *_args: None)
    monkeypatch.setattr("cavada_eval.performance_release.load_system_evidence", lambda _path: restricted)
    monkeypatch.setattr("cavada_eval.performance_release.public_system_evidence", lambda _evidence: public)
    monkeypatch.setattr("cavada_eval.public_verify.load_system_evidence", lambda _path: public)
    monkeypatch.setattr("cavada_eval.public_verify.public_system_evidence", lambda _evidence: public)
    monkeypatch.setattr("cavada_eval.public_verify._cross_check_public_system_evidence", lambda *_args: None)
    return restricted


def _add_execution_record(run: Path, *, owner: str = "executor-1") -> None:
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    record = {
        "record_version": "1.0.0",
        "engagement_id": "local-performance-engagement-1",
        "execution_owner_id": owner,
        "scope": "Execute the exact hash-bound test performance campaign.",
        "protocol_sha256": manifest["protocol_sha256"],
        "plan_sha256": manifest["plan"]["sha256"],
        "workload_sha256": manifest["workload"]["sha256"],
        "runtime_sha256": manifest["runtime"]["sha256"],
        "system_evidence_sha256": manifest["system_evidence"]["sha256"],
        "recorded_at": (datetime.fromisoformat(manifest["started_at"]) - timedelta(seconds=1)).isoformat(),
    }
    snapshot = run / "execution_record_snapshot.json"
    snapshot.write_text(json.dumps(record), encoding="utf-8")
    manifest["execution_record"] = {
        "record_version": record["record_version"],
        "engagement_id": record["engagement_id"],
        "execution_owner_id": owner,
        "sha256": sha256_file(snapshot),
        "recorded_at": record["recorded_at"],
    }
    engagement = {
        "engagement_version": "1.0.0",
        "engagement_id": record["engagement_id"],
        "status": "approved",
        "scope": "Run and release this exact hash-bound performance campaign.",
        "execution_owner_id": owner,
        "protocol_sha256": manifest["protocol_sha256"],
        "plan_sha256": manifest["plan"]["sha256"],
        "workload_sha256": manifest["workload"]["sha256"],
        "runtime_sha256": manifest["runtime"]["sha256"],
        "system_evidence_sha256": manifest["system_evidence"]["sha256"],
        "configuration_id": manifest["system_evidence"]["configuration_id"],
        "approved_at": (datetime.fromisoformat(manifest["started_at"]) - timedelta(minutes=2)).isoformat(),
        "expires_at": (datetime.fromisoformat(manifest["finished_at"]) + timedelta(days=2)).isoformat(),
    }
    engagement_snapshot = run / "engagement_snapshot.json"
    engagement_snapshot.write_text(json.dumps(engagement), encoding="utf-8")
    manifest["engagement"] = {
        **{field: engagement[field] for field in engagement if field != "scope"},
        "sha256": sha256_file(engagement_snapshot),
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _performance_reports(
        run,
        manifest,
        json.loads((run / "summary.json").read_text(encoding="utf-8")),
        [json.loads(line) for line in (run / "cells.jsonl").read_text(encoding="utf-8").splitlines()],
    )
    write_bundle(run)


def test_performance_export_is_sanitized_and_extracted_bundle_verifies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path, monkeypatch)
    _add_test_evidence(run, monkeypatch)
    archive_path = tmp_path / "public.tar.gz"

    result = export_public_performance(run, archive_path)
    second_archive = tmp_path / "public-copy.tar.gz"
    export_public_performance(run, second_archive)
    assert archive_path.read_bytes() == second_archive.read_bytes()

    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with tarfile.open(archive_path) as archive:
        assert all(member.uid == member.gid == 0 and not member.uname and not member.gname for member in archive.getmembers())
        archive.extractall(extracted, filter="data")
    assert result["assurance"] == "development"
    assert verify_bundle(extracted)["valid"] is True
    public_text = "\n".join(path.read_text(errors="ignore") for path in extracted.rglob("*") if path.is_file())
    assert "127.0.0.1" not in public_text
    assert "PRIVATE_TEST_API_ENV" not in public_text
    assert "RAW_PRIVATE_COMPLETION_42" not in public_text
    assert "PRIVATE_RAW_BODY" not in public_text
    assert "private-server" not in public_text
    assert (extracted / "report.html").is_file()
    assert json.loads((extracted / "system_evidence.json").read_text())["projection"] == "public"
    public_manifest = json.loads((extracted / "public_manifest.json").read_text())
    assert public_manifest["protocol_sha256"] == sha256_file(extracted / "protocol_snapshot.md")
    schema = json.loads((ROOT / "schemas" / "performance-publication-2.0.0.schema.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(public_manifest)
    forged_official = {**public_manifest, "official": True, "performance_protocol_version": "1.0.0"}
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(forged_official))
    assert any(list(error.path) == ["performance_protocol_version"] for error in errors)


def test_v2_public_projection_verifies_healthy_and_invalid_loadgen_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public = _export_v2_public(tmp_path, monkeypatch)
    assert verify_public_bundle(public)["semantic_valid"] is True
    manifest = json.loads((public / "public_manifest.json").read_text(encoding="utf-8"))
    observations = [json.loads(line) for line in (public / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    cells = [json.loads(line) for line in (public / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    assert manifest["publication_version"] == PERFORMANCE_PUBLICATION_VERSION
    v2_schema = json.loads((ROOT / "schemas" / "performance-publication-2.0.0.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(v2_schema, format_checker=FormatChecker()).validate(manifest)
    assert cells[0]["load_generator_valid"] is True
    assert {
        "dispatch_monotonic_ns",
        "first_token_monotonic_ns",
        "completed_monotonic_ns",
        "dispatch_lag_ms",
        "scheduled_ttft_ms",
        "scheduled_e2e_ms",
    } <= observations[0].keys()
    observation = observations[0]
    scheduled_ns = int(observation["scheduled_monotonic_ns"])
    dispatch_ns = scheduled_ns + 60_000_000_000
    observation.update(
        {
            "started_monotonic_ns": dispatch_ns,
            "finished_monotonic_ns": dispatch_ns + round(float(observation["e2e_ms"]) * 1_000_000),
            "client_queue_ms": 60_000.0,
            "dispatch_monotonic_ns": dispatch_ns,
            "first_token_monotonic_ns": dispatch_ns + round(float(observation["ttft_ms"]) * 1_000_000),
            "completed_monotonic_ns": dispatch_ns + round(float(observation["e2e_ms"]) * 1_000_000),
            "dispatch_lag_ms": 60_000.0,
            "scheduled_ttft_ms": 60_000.0 + float(observation["ttft_ms"]),
            "scheduled_e2e_ms": 60_000.0 + float(observation["e2e_ms"]),
        }
    )
    plan = load_performance_plan(public / "plan.toml")
    runtime_config = dict(manifest["runtime"])
    runtime = PerformanceRuntime(public / "public_manifest.json", str(runtime_config["sha256"]), runtime_config)
    cell = _expand_cells(plan, runtime)[0]
    metric = _cell_metrics_v2(observations, cell, plan, _measurement_window(observations), 1002, None)
    metric["block"] = 1
    cells = _public_cells({(1, str(cell["cell_key"])): metric}, {})
    manifest["status"] = "invalid-loadgen"
    manifest["cells"] = {
        "total": 1,
        "completed": 0,
        "with_errors": 0,
        "invalid_loadgen": 1,
        "skipped": 0,
        "slo_passed": 0,
        "slo_failed": 1,
    }
    summary = _campaign_summary(manifest, cells, observations)
    manifest["limitations"] = summary["limitations"]
    (public / "observations.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in observations), encoding="utf-8")
    (public / "cells.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in cells), encoding="utf-8")
    _write_cells_csv(public / "cells.csv", cells)
    _write_json(public / "summary.json", summary)
    _write_json(public / "public_manifest.json", manifest)
    shutil.rmtree(public / "figures", ignore_errors=True)
    _performance_reports(public, _public_presentation_manifest(manifest), summary, cells)
    write_bundle(public)

    Draft202012Validator(v2_schema, format_checker=FormatChecker()).validate(manifest)
    assert verify_public_bundle(public)["semantic_valid"] is True
    assert cells[0]["status"] == "invalid-loadgen"
    assert cells[0]["client_queue_ms"]["p95"] == 60_000.0
    assert cells[0]["dispatch_lag_ms"]["p95"] == 60_000.0
    assert cells[0]["slo_passed"] is False
    assert cells[0]["goodput_requests"] == cells[0]["goodput_requests_per_second"] == 0


@pytest.mark.parametrize("relative", ["report.html", "report.pdf", "figures/ttft.svg"])
def test_v2_public_verifier_reconstructs_human_presentation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    public = _export_v2_public(tmp_path, monkeypatch)
    target = public / relative
    assert target.is_file()
    target.write_bytes(target.read_bytes() + b"\nALL SYSTEMS PASSED OFFICIALLY\n")
    write_bundle(public)

    with pytest.raises(ProtocolError, match="presentation differs from the verified projection"):
        verify_public_bundle(public)


def test_v2_closed_loop_public_projection_keeps_open_loop_aggregates_not_applicable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public = _export_v2_public(tmp_path, monkeypatch, open_loop=False)
    assert verify_public_bundle(public)["semantic_valid"] is True
    cell = json.loads((public / "cells.jsonl").read_text(encoding="utf-8").splitlines()[0])

    assert cell["status"] == "completed"
    assert cell["serving_slo_passed"] is True
    assert cell["load_generator_valid"] is None
    assert cell["load_generator_gates"] == {}
    assert cell["goodput_requests"] == cell["successes"] == 1
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
    ):
        assert cell[field] is None


@pytest.mark.parametrize(
    "target",
    ["schedule", "dispatch", "queue", "rate_fidelity", "measurement_window", "throughput_window", "request_rate", "token_rate"],
)
def test_v2_public_verifier_rejects_resealed_timing_and_rate_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    public = _export_v2_public(tmp_path, monkeypatch)
    if target in {"rate_fidelity", "measurement_window", "throughput_window", "request_rate", "token_rate"}:
        cells = [json.loads(line) for line in (public / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
        field = {
            "rate_fidelity": "dispatch_rate_fidelity",
            "measurement_window": "measurement_window_seconds",
            "throughput_window": "throughput_window_seconds",
            "request_rate": "requests_per_second",
            "token_rate": "output_tokens_per_second",
        }[target]
        cells[0][field] = float(cells[0][field]) / 2
        manifest = json.loads((public / "public_manifest.json").read_text(encoding="utf-8"))
        observations = [json.loads(line) for line in (public / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
        (public / "cells.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in cells), encoding="utf-8")
        _write_cells_csv(public / "cells.csv", cells)
        _write_json(public / "summary.json", _campaign_summary(manifest, cells, observations))
        write_bundle(public)
    else:
        observations = [json.loads(line) for line in (public / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
        field = {"schedule": "scheduled_monotonic_ns", "dispatch": "dispatch_monotonic_ns", "queue": "client_queue_ms"}[target]
        observations[0][field] += 1.0 if target == "queue" else 1_000_000
        (public / "observations.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in observations), encoding="utf-8"
        )
        write_bundle(public)

    with pytest.raises(ProtocolError):
        verify_public_bundle(public)


@pytest.mark.parametrize(
    "field",
    ["measurement_window_seconds", "throughput_window_seconds", "requests_per_second", "output_tokens_per_second"],
)
def test_v2_restricted_verifier_rejects_resealed_denominator_and_rate_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    run = _run(tmp_path, monkeypatch, open_loop=True)
    cells = [json.loads(line) for line in (run / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    cells[0][field] = float(cells[0][field]) / 2
    (run / "cells.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in cells), encoding="utf-8")
    write_bundle(run)

    with pytest.raises(ProtocolError, match="metrics differ from immutable observations"):
        export_public_performance(run, tmp_path / "tampered.tar.gz")


def test_v2_restricted_verifier_rejects_resealed_report_tampering(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path, monkeypatch)
    (run / "report.html").write_text("<h1>All performance SLOs passed</h1>", encoding="utf-8")
    write_bundle(run)

    with pytest.raises(ProtocolError, match="presentation differs from immutable evidence"):
        verify_performance_source_bundle(run)


def test_development_export_preserves_completed_with_errors_without_official_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path, monkeypatch, response_error=True)
    source_manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    source_manifest["official_requested"] = True
    (run / "manifest.json").write_text(json.dumps(source_manifest), encoding="utf-8")
    write_bundle(run)
    archive_path = tmp_path / "public-errors.tar.gz"

    result = export_public_performance(run, archive_path)
    extracted = tmp_path / "public-errors"
    extracted.mkdir()
    with tarfile.open(archive_path) as archive:
        archive.extractall(extracted, filter="data")

    manifest = json.loads((extracted / "public_manifest.json").read_text(encoding="utf-8"))
    cells = [json.loads(line) for line in (extracted / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    observations = [json.loads(line) for line in (extracted / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    assert result["status"] == manifest["status"] == "completed-with-errors"
    assert manifest["official"] is False and manifest["assurance"] == "development" and manifest["release"] is None
    assert cells[0]["status"] == "completed-with-errors" and cells[0]["error_types"] == {"_ResponseError": 1}
    assert cells[0]["warnings"] and observations[0]["status"] == "error"
    assert (observations[0]["input_tokens"], observations[0]["output_tokens"]) == (8.0, 2.0)
    assert verify_public_bundle(extracted)["assurance"] == "development"
    schema = json.loads((ROOT / "schemas" / "performance-publication-2.0.0.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)


def test_performance_export_rejects_reconciliation_drift_before_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path, monkeypatch)
    manifest = json.loads((run / "manifest.json").read_text())
    manifest["request_reconciliation"]["accepted"] = 0
    (run / "manifest.json").write_text(json.dumps(manifest))
    write_bundle(run)
    output = tmp_path / "must-not-exist.tar.gz"

    with pytest.raises(ProtocolError, match="differs from the immutable ledgers"):
        export_public_performance(run, output)
    assert not output.exists()


def test_performance_export_rejects_resealed_engagement_projection_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path, monkeypatch)
    _add_test_evidence(run, monkeypatch)
    _add_execution_record(run)
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["engagement"]["configuration_id"] = "cfg-sha256:" + "f" * 64
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    write_bundle(run)
    output = tmp_path / "must-not-exist.tar.gz"

    with pytest.raises(ProtocolError, match="engagement metadata differs from its snapshot"):
        export_public_performance(run, output)

    assert not output.exists()


def test_authentic_reference_inputs_pass_official_gate() -> None:
    reference = load_performance_plan(ROOT / "performance" / "plans" / "llm-serving-v2.toml")
    _require_official_reference_inputs(
        sha256_file(ROOT / "PERFORMANCE_PROTOCOL_V2.md"),
        reference.sha256,
        reference.workload_sha256,
        reference.workload_assets,
        repo_root=ROOT,
    )


def test_official_release_rejects_development_plan_spoof_before_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path, monkeypatch)
    evidence = _add_test_evidence(run, monkeypatch)
    _add_execution_record(run)
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["official_requested"] = manifest["officially_valid"] = True
    manifest["source"] = {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64}
    manifest_path.write_text(json.dumps(manifest))
    write_bundle(run)

    governance = tmp_path / "governance"
    governance.mkdir()
    review = governance / "review.txt"
    qualification = governance / "qualification.txt"
    review.write_text("Reviewed exact immutable performance bundle.")
    qualification.write_text("Qualified performance reviewer evidence.")
    finished = datetime.fromisoformat(manifest["finished_at"])
    now = finished + timedelta(minutes=1)
    approval: dict[str, Any] = {
        "release_version": PERFORMANCE_PUBLICATION_VERSION,
        "release_id": "release-1",
        "status": "approved",
        "run_id": manifest["run_id"],
        "bundle_sha256": sha256_file(run / "bundle.json"),
        "manifest_sha256": sha256_file(manifest_path),
        "configuration_id": evidence["configuration_id"],
        "engagement_id": manifest["engagement"]["engagement_id"],
        "engagement_sha256": manifest["engagement"]["sha256"],
        "execution_owner_id": "executor-1",
        "approver_id": "reviewer-1",
        "independent": True,
        "conflicts": [],
        "conflict_mitigation": "",
        "permitted_claims": [PERMITTED_CLAIM],
        "limitations_acknowledged": True,
        "review_evidence": review.name,
        "review_evidence_sha256": sha256_file(review),
        "qualification_evidence": qualification.name,
        "qualification_evidence_sha256": sha256_file(qualification),
        "approved_at": finished.isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    approval_path = governance / "approval.json"
    approval_path.write_text(json.dumps(approval))

    release = _release_approval(run, manifest, approval_path, now)
    assert release["approver_id"] == "reviewer-1" and release["engagement_id"] == manifest["engagement"]["engagement_id"]
    assert release["approval_sha256"] == sha256_bytes(approval_path.read_bytes())
    output = tmp_path / "official.tar.gz"
    with pytest.raises(ProtocolError, match="exact reference plan"):
        export_public_performance(run, output, approval_path=approval_path, now=now)
    assert not output.exists()

    approval["execution_owner_id"] = "different-executor"
    approval_path.write_text(json.dumps(approval))
    with pytest.raises(ProtocolError, match="execution_owner_id does not match"):
        _release_approval(run, manifest, approval_path, now)

    approval["execution_owner_id"] = "executor-1"
    approval["approver_id"] = approval["execution_owner_id"]
    approval_path.write_text(json.dumps(approval))
    with pytest.raises(ProtocolError, match="independent"):
        _release_approval(run, manifest, approval_path, now)


def test_performance_release_approval_rejects_symlink_and_engagement_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path, monkeypatch)
    evidence = _add_test_evidence(run, monkeypatch)
    _add_execution_record(run)
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    governance = tmp_path / "governance"
    governance.mkdir()
    review = governance / "review.txt"
    qualification = governance / "qualification.txt"
    review.write_text("Reviewed exact immutable performance bundle.", encoding="utf-8")
    qualification.write_text("Qualified performance reviewer evidence.", encoding="utf-8")
    finished = datetime.fromisoformat(manifest["finished_at"])
    now = finished + timedelta(minutes=1)
    approval = {
        "release_version": PERFORMANCE_PUBLICATION_VERSION,
        "release_id": "release-1",
        "status": "approved",
        "run_id": manifest["run_id"],
        "bundle_sha256": sha256_file(run / "bundle.json"),
        "manifest_sha256": sha256_file(run / "manifest.json"),
        "configuration_id": evidence["configuration_id"],
        "engagement_id": "different-engagement",
        "engagement_sha256": manifest["engagement"]["sha256"],
        "execution_owner_id": "executor-1",
        "approver_id": "reviewer-1",
        "independent": True,
        "conflicts": [],
        "conflict_mitigation": "",
        "permitted_claims": [PERMITTED_CLAIM],
        "limitations_acknowledged": True,
        "review_evidence": review.name,
        "review_evidence_sha256": sha256_file(review),
        "qualification_evidence": qualification.name,
        "qualification_evidence_sha256": sha256_file(qualification),
        "approved_at": finished.isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    approval_path = governance / "approval.json"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")

    with pytest.raises(ProtocolError, match="engagement_id does not match"):
        _release_approval(run, manifest, approval_path, now)

    approval["engagement_id"] = manifest["engagement"]["engagement_id"]
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    symlink = governance / "approval-link.json"
    symlink.symlink_to(approval_path)
    with pytest.raises(ProtocolError, match="regular file"):
        _release_approval(run, manifest, symlink, now)
