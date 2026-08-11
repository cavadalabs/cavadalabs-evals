from __future__ import annotations

import copy
import json
import runpy
import sys
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError  # type: ignore[import-untyped]

from cavada_eval.performance import load_performance_plan, load_performance_runtime, run_performance_campaign
from cavada_eval.protocol import ProtocolError, sha256_file

ROOT = Path(__file__).parents[1]
SCHEMAS = ROOT / "schemas"
PERFORMANCE_MANIFEST_SCHEMAS = (
    "performance-manifest.schema.json",
    "performance-manifest-2.0.0.schema.json",
)
PERFORMANCE_PLAN_SCHEMAS = (
    "performance-plan.schema.json",
    "performance-plan-2.0.0.schema.json",
)


def _schema(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((SCHEMAS / name).read_text(encoding="utf-8")))


def _validate(name: str, value: Any) -> None:
    Draft202012Validator(_schema(name), format_checker=FormatChecker()).validate(value)


def _matching_schemas(names: tuple[str, ...], value: Any) -> list[str]:
    return [name for name in names if not list(Draft202012Validator(_schema(name), format_checker=FormatChecker()).iter_errors(value))]


def _performance_inputs(root: Path, endpoint: str) -> tuple[Path, Path]:
    protocol = "PERFORMANCE_PROTOCOL_V2.md"
    (root / protocol).write_bytes((ROOT / protocol).read_bytes())
    workload = root / "workload.jsonl"
    workload.write_text(json.dumps({"id": "ctx-8", "context_tokens": 8, "repeat_text": " datum", "repeat_count": 8}) + "\n", encoding="utf-8")
    plan = root / "plan.toml"
    load_generator = """[load_generator]
minimum_dispatch_rate_fraction = 0.98
maximum_dispatch_lag_p95_ms = 100
maximum_dispatch_lag_ms = 1000
"""
    plan.write_text(
        f'''plan_version = "2.0.0"
revision = "2.0.0"
name = "schema-contract"
description = "One-request schema contract campaign."
profile = "llm-serving-v2"
data_classification = "synthetic"
[workload]
id = "schema-workload"
revision = "1.0.0"
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
open_loop_duration_seconds = 0
open_loop_arrival_distribution = "fixed"
bootstrap_samples = 100
seed = 1
randomize_cells = false
cooldown_seconds = 0
max_in_flight = 1
{load_generator}
[limits]
timeout_seconds = 2
max_requests = 1
max_total_tokens = 100
max_campaign_seconds = 5
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
concurrency = [1]
''',
        encoding="utf-8",
    )
    runtime = root / "runtime.toml"
    runtime.write_text(
        f'''runtime_version = "1.0.0"
id = "schema-runtime"
endpoint = "{endpoint}"
request_model = "schema-model"
expected_model = "schema-model"
model_revision = "model-revision"
api_key_env = "MISSING_SCHEMA_KEY"
engine = "schema-engine"
engine_revision = "engine-revision"
model_artifact_revision = "{'c' * 64}"
dtype = "fp16"
quantization = "none"
gpu_count = 1
gpu_model = "schema-gpu"
tensor_parallel = 1
max_context_tokens = 10
launch_command_sanitized = "schema-server"
''',
        encoding="utf-8",
    )
    return plan, runtime


def test_every_schema_is_valid_draft_2020_12() -> None:
    for path in SCHEMAS.glob("*.schema.json"):
        Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))


def test_real_behavior_manifest_metrics_and_bundle_conform(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    demo = runpy.run_path(str(ROOT / "examples" / "offline_demo.py"))
    monkeypatch.setattr(sys, "argv", ["offline_demo.py", "--output-root", str(tmp_path)])
    assert demo["main"]() == 0
    run_dir = Path(json.loads(capsys.readouterr().out)["run"])
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    bundle = json.loads((run_dir / "bundle.json").read_text(encoding="utf-8"))

    _validate("manifest.schema.json", manifest)
    _validate("metrics.schema.json", metrics)
    _validate("bundle.schema.json", bundle)

    missing_reproduction = dict(manifest)
    missing_reproduction.pop("reproduction_command")
    with pytest.raises(ValidationError, match="reproduction_command"):
        _validate("manifest.schema.json", missing_reproduction)

    unknown = {**manifest, "unknown_contract_field": True}
    with pytest.raises(ValidationError, match="Additional properties"):
        _validate("manifest.schema.json", unknown)

    official = copy.deepcopy(manifest)
    official.update({"status": "passed", "official_requested": True, "official": True})
    official["source"].update({"commit": "a" * 40, "dirty": False})
    official["target"]["revision"] = "b" * 40
    official["judge"]["revision"] = "c" * 40
    for model in official["judge"]["models"]:
        model["revision"] = "c" * 40
    official["parameters"].update({"mode": "official", "case_review_policy": "approved-only", "max_cases": 0})
    official["judge_qualification"] = {
        "qualification_sha256": "b" * 64,
        "approval_sha256": "c" * 64,
        "approval_id": "approval-1",
        "approver_id": "reviewer-1",
        "approved_at": "2026-08-07T10:00:00Z",
        "expires_at": "2027-08-07T10:00:00Z",
        "approver_qualification_evidence_sha256": "3" * 64,
    }
    official["engagement"] = {
        "engagement_id": "engagement-1",
        "sha256": "d" * 64,
        "status": "approved",
        "cavadalabs_roles": ["evaluator"],
        "jurisdictions": ["EU"],
        "permitted_claims": ["Declared benchmark result"],
        "prohibited_claims": ["Legal certification"],
        "execution_owner_id": "owner-1",
        "commercial_owner_id": "owner-2",
        "approved_at": "2026-08-07T10:00:00Z",
        "expires_at": "2027-08-07T10:00:00Z",
        "authorization_evidence_sha256": "e" * 64,
        "conflict_assessment_evidence_sha256": "f" * 64,
        "legal_applicability_evidence_sha256": "1" * 64,
        "approver_qualification_evidence_sha256": "2" * 64,
    }
    _validate("manifest.schema.json", official)
    official["engagement"] = None
    with pytest.raises(ValidationError):
        _validate("manifest.schema.json", official)


def test_real_performance_manifest_and_bundle_cover_final_abort_and_official_contract(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        plan_path, runtime_path = _performance_inputs(tmp_path, f"http://127.0.0.1:{server.server_port}/v1")
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
    bundle = json.loads((run_dir / "bundle.json").read_text(encoding="utf-8"))
    manifest_schema = "performance-manifest-2.0.0.schema.json"
    _validate(manifest_schema, manifest)
    assert _matching_schemas(PERFORMANCE_MANIFEST_SCHEMAS, manifest) == [manifest_schema]
    plan_snapshot = tomllib.loads((run_dir / "plan_snapshot.toml").read_text(encoding="utf-8"))
    assert _matching_schemas(PERFORMANCE_PLAN_SCHEMAS, plan_snapshot) == ["performance-plan-2.0.0.schema.json"]
    _validate("bundle.schema.json", bundle)
    assert manifest["request_reconciliation"]["campaign_complete"] is True

    aborted = copy.deepcopy(manifest)
    aborted.update({"status": "aborted", "officially_valid": False, "abort_reason": "identity mismatch"})
    for field in ("estimated_cost", "cells", "warmups"):
        aborted.pop(field)
    _validate(manifest_schema, aborted)

    official = copy.deepcopy(manifest)
    official.update(
        {
            "status": "completed",
            "official_requested": True,
            "officially_valid": True,
            "system_evidence": {
                "configuration_id": "cfg-sha256:" + "3" * 64,
                "sha256": "4" * 64,
                "projection": "restricted",
                "collected_at": "2026-08-07T10:00:00Z",
            },
            "execution_record": {
                "record_version": "1.0.0",
                "engagement_id": "engagement-1",
                "execution_owner_id": "executor-1",
                "sha256": "6" * 64,
                "recorded_at": "2026-08-07T09:00:00Z",
            },
            "engagement": {
                "engagement_version": "1.0.0",
                "engagement_id": "engagement-1",
                "status": "approved",
                "execution_owner_id": "executor-1",
                "protocol_sha256": manifest["protocol_sha256"],
                "plan_sha256": manifest["plan"]["sha256"],
                "workload_sha256": manifest["workload"]["sha256"],
                "runtime_sha256": manifest["runtime"]["sha256"],
                "system_evidence_sha256": "4" * 64,
                "configuration_id": "cfg-sha256:" + "3" * 64,
                "approved_at": "2026-08-07T08:00:00Z",
                "expires_at": "2027-08-07T10:00:00Z",
                "sha256": "7" * 64,
            },
        }
    )
    official["source"].update({"commit": "5" * 40, "dirty": False})
    official["cells"].update({"completed": official["cells"]["completed"] + official["cells"]["with_errors"], "with_errors": 0})
    official["warmups"].update({"successes": official["warmups"]["total"], "errors": 0})
    _validate(manifest_schema, official)
    official["system_evidence"]["projection"] = "public"
    with pytest.raises(ValidationError):
        _validate(manifest_schema, official)
    official["system_evidence"]["projection"] = "restricted"
    official["execution_record"] = None
    with pytest.raises(ValidationError):
        _validate(manifest_schema, official)
    official["execution_record"] = {
        "record_version": "1.0.0",
        "engagement_id": "engagement-1",
        "execution_owner_id": "executor-1",
        "sha256": "6" * 64,
        "recorded_at": "2026-08-07T09:00:00Z",
    }
    official["engagement"] = None
    with pytest.raises(ValidationError):
        _validate(manifest_schema, official)
    official["engagement"] = {
        "engagement_version": "1.0.0",
        "engagement_id": "engagement-1",
        "status": "approved",
        "execution_owner_id": "executor-1",
        "protocol_sha256": manifest["protocol_sha256"],
        "plan_sha256": manifest["plan"]["sha256"],
        "workload_sha256": manifest["workload"]["sha256"],
        "runtime_sha256": manifest["runtime"]["sha256"],
        "system_evidence_sha256": "4" * 64,
        "configuration_id": "cfg-sha256:" + "3" * 64,
        "approved_at": "2026-08-07T08:00:00Z",
        "expires_at": "2027-08-07T10:00:00Z",
        "sha256": "7" * 64,
    }
    official["performance_protocol_version"] = "1.0.0"
    with pytest.raises(ValidationError, match="was expected"):
        _validate(manifest_schema, official)

    unknown = {**manifest, "unknown_contract_field": True}
    with pytest.raises(ValidationError, match="Additional properties"):
        _validate(manifest_schema, unknown)


def test_performance_input_schemas_match_loader_contract(tmp_path: Path) -> None:
    plan_path, runtime_path = _performance_inputs(tmp_path, "http://127.0.0.1:1/v1")
    plan = tomllib.loads(plan_path.read_text(encoding="utf-8"))
    runtime = tomllib.loads(runtime_path.read_text(encoding="utf-8"))
    workload = json.loads((tmp_path / "workload.jsonl").read_text(encoding="utf-8"))
    assert _matching_schemas(PERFORMANCE_PLAN_SCHEMAS, plan) == ["performance-plan-2.0.0.schema.json"]
    _validate("performance-runtime.schema.json", runtime)
    _validate("performance-workload-item.schema.json", workload)
    reference_v2 = tomllib.loads((ROOT / "performance" / "plans" / "llm-serving-v2.toml").read_text())
    assert _matching_schemas(PERFORMANCE_PLAN_SCHEMAS, reference_v2) == ["performance-plan-2.0.0.schema.json"]
    for historical_path in sorted((ROOT / "performance" / "plans").glob("*-v1.toml")):
        historical = tomllib.loads(historical_path.read_text(encoding="utf-8"))
        assert _matching_schemas(PERFORMANCE_PLAN_SCHEMAS, historical) == ["performance-plan.schema.json"]
    assert reference_v2["load_generator"] == {
        "minimum_dispatch_rate_fraction": 0.98,
        "maximum_dispatch_lag_p95_ms": 100,
        "maximum_dispatch_lag_ms": 1000,
    }
    missing_loadgen_gate = copy.deepcopy(reference_v2)
    missing_loadgen_gate["load_generator"].pop("maximum_dispatch_lag_ms")
    with pytest.raises(ValidationError, match="maximum_dispatch_lag_ms"):
        _validate("performance-plan-2.0.0.schema.json", missing_loadgen_gate)
    _validate(
        "performance-execution-record.schema.json",
        {
            "record_version": "1.0.0",
            "engagement_id": "engagement-1",
            "execution_owner_id": "executor-1",
            "scope": "Execute the exact hash-bound performance campaign.",
            "protocol_sha256": "1" * 64,
            "plan_sha256": "2" * 64,
            "workload_sha256": "3" * 64,
            "runtime_sha256": "4" * 64,
            "system_evidence_sha256": "5" * 64,
            "recorded_at": "2026-08-07T09:00:00Z",
        },
    )
    _validate(
        "performance-engagement.schema.json",
        {
            "engagement_version": "1.0.0",
            "engagement_id": "engagement-1",
            "status": "approved",
            "scope": "Run and release the exact hash-bound performance campaign.",
            "execution_owner_id": "executor-1",
            "protocol_sha256": "1" * 64,
            "plan_sha256": "2" * 64,
            "workload_sha256": "3" * 64,
            "runtime_sha256": "4" * 64,
            "system_evidence_sha256": "5" * 64,
            "configuration_id": "cfg-sha256:" + "6" * 64,
            "approved_at": "2026-08-07T08:00:00Z",
            "expires_at": "2026-08-08T08:00:00Z",
        },
    )

    runtime["model_artifact_revision"] = "not-a-sha256"
    _validate("performance-runtime.schema.json", runtime)
    runtime_path.write_text(runtime_path.read_text(encoding="utf-8").replace("c" * 64, "not-a-sha256"), encoding="utf-8")
    with pytest.raises(ProtocolError, match="model_artifact_revision"):
        load_performance_runtime(runtime_path)


def test_versioned_open_loop_output_schemas_require_loadgen_status() -> None:
    manifest = _schema("performance-manifest-2.0.0.schema.json")
    publication = _schema("performance-publication-2.0.0.schema.json")
    assert manifest["properties"]["performance_protocol_version"] == {"const": "2.0.0"}
    assert manifest["properties"]["report_version"] == {"const": "2.0.0"}
    assert publication["properties"]["publication_version"] == {"const": "2.0.0"}
    assert publication["$defs"]["release"]["properties"]["release_version"] == {"const": "2.0.0"}
    for schema in (manifest, publication):
        assert "invalid-loadgen" in schema["properties"]["status"]["enum"]
        cells = {
            "total": 1,
            "completed": 0,
            "with_errors": 0,
            "invalid_loadgen": 1,
            "skipped": 0,
            "slo_passed": 0,
            "slo_failed": 1,
        }
        Draft202012Validator(schema["$defs"]["cells"]).validate(cells)
        cells.pop("invalid_loadgen")
        with pytest.raises(ValidationError, match="invalid_loadgen"):
            Draft202012Validator(schema["$defs"]["cells"]).validate(cells)
