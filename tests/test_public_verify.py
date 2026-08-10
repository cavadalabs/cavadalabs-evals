from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from cavada_eval.artifacts import verify_bundle as verify_artifact_bundle
from cavada_eval.artifacts import write_bundle
from cavada_eval.cli import EXIT_INTEGRITY, main
from cavada_eval.performance import (
    PerformanceRuntime,
    _campaign_summary,
    _cell_metrics,
    _expand_cells,
    _write_cells_csv,
    load_performance_plan,
)
from cavada_eval.performance_release import PERMITTED_CLAIM, _public_cells, _public_observations
from cavada_eval.protocol import PROTOCOL_VERSION, REPORT_VERSION, ProtocolError, sha256_bytes, sha256_file, wilson_interval, write_category_csv
from cavada_eval.public_verify import verify_public_bundle
from cavada_eval.system_evidence import system_configuration_id

ROOT = Path(__file__).parents[1]


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _behavior_bundle(root: Path) -> Path:
    root.mkdir()
    lower, upper = wilson_interval(1, 1)
    category = {
        "category": "quality",
        "total": 1,
        "observations": 1,
        "pass": 1,
        "fail": 0,
        "invalid": 0,
        "error": 0,
        "skipped": 0,
        "pass_rate": 1.0,
        "pass_rate_ci": {"lower": lower, "upper": upper, "confidence": 0.95},
        "pass_rate_ci95": {"lower": lower, "upper": upper},
        "ci95_lower": lower,
        "ci95_upper": upper,
        "confidence": 0.95,
    }
    summary = {
        "protocol_version": PROTOCOL_VERSION,
        "report_version": REPORT_VERSION,
        "run_id": "behavior-run-1",
        "status": "passed",
        "suite": {
            "name": "behavior-public-v1",
            "version": "1.0.0",
            "status": "approved",
            "dataset_sha256": "1" * 64,
            "rubric_sha256": "2" * 64,
            "suite_config_sha256": "3" * 64,
            "data_classification": "synthetic",
            "profile": "text-generation",
        },
        "target": {"label": "public-target", "revision": "4" * 40},
        "metrics": {
            "total": 1,
            "observations": 1,
            "pass": 1,
            "fail": 0,
            "invalid": 0,
            "error": 0,
            "skipped": 0,
            "pass_rate": 1.0,
            "pass_rate_ci": {"lower": lower, "upper": upper, "confidence": 0.95},
            "pass_rate_ci95": {"lower": lower, "upper": upper},
            "officially_valid": True,
            "analysis_unit": "case",
            "evaluation_cases": 1,
            "target_observations": 1,
            "gate_failures": [],
            "aborted": False,
        },
        "categories": [category],
        "gates": [{"category": None, "metric": "pass_rate_ci.lower", "min": 0.2, "confidence": 0.95}],
        "limitations": ["finite sampled scope"],
    }
    _write_json(root / "summary.json", summary)
    write_category_csv(root / "category_results.csv", [category])
    (root / "report_public.html").write_text("<!doctype html><title>Public behavior report</title>\n", encoding="utf-8")
    (root / "report_public.pdf").write_bytes(b"%PDF-1.4\n%%EOF\n")
    public_files = {
        path.name: sha256_file(path) for path in (root / "summary.json", root / "category_results.csv", root / "report_public.html", root / "report_public.pdf")
    }
    now = datetime.now(timezone.utc)
    release = {
        "release_version": "1.0.0",
        "release_id": "release-1",
        "run_id": "behavior-run-1",
        "bundle_sha256": "5" * 64,
        "manifest_sha256": "6" * 64,
        "engagement_id": "engagement-1",
        "engagement_sha256": "7" * 64,
        "approval_sha256": "8" * 64,
        "assurance_level": "approved",
        "permitted_claims": ["Bounded protocol-conformance result."],
        "decision_statuses": {
            "statistical": "passed",
            "security": "passed",
            "privacy_legal": "not-applicable",
            "disclosure": "passed",
            "release": "passed",
        },
        "evaluation_started_at": (now - timedelta(minutes=3)).isoformat(),
        "evaluation_finished_at": (now - timedelta(minutes=2)).isoformat(),
        "approved_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "public_files": public_files,
    }
    _write_json(root / "public_release.json", release)
    write_bundle(root)
    return root


def _performance_bundle(root: Path) -> Path:
    root.mkdir()
    (root / "protocol_snapshot.md").write_bytes((ROOT / "PERFORMANCE_PROTOCOL_V1_0.md").read_bytes())
    workload = root / "workload.jsonl"
    workload.write_text(json.dumps({"id": "ctx-8", "context_tokens": 8, "repeat_text": " datum", "repeat_count": 8}) + "\n", encoding="utf-8")
    plan_path = root / "plan.toml"
    plan_path.write_text(
        f'''plan_version = "1.0.0"
revision = "1.0.0"
name = "public-verifier-v1"
description = "Minimal public verifier fixture."
profile = "llm-serving-v1"
data_classification = "synthetic"
[workload]
id = "public-verifier-v1"
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
open_loop_arrival_distribution = "fixed"
bootstrap_samples = 100
seed = 1
randomize_cells = false
cooldown_seconds = 0
max_in_flight = 1
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
    plan = load_performance_plan(plan_path)
    runtime: dict[str, Any] = {
        "runtime_version": "1.0.0",
        "id": "runtime-public",
        "request_model": "test-model",
        "expected_model": "test-model",
        "model_revision": "a" * 40,
        "engine": "test-engine",
        "engine_revision": "b" * 40,
        "model_artifact_revision": "c" * 64,
        "dtype": "fp16",
        "quantization": "none",
        "gpu_count": 1,
        "gpu_model": "test-gpu",
        "tensor_parallel": 1,
        "max_context_tokens": 10,
        "launch_command_sanitized": "test-server",
        "pricing": None,
        "sha256": "d" * 64,
    }
    cell = _expand_cells(plan, PerformanceRuntime(root / "public_manifest.json", runtime["sha256"], runtime))[0]
    observation = {
        "cell_key": cell["cell_key"],
        "scenario_id": cell["scenario_id"],
        "block": 1,
        "phase": "measured",
        "request_index": 1,
        "workload_id": "ctx-8",
        "declared_context_tokens": 8,
        "requested_output_tokens": 2,
        "client_queue_ms": 0.0,
        "scheduled_monotonic_ns": 1_000_000_000,
        "batch_started_monotonic_ns": 1_000_000_000,
        "started_monotonic_ns": 1_000_000_000,
        "finished_monotonic_ns": 2_000_000_000,
        "status": "success",
        "reported_model": "test-model",
        "input_tokens": 8.0,
        "output_tokens": 2.0,
        "input_token_match": True,
        "ttft_ms": 10.0,
        "e2e_ms": 20.0,
        "tpot_ms": 10.0,
        "decode_tokens_per_second": 100.0,
        "headers_ms": 1.0,
        "inter_chunk_ms": {},
        "request_bytes": 100,
        "response_bytes": 200,
    }
    observations = _public_observations([observation])
    metric = _cell_metrics(observations, cell, plan, 1.0, 1002, None)
    metric["block"] = 1
    cells = _public_cells({(1, str(cell["cell_key"])): metric}, {})
    (root / "observations.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in observations), encoding="utf-8")
    (root / "cells.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in cells), encoding="utf-8")
    _write_cells_csv(root / "cells.csv", cells, protocol_version="1.0.0")
    now = datetime.now(timezone.utc)
    manifest = {
        "publication_version": "1.0.0",
        "performance_protocol_version": "1.0.0",
        "protocol_sha256": sha256_file(root / "protocol_snapshot.md"),
        "run_id": "performance-run-1",
        "evaluation_started_at": (now - timedelta(minutes=2)).isoformat(),
        "evaluation_finished_at": (now - timedelta(minutes=1)).isoformat(),
        "status": "completed",
        "assurance": "development",
        "official": False,
        "source_manifest_sha256": "e" * 64,
        "source_bundle_sha256": "f" * 64,
        "plan": {
            "name": plan.config["name"],
            "revision": plan.config["revision"],
            "sha256": plan.sha256,
            "profile": plan.config["profile"],
            "data_classification": plan.config["data_classification"],
            "open_loop_arrival_distribution": "fixed",
            "execution_seed": 1,
            "minimum_p99_observations": 1,
        },
        "workload": {
            "id": plan.config["workload"]["id"],
            "revision": plan.config["workload"]["revision"],
            "mode": plan.config["workload"]["mode"],
            "sha256": plan.workload_sha256,
            "asset_set_sha256": sha256_bytes(b"{}"),
            "assets": {},
            "cases": 1,
        },
        "runtime": runtime,
        "system_evidence": None,
        "source": {"commit": "", "dirty": True, "status_sha256": "0" * 64},
        "cells": {"total": 1, "completed": 1, "with_errors": 0, "skipped": 0, "slo_passed": 1, "slo_failed": 0},
        "warmups": {"total": 0, "successes": 0, "errors": 0},
        "request_reconciliation": {
            "planned": 1,
            "scheduled": 1,
            "accepted": 1,
            "responses": 1,
            "warmup_outcomes": 0,
            "measured_outcomes": 1,
            "terminal_outcomes": 1,
            "ledgers_complete": True,
            "campaign_complete": True,
        },
        "token_usage": {"input": 8.0, "output": 2.0, "total": 10.0},
        "estimated_cost": None,
        "release": None,
        "limitations": [
            "Client-side measurements include network transport between the load generator and endpoint.",
            "Inter-chunk timing is diagnostic and is not token-level timing.",
            "TPOT is derived from provider-reported output tokens and elapsed time after TTFT.",
            "Performance results do not establish response quality or universal deployment capacity.",
        ],
    }
    _write_json(root / "summary.json", _campaign_summary(manifest, cells, observations))
    _write_json(root / "public_manifest.json", manifest)
    write_bundle(root)
    return root


def _attach_public_system_evidence(bundle: Path) -> None:
    manifest = json.loads((bundle / "public_manifest.json").read_text(encoding="utf-8"))
    collected_at = datetime.fromisoformat(manifest["evaluation_started_at"]) - timedelta(minutes=1)
    evidence: dict[str, Any] = {
        "evidence_version": "1.0.0",
        "configuration_id": "",
        "projection": "public",
        "collected_at": collected_at.isoformat(),
        "collection_method": "mixed",
        "server": {
            "host_id": None,
            "os": {"name": "Linux", "version": "1", "kernel": "1"},
            "cpu": {"model": "test-cpu", "architecture": "x86_64", "sockets": 1, "physical_cores": 1, "logical_cores": 1},
            "memory": {"total_bytes": 1024},
            "numa": {"nodes": 1, "policy": "local"},
            "accelerators": [
                {
                    "index": 0,
                    "vendor": "test-vendor",
                    "model": "test-gpu",
                    "uuid": None,
                    "vram_bytes": 1024,
                    "pci_bus_id": None,
                    "power_limit_watts": 1,
                    "graphics_clock_limit_mhz": 1,
                    "memory_clock_limit_mhz": 1,
                }
            ],
            "accelerator_topology": "one accelerator",
        },
        "software": {
            "driver": {"name": "test-driver", "version": "1"},
            "compute_runtime": {"name": "test-compute", "version": "1"},
            "engine": {"name": "test-engine", "revision": "b" * 40, "binary_sha256": "9" * 64, "container_image_digest": None},
            "model": {
                "name": "test-model",
                "revision": "a" * 40,
                "artifact_sha256": "c" * 64,
                "dtype": "fp16",
                "quantization": "none",
            },
        },
        "serving": {
            "launch_command_sanitized": "test-server",
            "max_context_tokens": 10,
            "max_batch_size": 1,
            "max_batch_tokens": 10,
            "continuous_batching": True,
            "prefix_cache": False,
            "kv_cache_dtype": "fp16",
            "tensor_parallel": 1,
            "pipeline_parallel": 1,
            "data_parallel": 1,
            "parallel_slots": 1,
        },
        "load_generator": {
            "host_id": None,
            "os": {"name": "Linux", "version": "1", "kernel": "1"},
            "cpu": {"model": "test-load-cpu", "architecture": "x86_64", "logical_cores": 1},
            "memory": {"total_bytes": 1024},
            "client": {"name": "cavadalabs-evals", "revision": "1" * 40},
            "colocated_with_server": False,
        },
        "network": {
            "relationship": "direct-lan",
            "transport": "tcp",
            "endpoint_host": None,
            "endpoint_port": None,
            "route": None,
            "rtt_ms": {"method": "tcp", "samples": 1, "median": 1.0, "p95": 1.0, "measured_at": "2026-08-07T11:59:00+02:00"},
        },
        "artifacts": [],
        "unavailable": {
            "/server/host_id": "redacted from public projection",
            "/server/accelerators/0/uuid": "redacted from public projection",
            "/server/accelerators/0/pci_bus_id": "redacted from public projection",
            "/software/engine/container_image_digest": "not applicable",
            "/load_generator/host_id": "redacted from public projection",
            "/network/endpoint_host": "redacted from public projection",
            "/network/endpoint_port": "redacted from public projection",
            "/network/route": "redacted from public projection",
        },
    }
    evidence["configuration_id"] = system_configuration_id(evidence)
    _write_json(bundle / "system_evidence.json", evidence)
    manifest["system_evidence"] = {
        "configuration_id": evidence["configuration_id"],
        "sha256": sha256_file(bundle / "system_evidence.json"),
        "projection": "public",
    }
    cells = [json.loads(line) for line in (bundle / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    observations = [json.loads(line) for line in (bundle / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    _write_json(bundle / "summary.json", _campaign_summary(manifest, cells, observations))
    _write_json(bundle / "public_manifest.json", manifest)
    write_bundle(bundle)


def _reseal_behavior_summary(bundle: Path, summary: dict[str, Any]) -> None:
    _write_json(bundle / "summary.json", summary)
    release = json.loads((bundle / "public_release.json").read_text(encoding="utf-8"))
    release["public_files"]["summary.json"] = sha256_file(bundle / "summary.json")
    _write_json(bundle / "public_release.json", release)
    write_bundle(bundle)


def _reseal_performance_cells(
    bundle: Path,
    mutation: Callable[[dict[str, Any], dict[str, Any]], None],
) -> None:
    cells = [json.loads(line) for line in (bundle / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    manifest = json.loads((bundle / "public_manifest.json").read_text(encoding="utf-8"))
    mutation(cells[0], manifest)
    (bundle / "cells.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in cells), encoding="utf-8")
    observations = [json.loads(line) for line in (bundle / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    _write_cells_csv(bundle / "cells.csv", cells, protocol_version=str(manifest["performance_protocol_version"]))
    _write_json(bundle / "summary.json", _campaign_summary(manifest, cells, observations))
    _write_json(bundle / "public_manifest.json", manifest)
    write_bundle(bundle)


def test_verify_public_behavior_bundle_and_reject_resealed_semantic_drift(tmp_path: Path) -> None:
    bundle = _behavior_bundle(tmp_path / "behavior")
    assert verify_public_bundle(bundle) == {
        "valid": True,
        "semantic_valid": True,
        "type": "behavior",
        "assurance": "approved",
        "authenticity": "unverified",
        "bundle_signature": "absent",
    }

    summary = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))
    summary["categories"][0]["pass_rate"] = 0.5
    _reseal_behavior_summary(bundle, summary)

    with pytest.raises(ProtocolError, match="pass rate does not reconcile"):
        verify_public_bundle(bundle)


def test_verify_public_bundle_reads_only_its_verified_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _behavior_bundle(tmp_path / "behavior-race")

    def verify_then_mutate_source(snapshot: Path, *, signing_key_env: str) -> dict[str, Any]:
        result = verify_artifact_bundle(snapshot, signing_key_env=signing_key_env)
        summary = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))
        summary["status"] = "failed"
        _write_json(bundle / "summary.json", summary)
        return result

    monkeypatch.setattr("cavada_eval.public_verify.verify_bundle", verify_then_mutate_source)
    assert verify_public_bundle(bundle)["semantic_valid"] is True
    assert json.loads((bundle / "summary.json").read_text(encoding="utf-8"))["status"] == "failed"


def test_verify_public_behavior_rejects_resealed_metric_forgery(tmp_path: Path) -> None:
    bundle = _behavior_bundle(tmp_path / "behavior-metric")
    summary = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))
    summary["metrics"]["pass_rate"] = 0.5
    _reseal_behavior_summary(bundle, summary)

    with pytest.raises(ProtocolError, match="metrics pass_rate does not reconcile"):
        verify_public_bundle(bundle)


def test_verify_cli_returns_integrity_exit_for_semantic_drift(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bundle = _behavior_bundle(tmp_path / "behavior-cli")
    summary = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))
    summary["metrics"]["pass_rate"] = 0.5
    _reseal_behavior_summary(bundle, summary)

    assert main(["verify", str(bundle)]) == EXIT_INTEGRITY
    assert json.loads(capsys.readouterr().out)["semantic_valid"] is False


def test_verify_public_behavior_rejects_unreconstructible_metrics(tmp_path: Path) -> None:
    bundle = _behavior_bundle(tmp_path / "behavior-unknown-metric")
    summary = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))
    summary["metrics"]["opaque_score"] = 1.0
    _reseal_behavior_summary(bundle, summary)

    with pytest.raises(ProtocolError, match="exact reconstructible projection"):
        verify_public_bundle(bundle)


def test_verify_public_behavior_recomputes_preregistered_gates(tmp_path: Path) -> None:
    bundle = _behavior_bundle(tmp_path / "behavior-gate")
    summary = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))
    summary["gates"][0]["min"] = 0.99
    _reseal_behavior_summary(bundle, summary)

    with pytest.raises(ProtocolError, match="failed its preregistered threshold"):
        verify_public_bundle(bundle)


@pytest.mark.parametrize("claim", ["Certified result", "Legally compliant system", "Universally safe model"])
def test_verify_public_behavior_rejects_prohibited_claims(tmp_path: Path, claim: str) -> None:
    bundle = _behavior_bundle(tmp_path / claim.split()[0].casefold())
    release = json.loads((bundle / "public_release.json").read_text(encoding="utf-8"))
    release["permitted_claims"] = [claim]
    _write_json(bundle / "public_release.json", release)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="unsupported certification, legal, or universal claim"):
        verify_public_bundle(bundle)


def test_verify_public_behavior_rejects_evaluation_release_time_inversion(tmp_path: Path) -> None:
    bundle = _behavior_bundle(tmp_path / "behavior-time")
    release = json.loads((bundle / "public_release.json").read_text(encoding="utf-8"))
    release["evaluation_finished_at"] = release["expires_at"]
    _write_json(bundle / "public_release.json", release)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="not currently effective"):
        verify_public_bundle(bundle)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda summary: summary.__setitem__("target", {"label": "public-target"}), "target has an invalid shape"),
        (lambda summary: summary["target"].__setitem__("revision", "latest"), "official public behavior target revision"),
        (lambda summary: summary.__setitem__("limitations", []), "limitations must be a non-empty"),
    ],
)
def test_verify_public_behavior_rejects_target_and_limitation_mutations(
    tmp_path: Path,
    mutation: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    bundle = _behavior_bundle(tmp_path / f"behavior-contract-{len(list(tmp_path.iterdir()))}")
    summary = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))
    mutation(summary)
    _reseal_behavior_summary(bundle, summary)

    with pytest.raises(ProtocolError, match=message):
        verify_public_bundle(bundle)


def test_verify_public_performance_bundle_and_reject_resealed_mutations(tmp_path: Path) -> None:
    bundle = _performance_bundle(tmp_path / "performance")
    result = verify_public_bundle(bundle)
    assert (result["type"], result["assurance"], result["authenticity"]) == ("performance", "development", "unverified")

    manifest_path = bundle / "public_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    manifest.update(
        {
            "official": False,
            "assurance": "approved",
            "release": {
                "release_version": "1.0.0",
                "release_id": "release-1",
                "approval_sha256": "1" * 64,
                "approver_id": "reviewer-1",
                "engagement_id": "engagement-1",
                "engagement_sha256": "2" * 64,
                "permitted_claims": [PERMITTED_CLAIM],
                "approved_at": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(days=1)).isoformat(),
            },
        }
    )
    _write_json(manifest_path, manifest)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="development.*incoherent"):
        verify_public_bundle(bundle)


@pytest.mark.parametrize("field", ["model_revision", "engine_revision"])
def test_verify_official_public_performance_rejects_mutable_runtime_revisions(
    tmp_path: Path, field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _performance_bundle(tmp_path / f"performance-mutable-{field}")
    monkeypatch.setattr("cavada_eval.public_verify.PERFORMANCE_PROTOCOL_VERSION", "1.0.0")
    manifest = json.loads((bundle / "public_manifest.json").read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    manifest.update(
        {
            "official": True,
            "assurance": "approved",
            "release": {
                "release_version": "1.0.0",
                "release_id": "release-1",
                "approval_sha256": "1" * 64,
                "approver_id": "reviewer-1",
                "engagement_id": "engagement-1",
                "engagement_sha256": "2" * 64,
                "permitted_claims": [PERMITTED_CLAIM],
                "approved_at": now.isoformat(),
                "expires_at": (now + timedelta(days=1)).isoformat(),
            },
        }
    )
    manifest["runtime"][field] = "latest"
    cells = [json.loads(line) for line in (bundle / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    observations = [json.loads(line) for line in (bundle / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    _write_json(bundle / "summary.json", _campaign_summary(manifest, cells, observations))
    _write_json(bundle / "public_manifest.json", manifest)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="runtime revisions are not content-addressed"):
        verify_public_bundle(bundle)


def _forge_p95(cell: dict[str, Any], _manifest: dict[str, Any]) -> None:
    cell["ttft_ms"]["p95"] += 1


def _forge_slo(cell: dict[str, Any], manifest: dict[str, Any]) -> None:
    cell["slo_gates"]["ttft_p95"] = False
    cell["slo_passed"] = False
    manifest["cells"]["slo_passed"] = 0
    manifest["cells"]["slo_failed"] = 1


def _forge_goodput(cell: dict[str, Any], _manifest: dict[str, Any]) -> None:
    cell["goodput_requests_per_second"] += 1


def _forge_measurement_window(cell: dict[str, Any], _manifest: dict[str, Any]) -> None:
    cell["measurement_window_seconds"] /= 2
    for field in ("requests_per_second", "goodput_requests_per_second", "input_tokens_per_second", "output_tokens_per_second"):
        cell[field] *= 2


@pytest.mark.parametrize("mutation", [_forge_p95, _forge_slo, _forge_goodput, _forge_measurement_window])
def test_verify_public_performance_recalculates_cell_metrics(
    tmp_path: Path,
    mutation: Callable[[dict[str, Any], dict[str, Any]], None],
) -> None:
    bundle = _performance_bundle(tmp_path / "performance-metrics")
    _reseal_performance_cells(bundle, mutation)

    with pytest.raises(ProtocolError, match="cell metrics differ from observations and plan"):
        verify_public_bundle(bundle)


def test_verify_public_performance_recalculates_observation_token_timing(tmp_path: Path) -> None:
    bundle = _performance_bundle(tmp_path / "performance-observation-timing")
    observations = [json.loads(line) for line in (bundle / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    observations[0]["tpot_ms"] = 0.000001
    observations[0]["decode_tokens_per_second"] = 1_000_000_000.0
    (bundle / "observations.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in observations), encoding="utf-8")
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="token timing differs from latency and provider usage"):
        verify_public_bundle(bundle)


def test_public_performance_contract_preserves_p99_warning(tmp_path: Path) -> None:
    bundle = _performance_bundle(tmp_path / "performance-p99-warning")
    cell = json.loads((bundle / "cells.jsonl").read_text(encoding="utf-8").splitlines()[0])

    assert cell["warnings"] == ["fewer than 1000 successful observations; p99 uncertainty remains high"]
    assert verify_public_bundle(bundle)["semantic_valid"] is True


def test_verify_public_performance_rejects_hidden_warmup_token_totals(tmp_path: Path) -> None:
    bundle = _performance_bundle(tmp_path / "performance-warmup-tokens")
    manifest = json.loads((bundle / "public_manifest.json").read_text(encoding="utf-8"))
    manifest["token_usage"] = {"input": 9.0, "output": 2.0, "total": 11.0}
    cells = [json.loads(line) for line in (bundle / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
    observations = [json.loads(line) for line in (bundle / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    _write_json(bundle / "summary.json", _campaign_summary(manifest, cells, observations))
    _write_json(bundle / "public_manifest.json", manifest)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="token usage differs from measured observations"):
        verify_public_bundle(bundle)


def test_verify_public_performance_requires_canonical_versioned_protocol(tmp_path: Path) -> None:
    bundle = _performance_bundle(tmp_path / "performance-protocol")
    (bundle / "protocol_snapshot.md").write_text("# self-declared protocol\n", encoding="utf-8")
    manifest = json.loads((bundle / "public_manifest.json").read_text(encoding="utf-8"))
    manifest["protocol_sha256"] = sha256_file(bundle / "protocol_snapshot.md")
    _write_json(bundle / "public_manifest.json", manifest)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="not the canonical versioned protocol"):
        verify_public_bundle(bundle)


def test_verify_public_performance_rejects_evaluation_time_inversion(tmp_path: Path) -> None:
    bundle = _performance_bundle(tmp_path / "performance-time")
    manifest = json.loads((bundle / "public_manifest.json").read_text(encoding="utf-8"))
    manifest["evaluation_started_at"], manifest["evaluation_finished_at"] = (
        manifest["evaluation_finished_at"],
        manifest["evaluation_started_at"],
    )
    _write_json(bundle / "public_manifest.json", manifest)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="timestamps are out of order"):
        verify_public_bundle(bundle)


@pytest.mark.parametrize(
    ("field", "value", "evidence_path"),
    [
        ("gpu_model", "forged-gpu", "server.accelerators model"),
        ("expected_model", "forged-model", "software.model.name"),
        ("launch_command_sanitized", "forged-server", "serving.launch_command_sanitized"),
    ],
)
def test_verify_public_performance_cross_checks_public_system_evidence(
    tmp_path: Path,
    field: str,
    value: str,
    evidence_path: str,
) -> None:
    bundle = _performance_bundle(tmp_path / f"performance-evidence-{field}")
    _attach_public_system_evidence(bundle)
    assert verify_public_bundle(bundle)["semantic_valid"] is True
    manifest = json.loads((bundle / "public_manifest.json").read_text(encoding="utf-8"))
    manifest["runtime"][field] = value
    _write_json(bundle / "public_manifest.json", manifest)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match=evidence_path):
        verify_public_bundle(bundle)


def test_verify_public_performance_binds_load_generator_revision_to_source(tmp_path: Path) -> None:
    bundle = _performance_bundle(tmp_path / "performance-load-generator")
    _attach_public_system_evidence(bundle)
    manifest_path = bundle / "public_manifest.json"
    evidence_path = bundle / "system_evidence.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source"]["commit"] = "1" * 40
    _write_json(manifest_path, manifest)
    write_bundle(bundle)
    assert verify_public_bundle(bundle)["semantic_valid"] is True

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["load_generator"]["client"]["revision"] = "2" * 40
    evidence["configuration_id"] = system_configuration_id(evidence)
    _write_json(evidence_path, evidence)
    manifest["system_evidence"]["configuration_id"] = evidence["configuration_id"]
    manifest["system_evidence"]["sha256"] = sha256_file(evidence_path)
    _write_json(manifest_path, manifest)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="load_generator.client"):
        verify_public_bundle(bundle)


def test_verify_public_performance_rejects_unavailable_accelerator_identity(tmp_path: Path) -> None:
    bundle = _performance_bundle(tmp_path / "performance-evidence-unavailable-gpu")
    _attach_public_system_evidence(bundle)
    evidence_path = bundle / "system_evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["server"]["accelerators"] = None
    evidence["unavailable"].pop("/server/accelerators/0/uuid")
    evidence["unavailable"].pop("/server/accelerators/0/pci_bus_id")
    evidence["unavailable"]["/server/accelerators"] = "unavailable in forged public projection"
    evidence["configuration_id"] = system_configuration_id(evidence)
    _write_json(evidence_path, evidence)
    manifest = json.loads((bundle / "public_manifest.json").read_text(encoding="utf-8"))
    manifest["system_evidence"]["configuration_id"] = evidence["configuration_id"]
    manifest["system_evidence"]["sha256"] = sha256_file(evidence_path)
    _write_json(bundle / "public_manifest.json", manifest)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="server.accelerators unavailable"):
        verify_public_bundle(bundle)


def test_verify_public_performance_rejects_restricted_evidence_mislabeled_by_manifest(tmp_path: Path) -> None:
    bundle = _performance_bundle(tmp_path / "performance-restricted-evidence")
    _attach_public_system_evidence(bundle)
    evidence_path = bundle / "system_evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["projection"] = "restricted"
    replacements = {
        "/server/host_id": (evidence["server"], "host_id", "private-server"),
        "/server/accelerators/0/uuid": (evidence["server"]["accelerators"][0], "uuid", "private-device"),
        "/server/accelerators/0/pci_bus_id": (evidence["server"]["accelerators"][0], "pci_bus_id", "0000:01:00.0"),
        "/load_generator/host_id": (evidence["load_generator"], "host_id", "private-loadgen"),
        "/network/endpoint_host": (evidence["network"], "endpoint_host", "private-endpoint"),
        "/network/endpoint_port": (evidence["network"], "endpoint_port", 8000),
        "/network/route": (evidence["network"], "route", "private route"),
    }
    for pointer, (container, field, value) in replacements.items():
        container[field] = value
        evidence["unavailable"].pop(pointer)
    evidence["configuration_id"] = system_configuration_id(evidence)
    _write_json(evidence_path, evidence)
    manifest = json.loads((bundle / "public_manifest.json").read_text(encoding="utf-8"))
    manifest["system_evidence"]["configuration_id"] = evidence["configuration_id"]
    manifest["system_evidence"]["sha256"] = sha256_file(evidence_path)
    _write_json(bundle / "public_manifest.json", manifest)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="projection or configuration_id mismatch"):
        verify_public_bundle(bundle)


@pytest.mark.parametrize("name", ["report_public.html", "report_public.pdf"])
@pytest.mark.parametrize("leak", ["/Users/alice/private/model.gguf", "sk-abcdefghijklmnop"])  # secret-scan: allow
def test_verify_public_bundle_scans_every_public_report(tmp_path: Path, name: str, leak: str) -> None:
    bundle = _behavior_bundle(tmp_path / "behavior-leak")
    report = bundle / name
    report.write_bytes(("%PDF-1.4\n" if name.endswith(".pdf") else "<!doctype html>").encode() + leak.encode())
    release = json.loads((bundle / "public_release.json").read_text(encoding="utf-8"))
    release["public_files"][name] = sha256_file(report)
    _write_json(bundle / "public_release.json", release)
    write_bundle(bundle)

    with pytest.raises(ProtocolError, match="textual artifact contains restricted evidence"):
        verify_public_bundle(bundle)


def test_verify_public_bundle_rejects_unknown_and_ambiguous_formats(tmp_path: Path) -> None:
    unknown = tmp_path / "unknown"
    unknown.mkdir()
    (unknown / "artifact.txt").write_text("not a public projection\n", encoding="utf-8")
    write_bundle(unknown)
    with pytest.raises(ProtocolError, match="exactly one recognized"):
        verify_public_bundle(unknown)

    behavior = _behavior_bundle(tmp_path / "ambiguous")
    _write_json(behavior / "public_manifest.json", {})
    write_bundle(behavior)
    with pytest.raises(ProtocolError, match="exactly one recognized"):
        verify_public_bundle(behavior)
