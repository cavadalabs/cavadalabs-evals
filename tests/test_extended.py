from __future__ import annotations

import base64
import json
import threading
import time
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import cavada_eval.annotations as annotation_module
import cavada_eval.assets as asset_module
from cavada_eval.annotations import annotation_agreement, export_annotation_package, ingest_adjudications, ingest_annotations
from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.comparison import _analysis_rows
from cavada_eval.external import import_external_results
from cavada_eval.metrics import contains_pii_like, deterministic_evaluation, error_rate, normalize_text, retrieval_scores
from cavada_eval.pairwise import _winner
from cavada_eval.pilot import audit_pilot_campaign
from cavada_eval.program import (
    load_evidence_crosswalk,
    load_program_registry,
    validate_case_blueprint,
    validate_cross_suite_duplicates,
    validate_judge_qualification_blueprint,
)
from cavada_eval.protocol import ProtocolError, Suite, load_suite, semantic_duplicate_candidates, sha256_bytes, sha256_file, validate_suite, wilson_gate_power
from cavada_eval.runner import (
    _CallEvidenceError,
    _distribution_shift_summary,
    _judge_calibration_summary,
    _post_json,
    _post_openai_stream,
    _scenario_analysis_rows,
    build_target_payload,
    call_target,
    run,
)
from cavada_eval.statistics import bootstrap_mean_interval, mcnemar_exact, paired_binary_comparison


def _suite(tmp_path: Path) -> Path:
    root = tmp_path / "suite"
    root.mkdir(parents=True)
    (root / "suite.toml").write_text(
        """protocol_version = "1.0.0"
name = "extended"
version = "1.0.0"
status = "candidate"
description = "Extended test suite"
data_classification = "synthetic"
dataset = "dataset.jsonl"
rubric = "rubric.md"
[[gates]]
metric = "pass_rate"
min = 1.0
[target]
kind = "json"
request_field = "message"
response_field = "answer"
reported_model_field = "model"
""",
        encoding="utf-8",
    )
    case = {
        "id": "one",
        "input": "Question",
        "category": "quality",
        "risk_domain": "quality",
        "severity": "low",
        "expected_behavior": "answer",
        "expected_behavior_reason": "Answer correctly.",
        "language": "en",
        "locale": "en-US",
        "split": "practice",
        "review": {"status": "approved", "method": "test"},
        "source": {"origin": "test"},
    }
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    (root / "rubric.md").write_text("Judge correctness.", encoding="utf-8")
    return root


def test_statistics_are_deterministic_and_paired() -> None:
    first = bootstrap_mean_interval([0, 1, 1], samples=500, seed=7)
    assert first == bootstrap_mean_interval([0, 1, 1], samples=500, seed=7)
    assert mcnemar_exact([True, True, False], [True, False, True])["discordant"] == 2
    comparison = paired_binary_comparison({"a": True, "b": False}, {"a": True, "b": True}, samples=500)
    assert comparison["absolute_delta"] == 0.5 and comparison["wins"] == 1
    assert normalize_text("Ｃafé\u0301  TEST") == normalize_text("Café́ test")
    assert contains_pii_like("Contact person@example.test") is True
    assert wilson_gate_power(142, 0.95, 0.99) >= 0.80
    assert wilson_gate_power(141, 0.95, 0.99) < 0.80


def test_distribution_shift_summary_is_paired_and_fail_closed() -> None:
    cases = (
        {"id": "baseline", "category": "quality", "operating_condition": "normal"},
        {
            "id": "shift",
            "category": "quality",
            "operating_condition": "distribution-shift",
            "distribution_shift_reference_id": "baseline",
        },
        {
            "id": "invalid-shift",
            "category": "quality",
            "operating_condition": "distribution-shift",
            "distribution_shift_reference_id": "missing-result",
        },
    )
    summary = _distribution_shift_summary(
        [
            {"case_id": "baseline", "status": "pass"},
            {"case_id": "shift", "status": "fail"},
        ],
        cases,
        confidence=0.95,
        samples=500,
        seed=0,
    )
    assert summary is not None
    assert summary["declared_pairs"] == 2 and summary["valid_pairs"] == 1 and summary["invalid_pairs"] == 1
    assert summary["comparison"]["absolute_delta"] == -1.0


def test_distribution_shift_case_requires_a_matched_reference() -> None:
    suite = load_suite(Path("suites/cavada-core-assistant-text-v1"))
    cases = [dict(case) for case in suite.cases]
    shifted = next(case for case in cases if case.get("operating_condition") == "distribution-shift")
    shifted["distribution_shift_reference_id"] = "missing"
    errors = validate_suite(Suite(suite.root, suite.config, tuple(cases), suite.rubric, suite.dataset_path, suite.rubric_path))
    assert any("distribution-shift reference does not exist" in error for error in errors)


def test_scenario_analysis_does_not_count_variants_as_independent() -> None:
    cases = (
        {"id": "primary", "scenario_group_id": "group", "scenario_role": "primary", "category": "quality", "risk_domain": "quality", "severity": "low"},
        {"id": "variant", "scenario_group_id": "group", "scenario_role": "variant", "category": "quality", "risk_domain": "quality", "severity": "low"},
    )
    rows = [
        {"case_id": "primary", "scenario_id": "group", "status": "pass"},
        {"case_id": "variant", "scenario_id": "group", "status": "fail"},
    ]
    aggregated = _scenario_analysis_rows(rows, cases)
    assert aggregated is not None and len(aggregated) == 1
    assert aggregated[0]["case_id"] == "group" and aggregated[0]["status"] == "fail"


def test_comparison_reads_the_declared_analysis_unit(tmp_path: Path) -> None:
    (tmp_path / "case_results.jsonl").write_text('{"case_id":"one","status":"pass"}\n')
    (tmp_path / "scenario_results.jsonl").write_text('{"case_id":"group","status":"fail"}\n')
    rows, unit = _analysis_rows(tmp_path, {"metrics": {"analysis_unit": "scenario"}})
    assert unit == "scenario" and rows == [{"case_id": "group", "status": "fail"}]


def test_complete_pilot_campaign_is_verified(tmp_path: Path) -> None:
    suite = {
        "name": "core",
        "version": "1.0.0",
        "dataset_sha256": "a" * 64,
        "rubric_sha256": "b" * 64,
        "suite_config_sha256": "c" * 64,
    }
    judge = {
        "requested_model": "judge",
        "expected_reported_model": "judge",
        "revision": "judge-revision",
        "endpoint": "http://127.0.0.1:8010/v1",
        "prompt_sha256": "d" * 64,
        "response_schema": "judgment.schema.json@1.0.0",
        "temperature": 0,
        "max_tokens": 600,
        "judge_repetitions": 3,
        "models": [{"id": "primary", "model": "judge", "expected_model": "judge", "revision": "judge-revision"}],
        "consensus": "majority",
    }
    specs = [
        ("target", "family-a", 262),
        ("target", "family-b", 230),
        ("target", "family-c", 197),
        ("positive-control", "positive", 328),
        ("negative-control", "negative", 0),
    ]
    campaign_runs = []
    for index, (role, alias, passed) in enumerate(specs):
        run_dir = tmp_path / f"run-{index}"
        run_dir.mkdir()
        scenario_rows = [
            {"case_id": f"scenario-{scenario}", "category": "quality", "status": "pass" if scenario < passed else "fail"}
            for scenario in range(328)
        ]
        case_rows = [
            {
                "case_id": f"case-{case}",
                "scenario_id": f"scenario-{min(case, 327)}",
                "repetition": repetition,
                "status": "pass" if min(case, 327) < passed else "fail",
            }
            for case in range(404)
            for repetition in range(1, 4)
        ]
        (run_dir / "case_results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in case_rows), encoding="utf-8")
        (run_dir / "scenario_results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in scenario_rows), encoding="utf-8")
        manifest = {
            "protocol_version": "1.0.0",
            "schema_version": "1.0.0",
            "report_version": "1.0.0",
            "metric_version": "1.0.0",
            "adapter_contract_version": "1.0.0",
            "run_id": f"run-{index}",
            "status": "passed" if role != "negative-control" else "failed",
            "finished_at": "2026-08-05T12:00:00+00:00",
            "abort_reason": "",
            "suite": suite,
            "target": {"expected_reported_model": f"model-{index}", "revision": f"revision-{index}"},
            "judge": judge,
            "parameters": {
                "mode": "candidate",
                "max_cases": 0,
                "repetitions": 3,
                "judge_repetitions": 3,
                "timeout_seconds": 90,
                "concurrency": 1,
                "requests_per_second": 1,
                "case_order_sha256": "e" * 64,
            },
            "metrics": {
                "analysis_unit": "scenario",
                "aggregate_scope": "single-construct",
                "constructs": ["quality"],
                "evaluation_cases": 404,
                "total": 328,
                "observations": 328,
                "target_observations": 1212,
                "pass": passed,
                "fail": 328 - passed,
                "invalid": 0,
                "error": 0,
                "skipped": 0,
                "pass_rate": passed / 328,
                "evidence_reconciliation": {
                    "valid": True,
                    "expected_observations": 1212,
                    "case_results": 1212,
                    "errors": [],
                },
            },
            "source": {"commit": "f" * 40, "dirty": False},
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest))
        write_bundle(run_dir)
        campaign_runs.append({"role": role, "family_alias": alias, "path": run_dir.name})
    qualification = {
        "qualification_version": "2.0.0",
        "passed": True,
        "rubric_sha256": suite["rubric_sha256"],
        "run_manifest_sha256": "1" * 64,
        "corpus_manifest_sha256": "2" * 64,
        "blueprint_sha256": "3" * 64,
        "corpus_dataset_sha256": "4" * 64,
        "bundle_verification": {"valid": True},
        "judge_configuration": judge,
        "judges": {"primary": {"passed": True}},
    }
    qualification_path = tmp_path / "qualification.json"
    qualification_path.write_text(json.dumps(qualification))
    approver_qualification = tmp_path / "approver-qualification.txt"
    approver_qualification.write_text("independent reviewer competence evidence")
    approval = {
        "approval_version": "2.0.0",
        "approval_id": "approval-1",
        "scope": "judge-qualification",
        "status": "passed",
        "independent": True,
        "qualification_sha256": sha256_file(qualification_path),
        "approver_id": "independent-reviewer",
        "approver_qualification_evidence": approver_qualification.name,
        "approver_qualification_evidence_sha256": sha256_file(approver_qualification),
        "conflicts": "none declared",
        "decision_rationale": "The preregistered evidence and gates were independently reviewed.",
        "approved_at": "2026-08-05T12:00:00+00:00",
        "expires_at": "2099-08-05T12:00:00+00:00",
    }
    evidence = {
        "qualification.json": qualification,
        "approval.json": approval,
        "transcript.json": {"status": "passed", "identity_blinded": True, "independent_reviewers": 2, "separate_adjudicator": True},
    }
    evidence_records = {}
    for name, value in evidence.items():
        path = tmp_path / name
        path.write_text(json.dumps(value))
        evidence_records[name] = {"path": name, "sha256": sha256_file(path)}
    campaign = {
        "campaign_version": "1.0.0",
        "suite": suite,
        "requirements": {
            "minimum_model_families": 3,
            "minimum_target_repetitions": 3,
            "minimum_judge_repetitions": 3,
            "evaluation_cases": 404,
            "independent_scenarios": 328,
            "positive_control_min_pass_rate": 1.0,
            "negative_control_max_pass_rate": 0.25,
        },
        "judge_qualification": evidence_records["qualification.json"],
        "judge_independent_approval": evidence_records["approval.json"],
        "transcript_review": evidence_records["transcript.json"],
        "runs": campaign_runs,
    }
    campaign_path = tmp_path / "campaign.json"
    campaign_path.write_text(json.dumps(campaign))
    result = audit_pilot_campaign(campaign_path, tmp_path / "pilot-audit.json")
    assert result["passed"] is True and result["role_counts"] == {"target": 3, "positive-control": 1, "negative-control": 1}
    campaign["runs"] = campaign_runs[:-1]
    incomplete_path = tmp_path / "campaign-incomplete.json"
    incomplete_path.write_text(json.dumps(campaign))
    incomplete = audit_pilot_campaign(incomplete_path, tmp_path / "pilot-audit-incomplete.json")
    assert incomplete["passed"] is False and "pilot campaign requires positive and negative control runs" in incomplete["errors"]

    unsafe = {**campaign, "runs": [{**campaign_runs[0], "path": "../run-0"}, *campaign_runs[1:]]}
    unsafe_path = tmp_path / "campaign-unsafe.json"
    unsafe_output = tmp_path / "pilot-audit-unsafe.json"
    unsafe_path.write_text(json.dumps(unsafe))
    with pytest.raises(ProtocolError, match="package-relative"):
        audit_pilot_campaign(unsafe_path, unsafe_output)
    assert not unsafe_output.exists()

    unsafe_evidence = {**campaign, "runs": campaign_runs, "transcript_review": {"path": str(tmp_path / "transcript.json"), "sha256": "a" * 64}}
    unsafe_evidence_path = tmp_path / "campaign-unsafe-evidence.json"
    unsafe_evidence_output = tmp_path / "pilot-audit-unsafe-evidence.json"
    unsafe_evidence_path.write_text(json.dumps(unsafe_evidence))
    with pytest.raises(ProtocolError, match="package-relative"):
        audit_pilot_campaign(unsafe_evidence_path, unsafe_evidence_output)
    assert not unsafe_evidence_output.exists()

    weak = {**campaign, "runs": campaign_runs, "requirements": {**campaign["requirements"], "minimum_model_families": 1}}
    weak_path = tmp_path / "campaign-weak.json"
    weak_path.write_text(json.dumps(weak))
    with pytest.raises(ProtocolError, match="at least three families"):
        audit_pilot_campaign(weak_path, tmp_path / "pilot-audit-weak.json")

    control_manifest_path = tmp_path / "run-3" / "manifest.json"
    control_manifest = json.loads(control_manifest_path.read_text(encoding="utf-8"))
    control_scenarios_path = tmp_path / "run-3" / "scenario_results.jsonl"
    control_scenarios = [json.loads(line) for line in control_scenarios_path.read_text(encoding="utf-8").splitlines()]
    control_scenarios[0]["category"] = "security"
    control_scenarios_path.write_text("".join(json.dumps(row) + "\n" for row in control_scenarios), encoding="utf-8")
    control_manifest["metrics"]["aggregate_scope"] = "not-applicable"
    control_manifest["metrics"]["constructs"] = ["quality", "security"]
    control_manifest_path.write_text(json.dumps(control_manifest), encoding="utf-8")
    write_bundle(tmp_path / "run-3")
    multi_construct_path = tmp_path / "campaign-multi-construct-control.json"
    multi_construct_path.write_text(json.dumps({**campaign, "runs": campaign_runs}))
    multi_construct = audit_pilot_campaign(multi_construct_path, tmp_path / "pilot-audit-multi-construct-control.json")
    assert multi_construct["passed"] is False
    assert any("cannot use an aggregate pass-rate threshold" in error for error in multi_construct["errors"])
    control_scenarios[0]["category"] = "quality"
    control_scenarios_path.write_text("".join(json.dumps(row) + "\n" for row in control_scenarios), encoding="utf-8")
    control_manifest["metrics"]["aggregate_scope"] = "single-construct"
    control_manifest["metrics"]["constructs"] = ["quality"]
    control_manifest_path.write_text(json.dumps(control_manifest), encoding="utf-8")
    write_bundle(tmp_path / "run-3")

    nonfinite_manifest_path = tmp_path / "run-2" / "manifest.json"
    nonfinite_manifest = json.loads(nonfinite_manifest_path.read_text(encoding="utf-8"))
    original_pass_rate = nonfinite_manifest["metrics"]["pass_rate"]
    nonfinite_manifest["metrics"]["pass_rate"] = float("nan")
    nonfinite_manifest_path.write_text(json.dumps(nonfinite_manifest), encoding="utf-8")
    write_bundle(tmp_path / "run-2")
    nonfinite_path = tmp_path / "campaign-nonfinite.json"
    nonfinite_path.write_text(json.dumps({**campaign, "runs": campaign_runs}))
    nonfinite = audit_pilot_campaign(nonfinite_path, tmp_path / "pilot-audit-nonfinite.json")
    assert nonfinite["passed"] is False
    assert next(run for run in nonfinite["runs"] if run["run_id"] == "run-2")["pass_rate"] is None
    nonfinite_manifest["metrics"]["pass_rate"] = original_pass_rate
    nonfinite_manifest_path.write_text(json.dumps(nonfinite_manifest), encoding="utf-8")
    write_bundle(tmp_path / "run-2")

    scenario_path = tmp_path / "run-0" / "scenario_results.jsonl"
    scenario_rows = [json.loads(line) for line in scenario_path.read_text(encoding="utf-8").splitlines()]
    scenario_rows[0]["status"] = "fail"
    scenario_path.write_text("".join(json.dumps(row) + "\n" for row in scenario_rows), encoding="utf-8")
    write_bundle(tmp_path / "run-0")
    inconsistent_path = tmp_path / "campaign-inconsistent.json"
    inconsistent_path.write_text(json.dumps({**campaign, "runs": campaign_runs}))
    inconsistent = audit_pilot_campaign(inconsistent_path, tmp_path / "pilot-audit-inconsistent.json")
    assert inconsistent["passed"] is False
    assert any("scenario ledger disagrees" in error or "metrics do not reconcile" in error for error in inconsistent["errors"])


def test_program_registry_is_valid_and_rejects_duplicate_identity(tmp_path: Path) -> None:
    repo = Path.cwd()
    registry_path = repo / "program" / "registry.toml"
    registry = load_program_registry(registry_path, repo_root=repo)
    assert registry["summary"]["by_status"]["candidate"] == 2
    assert registry["summary"]["by_status"]["draft"] == 1
    assert registry["summary"]["by_status"]["planned"] == 15
    assert registry["summary"]["official_capable"] == 0
    assert registry["summary"]["sources"]["count"] == 30
    assert registry["summary"]["sources"]["by_official_use"]["blocked"] == 1
    assert registry["summary"]["crosswalk"]["count"] == 18
    assert registry["summary"]["crosswalk"]["by_status"]["implemented-partial"] == 5

    duplicate = tmp_path / "registry.toml"
    duplicate.write_text(
        registry_path.read_text(encoding="utf-8").replace('id = "memo4345-v1"', 'id = "security-privacy-smoke-v1"', 1),
        encoding="utf-8",
    )
    try:
        load_program_registry(duplicate, repo_root=repo)
    except ProtocolError as exc:
        assert "duplicate suite id" in str(exc)
    else:  # pragma: no cover - assertion branch
        raise AssertionError("duplicate program suite identity was accepted")


def test_evidence_crosswalk_rejects_unregistered_sources(tmp_path: Path) -> None:
    crosswalk = tmp_path / "crosswalk.toml"
    crosswalk.write_text(
        '''crosswalk_version = "1.0.0"
reviewed_at = "2026-08-05"
review_due = "2026-11-03"
claim_policy = "No compliance claim."
[[mappings]]
id = "unknown-framework"
source_id = "not-registered"
source_version = "1"
status = "reference-only"
scope = "test"
repository_evidence = ["test"]
external_evidence = ["test"]
limitations = ["test"]
'''
    )
    with pytest.raises(ProtocolError, match="absent from the source register"):
        load_evidence_crosswalk(crosswalk, {"known-source"}, repo_root=tmp_path)


def test_evidence_crosswalk_rejects_missing_repository_evidence(tmp_path: Path) -> None:
    crosswalk = tmp_path / "crosswalk.toml"
    crosswalk.write_text(
        '''crosswalk_version = "1.0.0"
reviewed_at = "2026-08-05"
review_due = "2026-11-03"
claim_policy = "No compliance claim."
[[mappings]]
id = "known-framework"
source_id = "known-source"
source_version = "1"
status = "reference-only"
scope = "test"
repository_evidence = ["missing.md"]
external_evidence = ["test"]
limitations = ["test"]
'''
    )
    with pytest.raises(ProtocolError, match="repository_evidence does not exist: missing.md"):
        load_evidence_crosswalk(crosswalk, {"known-source"}, repo_root=tmp_path)


def test_cross_suite_duplicates_are_rejected(tmp_path: Path) -> None:
    left = _suite(tmp_path / "left")
    right = _suite(tmp_path / "right")
    right_config = right / "suite.toml"
    right_config.write_text(right_config.read_text().replace('name = "extended"', 'name = "extended-right"'))
    errors = validate_cross_suite_duplicates([load_suite(left), load_suite(right)])
    assert errors == ["cross-suite duplicate inputs: extended/one, extended-right/one"]


def test_blueprint_contract_rejects_missing_case_metadata() -> None:
    root = Path("suites/cavada-core-assistant-text-v1").resolve()
    with (root / "suite.toml").open("rb") as handle:
        config = tomllib.load(handle)
    case = json.loads((root / config["dataset"]).read_text(encoding="utf-8").splitlines()[0])
    case.pop("ambiguity")
    suite = Suite(root, config, (case,), "rubric", root / config["dataset"], root / config["rubric"])
    errors = validate_case_blueprint(root / "case_blueprint.toml", suite)
    assert "case[1] missing blueprint fields: ['ambiguity']" in errors


def test_core_public_and_practice_cases_have_no_token_containment_duplicates() -> None:
    suite = load_suite(Path("suites/cavada-core-assistant-text-v1").resolve())
    assert semantic_duplicate_candidates(suite) == []


def test_judge_qualification_blueprint_rejects_underpowered_samples(tmp_path: Path) -> None:
    root = Path("suites/cavada-core-assistant-text-v1").resolve()
    with (root / "suite.toml").open("rb") as handle:
        config = tomllib.load(handle)
    source = root / "judge" / "qualification_blueprint.toml"
    weak = tmp_path / "weak.toml"
    weak.write_text(source.read_text(encoding="utf-8").replace("pass_target = 100", "pass_target = 1", 1), encoding="utf-8")
    suite = Suite(root, config, (), "rubric", root / config["dataset"], root / config["rubric"])
    errors = validate_judge_qualification_blueprint(weak, suite)
    assert "module[1].pass_target does not achieve minimum_power" in errors


def test_deterministic_structured_retrieval_and_transcript_metrics() -> None:
    result = deterministic_evaluation(
        {
            "expected_json": True,
            "json_schema": {"type": "object", "required": ["answer"], "properties": {"answer": {"type": "string"}}, "additionalProperties": False},
            "expected_json_value": {"answer": "ok"},
            "expected_retrieval_ids": ["a", "b"],
            "retrieval_k": 2,
            "retrieval_minimums": {"recall_at_k": 1.0},
        },
        '{"answer":"ok"}',
        retrieved_ids=["a", "b"],
    )
    assert result["hard_pass"] is True
    assert result["scores"]["structured_field_accuracy"] == 1.0
    assert retrieval_scores(["a"], ["a"], 1)["ndcg_at_k"] == 1.0
    assert error_rate("hello world".split(), "hello word".split()) == 0.5

    null_result = deterministic_evaluation(
        {
            "expected_json": True,
            "json_schema": {"type": "object"},
            "expected_json_value": {"answer": "ok"},
        },
        "null",
    )
    assert null_result["checks"]["json_validity"] is True
    assert null_result["checks"]["json_schema"] is False
    assert null_result["checks"]["structured_field_accuracy"] is False
    assert null_result["hard_pass"] is False

    value_only = deterministic_evaluation({"expected_json_value": {"answer": "ok"}}, "{}")
    assert value_only["checks"]["json_validity"] is True
    assert value_only["checks"]["structured_field_accuracy"] is False
    assert value_only["hard_pass"] is False

    empty_structure = deterministic_evaluation({"expected_json_value": {"items": []}}, '{"other":[]}')
    assert empty_structure["checks"]["structured_field_accuracy"] is False

    malformed_tools = deterministic_evaluation({}, "answer", tool_calls=["not-an-object"])
    assert malformed_tools["checks"]["tool_calls_valid"] is False
    assert malformed_tools["hard_pass"] is False


def test_judge_calibration_reports_false_pass_risk_by_slice(tmp_path: Path) -> None:
    suite = load_suite(_suite(tmp_path))
    passing = {**suite.cases[0], "id": "pass-case", "judge_gold_verdict": "pass", "probe_type": "standard"}
    failing = {
        **suite.cases[0],
        "id": "fail-case",
        "severity": "critical",
        "judge_gold_verdict": "fail",
        "probe_type": "borderline",
    }
    calibration_suite = Suite(suite.root, suite.config, (passing, failing), suite.rubric, suite.dataset_path, suite.rubric_path)
    rows = [
        {"judge_id": "primary", "case_id": "pass-case", "judgment": {"verdict": "pass"}},
        {"judge_id": "primary", "case_id": "fail-case", "judgment": {"verdict": "pass"}},
    ]
    result = _judge_calibration_summary(rows, calibration_suite)["primary"]
    assert result["accuracy"] == 0.5 and result["failure_sensitivity"] == 0.0
    assert result["false_pass_rate"] == 1.0 and result["pass_specificity"] == 1.0
    assert result["slices"]["severity"]["critical"]["false_pass"] == 1
    assert result["failure_sensitivity_ci"]["lower"] == 0.0
    assert result["slices"]["probe_type"]["borderline"]["false_pass"] == 1


def test_bundle_verification_detects_tampering(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    artifact = run_dir / "result.json"
    artifact.write_text("{}\n", encoding="utf-8")
    write_bundle(run_dir)
    assert verify_bundle(run_dir)["valid"] is True
    artifact.write_text('{"tampered":true}\n', encoding="utf-8")
    result = verify_bundle(run_dir)
    assert result["valid"] is False
    assert result["failures"] == ["hash mismatch: result.json"]
    artifact.write_text("{}\n", encoding="utf-8")
    extra = run_dir / "unlisted.txt"
    extra.write_text("misleading", encoding="utf-8")
    assert "unlisted artifact: unlisted.txt" in verify_bundle(run_dir)["failures"]

    empty = tmp_path / "empty"
    empty.mkdir()
    write_bundle(empty)
    with pytest.raises(ProtocolError, match="malformed bundle"):
        verify_bundle(empty)

    malformed = tmp_path / "malformed"
    malformed.mkdir()
    malformed_bundle = {
        "bundle_version": "1.0.0",
        "algorithm": "sha256",
        "files": {
            "../outside.txt": "a" * 64,
            r"..\outside.txt": "b" * 64,
            r"C:outside.txt": "c" * 64,
            "evidence.txt": "not-a-sha256",
        },
    }
    (malformed / "bundle.json").write_text(json.dumps(malformed_bundle), encoding="utf-8")
    (malformed / "checksums.txt").write_text(
        f"{'a' * 64}  ../outside.txt\n{'b' * 64}  ..\\outside.txt\n{'c' * 64}  C:outside.txt\nnot-a-sha256  evidence.txt\n",
        encoding="utf-8",
    )
    malformed_result = verify_bundle(malformed)
    assert malformed_result["valid"] is False
    assert "unsafe artifact path: ../outside.txt" in malformed_result["failures"]
    assert r"unsafe artifact path: ..\outside.txt" in malformed_result["failures"]
    assert r"unsafe artifact path: C:outside.txt" in malformed_result["failures"]
    assert "malformed artifact entry: evidence.txt" in malformed_result["failures"]

    outside = tmp_path / "outside"
    outside.mkdir()
    outside_artifact = outside / "evidence.txt"
    outside_artifact.write_text("outside", encoding="utf-8")
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    (unsafe / "linked").symlink_to(outside, target_is_directory=True)
    unsafe_bundle = {"bundle_version": "1.0.0", "algorithm": "sha256", "files": {"linked/evidence.txt": sha256_file(outside_artifact)}}
    (unsafe / "bundle.json").write_text(json.dumps(unsafe_bundle), encoding="utf-8")
    (unsafe / "checksums.txt").write_text(f"{sha256_file(outside_artifact)}  linked/evidence.txt\n", encoding="utf-8")
    unsafe_result = verify_bundle(unsafe)
    assert unsafe_result["valid"] is False
    assert any("unsafe" in failure for failure in unsafe_result["failures"])


def test_conversation_input_must_match_final_user_turn(tmp_path: Path) -> None:
    root = _suite(tmp_path)
    case = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    case["messages"] = [{"role": "user", "content": "Different question"}]
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    try:
        load_suite(root)
    except ProtocolError as exc:
        assert "must exactly match" in str(exc)
    else:  # pragma: no cover - assertion branch
        raise AssertionError("mismatched conversation was accepted")


def test_malicious_asset_path_is_rejected_before_parsing(tmp_path: Path) -> None:
    root = _suite(tmp_path)
    case = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    case["input"] = [{"type": "image", "asset": "../outside.png", "mime_type": "image/png"}]
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    try:
        load_suite(root)
    except ProtocolError as exc:
        assert "escapes the suite" in str(exc)
    else:  # pragma: no cover - assertion branch
        raise AssertionError("path traversal asset was accepted")


def test_fake_image_extension_does_not_bypass_magic_check(tmp_path: Path) -> None:
    root = _suite(tmp_path)
    (root / "fake.png").write_text("not an image", encoding="utf-8")
    case = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    case["input"] = [{"type": "image", "asset": "fake.png", "mime_type": "image/png"}]
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    try:
        load_suite(root)
    except ProtocolError as exc:
        assert "cannot be verified from file magic" in str(exc)
    else:  # pragma: no cover - assertion branch
        raise AssertionError("fake image was accepted")


def test_truncated_png_is_rejected_without_decompression(tmp_path: Path) -> None:
    root = _suite(tmp_path)
    (root / "truncated.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    case = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    case["input"] = [{"type": "image", "asset": "truncated.png", "mime_type": "image/png"}]
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    try:
        load_suite(root)
    except ProtocolError as exc:
        assert "PNG has no complete IEND" in str(exc)
    else:  # pragma: no cover - assertion branch
        raise AssertionError("truncated PNG was accepted")


def test_pairwise_judgment_schema_is_strict() -> None:
    raw = {"choices": [{"message": {"content": '{"winner":"A","reason":"better","confidence":0.8}'}}]}
    assert _winner(raw) == ("A", "better", 0.8)
    try:
        _winner({"choices": [{"message": {"content": '{"winner":"baseline"}'}}]})
    except ProtocolError:
        pass
    else:  # pragma: no cover - assertion branch
        raise AssertionError("malformed pairwise output was accepted")


def test_free_form_external_import_is_rejected_before_output(tmp_path: Path) -> None:
    source = tmp_path / "external.json"
    source.write_text(
        json.dumps(
            {
                "adapter_version": "1.0.0",
                "source": {
                    "name": "fixture",
                    "version": "1",
                    "commit": "abc123",
                    "license": "test-only",
                    "dataset_sha256": "a" * 64,
                    "evaluator_sha256": "b" * 64,
                    "invocation": "fixture --offline",
                },
                "suite": {"name": "fixture"},
                "results": [{"case_id": "one", "status": "pass"}],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "import"
    with pytest.raises(ProtocolError, match="unsupported external adapter"):
        import_external_results(source, output)
    assert not output.exists()


def test_recorded_target_adapter_is_offline_and_pinned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _suite(tmp_path)
    responses = root / "responses.jsonl"
    responses.write_text(json.dumps({"case_id": "one", "answer": "Recorded answer", "model": "recorded-model"}) + "\n", encoding="utf-8")
    config = (root / "suite.toml").read_text(encoding="utf-8").replace(
        'kind = "json"',
        f'kind = "recorded"\nresponses = "responses.jsonl"\nresponses_sha256 = "{sha256_file(responses)}"',
    )
    (root / "suite.toml").write_text(config, encoding="utf-8")
    suite = load_suite(root)
    answer, _, reported, payload, transport = call_target(suite, "recorded://suite", "", {"case_id": "one", "input": "Question"}, None, 1)
    assert (answer, reported) == ("Recorded answer", "recorded-model")
    assert payload["source_sha256"] and transport["recorded"] is True

    def mutate_after_hash(path: Path) -> str:
        digest = sha256_file(path)
        path.write_text(json.dumps({"case_id": "one", "answer": "Mutated", "model": "recorded-model"}) + "\n", encoding="utf-8")
        return digest

    monkeypatch.setattr("cavada_eval.runner.sha256_file", mutate_after_hash)
    answer, _, _, _, _ = call_target(suite, "recorded://suite", "", {"case_id": "one", "input": "Question"}, None, 1)
    assert answer == "Recorded answer"
    responses.write_text(json.dumps({"case_id": "one", "answer": "Mutated", "model": "recorded-model"}) + "\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="recorded response source changed after validation"):
        call_target(suite, "recorded://suite", "", {"case_id": "one", "input": "Question"}, None, 1)


def test_encoded_asset_hash_and_payload_use_one_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    asset = tmp_path / "asset.txt"
    original = b"original asset"
    asset.write_bytes(original)
    original_sha256_file = asset_module.sha256_file

    def mutate_after_hash(path: Path) -> str:
        digest = original_sha256_file(path)
        path.write_bytes(b"mutated asset")
        return digest

    monkeypatch.setattr(asset_module, "sha256_file", mutate_after_hash)
    encoded = asset_module.encoded_content(
        [{"type": "document", "asset": asset.name, "mime_type": "text/plain", "sha256": sha256_bytes(original)}],
        suite_root=tmp_path,
    )
    assert isinstance(encoded, list)
    assert encoded[0]["sha256"] == sha256_bytes(original)
    assert base64.b64decode(encoded[0]["data_base64"]) == original


def test_annotation_package_is_blind_and_never_overwrites(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _suite(tmp_path)
    suite = load_suite(root)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    raw_path = run_dir / "raw_responses.jsonl"
    raw_path.write_text(
        json.dumps({"case_id": "one", "repetition": 1, "reported_model": "secret-model", "response": {"answer": "Anonymous answer", "model": "secret-model"}}) + "\n",
        encoding="utf-8",
    )
    source_manifest = {
        "protocol_version": suite.config["protocol_version"],
        "run_id": "annotation-source",
        "status": "passed",
        "suite": {
            "name": suite.name,
            "version": suite.version,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
            "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
        },
        "target": {"label": "secret-model"},
        "artifacts": {"raw_responses.jsonl": sha256_file(raw_path)},
    }
    (run_dir / "manifest.json").write_text(json.dumps(source_manifest) + "\n", encoding="utf-8")
    write_bundle(run_dir)
    output = tmp_path / "annotations"
    linkage = tmp_path / "restricted" / "linkage.jsonl"
    original_annotation_sha256_file = annotation_module.sha256_file

    def mutate_raw_after_hash(path: Path) -> str:
        digest = original_annotation_sha256_file(path)
        if path.resolve() == raw_path.resolve():
            raw_path.write_text(
                json.dumps({"case_id": "one", "repetition": 1, "response": {"answer": "Mutated answer", "model": "secret-model"}}) + "\n",
                encoding="utf-8",
            )
        return digest

    monkeypatch.setattr(annotation_module, "sha256_file", mutate_raw_after_hash)
    manifest = export_annotation_package(suite, run_dir, output, linkage)
    monkeypatch.setattr(annotation_module, "sha256_file", original_annotation_sha256_file)
    annotation = json.loads((output / "annotations.jsonl").read_text(encoding="utf-8"))
    public_text = json.dumps(annotation) + (output / "package_manifest.json").read_text(encoding="utf-8")
    assert manifest["identity_blinded"] is True and "Anonymous answer" in public_text
    assert "Mutated answer" not in public_text
    assert "secret-model" not in public_text and "split" not in annotation
    assert not (output / "linkage.restricted.jsonl").exists() and '"case_id": "one"' in linkage.read_text(encoding="utf-8")
    annotation.update(
        {
            "label": "pass",
            "criterion_findings": {"correct": True},
            "rationale": "The response meets the criterion.",
            "confidence": 0.9,
        }
    )
    original_response = annotation["response"]
    annotation["response"] = "Changed after export"
    (output / "annotations.jsonl").write_text(json.dumps(annotation) + "\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="restricted linkage is invalid"):
        ingest_annotations(
            output,
            linkage,
            tmp_path / "mutated-review",
            reviewer_id="reviewer-x",
            qualification_evidence="qualification-x",
            conflicts="none declared",
        )
    annotation["response"] = original_response
    (output / "annotations.jsonl").write_text(json.dumps(annotation) + "\n", encoding="utf-8")
    left = tmp_path / "review-left"
    right = tmp_path / "review-right"
    completed_annotations_raw = (output / "annotations.jsonl").read_bytes()

    def mutate_annotations_before_hash(path: Path) -> str:
        if path.resolve() == (output / "annotations.jsonl").resolve():
            changed = {**annotation, "rationale": "Changed after parsing."}
            path.write_text(json.dumps(changed) + "\n", encoding="utf-8")
        return original_annotation_sha256_file(path)

    monkeypatch.setattr(annotation_module, "sha256_file", mutate_annotations_before_hash)
    left_manifest = ingest_annotations(
        output,
        linkage,
        left,
        reviewer_id="reviewer-a",
        qualification_evidence="qualification-a",
        conflicts="none declared",
    )
    monkeypatch.setattr(annotation_module, "sha256_file", original_annotation_sha256_file)
    assert left_manifest["completed_annotations_sha256"] == sha256_bytes(completed_annotations_raw)
    annotation.update(
        {
            "label": "fail",
            "criterion_findings": {"correct": False},
            "rationale": "The response fails the criterion.",
            "failure_severity": "medium",
            "confidence": 0.8,
        }
    )
    (output / "annotations.jsonl").write_text(json.dumps(annotation) + "\n", encoding="utf-8")
    ingest_annotations(output, linkage, right, reviewer_id="reviewer-b", qualification_evidence="qualification-b", conflicts="none declared")
    right_manifest_path = right / "evidence_manifest.json"
    right_manifest = json.loads(right_manifest_path.read_text(encoding="utf-8"))
    right_manifest["source_run_bundle_sha256"] = "f" * 64
    right_manifest_path.write_text(json.dumps(right_manifest) + "\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="same exact source package"):
        annotation_agreement(left, right, tmp_path / "mismatched-agreement", bootstrap_samples=100)
    right_manifest["source_run_bundle_sha256"] = manifest["source_run_bundle_sha256"]
    right_manifest_path.write_text(json.dumps(right_manifest) + "\n", encoding="utf-8")
    agreement_dir = tmp_path / "agreement"
    left_labels_path = left / "labels.jsonl"

    def mutate_labels_after_hash(path: Path) -> str:
        digest = original_annotation_sha256_file(path)
        if path.resolve() == left_labels_path.resolve():
            changed = json.loads(left_labels_path.read_text(encoding="utf-8"))
            changed.update(
                {
                    "label": "fail",
                    "criterion_findings": {"correct": False},
                    "rationale": "Changed after hashing.",
                    "failure_severity": "medium",
                }
            )
            left_labels_path.write_text(json.dumps(changed) + "\n", encoding="utf-8")
        return digest

    monkeypatch.setattr(annotation_module, "sha256_file", mutate_labels_after_hash)
    agreement = annotation_agreement(left, right, agreement_dir, bootstrap_samples=100)
    monkeypatch.setattr(annotation_module, "sha256_file", original_annotation_sha256_file)
    assert agreement["raw_agreement"] == 0 and agreement["disagreements"] == 1
    assert agreement["source_package"]["source_run_bundle_sha256"] == manifest["source_run_bundle_sha256"]
    disagreement = json.loads((agreement_dir / "disagreements.jsonl").read_text(encoding="utf-8"))
    assert "reviewer_id" not in json.dumps(disagreement)
    disagreement["decision"] = {
        "label": "pass",
        "criterion_findings": {"correct": True},
        "rationale": "The response satisfies the governing criterion.",
        "failure_severity": None,
        "confidence": 0.95,
        "escalation_flags": [],
    }
    (agreement_dir / "disagreements.jsonl").write_text(json.dumps(disagreement) + "\n", encoding="utf-8")
    adjudication_dir = tmp_path / "adjudication"
    adjudication = ingest_adjudications(
        agreement_dir,
        left,
        right,
        adjudication_dir,
        adjudicator_id="adjudicator-c",
        qualification_evidence="qualification-c",
        conflicts="none declared",
    )
    preserved = json.loads((adjudication_dir / "adjudications.jsonl").read_text(encoding="utf-8"))
    assert adjudication["adjudications"] == 1
    assert {review["label"] for review in preserved["source_reviews"]} == {"pass", "fail"}
    try:
        export_annotation_package(suite, run_dir, output, linkage)
    except ProtocolError as exc:
        assert "already exists" in str(exc)
    else:  # pragma: no cover - assertion branch
        raise AssertionError("annotation package overwrote existing evidence")


def test_openai_target_prepends_hash_pinned_system_prompt(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        payload: dict[str, object] = {}

        def do_POST(self) -> None:  # noqa: N802
            Handler.payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            body = b'{"model":"target-real","choices":[{"message":{"content":"Answer"}}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    root = _suite(tmp_path)
    system_prompt = root / "system.txt"
    system_prompt.write_text("Fixed system prompt.\n", encoding="utf-8")
    config = (root / "suite.toml").read_text(encoding="utf-8").replace(
        'kind = "json"',
        f'kind = "openai"\nsystem_prompt = "system.txt"\nsystem_prompt_sha256 = "{sha256_file(system_prompt)}"',
    )
    (root / "suite.toml").write_text(config, encoding="utf-8")
    suite = load_suite(root)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        answer, _, reported, _, _ = call_target(
            suite, f"http://127.0.0.1:{server.server_port}", "", "Question", "target-request", 5
        )
    finally:
        server.shutdown()
        thread.join()
    assert (answer, reported) == ("Answer", "target-real")
    assert Handler.payload["messages"] == [
        {"role": "system", "content": "Fixed system prompt.\n"},
        {"role": "user", "content": "Question"},
    ]
    system_prompt.write_text("Mutated system prompt.\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="target system prompt changed after validation"):
        build_target_payload(suite, "Question", "target-request")


def test_retry_reuses_idempotency_key() -> None:
    class Handler(BaseHTTPRequestHandler):
        attempts = 0
        keys: list[str] = []

        def do_POST(self) -> None:  # noqa: N802
            Handler.attempts += 1
            Handler.keys.append(str(self.headers.get("Idempotency-Key")))
            self.rfile.read(int(self.headers["Content-Length"]))
            if Handler.attempts == 1:
                self.send_response(503)
                self.end_headers()
                return
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result, transport = _post_json(f"http://127.0.0.1:{server.server_port}/", {"test": True}, "", 5, request_id="fixed-request", retries=1)
    finally:
        server.shutdown()
        thread.join()
    assert result == {"ok": True} and transport["attempts"] == 2
    assert Handler.keys == ["fixed-request", "fixed-request"]
    assert transport["attempt_errors"][0]["http_status"] == 503


def test_timeout_is_single_attempt_transport_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def timeout(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise TimeoutError("timed out")

    monkeypatch.setattr("cavada_eval.runner._urlopen", timeout)
    with pytest.raises(_CallEvidenceError, match="timed out") as caught:
        _post_json("http://127.0.0.1/target", {"test": True}, "", 1, request_id="timeout-request")
    assert calls == 1 and caught.value.transport["attempts"] == 1
    assert caught.value.transport["attempt_errors"][0]["kind"] == "timeout"


def test_non_streaming_response_bodies_have_total_deadlines() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            body = b'{"error":"slow response"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                for byte in body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.03)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        started = time.monotonic()
        with pytest.raises(_CallEvidenceError, match="timed out|total request timeout") as json_caught:
            _post_json(url + "/json", {"test": True}, "", 0.1, request_id="deadline-json")
        json_elapsed = time.monotonic() - started

        started = time.monotonic()
        with pytest.raises(_CallEvidenceError, match="timed out|total request timeout") as stream_caught:
            _post_openai_stream(
                url + "/chat/completions",
                {"model": "target", "stream": True},
                "",
                0.1,
                request_id="deadline-non-sse",
            )
        stream_elapsed = time.monotonic() - started
    finally:
        server.shutdown()
        thread.join()

    assert json_elapsed < 0.3 and stream_elapsed < 0.3
    assert json_caught.value.raw is not None and json_caught.value.raw["body_base64"]
    assert stream_caught.value.raw is not None and stream_caught.value.raw["stream_body_base64"]
    for caught in (json_caught, stream_caught):
        assert caught.value.transport["response_bytes"] > 0
        assert caught.value.transport["attempt_errors"][0]["kind"] == "timeout"


def test_http_headers_have_total_deadline() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            response = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}'
            try:
                for byte in response:
                    self.connection.sendall(bytes([byte]))
                    time.sleep(0.02)
            except OSError:
                pass

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(_CallEvidenceError, match="timed out|total request timeout") as caught:
            _post_json(f"http://127.0.0.1:{server.server_port}", {}, "", 0.1, request_id="slow-header")
        elapsed = time.monotonic() - started
    finally:
        server.shutdown()
        thread.join()

    assert elapsed < 0.3
    assert caught.value.transport["attempt_errors"][0]["kind"] == "timeout"


@pytest.mark.parametrize(
    ("judge_status", "judge_content", "expected_status"),
    [(503, "", "error"), (200, "not JSON", "invalid")],
)
def test_judge_transport_and_output_failures_remain_distinct_and_preserve_evidence(
    tmp_path: Path,
    judge_status: int,
    judge_content: str,
    expected_status: str,
) -> None:
    class Handler(BaseHTTPRequestHandler):
        judge_calls = 0

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            if self.path.endswith("/chat/completions"):
                Handler.judge_calls += 1
                status = judge_status
                body = (
                    json.dumps(
                        {
                            "model": "judge-real",
                            "choices": [{"message": {"content": judge_content}}],
                        }
                    ).encode()
                    if status == 200
                    else b'{"error":"judge unavailable"}'
                )
            else:
                status = 200
                body = b'{"answer":"Answer","model":"target-real"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    suite = load_suite(_suite(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        output = run(
            suite,
            repo_root=tmp_path,
            endpoint=base + "/target",
            model_label="target",
            expected_model="target-real",
            model_revision="target-rev",
            request_model=None,
            judge_endpoint=base + "/v1",
            judge_model="judge",
            expected_judge_model="judge-real",
            judge_revision="judge-rev",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=5,
            official=False,
            allow_external_judge=False,
        )
    finally:
        server.shutdown()
        thread.join()

    result = json.loads((output / "case_results.jsonl").read_text(encoding="utf-8"))
    judgment = json.loads((output / "judgments.jsonl").read_text(encoding="utf-8"))
    requests = [json.loads(line) for line in (output / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
    judge_request = next(row for row in requests if row["kind"] == "judge")
    assert result["status"] == judgment["status"] == expected_status
    assert Handler.judge_calls == 1
    assert judgment["raw"] is not None and judgment["transport"]["attempts"] == 1
    if expected_status == "error":
        assert judge_request["status"] == "error"
        assert judgment["raw"]["body_sha256"]
    else:
        assert judgment["raw"]["choices"][0]["message"]["content"] == judge_content


def test_stream_failure_carries_partial_wire_and_events() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            body = (
                b'data: {"model":"target-real","choices":[{"delta":{"content":"part"}}],'
                b'"usage":{"prompt_tokens":3,"completion_tokens":1}}\n\n'
                b"data: {malformed\n\n"
            )
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
        with pytest.raises(_CallEvidenceError, match="invalid JSON") as caught:
            _post_openai_stream(
                f"http://127.0.0.1:{server.server_port}/chat/completions",
                {"model": "target", "stream": True},
                "",
                5,
                request_id="stream-request",
            )
    finally:
        server.shutdown()
        thread.join()

    raw = caught.value.raw
    transport = caught.value.transport
    assert raw is not None
    assert raw["choices"][0]["message"]["content"] == "part"
    assert raw["usage"] == {"prompt_tokens": 3, "completion_tokens": 1}
    assert len(raw["stream_events"]) == 1 and raw["stream_body_sha256"]
    assert transport["request_id"] == "stream-request" and transport["response_bytes"] > 0
    assert len(transport["event_monotonic_ns"]) == 1
    assert transport["started_monotonic_ns"] <= transport["headers_monotonic_ns"] <= transport["finished_monotonic_ns"]
    assert transport["headers_monotonic_ns"] <= transport["first_content_monotonic_ns"] <= transport["finished_monotonic_ns"]


def test_stream_rejects_contradictory_model_identities() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            body = (
                b'data: {"model":"wrong-model","choices":[{"delta":{"content":"part"}}]}\n\n'
                b'data: {"model":"target-real","choices":[{"delta":{"content":"two"}}]}\n\n'
            )
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
        with pytest.raises(_CallEvidenceError, match="inconsistent model identities") as caught:
            _post_openai_stream(
                f"http://127.0.0.1:{server.server_port}/chat/completions",
                {"model": "target", "stream": True},
                "",
                5,
                request_id="identity-stream",
            )
    finally:
        server.shutdown()
        thread.join()

    assert caught.value.raw is not None
    assert [event["model"] for event in caught.value.raw["stream_events"]] == ["wrong-model", "target-real"]
    assert caught.value.transport["request_id"] == "identity-stream"


def test_stream_timeout_is_a_total_deadline() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            try:
                for index in range(5):
                    self.wfile.write(
                        f'data: {{"model":"target-real","choices":[{{"delta":{{"content":"{index}"}}}}]}}\n\n'.encode()
                    )
                    self.wfile.flush()
                    time.sleep(0.06)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    elapsed = 0.0
    try:
        with pytest.raises(_CallEvidenceError, match="timed out|total request timeout") as caught:
            _post_openai_stream(
                f"http://127.0.0.1:{server.server_port}/chat/completions",
                {"model": "target", "stream": True},
                "",
                0.1,
                request_id="deadline-stream",
            )
        elapsed = time.monotonic() - started
    finally:
        server.shutdown()
        thread.join()

    assert elapsed < 0.3
    assert caught.value.raw is not None and caught.value.raw["stream_events"]
    assert caught.value.transport["request_id"] == "deadline-stream"


def test_run_rejects_unpaired_judge_qualification_evidence(tmp_path: Path) -> None:
    qualification = tmp_path / "qualification.json"
    qualification.write_text("{}")
    with pytest.raises(ProtocolError, match="must be supplied together"):
        run(
            load_suite(_suite(tmp_path)),
            repo_root=tmp_path,
            endpoint="http://127.0.0.1:1/target",
            model_label="target",
            expected_model="target",
            model_revision="target-revision",
            request_model=None,
            judge_endpoint="http://127.0.0.1:1/v1",
            judge_model="judge",
            expected_judge_model="judge",
            judge_revision="judge-revision",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=1,
            official=False,
            allow_external_judge=False,
            judge_qualification=str(qualification),
        )


def test_token_budget_aborts_after_preserving_raw_evidence(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps({"answer": "Answer", "model": "target-real", "usage": {"prompt_tokens": 2, "completion_tokens": 2}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    suite = load_suite(_suite(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        output = run(
            suite,
            repo_root=tmp_path,
            endpoint=base,
            model_label="target",
            expected_model="target-real",
            model_revision="target-rev",
            request_model=None,
            judge_endpoint=base + "/v1",
            judge_model="judge",
            expected_judge_model="judge-real",
            judge_revision="judge-rev",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=5,
            official=False,
            allow_external_judge=False,
            max_total_tokens=1,
        )
    finally:
        server.shutdown()
        thread.join()
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["abort_reason"] == "budget exhausted: total tokens"
    assert (output / "raw_responses.jsonl").stat().st_size > 0


def test_multiple_identity_verified_judges_use_declared_consensus(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        judge_payloads: list[dict[str, object]] = []

        def do_POST(self) -> None:  # noqa: N802
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path.endswith("/chat/completions"):
                Handler.judge_payloads.append(payload)
                reported = "judge-primary-real" if payload["model"] == "judge-primary" else "judge-secondary-real"
                body = {"model": reported, "choices": [{"message": {"content": '{"verdict":"pass","score":5,"reason":"ok","criteria":{}}'}}]}
            else:
                body = {"answer": "Answer", "model": "target-real"}
            encoded = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    root = _suite(tmp_path)
    calibration_case = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    calibration_case["judge_gold_verdict"] = "pass"
    calibration_case["mandatory_criteria"] = ["The response must satisfy the test criterion."]
    (root / "dataset.jsonl").write_text(json.dumps(calibration_case) + "\n", encoding="utf-8")
    (root / "suite.toml").write_text(
        (root / "suite.toml").read_text(encoding="utf-8")
        + '\n[judge]\nconsensus = "unanimous"\nminimum_calibration_accuracy = 0.2\nadditional_models = [{model="judge-secondary", expected_model="judge-secondary-real", revision="secondary-rev"}]\n',
        encoding="utf-8",
    )
    suite = load_suite(root)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        output = run(
            suite,
            repo_root=tmp_path,
            endpoint=base + "/target",
            model_label="target",
            expected_model="target-real",
            model_revision="target-rev",
            request_model=None,
            judge_endpoint=base + "/v1",
            judge_model="judge-primary",
            expected_judge_model="judge-primary-real",
            judge_revision="primary-rev",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=5,
            official=False,
            allow_external_judge=False,
        )
    finally:
        server.shutdown()
        thread.join()
    judgments = [json.loads(line) for line in (output / "judgments.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["reported_model"] for row in judgments] == ["judge-primary-real", "judge-secondary-real"]
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "passed"
    assert manifest["metrics"]["judge_calibration"]["primary"]["accuracy"] == 1.0
    assert 0.2 < manifest["metrics"]["judge_calibration"]["primary"]["accuracy_ci"]["lower"] < 1.0
    assert all("mandatory_criteria" in payload["messages"][1]["content"] for payload in Handler.judge_payloads)


def test_deliberate_failure_fails_gate_and_preserves_evidence(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            if self.path.endswith("/chat/completions"):
                body = {"model": "judge-real", "choices": [{"message": {"content": '{"verdict":"fail","score":0,"reason":"wrong","criteria":{}}'}}]}
            else:
                body = {"answer": "Wrong answer", "model": "target-real"}
            encoded = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    suite = load_suite(_suite(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        output = run(
            suite,
            repo_root=tmp_path,
            endpoint=base + "/target",
            model_label="target",
            expected_model="target-real",
            model_revision="target-rev",
            request_model=None,
            judge_endpoint=base + "/v1",
            judge_model="judge",
            expected_judge_model="judge-real",
            judge_revision="judge-rev",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=5,
            official=False,
            allow_external_judge=False,
        )
    finally:
        server.shutdown()
        thread.join()
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed" and manifest["metrics"]["gate_failures"]
    assert (output / "raw_responses.jsonl").stat().st_size > 0 and verify_bundle(output)["valid"] is True


def test_resume_rejects_an_unfinalized_run_without_mutation(tmp_path: Path) -> None:
    suite = load_suite(_suite(tmp_path))
    run_dir = tmp_path / "runs" / "extended" / "interrupted"
    run_dir.mkdir(parents=True)
    sentinel = run_dir / "partial.jsonl"
    sentinel.write_bytes(b'{"preserved":true}\n')
    run_args: dict[str, Any] = {
        "repo_root": tmp_path,
        "endpoint": "http://127.0.0.1:9/target",
        "model_label": "target",
        "expected_model": "target-real",
        "model_revision": "target-rev",
        "request_model": None,
        "judge_endpoint": "http://127.0.0.1:9/v1",
        "judge_model": "judge",
        "expected_judge_model": "judge-real",
        "judge_revision": "judge-rev",
        "target_key_env": "MISSING_TARGET_KEY",
        "judge_key_env": "MISSING_JUDGE_KEY",
        "repetitions": 1,
        "judge_repetitions": 1,
        "max_cases": 0,
        "timeout": 5,
        "official": False,
        "allow_external_judge": False,
        "resume_dir": run_dir,
    }

    with pytest.raises(ProtocolError, match="runs are immutable and cannot be resumed"):
        run(suite, **run_args)

    assert sentinel.read_bytes() == b'{"preserved":true}\n'
    assert list(run_dir.iterdir()) == [sentinel]
