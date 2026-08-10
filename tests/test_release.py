from __future__ import annotations

import json
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.cli import _export
from cavada_eval.metrics import METRIC_VERSION, deterministic_evaluation
from cavada_eval.profiles import ADAPTER_CONTRACT_VERSION
from cavada_eval.protocol import (
    PROTOCOL_VERSION,
    REPORT_VERSION,
    SCHEMA_VERSION,
    ProtocolError,
    Suite,
    load_suite,
    sha256_bytes,
    sha256_file,
    summarize,
    write_category_csv,
)
from cavada_eval.public_verify import verify_public_bundle
from cavada_eval.release import (
    canonical_protocol_path,
    reconcile_behavior_evidence,
    suite_governance_snapshots,
    verified_engagement,
    verified_public_release,
)
from cavada_eval.runner import _judge_system_prompt, build_judge_payload, build_target_payload, run, target_case_prompt

NOW = datetime(2026, 8, 5, 12, tzinfo=timezone.utc)
TARGET_REVISION = "a" * 40
JUDGE_REVISION = "b" * 40


def _suite(root: Path) -> Suite:
    root.mkdir()
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
        "tags": ["release-fixture"],
        "review": {"status": "approved", "method": "test"},
        "source": {"origin": "test"},
    }
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    (root / "rubric.md").write_text("Judge correctness.", encoding="utf-8")
    for name in (
        "analysis-plan",
        "human-labels",
        "holdout-manifest",
        "pilot-audit",
        "statistical-review",
        "comparison-corpus",
        "candidate-pairs",
        "semantic-reviewer",
        "calibration-approver",
    ):
        (root / f"{name}.json").write_text(json.dumps({"evidence": name}), encoding="utf-8")
    dataset_hash = sha256_file(root / "dataset.jsonl")
    rubric_hash = sha256_file(root / "rubric.md")
    semantic = {
        "evidence_version": "2.0.0",
        "dataset_sha256": dataset_hash,
        "comparison_corpus": "comparison-corpus.json",
        "comparison_corpus_sha256": sha256_file(root / "comparison-corpus.json"),
        "detector": "fixture-detector",
        "detector_revision": "fixture-detector-v1",
        "detector_license": "test-only",
        "similarity_metric": "cosine",
        "threshold": 0.95,
        "cases": 1,
        "candidate_pairs": 0,
        "candidate_pairs_evidence": "candidate-pairs.json",
        "candidate_pairs_evidence_sha256": sha256_file(root / "candidate-pairs.json"),
        "confirmed_duplicates": 0,
        "reviewer_evidence": "semantic-reviewer.json",
        "reviewer_evidence_sha256": sha256_file(root / "semantic-reviewer.json"),
        "cross_split_reviewed": True,
        "cross_suite_reviewed": True,
        "independent_review_status": "passed",
        "passed": True,
        "performed_at": "2026-08-01T00:00:00Z",
    }
    semantic_path = root / "semantic-contamination.json"
    semantic_path.write_text(json.dumps(semantic), encoding="utf-8")
    semantic_hash = sha256_file(semantic_path)
    calibration = {
        "calibration_version": "2.0.0",
        "status": "passed",
        "protocol_version": PROTOCOL_VERSION,
        "suite": {
            "name": "release-test-v1",
            "version": "1.0.0",
            "dataset_sha256": dataset_hash,
            "rubric_sha256": rubric_hash,
        },
        "source_commit": "1" * 40,
        "analysis_plan": "analysis-plan.json",
        "analysis_plan_sha256": sha256_file(root / "analysis-plan.json"),
        "human_label_evidence": "human-labels.json",
        "human_label_evidence_sha256": sha256_file(root / "human-labels.json"),
        "holdout_manifest": "holdout-manifest.json",
        "holdout_manifest_sha256": sha256_file(root / "holdout-manifest.json"),
        "pilot_audit": "pilot-audit.json",
        "pilot_audit_sha256": sha256_file(root / "pilot-audit.json"),
        "statistical_review": "statistical-review.json",
        "statistical_review_sha256": sha256_file(root / "statistical-review.json"),
        "semantic_contamination_evidence": semantic_path.name,
        "semantic_contamination_evidence_sha256": semantic_hash,
        "gates_passed": True,
        "results": {"all_preregistered_gates": "passed"},
        "completed_at": "2026-08-01T00:00:00Z",
        "limitations": ["Test fixture only."],
    }
    calibration_path = root / "calibration.json"
    calibration_path.write_text(json.dumps(calibration), encoding="utf-8")
    calibration_approval = {
        "approval_version": "2.0.0",
        "approval_id": "suite-calibration-approval-1",
        "scope": "suite-calibration",
        "status": "passed",
        "independent": True,
        "calibration_sha256": sha256_file(calibration_path),
        "approver_id": "suite-calibration-reviewer",
        "approver_qualification_evidence": "calibration-approver.json",
        "approver_qualification_evidence_sha256": sha256_file(root / "calibration-approver.json"),
        "conflicts": "none declared",
        "decision_rationale": "The fixture evidence satisfies the declared gates.",
        "approved_at": "2026-08-01T00:00:00Z",
        "expires_at": "2099-08-01T00:00:00Z",
    }
    calibration_approval_path = root / "calibration-approval.json"
    calibration_approval_path.write_text(json.dumps(calibration_approval), encoding="utf-8")
    (root / "suite.toml").write_text(
        f'''protocol_version = "1.0.0"
name = "release-test-v1"
version = "1.0.0"
status = "approved"
description = "Release governance fixture"
data_classification = "synthetic"
dataset = "dataset.jsonl"
rubric = "rubric.md"
dataset_sha256 = "{dataset_hash}"
rubric_sha256 = "{rubric_hash}"

[[gates]]
metric = "pass_rate_ci.lower"
min = 0.2

[target]
kind = "json"
capabilities = ["text"]

[network]
allowed_hosts = ["127.0.0.1"]

[governance]
owner = "CavadaLabs test"
purpose = "Release verification test"
intended_use = "Protocol regression tests"
prohibited_use = "Production decisions"
license = "Internal test fixture"
origin = "Synthetic fixture"
created_at = "2026-08-01"
retention = "Ephemeral test retention"
personal_data = "None"
legal_basis_reference = "Not applicable: synthetic"
rotation_due = "2027-08-01"
contamination_status = "Reviewed"
canary_strategy = "None: synthetic fixture"
known_leaks = "None known"
representativeness = "Test-only single case"
transfer_restrictions = "None"
near_duplicate_threshold = 0.9
semantic_duplicate_threshold = 0.95

[dataset_integrity]
semantic_review_status = "passed"
semantic_review_evidence = "{semantic_path.name}"
semantic_review_evidence_sha256 = "{semantic_hash}"
semantic_detector = "fixture-detector"
semantic_detector_revision = "fixture-detector-v1"
cross_split_reviewed = true
cross_suite_reviewed = true

[calibration]
status = "passed"
evidence = "{calibration_path.name}"
evidence_sha256 = "{sha256_file(calibration_path)}"
independent_review = "passed"
independent_review_evidence = "{calibration_approval_path.name}"
independent_review_evidence_sha256 = "{sha256_file(calibration_approval_path)}"
''',
        encoding="utf-8",
    )
    return load_suite(root)


def _engagement(path: Path) -> tuple[dict[str, object], Suite]:
    suite = _suite(path.parent / "suite")
    governance_evidence = path.parent / "governance-evidence.txt"
    governance_evidence.write_text("Authorized and independently reviewed fixture evidence.\n", encoding="utf-8")
    governance_hash = sha256_file(governance_evidence)
    record: dict[str, object] = {
        "engagement_version": "1.1.0",
        "engagement_id": "engagement-1",
        "status": "approved",
        "cavadalabs_roles": ["evaluator"],
        "counterparty_roles": ["provider"],
        "scope": "Exact protocol-conformance evaluation of the named SUT revision.",
        "suite": {
            "protocol_version": PROTOCOL_VERSION,
            "name": suite.name,
            "version": suite.version,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
            "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
        },
        "sut": {"expected_model": "target-model", "revision": TARGET_REVISION},
        "execution_owner_id": "operator-1",
        "commercial_owner_id": "commercial-1",
        "system_owner_reference": "restricted-system-owner-record",
        "jurisdictions": ["EU"],
        "requested_claims": ["Protocol conformance"],
        "permitted_claims": ["Results conform to the named CavadaLabs protocol and suite within the report limitations."],
        "prohibited_claims": ["certified", "legally compliant", "universally safe"],
        "conflicts_assessed": True,
        "conflicts": [],
        "complaints_process_reference": "program/POLICY.md#complaints-and-appeals",
        "appeals_process_reference": "program/POLICY.md#complaints-and-appeals",
        "correction_revocation_reference": "program/POLICY.md#correction-revocation-and-lifecycle",
        "disclosure_policy_reference": "program/POLICY.md#disclosure-and-surveillance",
        "surveillance_required": False,
        "surveillance_plan_reference": "",
        "authorization_evidence": governance_evidence.name,
        "authorization_evidence_sha256": governance_hash,
        "conflict_assessment_evidence": governance_evidence.name,
        "conflict_assessment_evidence_sha256": governance_hash,
        "legal_applicability_evidence": governance_evidence.name,
        "legal_applicability_evidence_sha256": governance_hash,
        "approver_qualification_evidence": governance_evidence.name,
        "approver_qualification_evidence_sha256": governance_hash,
        "approver_id": "governance-reviewer",
        "approved_at": "2026-08-01T00:00:00Z",
        "expires_at": "2026-09-01T00:00:00Z",
    }
    path.write_text(json.dumps(record), encoding="utf-8")
    return record, suite


def _distribution(value: float = 0.0, *, count: int = 1) -> dict[str, float | int]:
    return {
        "count": count,
        "min": value,
        "max": value,
        "mean": value,
        "median": value,
        "stdev": 0.0,
        "p50": value,
        "p90": value,
        "p95": value,
        "p99": value,
    }


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _release_fixture(tmp_path: Path, *, public_report: str = "<p>sanitized</p>") -> tuple[Path, Path, Path, dict[str, object]]:
    engagement_path = tmp_path / "engagement.json"
    engagement, suite = _engagement(engagement_path)
    engagement_summary = verified_engagement(
        engagement_path,
        suite,
        expected_model="target-model",
        model_revision=TARGET_REVISION,
        now=NOW,
    )
    run = tmp_path / "run"
    run.mkdir()
    base: dict[str, object] = {
        "case_id": "one",
        "category": "quality",
        "risk_domain": "quality",
        "severity": "low",
        "language": "en",
        "locale": "en-US",
        "split": "practice",
        "operating_condition": "missing",
        "performance_phase": "steady",
        "case_review_status": "approved",
        "repetition": 1,
    }
    judge_fields: dict[str, object] = {
        "judge_id": "primary",
        "requested_model": "judge-model",
        "judge_revision": JUDGE_REVISION,
        "judge_repetition": 1,
        "model_repetition": 1,
    }
    case = suite.cases[0]
    target_raw = {"model": "target-model", "answer": "Answer"}
    requests = [
        {
            **base,
            "kind": "target",
            "request_id": "target-1",
            "payload": build_target_payload(suite, target_case_prompt(case, "json"), None),
        },
        {
            **base,
            **judge_fields,
            "kind": "judge",
            "request_id": "judge-1",
            "payload": build_judge_payload(suite, "judge-model", case, "Answer", target_raw),
        },
    ]
    target_transport = {"request_id": "target-1", "attempts": 1, "request_bytes": 10, "response_bytes": 20, "total_ms": 1.0}
    judge_transport = {"request_id": "judge-1", "attempts": 1, "request_bytes": 20, "response_bytes": 30, "total_ms": 1.0}
    responses = [
        {
            **base,
            "reported_model": "target-model",
            "response": target_raw,
            "transport": target_transport,
        }
    ]
    judgment = {"verdict": "pass", "score": 5, "reason": "Correct.", "criteria": {}}
    raw_content = json.dumps(judgment, sort_keys=True)
    judgments = [
        {
            **base,
            **judge_fields,
            "reported_model": "judge-model",
            "judgment": judgment,
            "raw": {"model": "judge-model", "choices": [{"message": {"content": raw_content}}]},
            "raw_content": raw_content,
            "transport": judge_transport,
        }
    ]
    deterministic = deterministic_evaluation(case, "Answer", target_raw=target_raw, retrieved_ids=[], tool_calls=[])
    results = [
        {
            **base,
            "status": "pass",
            "reason": "judge unanimous",
            "score": 5.0,
            "judge_agreement": 1.0,
            "deterministic": deterministic,
            "target_latency_ms": 1.0,
            "target_headers_ms": None,
            "target_response_bytes": 20,
            "duration_ms": 10.0,
        }
    ]
    core_metrics, categories = summarize(results)
    reconciliation = reconcile_behavior_evidence(
        ({"id": "one", "review": {"status": "approved"}},),
        1,
        requests,
        responses,
        judgments,
        results,
        expected_judgments_per_observation=1,
        consensus="unanimous",
    )
    metrics: dict[str, object] = {
        **core_metrics,
        "analysis_unit": "case",
        "evaluation_cases": 1,
        "target_observations": 1,
        "evidence_reconciliation": reconciliation,
        "constructs": ["quality"],
        "aggregate_scope": "single-construct",
        "legacy_overall_metrics_claimable": True,
        "pass_rate_bootstrap_ci": {"lower": 1.0, "upper": 1.0, "confidence": 0.95, "samples": 10_000, "seed": 0},
        "pass_rate_stratified_bootstrap_ci": {"lower": 1.0, "upper": 1.0, "confidence": 0.95, "samples": 10_000, "seed": 0, "strata": 1},
        "slices": {
            field: {str(base[field]): core_metrics}
            for field in ("risk_domain", "severity", "language", "locale", "split", "operating_condition")
        },
        "slice_disparities": {field: 0.0 for field in ("risk_domain", "severity", "language", "locale", "split", "operating_condition")},
        "stability": {
            "case_pass_fraction": _distribution(1.0),
            "stable_case_fraction": 1.0,
            "judge_agreement": _distribution(1.0),
            "judge_score": _distribution(5.0),
        },
        "judge_calibration": {},
        "performance": {
            "target_latency_ms": _distribution(1.0),
            "evaluation_duration_ms": _distribution(10.0),
            "target_response_bytes": _distribution(20.0),
            **{field: _distribution(count=0) for field in ("input_tokens", "output_tokens", "ttft_ms", "output_tokens_per_second")},
            "elapsed_seconds": 1.0,
            "observations_per_second": 1.0,
            "target_calls_per_second": 1.0,
            "observation_success_rate": 1.0,
            "observation_error_rate": 0.0,
        },
        "performance_by_phase": {
            **{field: _distribution(count=0) for field in ("cold", "warmup", "soak")},
            "steady": _distribution(1.0),
        },
        "budgets": {"target_calls": 1, "judge_calls": 1, "total_tokens": 0.0, "exhausted": False},
        "gate_failures": [],
        "aborted": False,
    }
    environment = {
        "python": "3.11",
        "platform": "test",
        "hardware": {"machine": "test", "processor": "test", "cpu_count": 1},
        "uv_lock_sha256": "",
    }
    suite_manifest = {
        "name": suite.name,
        "version": suite.version,
        "status": suite.status,
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
        "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
        "data_classification": "synthetic",
        "profile": "text-generation",
    }
    target_manifest = {
        "label": "target",
        "expected_reported_model": "target-model",
        "revision": TARGET_REVISION,
        "endpoint": "http://127.0.0.1:1/target",
        "request_model": None,
        "api_key_env": "TARGET_API_KEY",
        "kind": "json",
        "capabilities": ["text"],
        "recorded_responses_sha256": None,
    }
    judge_manifest = {
        "requested_model": "judge-model",
        "expected_reported_model": "judge-model",
        "revision": JUDGE_REVISION,
        "endpoint": "http://127.0.0.1:1/judge",
        "prompt_sha256": sha256_bytes(_judge_system_prompt(suite).encode()),
        "response_schema": "judgment.schema.json@1.0.0",
        "temperature": 0,
        "max_tokens": 600,
        "judge_repetitions": 1,
        "models": [{"id": "primary", "model": "judge-model", "expected_model": "judge-model", "revision": JUDGE_REVISION}],
        "consensus": "unanimous",
        "api_key_env": "JUDGE_API_KEY",
    }
    judge_approver_evidence = b"Independent judge approver qualification fixture evidence.\n"
    judge_approver_hash = sha256_bytes(judge_approver_evidence)
    qualification = {
        "qualification_version": "2.0.0",
        "passed": True,
        "run_manifest_sha256": sha256_bytes(b"qualified run manifest fixture"),
        "corpus_manifest_sha256": sha256_bytes(b"qualification corpus manifest fixture"),
        "blueprint_sha256": sha256_bytes(b"qualification blueprint fixture"),
        "corpus_dataset_sha256": sha256_bytes(b"qualification corpus dataset fixture"),
        "bundle_verification": {"valid": True},
        "judge_configuration": judge_manifest,
        "rubric_sha256": sha256_file(suite.rubric_path),
        "judges": {"primary": {"passed": True}},
    }
    qualification_raw = json.dumps(qualification, sort_keys=True).encode()
    qualification_hash = sha256_bytes(qualification_raw)
    judge_approval = {
        "approval_version": "2.0.0",
        "approval_id": "judge-approval-1",
        "scope": "judge-qualification",
        "status": "passed",
        "independent": True,
        "qualification_sha256": qualification_hash,
        "approver_id": "judge-reviewer",
        "approver_qualification_evidence": "judge-approver-evidence.txt",
        "approver_qualification_evidence_sha256": judge_approver_hash,
        "conflicts": "none declared",
        "decision_rationale": "The exact judge qualification fixture passed independent review.",
        "approved_at": "2026-08-01T00:00:00Z",
        "expires_at": "2099-08-01T00:00:00Z",
    }
    judge_approval_raw = json.dumps(judge_approval, sort_keys=True).encode()
    judge_approval_hash = sha256_bytes(judge_approval_raw)
    protocol_raw = canonical_protocol_path().read_bytes()
    manifest = {
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": sha256_bytes(protocol_raw),
        "schema_version": SCHEMA_VERSION,
        "report_version": REPORT_VERSION,
        "metric_version": METRIC_VERSION,
        "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
        "run_id": "run-1",
        "status": "passed",
        "official": True,
        "official_requested": True,
        "started_at": "2026-08-05T10:00:00Z",
        "finished_at": "2026-08-05T11:00:00Z",
        "abort_reason": "",
        "suite": suite_manifest,
        "engagement": engagement_summary,
        "target": target_manifest,
        "judge": judge_manifest,
        "judge_qualification": {
            "qualification_sha256": qualification_hash,
            "approval_sha256": judge_approval_hash,
            "approval_id": "judge-approval-1",
            "approver_id": "judge-reviewer",
            "approved_at": "2026-08-01T00:00:00Z",
            "expires_at": "2099-08-01T00:00:00Z",
            "approver_qualification_evidence_sha256": judge_approver_hash,
        },
        "external_judge_authorized": False,
        "external_authorization": None,
        "artifact_security": {
            "classification": "synthetic",
            "retention": None,
            "storage_attestation": None,
            "encryption_state": "not-attested",
            "immutability_state": "not-attested",
        },
        "parameters": {
            "mode": "official",
            "case_review_policy": "approved-only",
            "preset": "",
            "preset_version": None,
            "repetitions": 1,
            "judge_repetitions": 1,
            "max_cases": 0,
            "selected_cases": 1,
            "timeout_seconds": 30.0,
            "max_target_calls": 0,
            "max_judge_calls": 0,
            "max_total_tokens": 0,
            "max_elapsed_seconds": 0.0,
            "max_estimated_cost": 0.0,
            "non_inferiority_margin": None,
            "concurrency": 1,
            "requests_per_second": 0.0,
            "progress_events": False,
            "case_order_policy": "dataset order",
            "case_order_sha256": sha256_bytes(b"one"),
            "cache": {"target": "disabled", "judge": "disabled"},
        },
        "pricing": None,
        "source": {"commit": "c" * 40, "dirty": False, "status_sha256": "5" * 64},
        "environment": environment,
        "signing": {"key_env": "CAVADA_EVAL_SIGNING_KEY", "key_id": ""},
        "reproduction_command": "cavada-eval run suite --target-key-env TARGET_API_KEY --judge-key-env JUDGE_API_KEY --official",
        "public_reproduction_command": "cavada-eval run suite --official",
        "metrics": metrics,
        "artifacts": {},
    }
    _write_jsonl(run / "requests.jsonl", requests)
    _write_jsonl(run / "raw_responses.jsonl", responses)
    _write_jsonl(run / "judgments.jsonl", judgments)
    _write_jsonl(run / "case_results.jsonl", results)
    for name in ("engine_results.jsonl", "failures.jsonl", "adjudication_queue.jsonl"):
        _write_jsonl(run / name, [])
    _write_jsonl(
        run / "events.jsonl",
        [
            {
                "timestamp": "2026-08-05T10:00:00Z",
                "event": "observation_started",
                "case_id": "one",
                "repetition": 1,
                "monotonic_ns": 1_000_000_000,
            },
            {
                "timestamp": "2026-08-05T10:00:00.010000Z",
                "event": "observation_finished",
                "case_id": "one",
                "repetition": 1,
                "status": "pass",
                "monotonic_ns": 1_010_000_000,
            },
        ],
    )
    (run / "metrics.json").write_text(json.dumps(metrics, sort_keys=True), encoding="utf-8")
    write_category_csv(run / "category_results.csv", categories)
    (run / "environment.json").write_text(json.dumps(environment, sort_keys=True), encoding="utf-8")
    (run / "asset_inventory.json").write_text("{}\n", encoding="utf-8")
    (run / "protocol_snapshot.md").write_bytes(protocol_raw)
    (run / "suite_snapshot.toml").write_text((suite.root / "suite.toml").read_text(encoding="utf-8"), encoding="utf-8")
    (run / "dataset_snapshot.jsonl").write_bytes(suite.dataset_path.read_bytes())
    (run / "rubric_snapshot.md").write_bytes(suite.rubric_path.read_bytes())
    suite_evidence = suite_governance_snapshots(suite.root, suite.config)
    (run / "suite_evidence_manifest.json").write_text(
        json.dumps({relative: sha256_bytes(raw) for relative, raw in suite_evidence.items()}, sort_keys=True),
        encoding="utf-8",
    )
    for raw in suite_evidence.values():
        path = run / "suite_evidence" / sha256_bytes(raw)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    (run / "judge_qualification_snapshot.json").write_bytes(qualification_raw)
    (run / "judge_approval_snapshot.json").write_bytes(judge_approval_raw)
    judge_support = run / "judge_evidence" / judge_approver_hash
    judge_support.parent.mkdir(parents=True, exist_ok=True)
    judge_support.write_bytes(judge_approver_evidence)
    (run / "dataset_card.md").write_text("# Dataset card\n", encoding="utf-8")
    (run / "report.html").write_text("<p>private report</p>", encoding="utf-8")
    (run / "report_public.html").write_text(public_report, encoding="utf-8")
    for name in ("report.pdf", "report_public.pdf"):
        (run / name).write_bytes(b"%PDF-1.4\n%%EOF\n")
    summary = {
        "protocol_version": PROTOCOL_VERSION,
        "report_version": REPORT_VERSION,
        "run_id": "run-1",
        "status": "passed",
        "suite": suite_manifest,
        "target": {"label": "target", "revision": TARGET_REVISION},
        "metrics": metrics,
        "categories": categories,
        "limitations": ["finite sampled scope"],
    }
    (run / "summary.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    (run / "junit.xml").write_text('<?xml version="1.0"?><testsuite tests="1"><testcase name="one"/></testsuite>\n', encoding="utf-8")
    manifest["artifacts"] = {
        path.relative_to(run).as_posix(): sha256_file(path)
        for path in sorted(run.rglob("*"))
        if path.is_file()
    }
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    write_bundle(run)
    review_evidence = tmp_path / "review-evidence.txt"
    review_evidence.write_text("Independent review and reviewer qualification fixture evidence.\n", encoding="utf-8")
    review_hash = sha256_file(review_evidence)
    decision = {
        "status": "passed",
        "independent": True,
        "reviewer_id": "technical-reviewer",
        "review_evidence": review_evidence.name,
        "review_evidence_sha256": review_hash,
        "qualification_evidence": review_evidence.name,
        "qualification_evidence_sha256": review_hash,
        "conflicts": [],
        "conflict_mitigation": "",
        "rationale": "The bounded evidence passed the preregistered review criteria.",
    }
    approval: dict[str, object] = {
        "release_version": "1.0.0",
        "release_id": "release-1",
        "status": "approved",
        "run_id": "run-1",
        "bundle_sha256": sha256_file(run / "bundle.json"),
        "manifest_sha256": sha256_file(run / "manifest.json"),
        "engagement_id": engagement["engagement_id"],
        "engagement_sha256": sha256_file(engagement_path),
        "assurance_level": "approved",
        "permitted_claims": engagement["permitted_claims"],
        "limitations_acknowledged": True,
        "decisions": {
            "statistical": dict(decision),
            "security": dict(decision),
            "privacy_legal": {**decision, "reviewer_id": "legal-reviewer"},
            "disclosure": dict(decision),
            "release": {**decision, "reviewer_id": "release-reviewer"},
        },
        "approved_at": "2026-08-05T11:30:00Z",
        "expires_at": "2026-08-31T00:00:00Z",
    }
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    return run, engagement_path, approval_path, approval


def _reseal_forged_run(run: Path, approval_path: Path, approval: dict[str, object]) -> None:
    excluded = {"manifest.json", "bundle.json", "checksums.txt", "signature.json", "verification.json"}
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["artifacts"] = {
        path.relative_to(run).as_posix(): sha256_file(path)
        for path in sorted(run.rglob("*"))
        if path.is_file() and path.relative_to(run).as_posix() not in excluded
    }
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    write_bundle(run)
    approval["bundle_sha256"] = sha256_file(run / "bundle.json")
    approval["manifest_sha256"] = sha256_file(run / "manifest.json")
    approval_path.write_text(json.dumps(approval), encoding="utf-8")


def _nonpublic_external_fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, object]]:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    suite_snapshot = run / "suite_snapshot.toml"
    suite_snapshot.write_text(
        suite_snapshot.read_text(encoding="utf-8").replace('data_classification = "synthetic"', 'data_classification = "confidential"'),
        encoding="utf-8",
    )
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["suite"]["data_classification"] = "confidential"
    manifest["suite"]["suite_config_sha256"] = sha256_file(suite_snapshot)
    manifest["target"]["endpoint"] = "https://target.example/v1"
    manifest["judge"]["endpoint"] = "https://judge.example/v1"
    qualification_path = run / "judge_qualification_snapshot.json"
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    qualification["judge_configuration"] = manifest["judge"]
    qualification_path.write_text(json.dumps(qualification, sort_keys=True), encoding="utf-8")
    qualification_hash = sha256_file(qualification_path)
    judge_approval_path = run / "judge_approval_snapshot.json"
    judge_approval = json.loads(judge_approval_path.read_text(encoding="utf-8"))
    judge_approval["qualification_sha256"] = qualification_hash
    judge_approval_path.write_text(json.dumps(judge_approval, sort_keys=True), encoding="utf-8")
    manifest["judge_qualification"]["qualification_sha256"] = qualification_hash
    manifest["judge_qualification"]["approval_sha256"] = sha256_file(judge_approval_path)
    manifest["external_judge_authorized"] = True
    manifest["external_authorization"] = {
        "authorization_id": "authorization-1",
        "approver": "privacy-reviewer",
        "purpose": "Bounded behavior evaluation",
        "destinations": [
            {"host": "target.example", "region": "EU", "purpose": "target inference"},
            {"host": "judge.example", "region": "EU", "purpose": "blinded judging"},
        ],
        "expires_at": "2026-08-31T00:00:00Z",
        "sha256": "6" * 64,
    }
    manifest["artifact_security"] = {
        "classification": "confidential",
        "retention": None,
        "storage_attestation": {
            "attestation_id": "storage-1",
            "approver": "security-reviewer",
            "encryption_at_rest": True,
            "immutability": True,
            "effective_at": "2026-08-01T00:00:00Z",
            "expires_at": "2026-08-31T00:00:00Z",
            "sha256": "7" * 64,
        },
        "encryption_state": "attested",
        "immutability_state": "attested",
    }
    engagement_record = json.loads(engagement.read_text(encoding="utf-8"))
    engagement_record["suite"]["suite_config_sha256"] = manifest["suite"]["suite_config_sha256"]
    engagement.write_text(json.dumps(engagement_record), encoding="utf-8")
    manifest["engagement"]["sha256"] = sha256_file(engagement)
    approval["engagement_sha256"] = sha256_file(engagement)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    summary["suite"] = manifest["suite"]
    (run / "summary.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    _reseal_forged_run(run, approval_path, approval)
    return run, engagement, approval_path, approval


def test_engagement_is_exact_and_public_release_is_post_run_and_independent(tmp_path: Path) -> None:
    run, engagement, approval, _ = _release_fixture(tmp_path)
    released = verified_public_release(run, engagement, approval, now=NOW)
    assert released["release_id"] == "release-1"
    assert released["decision_statuses"]["release"] == "passed"

    archive = tmp_path / "public.tar.gz"
    _export(run, archive, True, engagement=str(engagement), release_approval=str(approval))
    with tarfile.open(archive) as exported:
        assert set(exported.getnames()) == {
            "bundle.json",
            "category_results.csv",
            "checksums.txt",
            "public_release.json",
            "report_public.html",
            "report_public.pdf",
            "summary.json",
        }
        assert all(
            (member.uid, member.gid, member.uname, member.gname, member.mtime, member.mode) == (0, 0, "", "", 0, 0o644)
            for member in exported.getmembers()
        )
        extracted = tmp_path / "public-extracted"
        extracted.mkdir()
        exported.extractall(extracted, filter="data")
    assert verify_bundle(extracted)["valid"] is True
    assert verify_public_bundle(extracted)["semantic_valid"] is True
    second_archive = tmp_path / "public-second.tar.gz"
    _export(run, second_archive, True, engagement=str(engagement), release_approval=str(approval))
    assert second_archive.read_bytes() == archive.read_bytes()


@pytest.mark.parametrize(("record_name", "result_field"), [("engagement", "engagement_sha256"), ("approval", "approval_sha256")])
def test_public_release_binds_the_exact_governance_bytes_it_validates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_name: str,
    result_field: str,
) -> None:
    run, engagement, approval, _ = _release_fixture(tmp_path)
    target = engagement if record_name == "engagement" else approval
    original = target.read_bytes()
    real_read = Path.read_bytes
    changed = False

    def read_then_replace(path: Path) -> bytes:
        nonlocal changed
        raw = real_read(path)
        if path == target and not changed:
            changed = True
            path.write_text("{}\n", encoding="utf-8")
        return raw

    monkeypatch.setattr(Path, "read_bytes", read_then_replace)
    released = verified_public_release(run, engagement, approval, now=NOW)

    assert released[result_field] == sha256_bytes(original)
    assert released[result_field] != sha256_file(target)


@pytest.mark.parametrize("record_name", ["engagement", "approval"])
def test_public_release_rejects_symlinked_governance_records(tmp_path: Path, record_name: str) -> None:
    run, engagement, approval, _ = _release_fixture(tmp_path)
    original = engagement if record_name == "engagement" else approval
    linked = tmp_path / f"linked-{original.name}"
    linked.symlink_to(original)

    with pytest.raises(ProtocolError, match="regular JSON file"):
        verified_public_release(
            run,
            linked if record_name == "engagement" else engagement,
            linked if record_name == "approval" else approval,
            now=NOW,
        )


def test_public_export_rejects_source_drift_after_release_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run, engagement, approval, _ = _release_fixture(tmp_path)
    output = tmp_path / "must-not-exist.tar.gz"
    summary = run / "summary.json"
    real_read = Path.read_bytes
    drifted = False

    def drift_then_read(path: Path) -> bytes:
        nonlocal drifted
        if path == summary and not drifted:
            drifted = True
            path.write_bytes(real_read(path) + b"\n")
        return real_read(path)

    monkeypatch.setattr(Path, "read_bytes", drift_then_read)
    with pytest.raises(ProtocolError, match="differs from the approved source bundle"):
        _export(run, output, True, engagement=str(engagement), release_approval=str(approval))
    assert not output.exists()


def test_restricted_export_archives_the_verified_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run, _, _, _ = _release_fixture(tmp_path)
    output = tmp_path / "restricted.tar.gz"
    summary = run / "summary.json"
    original = summary.read_bytes()
    real_copytree = shutil.copytree

    def copy_then_drift(src: Path, dst: Path, *args: object, **kwargs: object) -> Path:
        copied = real_copytree(src, dst, *args, **kwargs)
        if Path(src) == run:
            summary.write_bytes(b"changed after snapshot\n")
        return copied

    monkeypatch.setattr("cavada_eval.cli.shutil.copytree", copy_then_drift)
    _export(run, output, False)

    extracted = tmp_path / "restricted-extracted"
    extracted.mkdir()
    with tarfile.open(output) as archive:
        archive.extractall(extracted, filter="data")
    assert (extracted / "summary.json").read_bytes() == original
    assert verify_bundle(extracted)["valid"] is True


@pytest.mark.parametrize(("name", "message"), [("bundle.json", "source bundle changed"), ("manifest.json", "source manifest changed")])
def test_public_export_snapshots_approved_metadata_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    message: str,
) -> None:
    run, engagement, approval, _ = _release_fixture(tmp_path)
    output = tmp_path / "must-not-exist.tar.gz"

    def verify_then_drift(*args: object, **kwargs: object) -> dict[str, object]:
        record = verified_public_release(*args, **kwargs)  # type: ignore[arg-type]
        path = run / name
        path.write_bytes(path.read_bytes() + b"\n")
        return record

    monkeypatch.setattr("cavada_eval.cli.verified_public_release", verify_then_drift)
    with pytest.raises(ProtocolError, match=message):
        _export(run, output, True, engagement=str(engagement), release_approval=str(approval))
    assert not output.exists()


def test_public_release_rejects_boolean_only_fabricated_bundle(tmp_path: Path) -> None:
    run = tmp_path / "fabricated"
    run.mkdir()
    (run / "manifest.json").write_text(
        json.dumps({"run_id": "fake", "status": "passed", "official": True, "official_requested": True}),
        encoding="utf-8",
    )
    write_bundle(run)

    with pytest.raises(ProtocolError, match="exact completed behavior-run contract"):
        verified_public_release(run, tmp_path / "missing-engagement.json", tmp_path / "missing-approval.json", now=NOW)


def test_public_release_rejects_invalid_judgment_hidden_behind_pass_metrics(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    judgment = json.loads((run / "judgments.jsonl").read_text(encoding="utf-8"))
    judgment.update({"status": "invalid", "error": "malformed provider evidence"})
    _write_jsonl(run / "judgments.jsonl", [judgment])
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="only successful terminal evidence"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_requires_usage_for_priced_evidence(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    pricing = {
        "currency": "USD",
        "source": "test",
        "effective_at": "2026-01-01",
        "input_per_million": 1,
        "output_per_million": 1,
    }
    snapshot = run / "suite_snapshot.toml"
    snapshot.write_text(
        snapshot.read_text(encoding="utf-8")
        + '\n[pricing]\ncurrency = "USD"\nsource = "test"\neffective_at = "2026-01-01"\n'
        + "input_per_million = 1\noutput_per_million = 1\n",
        encoding="utf-8",
    )
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["pricing"] = pricing
    manifest["suite"]["suite_config_sha256"] = sha256_file(snapshot)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="provider usage evidence is required"):
        verified_public_release(run, engagement, approval_path, now=NOW)


@pytest.mark.parametrize("name", ["protocol_snapshot.md", "dataset_snapshot.jsonl", "rubric_snapshot.md"])
def test_public_release_rejects_mutated_canonical_input_snapshot(tmp_path: Path, name: str) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    path = run / name
    path.write_bytes(path.read_bytes() + b"\n")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="authoritative manifest digest"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_rejects_self_consistent_noncanonical_protocol_snapshot(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    snapshot = run / "protocol_snapshot.md"
    snapshot.write_bytes(snapshot.read_bytes() + b"\nforged")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["protocol_sha256"] = sha256_file(snapshot)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="not the canonical bytes"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_revalidates_exact_judge_qualification_snapshots(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    qualification_path = run / "judge_qualification_snapshot.json"
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    qualification["passed"] = False
    qualification_path.write_text(json.dumps(qualification, sort_keys=True), encoding="utf-8")
    qualification_hash = sha256_file(qualification_path)
    judge_approval_path = run / "judge_approval_snapshot.json"
    judge_approval = json.loads(judge_approval_path.read_text(encoding="utf-8"))
    judge_approval["qualification_sha256"] = qualification_hash
    judge_approval_path.write_text(json.dumps(judge_approval, sort_keys=True), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["judge_qualification"]["qualification_sha256"] = qualification_hash
    manifest["judge_qualification"]["approval_sha256"] = sha256_file(judge_approval_path)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="judge qualification report is incomplete"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_rejects_mutated_judge_supporting_evidence(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    support = next((run / "judge_evidence").iterdir())
    support.write_bytes(support.read_bytes() + b"tampered")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="judge approver qualification snapshot is missing or hash-mismatched"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_rejects_judge_approval_by_engagement_owner(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    judge_approval_path = run / "judge_approval_snapshot.json"
    judge_approval = json.loads(judge_approval_path.read_text(encoding="utf-8"))
    judge_approval["approver_id"] = "operator-1"
    judge_approval_path.write_text(json.dumps(judge_approval, sort_keys=True), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["judge_qualification"]["approver_id"] = "operator-1"
    manifest["judge_qualification"]["approval_sha256"] = sha256_file(judge_approval_path)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="judge approval is not independent"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_rejects_approved_suite_without_snapshot_governance(tmp_path: Path) -> None:
    run, engagement_path, approval_path, approval = _release_fixture(tmp_path)
    suite_snapshot = run / "suite_snapshot.toml"
    suite_snapshot.write_text(
        suite_snapshot.read_text(encoding="utf-8").split("\n[dataset_integrity]", 1)[0] + "\n",
        encoding="utf-8",
    )
    snapshot_hash = sha256_file(suite_snapshot)
    engagement = json.loads(engagement_path.read_text(encoding="utf-8"))
    engagement["suite"]["suite_config_sha256"] = snapshot_hash
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["suite"]["suite_config_sha256"] = snapshot_hash
    manifest["engagement"]["sha256"] = sha256_file(engagement_path)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    summary["suite"] = manifest["suite"]
    (run / "summary.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    approval["engagement_sha256"] = sha256_file(engagement_path)
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="closed reference set|passed calibration evidence"):
        verified_public_release(run, engagement_path, approval_path, now=NOW)


def test_public_release_rejects_mutated_suite_governance_blob(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    blob = next((run / "suite_evidence").iterdir())
    blob.write_bytes(blob.read_bytes() + b"tampered")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="suite governance evidence blob differs"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_reconstructs_target_payload_from_dataset_snapshot(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    requests = [json.loads(line) for line in (run / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
    requests[0]["payload"]["message"] = "Mutated question"
    _write_jsonl(run / "requests.jsonl", requests)
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="target payload differs from the canonical dataset"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_reconstructs_judge_payload_from_rubric_snapshot(tmp_path: Path) -> None:
    run, engagement_path, approval_path, approval = _release_fixture(tmp_path)
    snapshot = run / "rubric_snapshot.md"
    snapshot.write_text(snapshot.read_text(encoding="utf-8") + "\nAdditional criterion.", encoding="utf-8")
    rubric_hash = sha256_file(snapshot)
    engagement = json.loads(engagement_path.read_text(encoding="utf-8"))
    engagement["suite"]["rubric_sha256"] = rubric_hash
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["suite"]["rubric_sha256"] = rubric_hash
    manifest["judge"]["prompt_sha256"] = sha256_bytes(
        _judge_system_prompt(Suite(run, {}, (), snapshot.read_text(encoding="utf-8"), snapshot, snapshot)).encode()
    )
    manifest["engagement"]["sha256"] = sha256_file(engagement_path)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    summary["suite"] = manifest["suite"]
    (run / "summary.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    approval["engagement_sha256"] = sha256_file(engagement_path)
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="judge payload differs from the canonical case, rubric"):
        verified_public_release(run, engagement_path, approval_path, now=NOW)


def test_public_release_rejects_target_identity_in_judge_payload(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    requests = [json.loads(line) for line in (run / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
    requests[1]["payload"]["target_identity"] = "target-model"
    _write_jsonl(run / "requests.jsonl", requests)
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="judge payload exposes target identity"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_rejects_target_label_in_judge_payload(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    target_label = "private-target-label"
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["target"]["label"] = target_label
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    summary["target"]["label"] = target_label
    (run / "summary.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    requests = [json.loads(line) for line in (run / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
    requests[1]["payload"]["target_identity"] = target_label
    _write_jsonl(run / "requests.jsonl", requests)
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="judge payload exposes target identity"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_recomputes_hard_deterministic_checks(tmp_path: Path) -> None:
    run, engagement_path, approval_path, approval = _release_fixture(tmp_path)
    cases = [json.loads(line) for line in (run / "dataset_snapshot.jsonl").read_text(encoding="utf-8").splitlines()]
    cases[0]["forbidden_terms"] = ["answer"]
    _write_jsonl(run / "dataset_snapshot.jsonl", cases)
    dataset_hash = sha256_file(run / "dataset_snapshot.jsonl")
    engagement = json.loads(engagement_path.read_text(encoding="utf-8"))
    engagement["suite"]["dataset_sha256"] = dataset_hash
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["suite"]["dataset_sha256"] = dataset_hash
    manifest["engagement"]["sha256"] = sha256_file(engagement_path)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    summary["suite"] = manifest["suite"]
    (run / "summary.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    approval["engagement_sha256"] = sha256_file(engagement_path)
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="failed hard deterministic checks"):
        verified_public_release(run, engagement_path, approval_path, now=NOW)


@pytest.mark.parametrize(("field", "value"), [("category", "other"), ("severity", "critical")])
def test_public_release_binds_case_projection_to_the_dataset(tmp_path: Path, field: str, value: str) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    result = json.loads((run / "case_results.jsonl").read_text(encoding="utf-8"))
    result[field] = value
    _write_jsonl(run / "case_results.jsonl", [result])
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="case projection differs from the canonical dataset"):
        verified_public_release(run, engagement, approval_path, now=NOW)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("score", 0.0, "score or agreement differs"),
        ("judge_agreement", 0.1, "score or agreement differs"),
        ("target_latency_ms", 999_999.0, "telemetry or usage differs"),
        ("duration_ms", 888_888.0, "duration or status differs"),
    ],
)
def test_public_release_binds_derived_results_to_raw_evidence(
    tmp_path: Path,
    field: str,
    value: float,
    message: str,
) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    result = json.loads((run / "case_results.jsonl").read_text(encoding="utf-8"))
    result[field] = value
    _write_jsonl(run / "case_results.jsonl", [result])
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match=message):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_derives_analysis_unit_from_the_dataset(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    result = json.loads((run / "case_results.jsonl").read_text(encoding="utf-8"))
    _write_jsonl(run / "scenario_results.jsonl", [{**result, "case_id": "invented", "scenario_id": "invented"}])
    metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
    metrics["analysis_unit"] = "scenario"
    metrics["case_level"], metrics["case_categories"] = summarize([result])
    (run / "metrics.json").write_text(json.dumps(metrics, sort_keys=True), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["metrics"] = metrics
    manifest["artifacts"]["scenario_results.jsonl"] = sha256_file(run / "scenario_results.jsonl")
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    summary["metrics"] = metrics
    (run / "summary.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="analysis unit differs from the canonical dataset"):
        verified_public_release(run, engagement, approval_path, now=NOW)


@pytest.mark.parametrize("field", ["official_min_repetitions", "official_min_judge_repetitions"])
def test_public_release_enforces_immutable_suite_repetition_minimums(tmp_path: Path, field: str) -> None:
    run, engagement_path, approval_path, approval = _release_fixture(tmp_path)
    snapshot = run / "suite_snapshot.toml"
    snapshot.write_text(snapshot.read_text(encoding="utf-8").replace("\n[[gates]]", f"\n{field} = 2\n\n[[gates]]"), encoding="utf-8")
    snapshot_hash = sha256_file(snapshot)
    engagement = json.loads(engagement_path.read_text(encoding="utf-8"))
    engagement["suite"]["suite_config_sha256"] = snapshot_hash
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["suite"]["suite_config_sha256"] = snapshot_hash
    manifest["engagement"]["sha256"] = sha256_file(engagement_path)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    summary["suite"] = manifest["suite"]
    (run / "summary.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    approval["engagement_sha256"] = sha256_file(engagement_path)
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="below the immutable suite minimum"):
        verified_public_release(run, engagement_path, approval_path, now=NOW)


def test_public_release_rejects_unconfigured_engine_evidence(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    result = json.loads((run / "case_results.jsonl").read_text(encoding="utf-8"))
    identity_fields = (
        "case_id",
        "category",
        "risk_domain",
        "severity",
        "language",
        "locale",
        "split",
        "operating_condition",
        "distribution_shift_reference_id",
        "scenario_id",
        "case_review_status",
        "performance_phase",
        "repetition",
    )
    _write_jsonl(run / "engine_results.jsonl", [{**{field: result.get(field) for field in identity_fields}, "results": []}])
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="engine result ledger does not exactly match"):
        verified_public_release(run, engagement, approval_path, now=NOW)


@pytest.mark.parametrize("mutation", ["missing", "expired", "wrong-host"])
def test_nonpublic_external_release_requires_exact_current_authorization(tmp_path: Path, mutation: str) -> None:
    run, engagement, approval_path, approval = _nonpublic_external_fixture(tmp_path)
    assert verified_public_release(run, engagement, approval_path, now=NOW)["release_id"] == "release-1"
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    if mutation == "missing":
        manifest["external_authorization"] = None
        manifest["external_judge_authorized"] = False
        message = "non-public external endpoints require"
    elif mutation == "expired":
        manifest["external_authorization"]["expires_at"] = "2026-08-05T11:15:00Z"
        message = "external authorization is expired"
    else:
        manifest["external_authorization"]["destinations"][0]["host"] = "wrong.example"
        message = "host set differs"
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match=message):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_public_release_recomputes_gates_from_hashed_suite_snapshot(tmp_path: Path) -> None:
    run, engagement_path, approval_path, approval = _release_fixture(tmp_path)
    snapshot = run / "suite_snapshot.toml"
    snapshot.write_text(snapshot.read_text(encoding="utf-8").replace("min = 0.2", "min = 0.3"), encoding="utf-8")
    snapshot_hash = sha256_file(snapshot)
    engagement = json.loads(engagement_path.read_text(encoding="utf-8"))
    engagement["suite"]["suite_config_sha256"] = snapshot_hash
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["suite"]["suite_config_sha256"] = snapshot_hash
    manifest["engagement"]["sha256"] = sha256_file(engagement_path)
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    approval["engagement_sha256"] = sha256_file(engagement_path)
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match="gate results do not reconcile"):
        verified_public_release(run, engagement_path, approval_path, now=NOW)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("pass_rate_bootstrap_ci", "lower"), 0.123, "bootstrap metrics"),
        (("slices", "risk_domain", "quality", "pass_rate"), 0.123, "slice metrics"),
        (("stability", "stable_case_fraction"), 0.123, "stability metrics"),
        (("performance", "target_latency_ms", "mean"), 0.123, "performance metrics"),
        (("budgets", "target_calls"), 99, "budget metrics"),
        (("judge_calibration",), {"forged": {"accuracy": 1.0}}, "cannot claim judge calibration"),
    ],
)
def test_public_release_rejects_forged_derived_metric_groups(
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
    target = metrics
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] = value
    (run / "metrics.json").write_text(json.dumps(metrics, sort_keys=True), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["metrics"] = metrics
    (run / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    summary["metrics"] = metrics
    (run / "summary.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    _reseal_forged_run(run, approval_path, approval)

    with pytest.raises(ProtocolError, match=message):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_export_rejects_destination_inside_immutable_run_before_writing(tmp_path: Path) -> None:
    run, engagement, approval, _ = _release_fixture(tmp_path)
    output = run / "export.tar.gz"

    with pytest.raises(ProtocolError, match="outside the immutable run directory"):
        _export(run, output, True, engagement=str(engagement), release_approval=str(approval))

    assert not output.exists()


def test_public_release_rejects_self_approval_and_expired_evidence(tmp_path: Path) -> None:
    run, engagement, approval_path, approval = _release_fixture(tmp_path)
    decisions = approval["decisions"]
    assert isinstance(decisions, dict)
    decisions["release"]["reviewer_id"] = "technical-reviewer"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    with pytest.raises(ProtocolError, match="release decision maker must be distinct"):
        verified_public_release(run, engagement, approval_path, now=NOW)

    decisions["release"]["reviewer_id"] = "release-reviewer"
    approval["expires_at"] = "2026-08-05T11:45:00Z"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    with pytest.raises(ProtocolError, match="timing is invalid"):
        verified_public_release(run, engagement, approval_path, now=NOW)


def test_release_rejects_tampered_reviewer_evidence(tmp_path: Path) -> None:
    run, engagement, approval, _ = _release_fixture(tmp_path)
    (tmp_path / "review-evidence.txt").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="review evidence hash mismatch"):
        verified_public_release(run, engagement, approval, now=NOW)


def test_public_export_rejects_endpoint_or_key_environment_leaks(tmp_path: Path) -> None:
    run, engagement, approval, _ = _release_fixture(tmp_path, public_report="<p>TARGET_API_KEY</p>")
    output = tmp_path / "must-not-exist.tar.gz"

    with pytest.raises(ProtocolError, match="public export contains restricted evidence"):
        _export(run, output, True, engagement=str(engagement), release_approval=str(approval))

    assert not output.exists()


def test_official_execution_requires_engagement_before_network_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = _suite(tmp_path / "suite")
    monkeypatch.setattr("cavada_eval.runner.require_matching_source_checkout", lambda *_args: None)
    monkeypatch.setattr("cavada_eval.runner.load_suite", lambda *_args, **_kwargs: suite)
    with pytest.raises(ProtocolError, match="approved engagement governance record"):
        run(
            suite,
            repo_root=tmp_path,
            endpoint="http://127.0.0.1:1/target",
            model_label="target",
            expected_model="target-model",
            model_revision="a" * 40,
            request_model=None,
            judge_endpoint="http://127.0.0.1:1/v1",
            judge_model="judge",
            expected_judge_model="judge",
            judge_revision="b" * 40,
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=1,
            official=True,
            allow_external_judge=False,
        )
