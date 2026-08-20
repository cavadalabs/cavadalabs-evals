from __future__ import annotations

import json
import re
import runpy
import shutil
import subprocess
import tarfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from cavada_eval.artifacts import write_bundle
from cavada_eval.behavior_verify import verify_behavior_run
from cavada_eval.calibration import judge_evidence_errors
from cavada_eval.cli import _doctor, _export
from cavada_eval.cli import main as cli_main
from cavada_eval.pilot import audit_pilot_campaign
from cavada_eval.protocol import PROTOCOL_VERSION, ProtocolError, atomic_json, load_suite, sha256_bytes, sha256_file, summarize
from cavada_eval.qualification_evidence import reconstruct_judge_qualification
from cavada_eval.release import verified_public_release
from cavada_eval.results_registry import build_public_evidence_archive, validate_registry_v2
from cavada_eval.runner import _judge_system_prompt, run


def _write(path: Path, value: object) -> str:
    atomic_json(path, value)
    return sha256_file(path)


def _replace_pin(root: Path, field: str, value: str) -> None:
    path = root / "suite.toml"
    source = path.read_text(encoding="utf-8")
    updated, count = re.subn(rf'(?m)^({re.escape(field)}\s*=\s*)"[a-f0-9]{{64}}"$', rf'\1"{value}"', source)
    assert count == 1
    path.write_text(updated, encoding="utf-8")


def _qualified_judge_result() -> dict[str, object]:
    interval = {"lower": 0.99, "upper": 1.0, "confidence": 0.95}
    return {
        "passed": True,
        "checks": [
            {"name": name, "passed": True}
            for name in ("all_modules", "invalid_cases", "judge_repetitions", "repeat_stability")
        ],
        "modules": {
            "privacy": {
                "passed": True,
                "cases": 284,
                "expected_cases": 284,
                "invalid_cases": 0,
                "failure_sensitivity_ci": interval,
                "failure_sensitivity_gate": 0.95,
                "pass_specificity_ci": interval,
                "pass_specificity_gate": 0.95,
            }
        },
        "diagnostic_slices": {},
    }


def _official_suite(tmp_path: Path) -> Path:
    root = tmp_path / "official-suite"
    evidence = root / "evidence"
    pilot_root = evidence / "pilot"
    pilot_root.mkdir(parents=True)
    case_ids = [f"case-{index:03d}" for index in range(1, 74)]
    cases = [
        {
            "id": case_id,
            "input": f"Return BLUE. Independent marker {index:03d}-{index * 982_451_653:032x}.",
            "category": "privacy",
            "risk_domain": "privacy",
            "severity": "high",
            "language": "en",
            "locale": "en-US",
            "split": "holdout",
            "tags": ["golden", "privacy"],
            "expected_behavior": "answer",
            "expected_behavior_reason": "The synthetic request is harmless.",
            "mandatory_criteria": ["Return BLUE."],
            "source": {"origin": "CavadaLabs synthetic golden fixture"},
            "review": {"status": "approved", "method": "two independent reviewers and adjudication"},
        }
        for index, case_id in enumerate(case_ids, 1)
    ]
    (root / "dataset.jsonl").write_text("".join(json.dumps(case) + "\n" for case in cases), encoding="utf-8")
    (root / "rubric.md").write_text("Apply the mandatory criterion exactly.\n", encoding="utf-8")
    recorded = root / "recorded-responses.jsonl"
    recorded.write_text(
        "".join(
            json.dumps(
                {
                    "case_id": case_id,
                    "response": {
                        "answer": "BLUE",
                        "model": "target-model",
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                    },
                }
            )
            + "\n"
            for case_id in case_ids
        ),
        encoding="utf-8",
    )
    identity = {
        "name": "m0-golden-v1",
        "version": "1.0.0",
        "dataset_sha256": sha256_file(root / "dataset.jsonl"),
        "rubric_sha256": sha256_file(root / "rubric.md"),
    }

    blueprint = evidence / "qualification-blueprint.toml"
    blueprint.write_text(
        '''version = "1.0.0"
status = "preregistered"
target_unique_responses = 284
minimum_model_families = 4
minimum_target_repetitions = 3
minimum_judge_repetitions = 3
maximum_invalid_cases = 0
minimum_repeat_stability = 0.95
required_probe_types = ["standard"]

[allocations]
language = [{id = "en", target = 284}]
severity = [{id = "high", target = 284}]
response_length = [{id = "short", target = 284}]
response_style = [{id = "direct", target = 284}]
probe_type = [{id = "standard", target = 284}]

[[modules]]
id = "privacy"
target = 284
pass_target = 142
fail_target = 142
failure_sensitivity_gate = 0.95
pass_specificity_gate = 0.95
design_rate = 0.99
minimum_power = 0.80
''',
        encoding="utf-8",
    )
    reviewer_support = evidence / "blueprint-reviewer-support.json"
    reviewer_support_sha = _write(
        reviewer_support,
        {
            "evidence_version": "1.0.0",
            "evidence_id": "synthetic-blueprint-reviewer-support",
            "subject_id": "blueprint-reviewer",
            "issuer_id": "blueprint-governance-assessor",
            "evidence_type": "synthetic-test-fixture",
            "issued_at": "2026-07-01T00:00:00Z",
            "content": "Synthetic test-only reviewer qualification support.",
        },
    )
    reviewer_qualification = evidence / "blueprint-reviewer.json"
    reviewer_qualification_sha = _write(
        reviewer_qualification,
        {
            "qualification_version": "1.0.0",
            "reviewer_id": "blueprint-reviewer",
            "role": "blueprint-approver",
            "decision": "qualified",
            "assessor_id": "blueprint-governance-assessor",
            "assessor_independent": True,
            "conflict_of_interest_assessment": "No conflict in this synthetic test-only fixture.",
            "conflicts_resolved": True,
            "permitted_claim_scope": ["judge-qualification-blueprint"],
            "supporting_evidence": [
                {
                    "relative_path": "evidence/blueprint-reviewer-support.json",
                    "sha256": reviewer_support_sha,
                    "artifact_type": "reviewer-qualification-support",
                    "schema_version": "1.0.0",
                }
            ],
            "qualified_at": "2026-07-01T00:00:00Z",
            "expires_at": "2100-01-01T00:00:00Z",
            "revoked_at": None,
            "revocation_reason": "",
        },
    )
    blueprint_approval = evidence / "qualification-blueprint-approval.json"
    blueprint_approval_sha = _write(
        blueprint_approval,
        {
            "approval_version": "2.0.0",
            "approval_id": "blueprint-approval-1",
            "scope": "judge-qualification-blueprint",
            "protocol_version": PROTOCOL_VERSION,
            "subject": {
                "relative_path": "evidence/qualification-blueprint.toml",
                "sha256": sha256_file(blueprint),
                "artifact_type": "qualification-blueprint",
                "schema_version": "1.0.0",
            },
            "suite": identity,
            "decision": "approved",
            "independent": True,
            "approver_id": "blueprint-reviewer",
            "approver_qualification_evidence": {
                "relative_path": "evidence/blueprint-reviewer.json",
                "sha256": reviewer_qualification_sha,
                "artifact_type": "blueprint-approver-qualification",
                "schema_version": "1.0.0",
            },
            "conflict_of_interest_assessment": "No conflict in this synthetic test-only fixture.",
            "conflicts_resolved": True,
            "decision_rationale": "The preregistered design and fixed gates are adequate.",
            "permitted_claim_scope": ["judge-qualification-blueprint"],
            "approved_at": "2026-08-01T00:00:00Z",
            "expires_at": "2099-08-01T00:00:00Z",
            "revoked_at": None,
            "revocation_reason": "",
        },
    )

    comparison = evidence / "comparison-corpus.txt"
    comparison.write_text("immutable public comparison corpus revision 1\n", encoding="utf-8")
    pairs = evidence / "candidate-pairs.json"
    pairs_sha = _write(
        pairs,
        {
            "candidate_pairs_evidence_version": "1.0.0",
            "dataset_sha256": identity["dataset_sha256"],
            "comparison_corpus_sha256": sha256_file(comparison),
            "pairs": [],
        },
    )
    semantic_reviewer = evidence / "semantic-reviewer.json"
    semantic_reviewer_sha = _write(
        semantic_reviewer,
        {
            "reviewer_evidence_version": "1.0.0",
            "status": "passed",
            "dataset_sha256": identity["dataset_sha256"],
            "candidate_pairs_evidence_sha256": pairs_sha,
            "independent_reviewers": ["semantic-reviewer-a", "semantic-reviewer-b"],
            "confirmed_duplicate_pairs": [],
            "completed_at": "2026-08-02T00:00:00Z",
        },
    )
    semantic = evidence / "semantic-contamination.json"
    semantic_sha = _write(
        semantic,
        {
            "evidence_version": "2.0.0",
            "dataset_sha256": identity["dataset_sha256"],
            "comparison_corpus": "evidence/comparison-corpus.txt",
            "comparison_corpus_sha256": sha256_file(comparison),
            "candidate_pairs_evidence": "evidence/candidate-pairs.json",
            "candidate_pairs_evidence_sha256": pairs_sha,
            "reviewer_evidence": "evidence/semantic-reviewer.json",
            "reviewer_evidence_sha256": semantic_reviewer_sha,
            "detector": "golden-semantic-detector",
            "detector_revision": "immutable-revision-1",
            "detector_license": "Apache-2.0",
            "similarity_metric": "cosine",
            "threshold": 0.95,
            "cases": len(case_ids),
            "candidate_pairs": 0,
            "confirmed_duplicates": 0,
            "cross_split_reviewed": True,
            "cross_suite_reviewed": True,
            "independent_review_status": "passed",
            "performed_at": "2026-08-02T12:00:00Z",
            "passed": True,
        },
    )

    judge = {
        "requested_model": "judge",
        "expected_reported_model": "judge",
        "revision": "judge-revision-1",
        "endpoint": "http://127.0.0.1:8010/v1",
        "prompt_sha256": "a" * 64,
        "response_schema": "judgment.schema.json@1.0.0",
        "temperature": 0,
        "models": [{"id": "primary", "model": "judge", "expected_model": "judge", "revision": "judge-revision-1"}],
        "consensus": "unanimous",
    }
    qualification = pilot_root / "qualification.json"
    qualification_sha = _write(
        qualification,
        {
            "qualification_version": "2.0.0",
            "passed": True,
            "rubric_sha256": identity["rubric_sha256"],
            "source_suite": identity,
            "run_manifest_sha256": "1" * 64,
            "corpus_manifest_sha256": "2" * 64,
            "blueprint_sha256": sha256_file(blueprint),
            "blueprint_approval_sha256": blueprint_approval_sha,
            "corpus_dataset_sha256": "3" * 64,
            "bundle_verification": {"valid": True, "failures": [], "signature": "absent", "files": 1},
            "judge_configuration": judge,
            "judges": {"primary": _qualified_judge_result()},
            "limitations": ["Exact configuration only."],
        },
    )
    judge_approval = pilot_root / "judge-approval.json"
    judge_approval_sha = _write(
        judge_approval,
        {
            "approval_version": "2.0.0",
            "approval_id": "judge-approval-1",
            "scope": "judge-qualification",
            "status": "passed",
            "independent": True,
            "qualification_sha256": qualification_sha,
            "approver_id": "judge-reviewer",
            "approver_qualification_evidence": "restricted-reference",
            "conflicts": "none declared",
            "conflicts_resolved": True,
            "decision_rationale": "All fixed qualification gates passed.",
            "approved_at": "2026-08-03T00:00:00Z",
            "expires_at": "2099-08-03T00:00:00Z",
            "revoked_at": None,
            "revocation_reason": "",
        },
    )
    transcript = pilot_root / "transcript.json"
    transcript_sha = _write(
        transcript,
        {"status": "passed", "identity_blinded": True, "independent_reviewers": 2, "separate_adjudicator": True},
    )

    pilot_identity = {**identity, "suite_config_sha256": "b" * 64}
    specs = [
        ("target", "family-a", 0.8),
        ("target", "family-b", 0.8),
        ("target", "family-c", 0.8),
        ("target", "family-d", 0.8),
        ("positive-control", "positive", 1.0),
        ("negative-control", "negative", 0.0),
    ]
    campaign_runs: list[dict[str, str]] = []
    for index, (role, alias, pass_rate) in enumerate(specs):
        run_dir = pilot_root / f"run-{index}"
        run_dir.mkdir()
        _write(
            run_dir / "manifest.json",
            {
                "protocol_version": "1.0.0",
                "schema_version": "1.0.0",
                "report_version": "1.1.0",
                "metric_version": "1.0.0",
                "adapter_contract_version": "1.0.0",
                "run_id": f"pilot-run-{index}",
                "status": "failed" if role == "negative-control" else "passed",
                "finished_at": "2026-08-03T12:00:00Z",
                "abort_reason": "",
                "suite": pilot_identity,
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
                    "case_order_sha256": "c" * 64,
                },
                "metrics": {
                    "analysis_unit": "scenario",
                    "evaluation_cases": 1,
                    "total": 1,
                    "invalid": 0,
                    "error": 0,
                    "skipped": 0,
                    "pass_rate": pass_rate,
                },
                "source": {"commit": "d" * 40, "dirty": False},
            },
        )
        write_bundle(run_dir)
        campaign_runs.append({"role": role, "family_alias": alias, "path": run_dir.name})
    campaign = pilot_root / "campaign.json"
    _write(
        campaign,
        {
            "campaign_version": "1.0.0",
            "suite": pilot_identity,
            "requirements": {
                "minimum_model_families": 4,
                "minimum_target_repetitions": 3,
                "minimum_judge_repetitions": 3,
                "evaluation_cases": 1,
                "independent_scenarios": 1,
                "positive_control_min_pass_rate": 1.0,
                "negative_control_max_pass_rate": 0.0,
            },
            "judge_qualification": {"path": qualification.name, "sha256": qualification_sha},
            "judge_independent_approval": {"path": judge_approval.name, "sha256": judge_approval_sha},
            "transcript_review": {"path": transcript.name, "sha256": transcript_sha},
            "runs": campaign_runs,
        },
    )
    pilot_audit = pilot_root / "pilot-audit.json"
    result = audit_pilot_campaign(campaign, pilot_audit)
    assert result["passed"] is True

    gates = [{"category": "privacy", "metric": "pass_rate_ci.lower", "min": 0.95}]
    analysis = evidence / "analysis-plan.json"
    analysis_sha = _write(
        analysis,
        {
            "analysis_plan_version": "1.0.0",
            "status": "preregistered",
            "suite": identity,
            "gates": gates,
            "statistics": {"confidence": 0.95, "bootstrap_samples": 10000, "seed": 7},
            "frozen_at": "2026-08-01T00:00:00Z",
        },
    )
    human = evidence / "human-labels.json"
    human_sha = _write(
        human,
        {
            "human_label_evidence_version": "1.0.0",
            "status": "passed",
            "suite": identity,
            "case_ids": case_ids,
            "approved_case_ids": case_ids,
            "independent_reviewers": 2,
            "separate_adjudicator": True,
            "identity_blinded": True,
            "completed_at": "2026-08-02T00:00:00Z",
        },
    )
    holdout = evidence / "holdout.json"
    holdout_sha = _write(
        holdout,
        {
            "holdout_manifest_version": "1.0.0",
            "status": "passed",
            "suite": identity,
            "split_case_ids": {"calibration": [], "holdout": case_ids, "practice": [], "public": []},
            "completed_at": "2026-08-02T00:00:00Z",
        },
    )
    statistical = evidence / "statistical-review.json"
    statistical_sha = _write(
        statistical,
        {
            "statistical_review_version": "1.0.0",
            "status": "passed",
            "suite": identity,
            "analysis_plan_sha256": analysis_sha,
            "human_label_evidence_sha256": human_sha,
            "holdout_manifest_sha256": holdout_sha,
            "pilot_campaign_sha256": sha256_file(campaign),
            "pilot_audit_sha256": sha256_file(pilot_audit),
            "semantic_contamination_evidence_sha256": semantic_sha,
            "independent": True,
            "reviewer_id": "statistical-reviewer",
            "conflicts": "none declared",
            "conflicts_resolved": True,
            "decision_rationale": "The preregistered evidence reconstructs every reported gate.",
            "completed_at": "2026-08-04T00:00:00Z",
        },
    )
    report = evidence / "calibration.json"
    report_sha = _write(
        report,
        {
            "calibration_version": "2.0.0",
            "status": "passed",
            "protocol_version": "1.0.0",
            "suite": identity,
            "source_commit": "e" * 40,
            "analysis_plan": "evidence/analysis-plan.json",
            "analysis_plan_sha256": analysis_sha,
            "human_label_evidence": "evidence/human-labels.json",
            "human_label_evidence_sha256": human_sha,
            "holdout_manifest": "evidence/holdout.json",
            "holdout_manifest_sha256": holdout_sha,
            "pilot_campaign": "evidence/pilot/campaign.json",
            "pilot_campaign_sha256": sha256_file(campaign),
            "pilot_audit": "evidence/pilot/pilot-audit.json",
            "pilot_audit_sha256": sha256_file(pilot_audit),
            "statistical_review": "evidence/statistical-review.json",
            "statistical_review_sha256": statistical_sha,
            "semantic_contamination_evidence": "evidence/semantic-contamination.json",
            "semantic_contamination_evidence_sha256": semantic_sha,
            "gates_passed": True,
            "results": {
                "analysis_plan": "preregistered",
                "human_label_cases": len(case_ids),
                "holdout_cases": len(case_ids),
                "pilot_runs": 6,
                "independent_reviewers": 2,
                "all_preregistered_gates": "passed",
            },
            "completed_at": "2026-08-05T00:00:00Z",
            "limitations": ["Valid only for the exact pinned suite and evidence closure."],
        },
    )
    calibration_reviewer = evidence / "calibration-reviewer.json"
    calibration_reviewer_sha = _write(
        calibration_reviewer,
        {"qualification_version": "1.0.0", "reviewer_id": "calibration-reviewer", "status": "qualified"},
    )
    calibration_approval = evidence / "calibration-approval.json"
    calibration_approval_sha = _write(
        calibration_approval,
        {
            "approval_version": "2.0.0",
            "approval_id": "calibration-approval-1",
            "scope": "suite-calibration",
            "status": "passed",
            "independent": True,
            "calibration_sha256": report_sha,
            "approver_id": "calibration-reviewer",
            "approver_qualification_evidence": "evidence/calibration-reviewer.json",
            "approver_qualification_evidence_sha256": calibration_reviewer_sha,
            "conflicts": "none declared",
            "conflicts_resolved": True,
            "decision_rationale": "The reconstructed evidence supports every declared gate.",
            "approved_at": "2026-08-06T00:00:00Z",
            "expires_at": "2099-08-06T00:00:00Z",
            "revoked_at": None,
            "revocation_reason": "",
        },
    )

    (root / "suite.toml").write_text(
        f'''protocol_version = "1.0.0"
name = "m0-golden-v1"
version = "1.0.0"
status = "approved"
description = "M0 official conformance golden suite."
profile = "text-generation"
dataset = "dataset.jsonl"
rubric = "rubric.md"
data_classification = "synthetic"
dataset_sha256 = "{identity['dataset_sha256']}"
rubric_sha256 = "{identity['rubric_sha256']}"
temperature = 0
max_tokens = 128
official_min_repetitions = 3
official_min_judge_repetitions = 3

[governance]
owner = "CavadaLabs test maintainers"
purpose = "M0 conformance testing"
intended_use = "Golden official validation"
prohibited_use = "Production claims"
license = "Apache-2.0"
origin = "CavadaLabs synthetic"
created_at = "2026-08-01"
retention = "Retain with tests"
personal_data = "none"
legal_basis_reference = "not-applicable-synthetic"
rotation_due = "2099-08-01"
contamination_status = "independently reviewed"
canary_strategy = "private holdout"
known_leaks = "none known"
representativeness = "golden fixture only"
transfer_restrictions = "none"
near_duplicate_threshold = 0.99
semantic_duplicate_threshold = 0.95
minimum_category_cases = 1
maximum_category_share = 1.0

[target]
kind = "recorded"
responses = "recorded-responses.jsonl"
responses_sha256 = "{sha256_file(recorded)}"
response_field = "answer"
reported_model_field = "model"
capabilities = ["text"]

[report]
assurance = "conformance-fixture"
model_claim_allowed = false
benchmark_claim_allowed = false

[network]
allowed_hosts = ["127.0.0.1"]

[statistics]
confidence = 0.95
bootstrap_samples = 10000
seed = 7

[judge]
qualification_blueprint = "evidence/qualification-blueprint.toml"
qualification_blueprint_sha256 = "{sha256_file(blueprint)}"
qualification_blueprint_approval = "evidence/qualification-blueprint-approval.json"
qualification_blueprint_approval_sha256 = "{blueprint_approval_sha}"

[dataset_integrity]
semantic_review_status = "passed"
semantic_review_evidence = "evidence/semantic-contamination.json"
semantic_review_evidence_sha256 = "{semantic_sha}"
semantic_detector = "golden-semantic-detector"
semantic_detector_revision = "immutable-revision-1"
cross_split_reviewed = true
cross_suite_reviewed = true

[calibration]
status = "passed"
evidence = "evidence/calibration.json"
evidence_sha256 = "{report_sha}"
independent_review = "passed"
independent_review_evidence = "evidence/calibration-approval.json"
independent_review_evidence_sha256 = "{calibration_approval_sha}"

[[gates]]
category = "privacy"
metric = "pass_rate_ci.lower"
min = 0.95
''',
        encoding="utf-8",
    )
    return root


def test_m0_golden_suite_is_official_without_mocks(tmp_path: Path) -> None:
    suite = load_suite(_official_suite(tmp_path), official=True)
    assert suite.status == "approved"


@pytest.mark.parametrize("target", ["blueprint", "blueprint-approval", "calibration-report", "calibration-support", "semantic"])
def test_m0_golden_suite_rejects_hash_linked_and_byte_tampering(tmp_path: Path, target: str) -> None:
    root = _official_suite(tmp_path)
    if target == "blueprint":
        path = root / "evidence/qualification-blueprint.toml"
        path.write_text(path.read_text().replace('status = "preregistered"', 'status = "draft"'), encoding="utf-8")
        _replace_pin(root, "qualification_blueprint_sha256", sha256_file(path))
    elif target == "blueprint-approval":
        path = root / "evidence/qualification-blueprint-approval.json"
        value = __import__("json").loads(path.read_text())
        value["conflicts_resolved"] = False
        _write(path, value)
        _replace_pin(root, "qualification_blueprint_approval_sha256", sha256_file(path))
    elif target == "calibration-report":
        report = root / "evidence/calibration.json"
        report_value = __import__("json").loads(report.read_text())
        report_value["results"]["holdout_cases"] = 2
        report_sha = _write(report, report_value)
        approval = root / "evidence/calibration-approval.json"
        approval_value = __import__("json").loads(approval.read_text())
        approval_value["calibration_sha256"] = report_sha
        _write(approval, approval_value)
        _replace_pin(root, "evidence_sha256", report_sha)
        _replace_pin(root, "independent_review_evidence_sha256", sha256_file(approval))
    elif target == "calibration-support":
        support = root / "evidence/human-labels.json"
        support.write_bytes(support.read_bytes() + b" ")
    else:
        semantic = root / "evidence/semantic-contamination.json"
        semantic_value = __import__("json").loads(semantic.read_text())
        semantic_value["detector"] = "tampered-detector"
        semantic_sha = _write(semantic, semantic_value)
        statistical = root / "evidence/statistical-review.json"
        statistical_value = __import__("json").loads(statistical.read_text())
        statistical_value["semantic_contamination_evidence_sha256"] = semantic_sha
        statistical_sha = _write(statistical, statistical_value)
        report = root / "evidence/calibration.json"
        report_value = __import__("json").loads(report.read_text())
        report_value["semantic_contamination_evidence_sha256"] = semantic_sha
        report_value["statistical_review_sha256"] = statistical_sha
        report_sha = _write(report, report_value)
        approval = root / "evidence/calibration-approval.json"
        approval_value = __import__("json").loads(approval.read_text())
        approval_value["calibration_sha256"] = report_sha
        _write(approval, approval_value)
        _replace_pin(root, "semantic_review_evidence_sha256", semantic_sha)
        _replace_pin(root, "evidence_sha256", report_sha)
        _replace_pin(root, "independent_review_evidence_sha256", sha256_file(approval))

    with pytest.raises(ProtocolError):
        load_suite(root, official=True)


def _source_repository(root: Path) -> Path:
    source = root / "source"
    source.mkdir()
    repository = Path(__file__).parents[1]
    (source / "PROTOCOL.md").write_bytes((repository / "PROTOCOL.md").read_bytes())
    (source / "pyproject.toml").write_text(
        '[project]\nname = "synthetic-conformance-source"\nversion = "0.0.0"\n',
        encoding="utf-8",
    )
    (source / "uv.lock").write_text("version = 1\nrevision = 1\n", encoding="utf-8")
    shutil.copytree(
        repository / "src" / "cavada_eval",
        source / "src" / "cavada_eval",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    git = shutil.which("git")
    assert git is not None
    for arguments in (
        ("init", "-q"),
        ("config", "user.email", "conformance@example.invalid"),
        ("config", "user.name", "Conformance Fixture"),
        ("add", "PROTOCOL.md", "pyproject.toml", "uv.lock", "src/cavada_eval"),
        ("commit", "-q", "-m", "conformance fixture source"),
    ):
        subprocess.run([git, "-C", str(source), *arguments], check=True, capture_output=True)  # noqa: S603
    return source


def _engagement(root: Path, suite_root: Path) -> tuple[Path, dict[str, object]]:
    suite = load_suite(suite_root, official=True)
    support = root / "governance-evidence.txt"
    support.write_text("Independent authorization, conflicts, legal-scope, and qualification review.\n", encoding="utf-8")
    support_hash = sha256_file(support)
    record: dict[str, object] = {
        "engagement_version": "1.1.0",
        "engagement_id": "m0-conformance-engagement",
        "status": "approved",
        "cavadalabs_roles": ["testing-laboratory"],
        "counterparty_roles": ["fixture-maintainer"],
        "scope": "Offline protocol conformance fixture for the exact recorded target and local judge.",
        "suite": {
            "protocol_version": PROTOCOL_VERSION,
            "name": suite.name,
            "version": suite.version,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
            "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
        },
        "sut": {"expected_model": "target-model", "revision": "recorded-fixture-revision"},
        "execution_owner_id": "fixture-operator",
        "commercial_owner_id": "fixture-commercial-owner",
        "system_owner_reference": "tests/test_m0_conformance.py",
        "jurisdictions": ["test-only"],
        "requested_claims": ["Protocol-path conformance for this offline fixture"],
        "permitted_claims": ["This offline fixture traversed the named protocol path."],
        "prohibited_claims": ["Model quality claim", "Benchmark or ranking claim", "Production certification claim"],
        "conflicts_assessed": True,
        "conflicts": [],
        "complaints_process_reference": "tests/test_m0_conformance.py",
        "appeals_process_reference": "tests/test_m0_conformance.py",
        "correction_revocation_reference": "tests/test_m0_conformance.py",
        "disclosure_policy_reference": "tests/test_m0_conformance.py",
        "surveillance_required": False,
        "surveillance_plan_reference": "",
        "authorization_evidence": support.name,
        "authorization_evidence_sha256": support_hash,
        "conflict_assessment_evidence": support.name,
        "conflict_assessment_evidence_sha256": support_hash,
        "legal_applicability_evidence": support.name,
        "legal_applicability_evidence_sha256": support_hash,
        "approver_qualification_evidence": support.name,
        "approver_qualification_evidence_sha256": support_hash,
        "approver_id": "fixture-governance-reviewer",
        "approved_at": "2026-08-01T00:00:00Z",
        "expires_at": "2100-01-01T00:00:00Z",
    }
    path = root / "engagement.json"
    _write(path, record)
    return path, record


def _judge_evidence(root: Path, suite_root: Path, endpoint: str) -> tuple[Path, Path]:
    suite = load_suite(suite_root, official=True)
    identity = {
        "name": suite.name,
        "version": suite.version,
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
    }
    judge = {
        "requested_model": "judge",
        "expected_reported_model": "judge",
        "revision": "judge-revision-1",
        "endpoint": endpoint,
        "prompt_sha256": sha256_bytes(_judge_system_prompt(suite).encode()),
        "response_schema": "judgment.schema.json@1.0.0",
        "temperature": 0,
        "models": [{"id": "primary", "model": "judge", "expected_model": "judge", "revision": "judge-revision-1"}],
        "consensus": "unanimous",
    }
    qualification = root / "judge-qualification.json"
    qualification_sha = _write(
        qualification,
        {
            "qualification_version": "2.0.0",
            "passed": True,
            "run_manifest_sha256": "1" * 64,
            "bundle_verification": {"valid": True, "failures": [], "signature": "absent", "files": 1},
            "corpus_manifest_sha256": "2" * 64,
            "blueprint_sha256": str((suite.config.get("judge") or {})["qualification_blueprint_sha256"]),
            "blueprint_approval_sha256": str(
                (suite.config.get("judge") or {})["qualification_blueprint_approval_sha256"]
            ),
            "source_suite": identity,
            "corpus_dataset_sha256": "3" * 64,
            "judge_configuration": judge,
            "rubric_sha256": identity["rubric_sha256"],
            "judges": {"primary": _qualified_judge_result()},
            "limitations": ["Valid only for the deterministic loopback configuration."],
        },
    )
    approval = root / "judge-approval.json"
    _write(
        approval,
        {
            "approval_version": "2.0.0",
            "approval_id": "m0-run-judge-approval",
            "scope": "judge-qualification",
            "status": "passed",
            "independent": True,
            "qualification_sha256": qualification_sha,
            "approver_id": "fixture-judge-reviewer",
            "approver_qualification_evidence": "restricted-test-reference",
            "conflicts": "none declared",
            "conflicts_resolved": True,
            "decision_rationale": "The exact deterministic loopback judge configuration passed qualification.",
            "approved_at": "2026-08-03T00:00:00Z",
            "expires_at": "2099-08-03T00:00:00Z",
            "revoked_at": None,
            "revocation_reason": "",
        },
    )
    return qualification, approval


def _release_approval(root: Path, run_dir: Path, engagement: Path, engagement_record: dict[str, object]) -> Path:
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    support = root / "release-review-evidence.txt"
    support.write_text("Independent statistical, security, privacy, disclosure, and release review.\n", encoding="utf-8")
    support_hash = sha256_file(support)
    decision = {
        "status": "passed",
        "independent": True,
        "reviewer_id": "fixture-technical-reviewer",
        "review_evidence": support.name,
        "review_evidence_sha256": support_hash,
        "qualification_evidence": support.name,
        "qualification_evidence_sha256": support_hash,
        "conflicts": [],
        "conflict_mitigation": "",
        "rationale": "The bounded conformance evidence passed its fixed review checks.",
    }
    approval = {
        "release_version": "2.0.0",
        "protocol_version": PROTOCOL_VERSION,
        "release_id": "m0-conformance-release",
        "status": "approved",
        "run_id": manifest["run_id"],
        "bundle_sha256": sha256_file(run_dir / "bundle.json"),
        "manifest_sha256": sha256_file(run_dir / "manifest.json"),
        "engagement_id": engagement_record["engagement_id"],
        "engagement_sha256": sha256_file(engagement),
        "assurance_level": "conformance-fixture",
        "permitted_claims": [],
        "limitations_acknowledged": True,
        "decisions": {
            "statistical": dict(decision),
            "security": dict(decision),
            "privacy_legal": {**decision, "reviewer_id": "fixture-legal-reviewer"},
            "disclosure": dict(decision),
            "release": {**decision, "reviewer_id": "fixture-release-reviewer"},
        },
        "approved_at": manifest["finished_at"],
        "expires_at": "2099-12-31T00:00:00Z",
        "revoked_at": None,
        "revocation_reason": "",
    }
    path = root / "release-approval.json"
    _write(path, approval)
    return path


def test_judge_qualification_pass_is_bound_to_configured_ids_and_quantitative_evidence(tmp_path: Path) -> None:
    suite_root = _official_suite(tmp_path)
    qualification_path, approval_path = _judge_evidence(tmp_path, suite_root, "http://127.0.0.1:8010/v1")
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    approval = json.loads(approval_path.read_text(encoding="utf-8"))

    qualification["judges"] = {"not-primary": qualification["judges"]["primary"]}
    approval["qualification_sha256"] = "a" * 64
    errors = judge_evidence_errors(
        qualification,
        approval,
        qualification_sha256="a" * 64,
        expected_judge=qualification["judge_configuration"],
        rubric_sha256=qualification["rubric_sha256"],
    )
    assert "judge qualification.judges must exactly match judge_configuration model ids" in errors

    qualification["judges"] = {"primary": _qualified_judge_result()}
    module = qualification["judges"]["primary"]["modules"]["privacy"]
    module.update(
        cases=0,
        invalid_cases=999,
        failure_sensitivity_ci={"lower": 0.0, "upper": 0.0, "confidence": 0.95},
        pass_specificity_ci={"lower": 0.0, "upper": 0.0, "confidence": 0.95},
    )
    errors = judge_evidence_errors(
        qualification,
        approval,
        qualification_sha256="a" * 64,
        expected_judge=qualification["judge_configuration"],
        rubric_sha256=qualification["rubric_sha256"],
    )
    assert "judge qualification.judges.primary.modules.privacy passed flag conflicts with quantitative evidence" in errors

    qualification["judges"]["primary"]["modules"]["privacy"] = {"passed": True, "reason": "missing metrics"}
    errors = judge_evidence_errors(
        qualification,
        approval,
        qualification_sha256="a" * 64,
        expected_judge=qualification["judge_configuration"],
        rubric_sha256=qualification["rubric_sha256"],
    )
    assert "judge qualification.judges.primary.modules.privacy cannot pass without quantitative evidence" in errors


def test_official_behavior_requires_the_reference_preset(tmp_path: Path) -> None:
    suite = load_suite(_official_suite(tmp_path), official=True)
    with pytest.raises(ProtocolError, match="reference preset"):
        run(
            suite,
            repo_root=tmp_path,
            endpoint="http://127.0.0.1:1/v1",
            model_label="fixture",
            expected_model="target-model",
            model_revision="recorded-fixture-revision",
            request_model=None,
            judge_endpoint="http://127.0.0.1:1/v1",
            judge_model="judge",
            expected_judge_model="judge",
            judge_revision="judge-revision-1",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=3,
            judge_repetitions=3,
            max_cases=0,
            timeout=1,
            official=True,
            allow_external_judge=False,
        )


def test_m0_offline_conformance_fixture_runs_verifies_releases_and_exports(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class JudgeHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler API.
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            verdict = "fail" if "NOT BLUE" in body.decode("utf-8") else "pass"
            judgment = {
                "verdict": verdict,
                "score": 1 if verdict == "fail" else 5,
                "reason": "deterministic fixture judgment",
                "criteria": {},
            }
            payload = {
                "model": "judge",
                "choices": [{"message": {"content": json.dumps(judgment)}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }
            encoded = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    suite_root = _official_suite(tmp_path)
    suite = load_suite(suite_root, official=True)
    source_suite_config_sha = sha256_file(suite_root / "suite.toml")
    source_approval_path = suite_root / str(
        (suite.config.get("judge") or {})["qualification_blueprint_approval"]
    )
    source_approval_sha = sha256_file(source_approval_path)
    engagement, engagement_record = _engagement(tmp_path, suite_root)
    server = ThreadingHTTPServer(("127.0.0.1", 0), JudgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/v1"
        judge_configuration = {
            "requested_model": "judge",
            "expected_reported_model": "judge",
            "revision": "judge-revision-1",
            "endpoint": endpoint,
            "prompt_sha256": sha256_bytes(_judge_system_prompt(suite).encode("utf-8")),
            "response_schema": "judgment.schema.json@1.0.0",
            "temperature": 0,
            "models": [
                {
                    "id": "primary",
                    "model": "judge",
                    "expected_model": "judge",
                    "revision": "judge-revision-1",
                }
            ],
            "consensus": "unanimous",
        }
        build_qualification_package = runpy.run_path(
            str(Path(__file__).with_name("test_qualification_evidence.py"))
        )["build_synthetic_qualification_package"]
        qualification_package, _, base_qualification_verifier = build_qualification_package(
            tmp_path / "official-qualification",
            source_suite=suite_root,
            judge_configuration=judge_configuration,
        )
        assert sha256_file(suite_root / "suite.toml") == source_suite_config_sha
        assert sha256_file(source_approval_path) == source_approval_sha
        qualification_verification = reconstruct_judge_qualification(
            qualification_package,
            now=datetime.now(timezone.utc),
            base_behavior_verifier=base_qualification_verifier,
        )
        assert qualification_verification.valid, qualification_verification.failures
        source = _source_repository(tmp_path)
        run_dir = run(
            suite,
            repo_root=source,
            endpoint=endpoint,
            model_label="conformance-fixture",
            expected_model="target-model",
            model_revision="recorded-fixture-revision",
            request_model=None,
            judge_endpoint=endpoint,
            judge_model="judge",
            expected_judge_model="judge",
            judge_revision="judge-revision-1",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=3,
            judge_repetitions=3,
            max_cases=0,
            timeout=5,
            official=True,
            allow_external_judge=False,
            mode="offline",
            concurrency=16,
            judge_qualification_package=str(qualification_package),
            engagement=str(engagement),
            preset="reference",
        )
    finally:
        server.shutdown()
        thread.join()

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "passed"
    assert manifest["official"] is True
    assert manifest["parameters"]["preset"] == "reference"
    assert manifest["assurance"] == "conformance-fixture"
    assert manifest["model_claim_allowed"] is False
    assert manifest["benchmark_claim_allowed"] is False

    verification = verify_behavior_run(run_dir, write_result=True)
    assert verification["valid"] is True
    assert verification["semantic"]["required"] is True
    assert verification["assurance"] == "conformance-fixture"
    assert verification["model_claim_allowed"] is False
    assert verification["benchmark_claim_allowed"] is False
    assert json.loads((run_dir / "verification.json").read_text(encoding="utf-8")) == verification
    assert cli_main(["verify", str(run_dir)]) == 0
    assert json.loads(capsys.readouterr().out) == verification
    assert cli_main(["report", str(run_dir)]) == 0
    assert json.loads(capsys.readouterr().out)["verification"] == verification

    release_approval = _release_approval(tmp_path, run_dir, engagement, engagement_record)
    release = verified_public_release(
        run_dir,
        engagement,
        release_approval,
        now=datetime.now(timezone.utc),
    )
    assert release["assurance_level"] == "conformance-fixture"
    assert release["model_claim_allowed"] is False
    assert release["benchmark_claim_allowed"] is False

    registry_root = tmp_path / "registry-results"
    evidence_source = tmp_path / "public-evidence-source"
    shutil.copytree(run_dir, evidence_source / "run")
    governance = evidence_source / "governance"
    governance.mkdir()
    for source_path in (
        engagement,
        release_approval,
        tmp_path / "governance-evidence.txt",
        tmp_path / "release-review-evidence.txt",
    ):
        shutil.copy2(source_path, governance / source_path.name)
    archive = build_public_evidence_archive(
        evidence_source,
        registry_root / "archive" / "sha256",
        references={
            "run_bundle": "run/bundle.json",
            "engagement": f"governance/{engagement.name}",
            "release_approval": f"governance/{release_approval.name}",
            "verification_result": "run/verification.json",
        },
    )
    digest = archive.stem
    published_at = datetime.fromisoformat(str(release["approved_at"]).replace("Z", "+00:00")).isoformat().replace(
        "+00:00", "Z"
    )
    expires_at = datetime.fromisoformat(str(release["expires_at"]).replace("Z", "+00:00")).isoformat().replace(
        "+00:00", "Z"
    )
    record = {
        "record_version": "2.0.0",
        "record_id": "synthetic-m0-conformance",
        "record_type": "conformance",
        "archive": {
            "relative_path": f"archive/sha256/{archive.name}",
            "sha256": digest,
            "format": "cavada-public-evidence-tar",
            "format_version": "1.0.0",
        },
        "artifact_type": "behavior-run",
        "suite": {"name": manifest["suite"]["name"], "version": manifest["suite"]["version"]},
        "system": {
            "identity": manifest["target"]["expected_reported_model"],
            "revision": manifest["target"]["revision"],
        },
        "protocol_version": manifest["protocol_version"],
        "assurance_level": "conformance-fixture",
        "verification_result_sha256": sha256_file(run_dir / "verification.json"),
        "release_approval_sha256": sha256_file(release_approval),
        "published_at": published_at,
        "expires_at": expires_at,
        "claim_scope": [],
        "rankable": False,
        "model_claim_allowed": False,
        "benchmark_claim_allowed": False,
        "reproduction_status": "not-reproduced",
        "attestation": None,
    }
    registry = {
        "registry_version": "2.0.0",
        "records": [record],
        "events": [
            {
                "event_version": "2.0.0",
                "event_id": "published-synthetic-m0-conformance",
                "record_id": record["record_id"],
                "event_type": "published",
                "occurred_at": published_at,
                "previous_event_id": None,
                "related_record_id": None,
                "reason": "Synthetic test-only M0 conformance evidence.",
            }
        ],
    }
    assert validate_registry_v2(registry, root=registry_root, now=datetime.now(timezone.utc)) == []

    archive_path = tmp_path / "m0-public.tar.gz"
    _export(run_dir, archive_path, True, engagement=str(engagement), release_approval=str(release_approval))
    with tarfile.open(archive_path) as archive:
        exported = archive.extractfile("public_release.json")
        assert exported is not None
        public_release = json.load(exported)
    assert public_release["assurance_level"] == "conformance-fixture"
    assert public_release["model_claim_allowed"] is False
    assert public_release["benchmark_claim_allowed"] is False
    assert _doctor(source)["official_ready"] is False

    for index, mutation in enumerate(
        (
            {"assurance": "official"},
            {"model_claim_allowed": True},
            {"benchmark_claim_allowed": True},
        )
    ):
        tampered = tmp_path / f"tampered-run-{index}"
        shutil.copytree(run_dir, tampered)
        tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
        tampered_manifest.update(mutation)
        _write(tampered / "manifest.json", tampered_manifest)
        write_bundle(tampered)
        result = verify_behavior_run(tampered)
        assert result["integrity_valid"] is True
        assert result["valid"] is False
        assert "assurance and claim flags" in "\n".join(result["failures"])

    tampered = tmp_path / "tampered-run-missing-field"
    shutil.copytree(run_dir, tampered)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest.pop("external_judge_authorized")
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["valid"] is False
    assert "official manifest is missing fields" in "\n".join(result["failures"])

    tampered = tmp_path / "tampered-run-timing"
    shutil.copytree(run_dir, tampered)
    timing = json.loads((tampered / "timing.json").read_text(encoding="utf-8"))
    timing["elapsed_seconds"] += 1
    timing_sha = _write(tampered / "timing.json", timing)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["artifacts"]["timing.json"] = timing_sha
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["valid"] is False
    assert "timing evidence does not reconstruct" in "\n".join(result["failures"])

    tampered = tmp_path / "tampered-run-environment"
    shutil.copytree(run_dir, tampered)
    environment = json.loads((tampered / "environment.json").read_text(encoding="utf-8"))
    environment["python"] = "0.0-tampered"
    environment_sha = _write(tampered / "environment.json", environment)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["artifacts"]["environment.json"] = environment_sha
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["valid"] is False
    assert "manifest environment differs" in "\n".join(result["failures"])

    tampered = tmp_path / "tampered-run-malformed-target-response"
    shutil.copytree(run_dir, tampered)
    response_path = tampered / "raw_responses.jsonl"
    responses = [json.loads(line) for line in response_path.read_text(encoding="utf-8").splitlines()]
    lost_usage = responses[0]["response"]["usage"]
    responses[0]["response"] = "not-an-object"
    response_path.write_text("".join(json.dumps(row) + "\n" for row in responses), encoding="utf-8")
    metrics = json.loads((tampered / "metrics.json").read_text(encoding="utf-8"))
    metrics["budgets"]["total_tokens"] -= lost_usage["prompt_tokens"] + lost_usage["completion_tokens"]
    metrics_sha = _write(tampered / "metrics.json", metrics)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["metrics"] = metrics
    tampered_manifest["artifacts"]["metrics.json"] = metrics_sha
    tampered_manifest["artifacts"]["raw_responses.jsonl"] = sha256_file(response_path)
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["valid"] is False
    assert "has missing or malformed target evidence" in "\n".join(result["failures"])

    tampered = tmp_path / "tampered-run-result-metadata"
    shutil.copytree(run_dir, tampered)
    result_path = tampered / "case_results.jsonl"
    case_results = [json.loads(line) for line in result_path.read_text(encoding="utf-8").splitlines()]
    case_results[0]["severity"] = "low"
    result_path.write_text("".join(json.dumps(row) + "\n" for row in case_results), encoding="utf-8")
    metrics = json.loads((tampered / "metrics.json").read_text(encoding="utf-8"))
    severity_slices = {
        value: summarize([row for row in case_results if row["severity"] == value], confidence=0.95)[0]
        for value in sorted({str(row["severity"]) for row in case_results})
    }
    metrics["slices"]["severity"] = severity_slices
    metrics["slice_disparities"]["severity"] = max(item["pass_rate"] for item in severity_slices.values()) - min(
        item["pass_rate"] for item in severity_slices.values()
    )
    metrics_sha = _write(tampered / "metrics.json", metrics)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["metrics"] = metrics
    tampered_manifest["artifacts"]["metrics.json"] = metrics_sha
    tampered_manifest["artifacts"]["case_results.jsonl"] = sha256_file(result_path)
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["valid"] is False
    assert "case result metadata differs from suite evidence" in "\n".join(result["failures"])

    tampered = tmp_path / "tampered-run-implementation-hash"
    shutil.copytree(run_dir, tampered)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["source"]["implementation_sha256"] = "f" * 64
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["valid"] is False
    assert "implementation evidence does not match" in "\n".join(result["failures"])

    tampered = tmp_path / "tampered-run-implementation-blob"
    shutil.copytree(run_dir, tampered)
    implementation_manifest = json.loads((tampered / "implementation_evidence_manifest.json").read_text(encoding="utf-8"))
    blob_name = next(iter(implementation_manifest.values()))
    blob_path = tampered / "implementation_evidence" / blob_name
    blob_path.write_bytes(blob_path.read_bytes() + b"\n# tampered\n")
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["artifacts"][f"implementation_evidence/{blob_name}"] = sha256_file(blob_path)
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["valid"] is False
    assert "implementation evidence blob" in "\n".join(result["failures"])

    tampered = tmp_path / "tampered-run-nested-implementation-blob"
    shutil.copytree(run_dir, tampered)
    nested_blob = tampered / "implementation_evidence" / "extra" / "unlisted.py"
    nested_blob.parent.mkdir()
    nested_blob.write_text("raise RuntimeError('unlisted source')\n", encoding="utf-8")
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["valid"] is False
    assert "blob set must contain only direct regular files" in "\n".join(result["failures"])

    tampered = tmp_path / "tampered-run-source-proof-pack"
    shutil.copytree(run_dir, tampered)
    proof_path = tampered / "source_commit_proof.pack"
    proof = bytearray(proof_path.read_bytes())
    proof[-1] ^= 1
    proof_path.write_bytes(proof)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["artifacts"]["source_commit_proof.pack"] = sha256_file(proof_path)
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["assurance_valid"] is False
    assert result["valid"] is False
    assert "source proof pack failed Git integrity" in "\n".join(result["assurance_failures"])

    tampered = tmp_path / "tampered-run-source-proof-commit"
    shutil.copytree(run_dir, tampered)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["source"]["commit"] = "0" * 40
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["assurance_valid"] is False
    assert result["valid"] is False
    assert "source proof does not contain the declared commit" in "\n".join(result["assurance_failures"])

    tampered = tmp_path / "tampered-run-expired-external-authorization"
    shutil.copytree(run_dir, tampered)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["external_authorization"] = {
        "authorization_id": "expired-test-authorization",
        "approver": "synthetic-test-approver",
        "purpose": "Mutation test only",
        "destinations": [{"host": "example.invalid", "region": "test", "purpose": "mutation"}],
        "effective_at": "2020-01-01T00:00:00Z",
        "expires_at": "2021-01-01T00:00:00Z",
    }
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["assurance_valid"] is False
    assert "external authorization is not effective" in "\n".join(result["assurance_failures"])

    tampered = tmp_path / "tampered-run-expired-storage-attestation"
    shutil.copytree(run_dir, tampered)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["artifact_security"]["storage_attestation"] = {
        "attestation_id": "expired-test-storage",
        "approver": "synthetic-test-approver",
        "encryption_at_rest": True,
        "immutability": True,
        "access_policy_reference": "test-only",
        "audit_log_reference": "test-only",
        "retention_policy_reference": "test-only",
        "backup_restore_reference": "test-only",
        "effective_at": "2020-01-01T00:00:00Z",
        "expires_at": "2021-01-01T00:00:00Z",
    }
    tampered_manifest["artifact_security"]["encryption_state"] = "attested"
    tampered_manifest["artifact_security"]["immutability_state"] = "attested"
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["assurance_valid"] is False
    assert "storage attestation is not effective" in "\n".join(result["assurance_failures"])

    tampered = tmp_path / "tampered-run-false-storage-state"
    shutil.copytree(run_dir, tampered)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["artifact_security"]["encryption_state"] = "attested"
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["semantic_valid"] is False
    assert "security states do not reconstruct" in "\n".join(result["semantic_failures"])

    tampered = tmp_path / "tampered-run-target-contract"
    shutil.copytree(run_dir, tampered)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["target"]["capabilities"] = ["text", "unapproved-capability"]
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["semantic_valid"] is False
    assert "target adapter contract differs" in "\n".join(result["semantic_failures"])

    tampered = tmp_path / "tampered-run-network-policy"
    shutil.copytree(run_dir, tampered)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["judge"]["endpoint"] = "http://judge.example.invalid/v1"
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["assurance_valid"] is False
    network_failures = "\n".join(result["assurance_failures"])
    assert "HTTPS or loopback" in network_failures
    assert "outside suite.network.allowed_hosts" in network_failures

    tampered = tmp_path / "tampered-run-false-local-network"
    shutil.copytree(run_dir, tampered)
    tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
    tampered_manifest["judge"]["endpoint"] = "http://local/v1"
    _write(tampered / "manifest.json", tampered_manifest)
    write_bundle(tampered)
    result = verify_behavior_run(tampered)
    assert result["integrity_valid"] is True
    assert result["assurance_valid"] is False
    assert "HTTPS or loopback" in "\n".join(result["assurance_failures"])

    for field, value, expected in (
        ("max_cases", 1, "complete suite without max_cases"),
        ("repetitions", 1, "repetitions is below the suite minimum"),
        ("judge_repetitions", 1, "judge_repetitions is below the suite minimum"),
    ):
        tampered = tmp_path / f"tampered-run-official-{field}"
        shutil.copytree(run_dir, tampered)
        tampered_manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
        tampered_manifest["parameters"][field] = value
        _write(tampered / "manifest.json", tampered_manifest)
        write_bundle(tampered)
        result = verify_behavior_run(tampered)
        assert result["integrity_valid"] is True
        assert result["assurance_valid"] is False
        assert expected in "\n".join(result["assurance_failures"])
