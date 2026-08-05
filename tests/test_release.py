from __future__ import annotations

import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cavada_eval.artifacts import write_bundle
from cavada_eval.cli import _export
from cavada_eval.protocol import PROTOCOL_VERSION, ProtocolError, Suite, load_suite, sha256_file
from cavada_eval.release import verified_engagement, verified_public_release
from cavada_eval.runner import run

NOW = datetime(2026, 8, 5, 12, tzinfo=timezone.utc)


def _suite(root: Path) -> Suite:
    root.mkdir()
    (root / "suite.toml").write_text(
        '''protocol_version = "1.0.0"
name = "release-test-v1"
version = "1.0.0"
status = "candidate"
description = "Release governance fixture"
data_classification = "synthetic"
dataset = "dataset.jsonl"
rubric = "rubric.md"
''',
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
        "sut": {"expected_model": "target-model", "revision": "target-revision"},
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


def _release_fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, object]]:
    engagement_path = tmp_path / "engagement.json"
    engagement, suite = _engagement(engagement_path)
    engagement_summary = verified_engagement(
        engagement_path,
        suite,
        expected_model="target-model",
        model_revision="target-revision",
        now=NOW,
    )
    run = tmp_path / "run"
    run.mkdir()
    manifest = {
        "run_id": "run-1",
        "status": "passed",
        "official": True,
        "official_requested": True,
        "finished_at": "2026-08-05T11:00:00Z",
        "engagement": engagement_summary,
    }
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run / "report_public.html").write_text("<p>sanitized</p>", encoding="utf-8")
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


def test_engagement_is_exact_and_public_release_is_post_run_and_independent(tmp_path: Path) -> None:
    run, engagement, approval, _ = _release_fixture(tmp_path)
    released = verified_public_release(run, engagement, approval, now=NOW)
    assert released["release_id"] == "release-1"
    assert released["decision_statuses"]["release"] == "passed"

    archive = tmp_path / "public.tar.gz"
    _export(run, archive, True, engagement=str(engagement), release_approval=str(approval))
    with tarfile.open(archive) as exported:
        assert set(exported.getnames()) == {"report_public.html", "public_release.json"}


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


def test_official_execution_requires_engagement_before_network_access(tmp_path: Path) -> None:
    suite = _suite(tmp_path / "suite")
    with pytest.raises(ProtocolError, match="approved engagement governance record"):
        run(
            suite,
            repo_root=tmp_path,
            endpoint="http://127.0.0.1:1/target",
            model_label="target",
            expected_model="target-model",
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
            official=True,
            allow_external_judge=False,
        )
