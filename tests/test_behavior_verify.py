from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cavada_eval.artifacts import write_bundle
from cavada_eval.behavior_verify import _ledger_errors, _safe_path, suite_snapshot_files, verify_behavior_run
from cavada_eval.calibration import _qualification_structure_errors
from cavada_eval.metrics import deterministic_evaluation
from cavada_eval.protocol import ProtocolError, Suite
from cavada_eval.release import verified_public_release


def _bundle(root: Path, manifest: str | dict[str, object]) -> Path:
    root.mkdir()
    (root / "manifest.json").write_text(manifest if isinstance(manifest, str) else json.dumps(manifest), encoding="utf-8")
    write_bundle(root)
    return root


def test_candidate_is_integrity_only_but_official_claim_escalation_fails_closed(tmp_path: Path) -> None:
    run = _bundle(tmp_path / "run", {"run_id": "candidate", "official": False, "official_requested": False})
    candidate = verify_behavior_run(run)
    assert candidate["valid"] is True
    assert candidate["semantic"] == {"required": False, "valid": True, "failures": []}

    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["assurance"] = "official"
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    write_bundle(run)
    claimed = verify_behavior_run(run)
    assert claimed["semantic"]["required"] is True
    assert claimed["valid"] is False

    manifest.pop("assurance")
    manifest.update({"official": True, "official_requested": True, "status": "passed"})
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    write_bundle(run)
    escalated = verify_behavior_run(run, now=datetime(2026, 8, 5, tzinfo=timezone.utc))
    assert escalated["integrity_valid"] is True
    assert escalated["semantic"]["required"] is True
    assert escalated["valid"] is False

    with pytest.raises(ProtocolError) as caught:
        verified_public_release(run, tmp_path / "missing-engagement.json", tmp_path / "missing-approval.json")
    assert all(failure in str(caught.value) for failure in verify_behavior_run(run)["failures"])


@pytest.mark.parametrize(
    "manifest, expected",
    [
        ('{"official_requested":false,"official_requested":true}', "duplicate JSON key"),
        ('{"official_requested":false,"score":NaN}', "non-finite JSON number"),
    ],
)
def test_manifest_rejects_duplicate_keys_and_non_finite_numbers(tmp_path: Path, manifest: str, expected: str) -> None:
    result = verify_behavior_run(_bundle(tmp_path / "run", manifest))
    assert result["valid"] is False
    assert expected in "\n".join(result["failures"])


def test_safe_path_rejects_symlink_ancestor(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProtocolError, match="path is unsafe"):
        _safe_path(tmp_path, "linked/evidence.json", "evidence")


def test_qualification_v2_requires_nested_schema_fields() -> None:
    errors = _qualification_structure_errors(
        {
            "bundle_verification": {"valid": True},
            "judge_configuration": {},
            "judges": {"primary": {"passed": True}},
        }
    )
    assert "judge qualification.bundle_verification is missing fields" in "\n".join(errors)
    assert "judge qualification.judges.primary is missing fields" in "\n".join(errors)


def test_multi_judge_reconciliation_keys_include_judge_id(tmp_path: Path) -> None:
    case = {
        "id": "one",
        "input": "Question",
        "category": "quality",
        "risk_domain": "quality",
        "severity": "low",
        "expected_behavior": "answer",
        "expected_behavior_reason": "Answer the question.",
        "expected_contains": ["Answer"],
    }
    suite = Suite(tmp_path, {"target": {"kind": "json"}}, (case,), "rubric", tmp_path / "dataset.jsonl", tmp_path / "rubric.md")
    raw = {"answer": "Answer", "model": "target-real", "usage": {"prompt_tokens": 2, "completion_tokens": 2}}
    deterministic = deterministic_evaluation(case, "Answer", target_raw=raw, retrieved_ids=[], tool_calls=[])
    base = {"case_id": "one", "repetition": 1}
    target_transport = {"request_id": "target-1", "total_ms": 4.0, "headers_ms": 1.0, "response_bytes": 10}
    requests = [{**base, "kind": "target", "request_id": "target-1"}]
    requests.extend(
        {
            **base,
            "kind": "judge",
            "judge_id": judge_id,
            "judge_repetition": index,
            "model_repetition": 1,
            "request_id": f"judge-{judge_id}",
            "requested_model": f"{judge_id}-request",
            "judge_revision": f"{judge_id}-revision",
        }
        for index, judge_id in enumerate(("left", "right"), 1)
    )
    judgment = {"verdict": "pass", "score": 5, "reason": "ok", "criteria": {}}
    judge_content = json.dumps(judgment)
    judgments = [
        {
            **base,
            "judge_id": judge_id,
            "judge_repetition": index,
            "model_repetition": 1,
            "requested_model": f"{judge_id}-request",
            "judge_revision": f"{judge_id}-revision",
            "reported_model": f"{judge_id}-real",
            "judgment": judgment,
            "raw": {"model": f"{judge_id}-real", "choices": [{"message": {"content": judge_content}}]},
            "raw_content": judge_content,
            "transport": {"request_id": f"judge-{judge_id}"},
        }
        for index, judge_id in enumerate(("left", "right"), 1)
    ]
    rows = {
        "requests.jsonl": requests,
        "raw_responses.jsonl": [{**base, "reported_model": "target-real", "response": raw, "transport": target_transport}],
        "judgments.jsonl": judgments,
        "case_results.jsonl": [
            {
                **base,
                "status": "pass",
                "reason": "judge unanimous",
                "score": 5.0,
                "judge_agreement": 1.0,
                "deterministic": deterministic,
                "target_latency_ms": 4.0,
                "target_headers_ms": 1.0,
                "target_response_bytes": 10,
                "input_tokens": 2,
                "output_tokens": 2,
                "output_tokens_per_second": 500.0,
            }
        ],
    }
    for name, values in rows.items():
        (tmp_path / name).write_text("".join(json.dumps(value) + "\n" for value in values), encoding="utf-8")
    manifest = {
        "parameters": {"repetitions": 1, "judge_repetitions": 1},
        "target": {"expected_reported_model": "target-real"},
        "judge": {
            "consensus": "unanimous",
            "models": [
                {"id": "left", "model": "left-request", "expected_model": "left-real", "revision": "left-revision"},
                {"id": "right", "model": "right-request", "expected_model": "right-real", "revision": "right-revision"},
            ],
        },
    }
    baseline = _ledger_errors(suite, manifest, tmp_path)
    assert "judge request and output ledgers do not exactly reconcile" not in baseline
    assert not any("judge projection differs" in failure or "judge identity mismatch" in failure for failure in baseline)
    assert not any("case result performance projection differs" in failure for failure in baseline)

    judgments[0]["raw"]["model"] = "forged-model"
    (tmp_path / "judgments.jsonl").write_text("".join(json.dumps(value) + "\n" for value in judgments), encoding="utf-8")
    assert any("judge identity mismatch" in failure for failure in _ledger_errors(suite, manifest, tmp_path))

    judgments[0]["raw"]["model"] = "left-real"
    judgments[0]["raw_content"] = "forged projection"
    (tmp_path / "judgments.jsonl").write_text("".join(json.dumps(value) + "\n" for value in judgments), encoding="utf-8")
    assert any("judge projection differs" in failure for failure in _ledger_errors(suite, manifest, tmp_path))

    judgments[0]["raw_content"] = judge_content
    rows["case_results.jsonl"][0]["target_latency_ms"] = 4000.0
    (tmp_path / "judgments.jsonl").write_text("".join(json.dumps(value) + "\n" for value in judgments), encoding="utf-8")
    (tmp_path / "case_results.jsonl").write_text(
        "".join(json.dumps(value) + "\n" for value in rows["case_results.jsonl"]), encoding="utf-8"
    )
    assert any("case result performance projection differs" in failure for failure in _ledger_errors(suite, manifest, tmp_path))


def test_suite_snapshot_closes_pilot_campaign_and_every_run_bundle(tmp_path: Path) -> None:
    run = tmp_path / "pilot" / "run-one"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text('{"run_id":"pilot-one"}', encoding="utf-8")
    write_bundle(run)
    evidence = tmp_path / "pilot" / "evidence.json"
    evidence.write_text('{"status":"passed"}', encoding="utf-8")
    evidence_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()
    campaign = {
        "campaign_version": "1.0.0",
        "judge_qualification": {"path": evidence.name, "sha256": evidence_hash},
        "judge_independent_approval": {"path": evidence.name, "sha256": evidence_hash},
        "transcript_review": {"path": evidence.name, "sha256": evidence_hash},
        "runs": [{"role": "target", "family_alias": "family-a", "path": run.name}],
    }
    campaign_path = tmp_path / "pilot" / "campaign.json"
    campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
    campaign_hash = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
    report = {"pilot_campaign": "pilot/campaign.json", "pilot_campaign_sha256": campaign_hash}
    report_path = tmp_path / "calibration.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    report_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
    dataset = tmp_path / "dataset.jsonl"
    rubric = tmp_path / "rubric.md"
    dataset.write_text("", encoding="utf-8")
    rubric.write_text("rubric", encoding="utf-8")
    suite = Suite(
        tmp_path,
        {"calibration": {"evidence": report_path.name, "evidence_sha256": report_hash}},
        (),
        "rubric",
        dataset,
        rubric,
    )
    snapshots = suite_snapshot_files(suite)
    assert {
        "calibration.json",
        "pilot/campaign.json",
        "pilot/evidence.json",
        "pilot/run-one/manifest.json",
        "pilot/run-one/bundle.json",
        "pilot/run-one/checksums.txt",
    } <= set(snapshots)
