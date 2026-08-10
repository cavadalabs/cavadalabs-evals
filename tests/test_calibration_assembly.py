from __future__ import annotations

import json
import runpy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.calibration import judge_evidence_errors, qualify_judge_run
from cavada_eval.protocol import ProtocolError, Suite, load_suite, sha256_file
from cavada_eval.runner import _judge_calibration_summary

assemble = runpy.run_path("scripts/assemble_judge_calibration.py")["assemble"]


def test_exact_judge_qualification_requires_current_linked_independent_approval(tmp_path: Path) -> None:
    approver_evidence = tmp_path / "approver-qualification.txt"
    approver_evidence.write_text("qualified reviewer")
    judge = {
        "requested_model": "judge",
        "expected_reported_model": "judge",
        "revision": "fixed",
        "endpoint": "https://judge.example/v1",
        "prompt_sha256": "a" * 64,
        "response_schema": "judgment.schema.json@1.0.0",
        "temperature": 0,
        "max_tokens": 600,
        "judge_repetitions": 3,
        "models": [{"id": "primary", "model": "judge", "expected_model": "judge", "revision": "fixed"}],
        "consensus": "unanimous",
    }
    qualification = {
        "qualification_version": "2.0.0",
        "passed": True,
        "rubric_sha256": "b" * 64,
        "run_manifest_sha256": "c" * 64,
        "corpus_manifest_sha256": "d" * 64,
        "blueprint_sha256": "e" * 64,
        "corpus_dataset_sha256": "f" * 64,
        "bundle_verification": {"valid": True},
        "judge_configuration": judge,
        "judges": {"primary": {"passed": True}},
    }
    approval = {
        "approval_version": "2.0.0",
        "approval_id": "approval-1",
        "scope": "judge-qualification",
        "status": "passed",
        "independent": True,
        "qualification_sha256": "1" * 64,
        "approver_id": "reviewer",
        "approver_qualification_evidence": approver_evidence.name,
        "approver_qualification_evidence_sha256": sha256_file(approver_evidence),
        "conflicts": "none declared",
        "decision_rationale": "All preregistered qualification evidence passed review.",
        "approved_at": "2026-08-01T00:00:00Z",
        "expires_at": "2027-08-01T00:00:00Z",
    }
    now = datetime(2026, 8, 5, tzinfo=timezone.utc)
    assert not judge_evidence_errors(
        qualification,
        approval,
        qualification_sha256="1" * 64,
        expected_judge=judge,
        rubric_sha256="b" * 64,
        approval_root=tmp_path,
        now=now,
    )
    approver_evidence.write_text("tampered")
    assert "judge approver qualification evidence hash mismatch" in judge_evidence_errors(
        qualification,
        approval,
        qualification_sha256="1" * 64,
        expected_judge=judge,
        rubric_sha256="b" * 64,
        approval_root=tmp_path,
        now=now,
    )
    approver_evidence.write_text("qualified reviewer")
    changed = {**judge, "revision": "different"}
    errors = judge_evidence_errors(
        qualification,
        approval,
        qualification_sha256="1" * 64,
        expected_judge=changed,
        rubric_sha256="b" * 64,
        approval_root=tmp_path,
        now=now,
    )
    assert "judge qualification does not match the exact run configuration" in errors

    changed = {**judge, "judge_repetitions": 4}
    errors = judge_evidence_errors(
        qualification,
        approval,
        qualification_sha256="1" * 64,
        expected_judge=changed,
        rubric_sha256="b" * 64,
        approval_root=tmp_path,
        now=now,
    )
    assert "judge qualification does not match the exact run configuration" in errors

    changed = {**judge, "max_tokens": 601}
    errors = judge_evidence_errors(
        qualification,
        approval,
        qualification_sha256="1" * 64,
        expected_judge=changed,
        rubric_sha256="b" * 64,
        approval_root=tmp_path,
        now=now,
    )
    assert "judge qualification does not match the exact run configuration" in errors


def test_restricted_judge_calibration_corpus_is_balanced_and_runnable(tmp_path: Path) -> None:
    blueprint = tmp_path / "blueprint.toml"
    blueprint.write_text(
        '''version = "test"
target_unique_responses = 2
minimum_model_families = 2
[allocations]
language = [{id="en", target=1}, {id="it", target=1}]
severity = [{id="low", target=2}]
response_length = [{id="short", target=1}, {id="long", target=1}]
response_style = [{id="direct", target=1}, {id="terse", target=1}]
probe_type = [{id="standard", target=1}, {id="borderline", target=1}]
[[modules]]
id = "instruction-following"
target = 2
pass_target = 1
fail_target = 1
''',
        encoding="utf-8",
    )
    common = {
        "source_case_id": "source",
        "mandatory_criteria": ["Follow the explicit instruction."],
        "expected_behavior": "answer",
        "module": "instruction-following",
        "risk_domain": "quality",
        "severity": "low",
        "locale": "en-US",
        "source_run_manifest_sha256": "a" * 64,
        "gold_evidence_sha256": "b" * 64,
        "review_method": "two independent qualified reviewers; resolved gold evidence",
    }
    items = [
        {
            **common,
            "item_id": "cal-1",
            "input": "Reply only BLUE.",
            "response": "BLUE",
            "gold_verdict": "pass",
            "gold_rationale": "The exact instruction is satisfied.",
            "language": "en",
            "response_length": "short",
            "response_style": "direct",
            "probe_type": "standard",
            "model_family_alias": "family-a",
        },
        {
            **common,
            "item_id": "cal-2",
            "input": "Rispondi soltanto VERDE.",
            "response": "Il colore è VERDE.",
            "gold_verdict": "fail",
            "gold_rationale": "The response adds forbidden text.",
            "language": "it",
            "locale": "it-IT",
            "response_length": "long",
            "response_style": "terse",
            "probe_type": "borderline",
            "model_family_alias": "family-b",
        },
    ]
    source = tmp_path / "items.jsonl"
    source.write_text("".join(json.dumps(item) + "\n" for item in items), encoding="utf-8")
    output = tmp_path / "assembled"
    manifest = assemble(
        Path("suites/cavada-core-assistant-text-v1"),
        source,
        blueprint,
        output,
        corpus_version="1.0.0",
        frozen_at="2026-08-05T18:00:00+02:00",
    )
    suite = load_suite(output)
    assert manifest["items"] == len(suite.cases) == 2
    assert manifest["identity_blinded_to_judge"] is True
    assert suite.config["target"]["kind"] == "recorded"

    items[1]["gold_evidence_sha256"] = "invalid"
    source.write_text("".join(json.dumps(item) + "\n" for item in items), encoding="utf-8")
    with pytest.raises(ProtocolError, match="evidence hashes"):
        assemble(
            Path("suites/cavada-core-assistant-text-v1"),
            source,
            blueprint,
            tmp_path / "rejected",
            corpus_version="1.0.0",
            frozen_at="2026-08-05T18:00:00+02:00",
        )


def _calibration_run(root: Path, blueprint: Path) -> tuple[Path, Path]:
    root.mkdir()
    suite_config = root / "suite_snapshot.toml"
    suite_config.write_text('name = "calibration-test"\nversion = "1.0.0"\nstatus = "candidate"\n', encoding="utf-8")
    cases = (
        {
            "id": "pass-case",
            "category": "instruction-following",
            "judge_gold_verdict": "pass",
            "probe_type": "standard",
        },
        {
            "id": "fail-case",
            "category": "instruction-following",
            "judge_gold_verdict": "fail",
            "probe_type": "standard",
        },
    )
    dataset = root / "dataset_snapshot.jsonl"
    dataset.write_text("".join(json.dumps(case) + "\n" for case in cases), encoding="utf-8")
    rubric = root / "rubric_snapshot.md"
    rubric.write_text("Judge exact instruction following.\n", encoding="utf-8")
    judgments = [
        {
            "case_id": case["id"],
            "repetition": 1,
            "judge_id": "primary",
            "judge_repetition": repetition,
            "model_repetition": repetition,
            "judgment": {"verdict": case["judge_gold_verdict"]},
        }
        for case in cases
        for repetition in (1, 2)
    ]
    judgments_path = root / "judgments.jsonl"
    judgments_path.write_text("".join(json.dumps(row) + "\n" for row in judgments), encoding="utf-8")
    suite = Suite(root, {"name": "calibration-test", "version": "1.0.0", "status": "candidate"}, cases, rubric.read_text(), dataset, rubric)
    metrics = {"judge_calibration": _judge_calibration_summary(judgments, suite)}
    metrics_path = root / "metrics.json"
    metrics_path.write_text(json.dumps(metrics), encoding="utf-8")
    manifest = {
        "status": "passed",
        "finished_at": "2026-08-07T00:00:00+00:00",
        "suite": {
            "dataset_sha256": sha256_file(dataset),
            "rubric_sha256": sha256_file(rubric),
            "suite_config_sha256": sha256_file(suite_config),
        },
        "target": {"kind": "recorded", "recorded_responses_sha256": "s" * 64},
        "judge": {
            "models": [{"id": "primary", "model": "judge", "revision": "fixed"}],
            "prompt_sha256": "p" * 64,
            "max_tokens": 600,
            "judge_repetitions": 2,
        },
        "parameters": {"judge_repetitions": 2},
        "metrics": metrics,
        "artifacts": {
            "suite_snapshot.toml": sha256_file(suite_config),
            "dataset_snapshot.jsonl": sha256_file(dataset),
            "rubric_snapshot.md": sha256_file(rubric),
            "judgments.jsonl": sha256_file(judgments_path),
            "metrics.json": sha256_file(metrics_path),
        },
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    write_bundle(root)
    corpus = root.parent / f"{root.name}-corpus.json"
    corpus.write_text(
        json.dumps(
            {
                "dataset_sha256": sha256_file(dataset),
                "recorded_responses_sha256": "s" * 64,
                "blueprint_sha256": sha256_file(blueprint),
                "identity_blinded_to_judge": True,
                "independent_gold_required": True,
            }
        ),
        encoding="utf-8",
    )
    return root, corpus


def _reseal_calibration_run(run: Path) -> None:
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    metrics_path = run / "metrics.json"
    metrics_path.write_text(json.dumps(manifest["metrics"]), encoding="utf-8")
    manifest["artifacts"]["metrics.json"] = sha256_file(metrics_path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    write_bundle(run)


def test_judge_qualification_applies_lower_bound_and_stability_gates(tmp_path: Path) -> None:
    blueprint = tmp_path / "blueprint.toml"
    blueprint.write_text(
        '''minimum_judge_repetitions = 2
maximum_invalid_cases = 0
minimum_repeat_stability = 0.95
[[modules]]
id = "instruction-following"
target = 2
failure_sensitivity_gate = 0.2
pass_specificity_gate = 0.2
''',
        encoding="utf-8",
    )
    run, corpus = _calibration_run(tmp_path / "run", blueprint)
    report = qualify_judge_run(run, blueprint, corpus, tmp_path / "passed.json")
    assert report["passed"] is True
    assert report["run_bundle_sha256"] == sha256_file(run / "bundle.json")
    assert report["judges"]["primary"]["diagnostic_slices"]["probe_type"]["standard"]["cases"] == 2

    judgments_path = run / "judgments.jsonl"
    judgments = [json.loads(line) for line in judgments_path.read_text(encoding="utf-8").splitlines()]
    judgments[-1]["judgment"]["verdict"] = "pass"
    judgments_path.write_text("".join(json.dumps(row) + "\n" for row in judgments), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    cases = tuple(json.loads(line) for line in (run / "dataset_snapshot.jsonl").read_text(encoding="utf-8").splitlines())
    suite = Suite(run, {}, cases, "", run / "dataset_snapshot.jsonl", run / "rubric_snapshot.md")
    manifest["metrics"]["judge_calibration"] = _judge_calibration_summary(judgments, suite)
    manifest["artifacts"]["judgments.jsonl"] = sha256_file(judgments_path)
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    _reseal_calibration_run(run)
    failed = qualify_judge_run(run, blueprint, corpus, tmp_path / "failed.json")
    assert failed["passed"] is False


def test_judge_qualification_rejects_resealed_forged_aggregate(tmp_path: Path) -> None:
    blueprint = tmp_path / "blueprint.toml"
    blueprint.write_text(
        'minimum_judge_repetitions = 2\nmaximum_invalid_cases = 0\nminimum_repeat_stability = 0\n',
        encoding="utf-8",
    )
    run, corpus = _calibration_run(tmp_path / "run", blueprint)
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["metrics"]["judge_calibration"]["primary"]["accuracy"] = 0.0
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    _reseal_calibration_run(run)

    output = tmp_path / "forged.json"
    with pytest.raises(ProtocolError, match="do not reconcile with the immutable judgments and gold dataset"):
        qualify_judge_run(run, blueprint, corpus, output)
    assert not output.exists()


def test_judge_qualification_reads_only_verified_run_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    blueprint = tmp_path / "blueprint.toml"
    blueprint.write_text(
        'minimum_judge_repetitions = 2\nmaximum_invalid_cases = 0\nminimum_repeat_stability = 0\n',
        encoding="utf-8",
    )
    run, corpus = _calibration_run(tmp_path / "run", blueprint)
    expected_bundle = sha256_file(run / "bundle.json")
    expected_manifest = sha256_file(run / "manifest.json")

    def swap_live_source(snapshot: Path) -> dict[str, object]:
        result = verify_bundle(snapshot)
        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        manifest["target"]["recorded_responses_sha256"] = "b" * 64
        (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        write_bundle(run)
        return result

    monkeypatch.setattr("cavada_eval.calibration.verify_bundle", swap_live_source)
    report = qualify_judge_run(run, blueprint, corpus, tmp_path / "qualification.json")

    assert report["run_bundle_sha256"] == expected_bundle != sha256_file(run / "bundle.json")
    assert report["run_manifest_sha256"] == expected_manifest != sha256_file(run / "manifest.json")
