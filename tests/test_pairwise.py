from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.comparison import _require_compatible_manifests
from cavada_eval.pairwise import _winner, pairwise_runs
from cavada_eval.protocol import ProtocolError, Suite, load_suite, sha256_bytes, sha256_file
from cavada_eval.runner import _TransportError


def _suite(tmp_path: Path, *, first_input: str = "question a") -> Suite:
    root = tmp_path / "suite"
    root.mkdir()
    (root / "suite.toml").write_text(
        '''protocol_version = "1.0.0"
name = "suite"
version = "1.0.0"
status = "candidate"
description = "Pairwise test suite"
data_classification = "synthetic"
dataset = "dataset.jsonl"
rubric = "rubric.md"
''',
        encoding="utf-8",
    )
    cases = (
        {
            "id": case_id,
            "input": first_input if case_id == "a" else f"question {case_id}",
            "category": "quality",
            "risk_domain": "quality",
            "severity": "low",
            "expected_behavior": "safe_complete",
            "expected_behavior_reason": "quality",
            "review": {"status": "approved", "method": "test"},
            "source": {"origin": "test"},
        }
        for case_id in ("a", "b")
    )
    (root / "dataset.jsonl").write_text("".join(json.dumps(case) + "\n" for case in cases), encoding="utf-8")
    (root / "rubric.md").write_text("Prefer the more correct answer.", encoding="utf-8")
    return load_suite(root)


def _manifest(suite: Suite, run_id: str, selected_cases: int, repetitions: int) -> dict[str, Any]:
    return {
        "protocol_version": "1.0.0",
        "schema_version": "1.0.0",
        "metric_version": "1.0.0",
        "adapter_contract_version": "1.0.0",
        "run_id": run_id,
        "status": "passed",
        "official_requested": False,
        "suite": {
            "name": suite.name,
            "version": suite.version,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
            "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
        },
        "target": {
            "label": run_id,
            "expected_reported_model": run_id,
            "revision": f"{run_id}-revision",
            "request_model": f"{run_id}-request",
        },
        "judge": {
            "requested_model": "behavior-judge",
            "expected_reported_model": "behavior-judge-real",
            "revision": "behavior-judge-revision",
            "prompt_sha256": "d" * 64,
            "response_schema": "judgment.schema.json@1.0.0",
            "temperature": 0,
            "max_tokens": 600,
            "models": [{"id": "primary", "model": "behavior-judge"}],
            "consensus": "majority",
        },
        "parameters": {
            "mode": "candidate",
            "preset": "reference",
            "preset_version": "1.0.0",
            "repetitions": repetitions,
            "judge_repetitions": 3,
            "max_cases": 0,
            "selected_cases": selected_cases,
            "case_order_policy": "dataset order",
            "case_order_sha256": "e" * 64,
            "cache": {"target": "disabled", "judge": "disabled"},
        },
        "metrics": {
            "analysis_unit": "case",
            "officially_valid": True,
            "aborted": False,
            "gate_failures": [],
            "invalid": 0,
            "error": 0,
            "skipped": 0,
        },
    }


def _run(
    path: Path,
    suite: Suite,
    answers: list[tuple[str, int, str]],
    *,
    result_keys: list[tuple[str, int]] | None = None,
    mutate: tuple[str, Any] | None = None,
) -> Path:
    path.mkdir()
    keys = result_keys if result_keys is not None else [(case_id, repetition) for case_id, repetition, _ in answers]
    manifest = _manifest(
        suite,
        path.name,
        len({case_id for case_id, _ in keys}),
        max((repetition for _, repetition in keys), default=1),
    )
    if mutate is not None:
        manifest["parameters"][mutate[0]] = mutate[1]
    (path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (path / "case_results.jsonl").write_text(
        "".join(json.dumps({"case_id": case_id, "repetition": repetition, "status": "pass"}) + "\n" for case_id, repetition in keys),
        encoding="utf-8",
    )
    (path / "raw_responses.jsonl").write_text(
        "".join(
            json.dumps(
                {
                    "case_id": case_id,
                    "repetition": repetition,
                    "reported_model": path.name,
                    "response": {"answer": answer},
                }
            )
            + "\n"
            for case_id, repetition, answer in answers
        ),
        encoding="utf-8",
    )
    write_bundle(path)
    return path


def _kwargs() -> dict[str, Any]:
    return {
        "judge_endpoint": "http://127.0.0.1:8000/v1",
        "judge_model": "pairwise-judge",
        "expected_judge_model": "pairwise-judge-real",
        "judge_revision": "judge-revision",
    }


def _valid_response(winner: str) -> dict[str, Any]:
    content = json.dumps({"winner": winner, "reason": "more correct", "confidence": 0.9})
    return {"model": "pairwise-judge-real", "choices": [{"message": {"content": content}}]}


def test_pairwise_requires_exact_complete_contract_and_retains_both_orders(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right")])

    def judge(_url: str, payload: dict[str, Any], _key: str, _timeout: float, *, request_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        user = json.loads(payload["messages"][1]["content"])
        return _valid_response("A" if user["answer_A"] == "right" else "B"), {"request_id": request_id, "attempts": 1}

    monkeypatch.setattr("cavada_eval.pairwise._post_json", judge)
    output = tmp_path / "pairwise"
    manifest = pairwise_runs(baseline, candidate, suite, output, **_kwargs())

    rows = [json.loads(line) for line in (output / "pairwise_judgments.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["order"] for row in rows] == ["AB", "BA"]
    assert all(row["status"] == "valid" and row["request"] and row["raw"] and row["transport"] for row in rows)
    assert {key: value for key, value in manifest["metrics"].items() if key != "candidate_score_ci95"} == {
        "baseline": 0,
        "candidate": 1,
        "tie": 0,
        "invalid": 0,
        "error": 0,
        "total": 1,
        "observations": 1,
        "valid": 1,
        "candidate_score": 1.0,
    }
    assert manifest["metrics"]["candidate_score_ci95"]["lower"] == 1.0
    assert manifest["metrics"]["candidate_score_ci95"]["upper"] == 1.0
    assert manifest["baseline_run"]["bundle_sha256"] == sha256_file(baseline / "bundle.json")
    assert manifest["pairwise_version"] == "2.0.0"
    assert manifest["judge"] == {
        "model": "pairwise-judge",
        "expected_model": "pairwise-judge-real",
        "revision": "judge-revision",
        "endpoint": "http://127.0.0.1:8000/v1",
        "api_key_env": "JUDGE_API_KEY",
        "timeout_seconds": 90.0,
        "prompt_sha256": sha256_bytes(rows[0]["request"]["messages"][0]["content"].encode("utf-8")),
        "response_schema": "pairwise-winner@1.0.0",
        "temperature": 0,
        "max_tokens": 500,
    }
    assert verify_bundle(output)["valid"] is True


def test_pairwise_aggregates_repetitions_once_per_distinct_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left-1"), ("a", 2, "left-2")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right-1"), ("a", 2, "right-2")])

    def judge(
        _url: str,
        payload: dict[str, Any],
        _key: str,
        _timeout: float,
        *,
        request_id: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        user = json.loads(payload["messages"][1]["content"])
        preferred = "right" if user["answer_A"].endswith("1") or user["answer_B"].endswith("1") else "left"
        winner = "A" if user["answer_A"].startswith(preferred) else "B"
        return _valid_response(winner), {"request_id": request_id, "attempts": 1}

    monkeypatch.setattr("cavada_eval.pairwise._post_json", judge)
    manifest = pairwise_runs(baseline, candidate, suite, tmp_path / "pairwise", **_kwargs())

    assert manifest["metrics"] == {
        "baseline": 0,
        "candidate": 0,
        "tie": 0,
        "invalid": 1,
        "error": 0,
        "total": 1,
        "observations": 2,
        "valid": 0,
        "candidate_score": 0.0,
        "candidate_score_ci95": None,
    }


def test_pairwise_rejects_configuration_or_answer_set_mismatch_before_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    incompatible = _run(tmp_path / "incompatible", suite, [("a", 1, "right")], mutate=("timeout_seconds", 30))
    different = _run(tmp_path / "different", suite, [("b", 1, "right")])
    monkeypatch.setattr("cavada_eval.pairwise._post_json", lambda *_args, **_kwargs: pytest.fail("judge called during preflight"))

    with pytest.raises(ProtocolError, match="incompatible execution parameters"):
        pairwise_runs(baseline, incompatible, suite, tmp_path / "bad-config", **_kwargs())
    with pytest.raises(ProtocolError, match="identical case and repetition identifiers"):
        pairwise_runs(baseline, different, suite, tmp_path / "bad-set", **_kwargs())
    assert not (tmp_path / "bad-config").exists()
    assert not (tmp_path / "bad-set").exists()


@pytest.mark.parametrize("answer", ["Made by CANDIDATE-REQUEST", "Made by CANDIDATE"])
def test_pairwise_rejects_target_identity_in_answer_before_output_or_judge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, answer)])
    monkeypatch.setattr("cavada_eval.pairwise._post_json", lambda *_args, **_kwargs: pytest.fail("judge contacted"))
    output = tmp_path / "rejected"

    with pytest.raises(ProtocolError, match="payload exposes target identity"):
        pairwise_runs(baseline, candidate, suite, output, **_kwargs())

    assert not output.exists()


def test_pairwise_rejects_target_identity_in_input_before_output_or_judge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = _suite(tmp_path, first_input="Compare this for BASELINE-REVISION")
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right")])
    monkeypatch.setattr("cavada_eval.pairwise._post_json", lambda *_args, **_kwargs: pytest.fail("judge contacted"))
    output = tmp_path / "rejected"

    with pytest.raises(ProtocolError, match="payload exposes target identity"):
        pairwise_runs(baseline, candidate, suite, output, **_kwargs())

    assert not output.exists()


def test_pairwise_rejects_duplicate_or_missing_answers_before_output(tmp_path: Path) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    duplicate = _run(tmp_path / "duplicate", suite, [("a", 1, "right"), ("a", 1, "right again")])
    missing = _run(tmp_path / "missing", suite, [], result_keys=[("a", 1)])

    with pytest.raises(ProtocolError, match="duplicate raw answer"):
        pairwise_runs(baseline, duplicate, suite, tmp_path / "duplicate-output", **_kwargs())
    with pytest.raises(ProtocolError, match="one raw answer for every selected case"):
        pairwise_runs(baseline, missing, suite, tmp_path / "missing-output", **_kwargs())
    assert not (tmp_path / "duplicate-output").exists()
    assert not (tmp_path / "missing-output").exists()


@pytest.mark.parametrize("tamper", ["failed", "case-status", "identity"])
def test_pairwise_rejects_invalid_source_evidence_before_judge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right")])
    if tamper == "failed":
        manifest = json.loads((candidate / "manifest.json").read_text(encoding="utf-8"))
        manifest["status"] = "failed"
        (candidate / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    elif tamper == "case-status":
        row = json.loads((candidate / "case_results.jsonl").read_text(encoding="utf-8"))
        row["status"] = "error"
        (candidate / "case_results.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    else:
        row = json.loads((candidate / "raw_responses.jsonl").read_text(encoding="utf-8"))
        row["reported_model"] = "wrong-model"
        (candidate / "raw_responses.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    write_bundle(candidate)
    monkeypatch.setattr("cavada_eval.pairwise._post_json", lambda *_args, **_kwargs: pytest.fail("judge contacted"))

    with pytest.raises(ProtocolError):
        pairwise_runs(baseline, candidate, suite, tmp_path / "rejected", **_kwargs())
    assert not (tmp_path / "rejected").exists()


def test_pairwise_rejects_output_inside_input_run_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right")])
    monkeypatch.setattr("cavada_eval.pairwise._post_json", lambda *_args, **_kwargs: pytest.fail("judge contacted"))

    with pytest.raises(ProtocolError, match="outside the immutable input runs"):
        pairwise_runs(baseline, candidate, suite, baseline / "pairwise", **_kwargs())
    assert verify_bundle(baseline)["valid"] is True


def test_pairwise_rejects_forged_suite_before_output_or_judge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = _suite(tmp_path)
    forged = Suite(suite.root, suite.config, suite.cases, "forged in-memory rubric", suite.dataset_path, suite.rubric_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right")])
    monkeypatch.setattr("cavada_eval.pairwise._post_json", lambda *_args, **_kwargs: pytest.fail("judge contacted"))
    output = tmp_path / "rejected"

    with pytest.raises(ProtocolError, match="differs from the canonical validated suite"):
        pairwise_runs(baseline, candidate, forged, output, **_kwargs())

    assert not output.exists()


def test_pairwise_rejects_input_drift_between_verification_and_judge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right")])
    output = tmp_path / "rejected"

    def drift_after_compatibility(left: dict[str, Any], right: dict[str, Any]) -> None:
        _require_compatible_manifests(left, right)
        path = candidate / "raw_responses.jsonl"
        path.write_bytes(path.read_bytes() + b"\n")

    monkeypatch.setattr("cavada_eval.pairwise._require_compatible_manifests", drift_after_compatibility)
    monkeypatch.setattr("cavada_eval.pairwise._post_json", lambda *_args, **_kwargs: pytest.fail("judge contacted"))

    with pytest.raises(ProtocolError, match="bundle verification failed|changed during preflight"):
        pairwise_runs(baseline, candidate, suite, output, **_kwargs())
    assert not output.exists()


def test_pairwise_separates_transport_errors_and_preserves_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right")])
    calls = 0

    def judge(_url: str, payload: dict[str, Any], _key: str, _timeout: float, *, request_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        nonlocal calls
        calls += 1
        transport = {"request_id": request_id, "attempts": 1, "attempt_errors": [{"kind": "network"}]}
        if calls == 1:
            raise _TransportError("network down", request=payload, raw={"body_base64": ""}, transport=transport)
        return _valid_response("A"), transport

    monkeypatch.setattr("cavada_eval.pairwise._post_json", judge)
    output = tmp_path / "pairwise"
    manifest = pairwise_runs(baseline, candidate, suite, output, **_kwargs())

    rows = [json.loads(line) for line in (output / "pairwise_judgments.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["order"] for row in rows] == ["AB", "BA"]
    assert rows[0]["status"] == "error"
    assert rows[0]["request"] and rows[0]["raw"] == {"body_base64": ""} and rows[0]["transport"] and rows[0]["error"] == "network down"
    assert manifest["metrics"]["error"] == 1
    assert manifest["metrics"]["invalid"] == 0


def test_pairwise_marks_malformed_judgment_invalid_and_retains_reverse_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right")])
    calls = 0

    def judge(_url: str, _payload: dict[str, Any], _key: str, _timeout: float, *, request_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        nonlocal calls
        calls += 1
        raw = {"model": "pairwise-judge-real", "choices": [{"message": {"content": "not-json"}}]} if calls == 1 else _valid_response("A")
        return raw, {"request_id": request_id, "attempts": 1}

    monkeypatch.setattr("cavada_eval.pairwise._post_json", judge)
    output = tmp_path / "pairwise"
    manifest = pairwise_runs(baseline, candidate, suite, output, **_kwargs())

    rows = [json.loads(line) for line in (output / "pairwise_judgments.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["status"] for row in rows] == ["invalid", "valid"]
    assert rows[0]["request"] and rows[0]["raw"] and rows[0]["transport"] and "malformed" in rows[0]["error"]
    assert manifest["metrics"]["invalid"] == 1
    assert manifest["metrics"]["error"] == 0


def test_pairwise_identity_mismatch_aborts_after_preserving_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite = _suite(tmp_path)
    baseline = _run(tmp_path / "baseline", suite, [("a", 1, "left")])
    candidate = _run(tmp_path / "candidate", suite, [("a", 1, "right")])
    wrong = _valid_response("A")
    wrong["model"] = "wrong-judge"
    monkeypatch.setattr(
        "cavada_eval.pairwise._post_json",
        lambda _url, _payload, _key, _timeout, *, request_id: (wrong, {"request_id": request_id, "attempts": 1}),
    )
    output = tmp_path / "pairwise"

    with pytest.raises(ProtocolError, match="identity mismatch"):
        pairwise_runs(baseline, candidate, suite, output, **_kwargs())
    row = json.loads((output / "pairwise_judgments.jsonl").read_text(encoding="utf-8"))
    assert row["status"] == "invalid" and row["raw"]["model"] == "wrong-judge" and row["request"] and row["transport"]


@pytest.mark.parametrize(
    "content",
    [
        '{"winner":"A","reason":"ok","confidence":true}',
        '{"winner":"A","reason":"ok","confidence":0.8,"extra":1}',
    ],
)
def test_pairwise_judgment_requires_exact_fields_and_types(content: str) -> None:
    with pytest.raises(ProtocolError):
        _winner({"choices": [{"message": {"content": content}}]})
