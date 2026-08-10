from __future__ import annotations

import base64
import json
import shutil
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import cavada_eval.protocol as protocol_module
from cavada_eval.artifacts import verify_bundle
from cavada_eval.cli import _doctor
from cavada_eval.compliance import generate_control_report
from cavada_eval.profiles import benchmark_preset, canonical_preset, stratified_cases
from cavada_eval.protocol import (
    ProtocolError,
    Suite,
    _calibration_evidence_errors,
    _semantic_integrity_errors,
    apply_gates,
    load_suite,
    new_run_dir,
    promote_suite,
    semantic_duplicate_candidates,
    sha256_file,
    summarize,
    validate_suite,
    wilson_interval,
)
from cavada_eval.runner import _judge_result, _manifest_endpoint, run


def test_benchmark_presets_are_canonical_and_group_safe() -> None:
    cases = (
        {"id": "a", "scenario_group_id": "pair", "scenario_role": "primary", "category": "alpha", "risk_domain": "quality", "severity": "low", "language": "en", "split": "public"},
        {"id": "a-variant", "scenario_group_id": "pair", "scenario_role": "variant", "category": "alpha", "risk_domain": "quality", "severity": "low", "language": "en", "split": "public"},
        {"id": "b", "category": "beta", "risk_domain": "security", "severity": "high", "language": "it", "split": "practice"},
        {"id": "c", "category": "alpha", "risk_domain": "quality", "severity": "medium", "language": "it", "split": "practice"},
        {"id": "d", "category": "beta", "risk_domain": "security", "severity": "critical", "language": "en", "split": "public"},
    )
    selected = stratified_cases(cases, 4)
    assert selected == stratified_cases(cases, 4)
    assert len(selected) <= 4 and {case["category"] for case in selected} == {"alpha", "beta"}
    assert ({"a", "a-variant"} <= {case["id"] for case in selected}) or not ({"a", "a-variant"} & {case["id"] for case in selected})
    assert canonical_preset("full") == "reference"
    assert benchmark_preset("quick")["max_cases"] == 100
    assert benchmark_preset("reference")["performance_plan"] == "performance/plans/llm-serving-v2.toml"


def make_suite(tmp_path: Path, *, status: str = "approved", review: str = "approved") -> Path:
    root = tmp_path / "suite"
    root.mkdir(parents=True)
    (root / "suite.toml").write_text(
        f'''protocol_version = "1.0.0"
name = "test"
version = "1.0.0"
status = "{status}"
description = "Test suite"
data_classification = "synthetic"
dataset = "dataset.jsonl"
rubric = "rubric.md"
[[gates]]
metric = "pass_rate"
min = 1.0
'''
    )
    case = {
        "id": "one",
        "input": "Question",
        "category": "quality",
        "risk_domain": "quality",
        "severity": "low",
        "expected_behavior": "answer",
        "expected_behavior_reason": "A direct factual answer is required.",
        "review": {"status": review, "method": "test"},
        "source": {"project": "test"},
    }
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n")
    (root / "rubric.md").write_text("Judge correctly.")
    return root


def test_suite_name_cannot_escape_run_root(tmp_path: Path) -> None:
    root = make_suite(tmp_path)
    config = root / "suite.toml"
    config.write_text(config.read_text().replace('name = "test"', 'name = "../../escaped"'))

    with pytest.raises(ProtocolError, match="suite.name"):
        load_suite(root)

    assert not (tmp_path / "escaped").exists()


def test_suite_hashes_the_same_dataset_bytes_it_parses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = make_suite(tmp_path, status="candidate")
    dataset = root / "dataset.jsonl"
    original = dataset.read_bytes()
    changed_case = {**json.loads(original), "input": "Changed question"}
    changed = (json.dumps(changed_case) + "\n").encode()
    dataset.write_bytes(changed)
    config = root / "suite.toml"
    config.write_text(
        config.read_text().replace(
            'rubric = "rubric.md"\n',
            f'rubric = "rubric.md"\ndataset_sha256 = "{sha256_file(dataset)}"\nrubric_sha256 = "{sha256_file(root / "rubric.md")}"\n',
        )
    )
    dataset.write_bytes(original)
    original_read_jsonl = protocol_module._read_jsonl

    def mutate_after_parse(path: Path, raw: bytes | None = None) -> tuple[dict[str, object], ...]:
        rows = original_read_jsonl(path, raw)
        if path == dataset:
            dataset.write_bytes(changed)
        return rows

    monkeypatch.setattr(protocol_module, "_read_jsonl", mutate_after_parse)
    with pytest.raises(ProtocolError, match="dataset_sha256 does not match dataset"):
        load_suite(root)


def test_promotion_rejects_a_stale_suite_snapshot(tmp_path: Path) -> None:
    root = make_suite(tmp_path, status="approved")
    suite = load_suite(root)
    config = root / "suite.toml"
    config.write_text(config.read_text().replace('name = "test"', 'name = "changed"'))

    with pytest.raises(ProtocolError, match="suite changed after loading"):
        promote_suite(suite, "deprecated", actor="operator", evidence="ticket-1")

    assert 'status = "approved"' in config.read_text()


def test_official_suite_is_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ProtocolError, match="suite.status=approved"):
        load_suite(make_suite(tmp_path, status="candidate"), official=True)


@pytest.mark.parametrize("official", [False, True])
@pytest.mark.parametrize("in_messages", [False, True])
def test_suite_rejects_actual_image_modality_missing_from_profile_and_capabilities(
    tmp_path: Path, official: bool, in_messages: bool
) -> None:
    root = make_suite(tmp_path)
    asset = root / "pixel.png"
    asset.write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="))
    case = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    image = {
        "type": "image",
        "asset": asset.name,
        "mime_type": "image/png",
        "sha256": sha256_file(asset),
        "license": "test-only",
        "origin": "synthetic-test",
        "personal_data": "none",
    }
    if in_messages:
        case["messages"] = [
            {"role": "user", "content": [image]},
            {"role": "assistant", "content": "Acknowledged."},
            {"role": "user", "content": case["input"]},
        ]
    else:
        case["input"] = [image]
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    config = root / "suite.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "[[gates]]",
            'profile = "text-generation"\n[target]\nkind = "json"\ncapabilities = ["text"]\n[[gates]]',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ProtocolError) as caught:
        load_suite(root, official=official)

    assert "input modalities are not supported by suite.profile 'text-generation': ['image']" in str(caught.value)
    assert "input modalities are missing from target.capabilities: ['image']" in str(caught.value)


def test_official_media_suite_requires_capability_verified_judge_adapter(tmp_path: Path) -> None:
    root = make_suite(tmp_path)
    asset = root / "pixel.png"
    asset.write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="))
    case = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    case["input"] = [
        {
            "type": "image",
            "asset": asset.name,
            "mime_type": "image/png",
            "sha256": sha256_file(asset),
            "license": "test-only",
            "origin": "synthetic-test",
            "personal_data": "none",
        }
    ]
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    config = root / "suite.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "[[gates]]",
            'profile = "image-to-text"\n[target]\nkind = "json"\ncapabilities = ["image"]\n[[gates]]',
        ),
        encoding="utf-8",
    )

    load_suite(root)
    with pytest.raises(ProtocolError, match="capability-verifying, qualification-bound judge adapter"):
        load_suite(root, official=True)


def test_official_suite_rejects_unpinned_deepeval_engine(tmp_path: Path) -> None:
    loaded = load_suite(make_suite(tmp_path, status="approved"))
    suite = Suite(
        loaded.root,
        {**loaded.config, "metrics": {"deepeval": [{"name": "exact_match", "threshold": 1.0}]}},
        tuple({**case, "expected_output": "expected"} for case in loaded.cases),
        loaded.rubric,
        loaded.dataset_path,
        loaded.rubric_path,
    )

    assert any("do not support unpinned DeepEval" in error for error in validate_suite(suite, official=True))


def test_official_suite_requires_pinned_semantic_contamination_evidence(tmp_path: Path) -> None:
    with pytest.raises(ProtocolError) as caught:
        load_suite(make_suite(tmp_path, status="approved"), official=True)
    assert "passed semantic contamination review" in str(caught.value)


def test_official_suite_rejects_unreviewed_cases(tmp_path: Path) -> None:
    with pytest.raises(ProtocolError, match="all cases approved"):
        load_suite(make_suite(tmp_path, status="approved", review="needs_review"), official=True)


def test_near_duplicate_scan_skips_impossible_alignments(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = make_suite(tmp_path, status="candidate")
    config = root / "suite.toml"
    config.write_text(
        config.read_text(encoding="utf-8") + "\n[governance]\nnear_duplicate_threshold = 0.92\nsemantic_duplicate_threshold = 0.95\n",
        encoding="utf-8",
    )
    first = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    second = {**first, "id": "two", "input": "ZZZZZZZZ"}
    (root / "dataset.jsonl").write_text("\n".join(map(json.dumps, (first, second))) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        "cavada_eval.protocol.difflib.SequenceMatcher",
        lambda *_args, **_kwargs: pytest.fail("impossible matches must be rejected by the cheap upper bound"),
    )

    assert len(load_suite(root).cases) == 2


def test_official_run_rejects_code_from_a_different_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite = load_suite(make_suite(tmp_path))
    monkeypatch.setattr("cavada_eval.runner.__file__", str(tmp_path / "wheel" / "cavada_eval" / "runner.py"))

    with pytest.raises(ProtocolError, match="executed cavada_eval package"):
        run(
            suite,
            repo_root=Path(__file__).parents[1],
            endpoint="http://127.0.0.1/target",
            model_label="target",
            expected_model="target-real",
            model_revision="target-revision",
            request_model=None,
            judge_endpoint="http://127.0.0.1/judge",
            judge_model="judge",
            expected_judge_model="judge-real",
            judge_revision="judge-revision",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=5,
            official=True,
            allow_external_judge=False,
        )


def test_official_semantic_contamination_evidence_hash_is_verified(tmp_path: Path) -> None:
    root = make_suite(tmp_path, status="approved")
    (root / "semantic-evidence.json").write_text("{}")
    with (root / "suite.toml").open("a") as handle:
        handle.write(
            '\n[dataset_integrity]\nsemantic_review_status = "passed"\nsemantic_review_evidence = "semantic-evidence.json"\n'
            f'semantic_review_evidence_sha256 = "{"0" * 64}"\nsemantic_detector = "detector"\n'
            'semantic_detector_revision = "revision"\ncross_split_reviewed = true\ncross_suite_reviewed = true\n'
        )
    with pytest.raises(ProtocolError, match="evidence hash mismatch"):
        load_suite(root, official=True)


def test_semantic_contamination_secondary_evidence_is_hash_linked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite = load_suite(make_suite(tmp_path, status="candidate"))
    secondary: dict[str, Path] = {}
    for name in ("comparison-corpus", "candidate-pairs", "reviewer-evidence"):
        secondary[name] = suite.root / f"{name}.json"
        secondary[name].write_text(json.dumps({"evidence": name}))
    evidence = {
        "evidence_version": "2.0.0",
        "dataset_sha256": sha256_file(suite.dataset_path),
        "comparison_corpus": secondary["comparison-corpus"].name,
        "comparison_corpus_sha256": sha256_file(secondary["comparison-corpus"]),
        "detector": "detector",
        "detector_revision": "revision",
        "detector_license": "test",
        "similarity_metric": "cosine",
        "threshold": 0.9,
        "cases": len(suite.cases),
        "candidate_pairs": 0,
        "candidate_pairs_evidence": secondary["candidate-pairs"].name,
        "candidate_pairs_evidence_sha256": sha256_file(secondary["candidate-pairs"]),
        "confirmed_duplicates": 0,
        "cross_split_reviewed": True,
        "cross_suite_reviewed": True,
        "reviewer_evidence": secondary["reviewer-evidence"].name,
        "reviewer_evidence_sha256": sha256_file(secondary["reviewer-evidence"]),
        "independent_review_status": "passed",
        "performed_at": "2026-08-05T00:00:00Z",
        "passed": True,
    }
    evidence_path = suite.root / "semantic-evidence.json"
    evidence_path.write_text(json.dumps(evidence))
    integrity = {
        "semantic_review_evidence": evidence_path.name,
        "semantic_review_evidence_sha256": sha256_file(evidence_path),
        "semantic_detector": "detector",
        "semantic_detector_revision": "revision",
    }
    assert not _semantic_integrity_errors(suite, integrity)
    secondary["comparison-corpus"].write_text('{"tampered":true}')
    assert "official semantic comparison corpus hash mismatch" in _semantic_integrity_errors(suite, integrity)
    secondary["comparison-corpus"].write_text(json.dumps({"evidence": "comparison-corpus"}))

    invalid_evidence = {**evidence, "passed": False}
    evidence_path.write_text(json.dumps(invalid_evidence))
    integrity["semantic_review_evidence_sha256"] = sha256_file(evidence_path)
    original_sha256_file = protocol_module.sha256_file

    def replace_after_hash(path: Path) -> str:
        digest = original_sha256_file(path)
        if path == evidence_path:
            evidence_path.write_text(json.dumps(evidence))
        return digest

    monkeypatch.setattr(protocol_module, "sha256_file", replace_after_hash)
    assert "official semantic contamination evidence did not pass" in _semantic_integrity_errors(suite, integrity)


def test_suite_calibration_and_independent_approval_are_hash_linked(tmp_path: Path) -> None:
    suite = load_suite(make_suite(tmp_path, status="candidate"))
    evidence_paths: dict[str, Path] = {}
    for name in ("analysis-plan", "human-labels", "holdout", "pilot-audit", "statistical-review", "semantic-evidence", "approver-qualification"):
        evidence_paths[name] = suite.root / f"{name}.json"
        evidence_paths[name].write_text(json.dumps({"evidence": name}))
    semantic_hash = sha256_file(evidence_paths["semantic-evidence"])
    suite.config["dataset_integrity"] = {
        "semantic_review_evidence": evidence_paths["semantic-evidence"].name,
        "semantic_review_evidence_sha256": semantic_hash,
    }
    report = {
        "calibration_version": "2.0.0",
        "status": "passed",
        "protocol_version": "1.0.0",
        "suite": {
            "name": suite.name,
            "version": suite.version,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
        },
        "source_commit": "1" * 40,
        "analysis_plan": evidence_paths["analysis-plan"].name,
        "analysis_plan_sha256": sha256_file(evidence_paths["analysis-plan"]),
        "human_label_evidence": evidence_paths["human-labels"].name,
        "human_label_evidence_sha256": sha256_file(evidence_paths["human-labels"]),
        "holdout_manifest": evidence_paths["holdout"].name,
        "holdout_manifest_sha256": sha256_file(evidence_paths["holdout"]),
        "pilot_audit": evidence_paths["pilot-audit"].name,
        "pilot_audit_sha256": sha256_file(evidence_paths["pilot-audit"]),
        "statistical_review": evidence_paths["statistical-review"].name,
        "statistical_review_sha256": sha256_file(evidence_paths["statistical-review"]),
        "semantic_contamination_evidence": evidence_paths["semantic-evidence"].name,
        "semantic_contamination_evidence_sha256": semantic_hash,
        "gates_passed": True,
        "results": {"all_preregistered_gates": "passed"},
        "completed_at": "2026-08-04T00:00:00Z",
        "limitations": ["Valid only for the declared measurement target."],
    }
    report_path = suite.root / "calibration.json"
    report_path.write_text(json.dumps(report))
    approval = {
        "approval_version": "2.0.0",
        "approval_id": "approval-1",
        "scope": "suite-calibration",
        "status": "passed",
        "independent": True,
        "calibration_sha256": sha256_file(report_path),
        "approver_id": "reviewer",
        "approver_qualification_evidence": evidence_paths["approver-qualification"].name,
        "approver_qualification_evidence_sha256": sha256_file(evidence_paths["approver-qualification"]),
        "conflicts": "none declared",
        "decision_rationale": "The calibration evidence supports the declared scope.",
        "approved_at": "2026-08-04T00:00:00Z",
        "expires_at": "2027-08-04T00:00:00Z",
    }
    approval_path = suite.root / "calibration-approval.json"
    approval_path.write_text(json.dumps(approval))
    calibration = {
        "status": "passed",
        "evidence": report_path.name,
        "evidence_sha256": sha256_file(report_path),
        "independent_review": "passed",
        "independent_review_evidence": approval_path.name,
        "independent_review_evidence_sha256": sha256_file(approval_path),
    }
    now = datetime(2026, 8, 5, tzinfo=timezone.utc)
    assert not _calibration_evidence_errors(suite, calibration, now=now)
    original_analysis_plan = evidence_paths["analysis-plan"].read_text()
    evidence_paths["analysis-plan"].write_text('{"tampered":true}')
    assert "official calibration analysis plan hash mismatch" in _calibration_evidence_errors(suite, calibration, now=now)
    evidence_paths["analysis-plan"].write_text(original_analysis_plan)
    approval["calibration_sha256"] = "0" * 64
    approval_path.write_text(json.dumps(approval))
    calibration["independent_review_evidence_sha256"] = sha256_file(approval_path)
    assert "official calibration independent approval is incomplete, unlinked, or did not pass" in _calibration_evidence_errors(
        suite, calibration, now=now
    )


def test_doctor_fails_when_required_repository_resources_are_missing(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "uv.lock").touch()
    assert _doctor(tmp_path)["ready"] is False


@pytest.mark.parametrize(("field", "message"), [("tags", "valid tags"), ("source", "source and review method")])
def test_official_case_governance_requires_nonempty_provenance(tmp_path: Path, field: str, message: str) -> None:
    root = tmp_path / "suite"
    shutil.copytree("suites/template", root)
    config = root / "suite.toml"
    config.write_text(config.read_text().replace('status = "draft"', 'status = "approved"'))
    case = json.loads((root / "dataset.jsonl").read_text())
    case["review"]["status"] = "approved"
    case[field] = [] if field == "tags" else {"origin": ""}
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n")
    with pytest.raises(ProtocolError, match=message):
        load_suite(root, official=True)


def test_duplicate_cases_are_rejected(tmp_path: Path) -> None:
    root = make_suite(tmp_path)
    row = (root / "dataset.jsonl").read_text()
    (root / "dataset.jsonl").write_text(row + row)
    with pytest.raises(ProtocolError, match="duplicate case id"):
        load_suite(root)


def test_near_duplicates_require_a_shared_scenario_group(tmp_path: Path) -> None:
    root = make_suite(tmp_path)
    config = root / "suite.toml"
    config.write_text(config.read_text() + "\n[governance]\nnear_duplicate_threshold = 0.9\n")
    first = json.loads((root / "dataset.jsonl").read_text())
    first["scenario_group_id"] = "paired-1"
    second = {**first, "id": "two", "input": "Question!", "scenario_group_id": "paired-1"}
    (root / "dataset.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    assert len(load_suite(root).cases) == 2

    second["scenario_group_id"] = "independent-2"
    (root / "dataset.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    with pytest.raises(ProtocolError, match="near-duplicate case inputs"):
        load_suite(root)


def test_token_containment_duplicates_are_reported_without_blocking_draft_load(tmp_path: Path) -> None:
    root = make_suite(tmp_path)
    first = json.loads((root / "dataset.jsonl").read_text())
    first["input"] = "Question about alpha beta gamma"
    second = {**first, "id": "two", "input": "Separate practice question about alpha beta gamma"}
    (root / "dataset.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    candidates = semantic_duplicate_candidates(load_suite(root))
    assert candidates == [{"left": "one", "right": "two", "token_containment": 1.0}]


def test_secret_like_dataset_content_is_rejected(tmp_path: Path) -> None:
    root = make_suite(tmp_path)
    path = root / "dataset.jsonl"
    path.write_text(path.read_text().replace("Question", "sk-" + "a" * 26))
    with pytest.raises(ProtocolError, match="secret-like"):
        load_suite(root)


def test_preflight_rejects_invalid_regex_gate_and_metric_engine_config(tmp_path: Path) -> None:
    regex_root = make_suite(tmp_path / "regex")
    case = json.loads((regex_root / "dataset.jsonl").read_text())
    case["required_regex"] = ["["]
    (regex_root / "dataset.jsonl").write_text(json.dumps(case) + "\n")
    with pytest.raises(ProtocolError, match=r"required_regex\[1\].*valid regular expression"):
        load_suite(regex_root)

    gate_root = make_suite(tmp_path / "gate")
    gate_config = gate_root / "suite.toml"
    gate_config.write_text(gate_config.read_text().replace('metric = "pass_rate"', 'metric = "missing.value"'))
    with pytest.raises(ProtocolError, match=r"gate\[1\]\.metric"):
        load_suite(gate_root)

    metric_root = make_suite(tmp_path / "metric")
    metric_config = metric_root / "suite.toml"
    metric_config.write_text(metric_config.read_text() + '\n[metrics]\ndeepeval = [{name = "toxicity"}]\n')
    with pytest.raises(ProtocolError, match="identity- and destination-verifying judge adapter"):
        load_suite(metric_root)


def test_judge_output_must_be_strict() -> None:
    parsed, _ = _judge_result({"choices": [{"message": {"content": '{"verdict":"pass","score":5,"reason":"ok","criteria":{}}'}}]})
    assert parsed["verdict"] == "pass"
    with pytest.raises(ProtocolError):
        _judge_result({"choices": [{"message": {"content": "PASS"}}]})
    with pytest.raises(ProtocolError, match="exactly"):
        _judge_result({"choices": [{"message": {"content": '{"verdict":"pass","score":5,"reason":"ok"}'}}]})
    with pytest.raises(ProtocolError, match="criteria must be an object"):
        _judge_result({"choices": [{"message": {"content": '{"verdict":"pass","score":5,"reason":"ok","criteria":[]}'}}]})


def test_wilson_interval_and_immutable_run_paths(tmp_path: Path) -> None:
    low, high = wilson_interval(10, 10)
    assert 0 < low < high <= 1
    suite = load_suite(make_suite(tmp_path / "suite-root"))
    first = new_run_dir(tmp_path, suite, "model")[1]
    second = new_run_dir(tmp_path, suite, "model")[1]
    assert first != second and first.is_dir() and second.is_dir()

    finalized = tmp_path / "finished-run"
    finalized.mkdir()
    (finalized / "bundle.json").write_text("{}", encoding="utf-8")
    nested_output = finalized / "nested-output"
    with pytest.raises(ProtocolError, match="outside finalized run"):
        new_run_dir(nested_output, suite, "model")
    assert not nested_output.exists()


def test_repetitions_do_not_inflate_case_count() -> None:
    metrics, _ = summarize(
        [
            {"case_id": "one", "category": "quality", "status": "pass"},
            {"case_id": "one", "category": "quality", "status": "pass"},
            {"case_id": "two", "category": "quality", "status": "fail"},
        ]
    )
    assert metrics["total"] == 2
    assert metrics["observations"] == 3
    assert metrics["pass_rate"] == 0.5


def test_core_suite_development_case_executes_and_category_ci_gate_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loaded = load_suite(Path("suites/cavada-core-assistant-text-v1"))
    case = loaded.cases[0]
    assert case["review"]["status"] == "needs_review"
    calls: list[str] = []

    def target_stub(*_args: object, **_kwargs: object) -> tuple[object, ...]:
        calls.append("target")
        raw = {
            "model": "target-real",
            "choices": [{"message": {"content": "AMBER"}}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 1},
        }
        return "AMBER", raw, "target-real", {"model": "target-request"}, {
            "request_id": "target-request",
            "total_ms": 1.0,
            "headers_ms": 0.5,
            "response_bytes": 64,
        }

    def judge_stub(*_args: object, **_kwargs: object) -> tuple[object, ...]:
        calls.append("judge")
        judgment = {"verdict": "pass", "score": 5, "reason": "criterion satisfied", "criteria": {}}
        raw = {"model": "judge-real", "choices": [{"message": {"content": json.dumps(judgment)}}]}
        return judgment, raw, json.dumps(judgment), {"model": "judge-request"}, {
            "request_id": "judge-request",
            "total_ms": 1.0,
            "headers_ms": 0.5,
            "response_bytes": 64,
        }

    monkeypatch.setattr("cavada_eval.runner.call_target", target_stub)
    monkeypatch.setattr("cavada_eval.runner.call_judge", judge_stub)

    def execute(candidate: Suite) -> Path:
        return run(
            candidate,
            repo_root=tmp_path,
            endpoint="http://127.0.0.1/target",
            model_label="target",
            expected_model="target-real",
            model_revision="target-revision",
            request_model="target-request",
            judge_endpoint="http://127.0.0.1/v1",
            judge_model="judge-request",
            expected_judge_model="judge-real",
            judge_revision="judge-revision",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=1,
            timeout=5,
            official=False,
            allow_external_judge=False,
        )

    run_dir = execute(loaded)
    assert calls == ["target", "judge"]
    result = json.loads((run_dir / "case_results.jsonl").read_text())
    assert result["status"] == "pass" and result["scenario_id"] == case["scenario_group_id"]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["parameters"]["case_review_policy"] == "approved-and-needs-review"
    instruction_gate = next(
        failure for failure in manifest["metrics"]["gate_failures"] if failure["category"] == "instruction-following"
    )
    assert isinstance(instruction_gate["actual"], float)
    _, categories = summarize([{"case_id": "one", "category": "instruction-following", "status": "pass"}])
    unit_failures = apply_gates(loaded, {}, categories)
    assert next(failure for failure in unit_failures if failure["category"] == "instruction-following")["actual"] is not None

    rejected_case = {**case, "review": {**case["review"], "status": "rejected"}}
    rejected_suite = Suite(
        loaded.root,
        loaded.config,
        (rejected_case, *loaded.cases[1:]),
        loaded.rubric,
        loaded.dataset_path,
        loaded.rubric_path,
    )
    calls.clear()
    with pytest.raises(ProtocolError, match="differs from the canonical validated suite"):
        execute(rejected_suite)
    assert calls == []


def test_manifest_endpoint_never_records_query_values() -> None:
    assert _manifest_endpoint("https://example.test/v1?api-version=1&token=secret") == ("https://example.test/v1?api-version=[redacted]&token=[redacted]")
    with pytest.raises(ProtocolError, match="credentials"):
        _manifest_endpoint("https://user:password@example.test/v1")


def test_end_to_end_run_writes_auditable_artifacts(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers["Content-Length"])
            payload = json.loads(self.rfile.read(length))
            if self.path.endswith("/chat/completions"):
                body = {
                    "model": "judge-real",
                    "choices": [{"message": {"content": '{"verdict":"pass","score":5,"reason":"supported","criteria":{}}'}}],
                }
            else:
                assert payload["message"] == "Question"
                body = {"answer": "Supported answer", "model": "target-real", "sources": []}
            encoded = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    suite_root = make_suite(tmp_path / "fixture")
    suite_toml = suite_root / "suite.toml"
    suite_toml.write_text(
        suite_toml.read_text()
        + '\n[target]\nkind = "json"\nrequest_field = "message"\nresponse_field = "answer"\nreported_model_field = "model"\nsources_field = "sources"\n'
    )
    suite = load_suite(suite_root)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        run_dir = run(
            suite,
            repo_root=tmp_path,
            endpoint=base + "/target",
            model_label="target",
            expected_model="target-real",
            model_revision="test-revision",
            request_model=None,
            judge_endpoint=base + "/v1",
            judge_model="judge-request",
            expected_judge_model="judge-real",
            judge_revision="judge-test-revision",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=5,
            official=False,
            allow_external_judge=False,
            non_inferiority_margin=0.05,
        )
    finally:
        server.shutdown()
        thread.join()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["status"] == "passed"
    assert manifest["target"]["expected_reported_model"] == "target-real"
    assert manifest["parameters"]["non_inferiority_margin"] == 0.05
    assert "--non-inferiority-margin 0.05" in manifest["reproduction_command"]
    assert base not in manifest["public_reproduction_command"]
    assert "MISSING_TARGET_KEY" not in manifest["public_reproduction_command"]
    assert "MISSING_JUDGE_KEY" not in manifest["public_reproduction_command"]
    assert {
        "requests.jsonl",
        "raw_responses.jsonl",
        "judgments.jsonl",
        "case_results.jsonl",
        "metrics.json",
        "category_results.csv",
        "failures.jsonl",
        "environment.json",
        "protocol_snapshot.md",
        "suite_snapshot.toml",
        "dataset_card.md",
        "report.html",
        "report.pdf",
        "report_public.html",
        "report_public.pdf",
        "summary.json",
        "junit.xml",
        "figures/overall_scores.svg",
        "figures/category_scores.svg",
        "figures/latency.svg",
    } <= set(manifest["artifacts"])
    assert verify_bundle(run_dir)["valid"] is True
    control_report = generate_control_report(
        run_dir,
        Path("standards/control_catalog.toml"),
        tmp_path / "control-report",
    )
    ai_record = next(item for item in control_report["controls"] if item["control_id"] == "AI-ACT-12")
    assert ai_record["source_application"].startswith("Generally applicable since 2026-08-02")


def test_imported_memo_semantic_regressions() -> None:
    dataset = Path("suites/memo4345-v1/dataset.jsonl")
    rows = {row["id"]: row for row in map(json.loads, dataset.read_text().splitlines())}
    assert rows["memo4345-0004"]["expected_behavior"] == "abstain"
    assert rows["memo4345-0361"]["expected_behavior"] == "safe_complete"
    assert rows["memo4345-0362"]["expected_behavior"] == "safe_complete"
    assert rows["memo4345-0812"]["expected_behavior"] == "safe_complete"
    assert rows["memo4345-0912"]["expected_behavior"] == "refuse"
