from __future__ import annotations

import json
import shutil
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from pypdf import PdfReader

from cavada_eval.artifacts import verify_bundle
from cavada_eval.cli import _doctor
from cavada_eval.compliance import generate_control_report
from cavada_eval.profiles import benchmark_preset, canonical_preset, stratified_cases
from cavada_eval.protocol import (
    ProtocolError,
    _calibration_evidence_errors,
    apply_gates,
    deterministic_checks,
    environment_evidence,
    load_suite,
    new_run_dir,
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


def test_security_gate_can_target_a_severity_slice(tmp_path: Path) -> None:
    suite = load_suite(make_suite(tmp_path))
    suite.config["gates"] = [{"slice": "severity", "value": "critical", "metric": "pass_rate", "min": 1.0}]
    metrics = {"slices": {"severity": {"critical": {"pass_rate": 0.5}}}}

    assert apply_gates(suite, metrics, []) == [
        {"category": "severity:critical", "metric": "pass_rate", "minimum": 1.0, "actual": 0.5}
    ]
    suite.config["gates"] = [{"slice": "severity", "metric": "pass_rate", "min": 1.0}]
    assert "gates[0] slice gates require both slice and value" in validate_suite(suite)


def test_environment_evidence_records_amd_inventory_without_serials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "gpu_data": [
            {
                "gpu": 0,
                "asic": {
                    "market_name": "Radeon RX 7900 XTX",
                    "target_graphics_version": "gfx1100",
                    "subsystem_id": "0x7901",
                    "asic_serial": "private-serial",
                },
                "vram": {"size": {"value": 24560, "unit": "MB"}},
            }
        ]
    }
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}" if name == "amd-smi" else None)
    monkeypatch.setattr("cavada_eval.protocol.platform.platform", lambda: "test-platform")
    monkeypatch.setattr(
        "cavada_eval.protocol.subprocess.run",
        lambda *_args, **_kwargs: type("Result", (), {"returncode": 0, "stdout": json.dumps(payload)})(),
    )

    hardware = environment_evidence(tmp_path)["hardware"]
    assert hardware["gpu_inventory_source"] == "amd-smi"
    assert hardware["gpus"] == ["Radeon RX 7900 XTX, gfx1100, 24560 MB, subsystem 0x7901"]
    assert "private-serial" not in json.dumps(hardware)


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


def test_official_suite_is_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ProtocolError, match="suite.status=approved"):
        load_suite(make_suite(tmp_path, status="candidate"), official=True)


def test_official_suite_requires_pinned_semantic_contamination_evidence(tmp_path: Path) -> None:
    with pytest.raises(ProtocolError) as caught:
        load_suite(make_suite(tmp_path, status="approved"), official=True)
    assert "passed semantic contamination review" in str(caught.value)


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


def test_suite_calibration_and_independent_approval_are_hash_linked(tmp_path: Path) -> None:
    suite = load_suite(make_suite(tmp_path, status="candidate"))
    semantic_hash = "9" * 64
    suite.config["dataset_integrity"] = {"semantic_review_evidence_sha256": semantic_hash}
    report = {
        "calibration_version": "1.0.0",
        "status": "passed",
        "protocol_version": "1.0.0",
        "suite": {
            "name": suite.name,
            "version": suite.version,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
        },
        "source_commit": "1" * 40,
        "analysis_plan_sha256": "2" * 64,
        "human_label_evidence_sha256": "3" * 64,
        "holdout_manifest_sha256": "4" * 64,
        "pilot_audit_sha256": "5" * 64,
        "statistical_review_sha256": "6" * 64,
        "semantic_contamination_evidence_sha256": semantic_hash,
        "gates_passed": True,
        "results": {"all_preregistered_gates": "passed"},
        "completed_at": "2026-08-04T00:00:00Z",
        "limitations": ["Valid only for the declared measurement target."],
    }
    report_path = suite.root / "calibration.json"
    report_path.write_text(json.dumps(report))
    approval = {
        "approval_version": "1.0.0",
        "approval_id": "approval-1",
        "scope": "suite-calibration",
        "status": "passed",
        "independent": True,
        "calibration_sha256": sha256_file(report_path),
        "approver_id": "reviewer",
        "approver_qualification_evidence": "restricted-reference",
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


def test_judge_output_must_be_strict() -> None:
    parsed, _ = _judge_result({"choices": [{"message": {"content": '{"verdict":"pass","score":5,"reason":"ok"}'}}]})
    assert parsed["verdict"] == "pass"
    with pytest.raises(ProtocolError):
        _judge_result({"choices": [{"message": {"content": "PASS"}}]})


def test_deterministic_checks_cannot_be_overridden() -> None:
    checks = deterministic_checks({"required_terms": ["citation"], "forbidden_terms": ["secret"]}, "No evidence")
    assert checks == {
        "non_empty": True,
        "no_secret_like_output": True,
        "required_terms": False,
        "forbidden_terms": True,
    }


def test_wilson_interval_and_immutable_run_paths(tmp_path: Path) -> None:
    low, high = wilson_interval(10, 10)
    assert 0 < low < high <= 1
    suite = load_suite(make_suite(tmp_path / "suite-root"))
    first = new_run_dir(tmp_path, suite, "model")[1]
    second = new_run_dir(tmp_path, suite, "model")[1]
    assert first != second and first.is_dir() and second.is_dir()


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
                    "choices": [{"message": {"content": '{"verdict":"pass","score":5,"reason":"supported"}'}}],
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
        )
    finally:
        server.shutdown()
        thread.join()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["status"] == "passed"
    assert manifest["target"]["expected_reported_model"] == "target-real"
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
    report = PdfReader(run_dir / "report.pdf")
    report_text = "".join(page.extract_text() or "" for page in report.pages)
    assert len(report.pages) >= 2 and "Executive interpretation" in report_text and "Evidence metadata" in report_text
    control_report = generate_control_report(
        run_dir,
        Path("standards/control_catalog.toml"),
        tmp_path / "control-report",
    )
    ai_record = next(item for item in control_report["controls"] if item["control_id"] == "AI-ACT-12")
    assert ai_record["source_application"].startswith("Generally applicable since 2026-08-02")
