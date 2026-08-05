from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cavada_eval.annotations import export_annotation_package
from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.external import import_external_results
from cavada_eval.metrics import contains_pii_like, deterministic_evaluation, error_rate, normalize_text, retrieval_scores
from cavada_eval.pairwise import _winner
from cavada_eval.program import load_program_registry
from cavada_eval.protocol import ProtocolError, load_suite, sha256_file, wilson_gate_power
from cavada_eval.runner import _post_json, call_target, run
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


def test_program_registry_is_valid_and_rejects_duplicate_identity(tmp_path: Path) -> None:
    repo = Path.cwd()
    registry_path = repo / "program" / "registry.toml"
    registry = load_program_registry(registry_path, repo_root=repo)
    assert registry["summary"]["by_status"]["candidate"] == 2
    assert registry["summary"]["by_status"]["draft"] == 1
    assert registry["summary"]["by_status"]["planned"] == 15
    assert registry["summary"]["official_capable"] == 0
    assert registry["summary"]["sources"]["count"] == 24
    assert registry["summary"]["sources"]["by_official_use"]["blocked"] == 1

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


def test_external_import_is_pinned_and_verifiable(tmp_path: Path) -> None:
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
    assert import_external_results(source, output)["result_count"] == 1
    assert verify_bundle(output)["valid"] is True


def test_recorded_target_adapter_is_offline_and_pinned(tmp_path: Path) -> None:
    root = _suite(tmp_path)
    config = (root / "suite.toml").read_text(encoding="utf-8").replace('kind = "json"', 'kind = "recorded"\nresponses = "responses.jsonl"')
    (root / "suite.toml").write_text(config, encoding="utf-8")
    (root / "responses.jsonl").write_text(json.dumps({"case_id": "one", "answer": "Recorded answer", "model": "recorded-model"}) + "\n", encoding="utf-8")
    suite = load_suite(root)
    answer, _, reported, payload, transport = call_target(suite, "recorded://suite", "", {"case_id": "one", "input": "Question"}, None, 1)
    assert (answer, reported) == ("Recorded answer", "recorded-model")
    assert payload["source_sha256"] and transport["recorded"] is True


def test_annotation_package_is_blind_and_never_overwrites(tmp_path: Path) -> None:
    root = _suite(tmp_path)
    suite = load_suite(root)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text('{"target":{"label":"secret-model"}}\n', encoding="utf-8")
    (run_dir / "raw_responses.jsonl").write_text(
        json.dumps({"case_id": "one", "repetition": 1, "reported_model": "secret-model", "response": {"answer": "Anonymous answer", "model": "secret-model"}}) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "annotations"
    manifest = export_annotation_package(suite, run_dir, output)
    annotation = json.loads((output / "annotations.jsonl").read_text(encoding="utf-8"))
    public_text = json.dumps(annotation) + (output / "package_manifest.json").read_text(encoding="utf-8")
    assert manifest["identity_blinded"] is True and "Anonymous answer" in public_text
    assert "secret-model" not in public_text and "split" not in annotation
    try:
        export_annotation_package(suite, run_dir, output)
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
    (root / "system.txt").write_text("Fixed system prompt.\n", encoding="utf-8")
    config = (root / "suite.toml").read_text(encoding="utf-8").replace(
        'kind = "json"', 'kind = "openai"\nsystem_prompt = "system.txt"'
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
        def do_POST(self) -> None:  # noqa: N802
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path.endswith("/chat/completions"):
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
    (root / "dataset.jsonl").write_text(json.dumps(calibration_case) + "\n", encoding="utf-8")
    (root / "suite.toml").write_text(
        (root / "suite.toml").read_text(encoding="utf-8")
        + '\n[judge]\nconsensus = "unanimous"\nminimum_calibration_accuracy = 1.0\nadditional_models = [{model="judge-secondary", expected_model="judge-secondary-real", revision="secondary-rev"}]\n',
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


def test_resume_completes_an_unfinalized_run_without_duplicates(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        calls = 0

        def do_POST(self) -> None:  # noqa: N802
            Handler.calls += 1
            length = int(self.headers["Content-Length"])
            self.rfile.read(length)
            if self.path.endswith("/chat/completions"):
                body = {"model": "judge-real", "choices": [{"message": {"content": '{"verdict":"pass","score":5,"reason":"ok"}'}}]}
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

    suite = load_suite(_suite(tmp_path))
    run_dir = tmp_path / "runs" / "extended" / "interrupted"
    run_dir.mkdir(parents=True)
    manifest = {
        "protocol_version": "1.0.0",
        "schema_version": "1.0.0",
        "report_version": "1.0.0",
        "run_id": "interrupted",
        "status": "running",
        "official_requested": False,
        "started_at": "2026-08-03T00:00:00+00:00",
        "suite": {
            "name": suite.name,
            "version": suite.version,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
        },
        "target": {"label": "target", "expected_reported_model": "target-real", "revision": "target-rev", "request_model": None},
        "judge": {"requested_model": "judge", "expected_reported_model": "judge-real", "revision": "judge-rev"},
        "parameters": {"mode": "candidate", "repetitions": 1, "judge_repetitions": 1, "max_cases": 0, "timeout_seconds": 5},
        "source": {},
        "environment": {},
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    for name in ("requests.jsonl", "raw_responses.jsonl", "judgments.jsonl", "case_results.jsonl", "failures.jsonl"):
        (run_dir / name).write_text("", encoding="utf-8")
    (run_dir / "raw_responses.jsonl").write_text(
        json.dumps(
            {
                "case_id": "one",
                "repetition": 1,
                "reported_model": "target-real",
                "response": {"answer": "Answer", "model": "target-real"},
                "transport": {"request_id": "prior-target", "total_ms": 1, "headers_ms": 1, "response_bytes": 10},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "judgments.jsonl").write_text(
        json.dumps(
            {
                "case_id": "one",
                "repetition": 1,
                "judge_repetition": 1,
                "reported_model": "judge-real",
                "judgment": {"verdict": "pass", "score": 5, "reason": "ok", "criteria": {}},
            }
        )
        + "\n",
        encoding="utf-8",
    )

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
            resume_dir=run_dir,
        )
    finally:
        server.shutdown()
        thread.join()
    rows = [json.loads(line) for line in (output / "case_results.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1 and rows[0]["status"] == "pass"
    final = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert final["status"] == "passed" and len(final["resumed_at"]) == 1
    assert Handler.calls == 0
