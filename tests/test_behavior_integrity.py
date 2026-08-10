from __future__ import annotations

import io
import json
import threading
import time
from datetime import datetime, timezone
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from cavada_eval.protocol import ProtocolError, Suite, append_jsonl, atomic_json, load_suite, sha256_bytes, sha256_file, validate_suite
from cavada_eval.runner import (
    _behavior_reconciliation,
    _evidence_object,
    _external_authorization,
    _JudgeOutputError,
    _official_endpoint,
    _official_revision,
    _post_json,
    _post_openai_stream,
    _ResponseError,
    _TransportError,
    _usage_tokens,
    run,
)


class _Response(io.BytesIO):
    status = 200

    def __init__(self, body: bytes, content_type: str) -> None:
        super().__init__(body)
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _suite(tmp_path: Path) -> Path:
    root = tmp_path / "suite"
    root.mkdir()
    (root / "suite.toml").write_text(
        '''protocol_version = "1.0.0"
name = "integrity"
version = "1.0.0"
status = "candidate"
description = "Integrity test"
data_classification = "synthetic"
dataset = "dataset.jsonl"
rubric = "rubric.md"
[[gates]]
metric = "pass_rate"
min = 1.0
'''
    )
    (root / "dataset.jsonl").write_text(
        json.dumps(
            {
                "id": "one",
                "input": "Question",
                "category": "quality",
                "risk_domain": "quality",
                "severity": "low",
                "expected_behavior": "answer",
                "expected_behavior_reason": "Answer.",
                "review": {"status": "approved", "method": "test"},
                "source": {"origin": "test"},
            }
        )
        + "\n"
    )
    (root / "rubric.md").write_text("Judge correctly.")
    return root


def _candidate_run(suite: Suite, tmp_path: Path, *, model_label: str = "target") -> Path:
    return run(
        suite,
        repo_root=tmp_path,
        endpoint="http://127.0.0.1/target",
        model_label=model_label,
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
        timeout=1,
        official=False,
        allow_external_judge=False,
    )


def test_json_evidence_writers_reject_non_finite_numbers(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        atomic_json(tmp_path / "value.json", {"value": float("nan")})
    assert not (tmp_path / "value.json").exists()
    path = tmp_path / "value.jsonl"
    path.touch()
    with pytest.raises(ValueError):
        append_jsonl(path, {"value": float("inf")})
    assert path.read_text() == ""


def test_non_finite_target_json_is_preserved_as_response_error_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = load_suite(_suite(tmp_path))
    body = b'{"answer":"Answer","model":"target-real","value":NaN}'
    monkeypatch.setattr("cavada_eval.runner._urlopen", lambda *_args: _Response(body, "application/json"))
    monkeypatch.setattr("cavada_eval.runner.call_judge", lambda *_args, **_kwargs: pytest.fail("judge contacted"))

    output = _candidate_run(suite, tmp_path)

    response = json.loads((output / "raw_responses.jsonl").read_text(encoding="utf-8"))
    result = json.loads((output / "case_results.jsonl").read_text(encoding="utf-8"))
    events = [json.loads(line) for line in (output / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    started, finished = (next(event for event in events if event["event"] == name) for name in ("observation_started", "observation_finished"))
    assert response["status"] == result["status"] == "error"
    assert response["response"]["body_sha256"] == sha256_bytes(body)
    assert "Non-JSON response" in response["error"]
    assert result["duration_ms"] == round((finished["monotonic_ns"] - started["monotonic_ns"]) / 1_000_000, 1)
    assert (output / "bundle.json").is_file()


def test_non_finite_stream_event_is_strictly_rejected_with_wire_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'data: {"model":"target-real","choices":[{"delta":{"content":"part"}}],"usage":{"prompt_tokens":NaN}}\n\n'
    monkeypatch.setattr("cavada_eval.runner._urlopen", lambda *_args: _Response(body, "text/event-stream"))

    with pytest.raises(_ResponseError, match="invalid JSON") as caught:
        _post_openai_stream(
            "http://127.0.0.1/chat/completions",
            {"model": "target", "stream": True},
            "",
            1,
            request_id="strict-stream",
        )

    assert caught.value.raw is not None
    assert caught.value.raw["stream_body_sha256"] == sha256_bytes(body.splitlines(keepends=True)[0])
    assert caught.value.raw["stream_events"] == []
    assert caught.value.transport["request_id"] == "strict-stream"


def test_non_finite_judgment_is_invalid_and_run_finalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = load_suite(_suite(tmp_path))
    content = '{"verdict":"pass","score":5,"reason":"ok","criteria":{"quality":NaN}}'
    raw = {"model": "judge-real", "choices": [{"message": {"content": content}}]}
    monkeypatch.setattr(
        "cavada_eval.runner.call_target",
        lambda *_args, **_kwargs: (
            "Answer",
            {"model": "target-real", "answer": "Answer"},
            "target-real",
            {"message": "Question"},
            {"request_id": "target-request", "attempts": 1},
        ),
    )
    monkeypatch.setattr(
        "cavada_eval.runner._post_json",
        lambda *_args, **_kwargs: (raw, {"request_id": "judge-request", "attempts": 1}),
    )

    output = _candidate_run(suite, tmp_path)

    judgment = json.loads((output / "judgments.jsonl").read_text(encoding="utf-8"))
    result = json.loads((output / "case_results.jsonl").read_text(encoding="utf-8"))
    assert judgment["status"] == result["status"] == "invalid"
    assert "strict JSON" in judgment["error"]
    assert judgment["raw"]["choices"][0]["message"]["content"] == content
    assert (output / "bundle.json").is_file()


def test_post_redirect_is_not_followed() -> None:
    class Destination(BaseHTTPRequestHandler):
        calls = 0

        def do_POST(self) -> None:  # noqa: N802
            Destination.calls += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    destination = ThreadingHTTPServer(("127.0.0.1", 0), Destination)

    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(307)
            self.send_header("Location", f"http://localhost:{destination.server_port}/collect")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (destination, redirect)]
    for thread in threads:
        thread.start()
    try:
        with pytest.raises(_TransportError, match="HTTP 307"):
            _post_json(
                f"http://127.0.0.1:{redirect.server_port}/start",
                {"test": True},
                "",
                2,
                request_id="redirect-test",
            )
    finally:
        for server in (redirect, destination):
            server.shutdown()
        for thread in threads:
            thread.join()
    assert Destination.calls == 0


def test_official_endpoint_and_runtime_numbers_fail_closed(tmp_path: Path) -> None:
    for endpoint in ("https://example.test/v1?token=secret", "https://example.test/v1?", "https://example.test/v1#"):
        with pytest.raises(ProtocolError, match="query or fragment"):
            _official_endpoint(endpoint)
    suite = load_suite(_suite(tmp_path))
    with pytest.raises(ProtocolError, match="finite"):
        run(
            suite,
            repo_root=tmp_path,
            endpoint="http://127.0.0.1/target",
            model_label="target",
            expected_model="target",
            model_revision="revision",
            request_model=None,
            judge_endpoint="http://127.0.0.1/judge",
            judge_model="judge",
            expected_judge_model="judge",
            judge_revision="revision",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=float("nan"),
            official=False,
            allow_external_judge=False,
        )


def test_credentials_are_never_dispatched_over_remote_plaintext_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite = load_suite(_suite(tmp_path))
    monkeypatch.setenv("TARGET_TEST_KEY", "test-secret-value")
    monkeypatch.setattr("cavada_eval.runner.call_target", lambda *_args, **_kwargs: pytest.fail("network contacted"))

    with pytest.raises(ProtocolError, match="credentials require HTTPS"):
        run(
            suite,
            repo_root=tmp_path,
            endpoint="http://target.example/v1",
            model_label="target",
            expected_model="target-real",
            model_revision="target-revision",
            request_model=None,
            judge_endpoint="http://127.0.0.1/judge",
            judge_model="judge",
            expected_judge_model="judge-real",
            judge_revision="judge-revision",
            target_key_env="TARGET_TEST_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=1,
            official=False,
            allow_external_judge=False,
        )

    assert not (tmp_path / "runs").exists()


def test_run_rejects_mutated_suite_object_before_output_or_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite = load_suite(_suite(tmp_path))
    suite.config["description"] = "mutated after validation"
    monkeypatch.setattr("cavada_eval.runner.call_target", lambda *_args, **_kwargs: pytest.fail("network contacted"))

    with pytest.raises(ProtocolError, match="differs from the canonical validated suite"):
        _candidate_run(suite, tmp_path)

    assert not (tmp_path / "runs").exists()


def test_run_rejects_suite_config_byte_change_between_validation_and_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = load_suite(_suite(tmp_path))
    suite_config = suite.root / "suite.toml"
    original = suite_config.read_bytes()

    def mutate_suite_config(_repo_root: Path) -> dict[str, object]:
        suite_config.write_bytes(original + b"\n")
        return {}

    monkeypatch.setattr("cavada_eval.runner.environment_evidence", mutate_suite_config)
    monkeypatch.setattr("cavada_eval.runner.call_target", lambda *_args, **_kwargs: pytest.fail("network contacted"))

    with pytest.raises(ProtocolError, match="suite.toml changed after canonical validation"):
        _candidate_run(suite, tmp_path)

    assert not (tmp_path / "runs").exists()


@pytest.mark.parametrize(
    ("endpoint", "judge_endpoint", "message"),
    [
        ("http://target.example/v1", "http://127.0.0.1/judge", "non-public target data requires HTTPS"),
        ("http://127.0.0.1/target", "http://judge.example/v1", "non-public judge data requires HTTPS"),
    ],
)
def test_non_public_data_rejects_remote_plaintext_without_credentials_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
    judge_endpoint: str,
    message: str,
) -> None:
    root = _suite(tmp_path)
    suite_config = root / "suite.toml"
    suite_config.write_text(
        suite_config.read_text(encoding="utf-8").replace('data_classification = "synthetic"', 'data_classification = "restricted"'),
        encoding="utf-8",
    )
    suite = load_suite(root)
    monkeypatch.setattr("cavada_eval.runner.call_target", lambda *_args, **_kwargs: pytest.fail("network contacted"))
    monkeypatch.setattr("cavada_eval.runner.call_judge", lambda *_args, **_kwargs: pytest.fail("network contacted"))

    with pytest.raises(ProtocolError, match=message):
        run(
            suite,
            repo_root=tmp_path,
            endpoint=endpoint,
            model_label="target",
            expected_model="target-real",
            model_revision="target-revision",
            request_model=None,
            judge_endpoint=judge_endpoint,
            judge_model="judge",
            expected_judge_model="judge-real",
            judge_revision="judge-revision",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=1,
            official=False,
            allow_external_judge=True,
        )

    assert not (tmp_path / "runs").exists()


def test_official_resume_is_rejected_before_suite_dispatch(tmp_path: Path) -> None:
    suite = load_suite(_suite(tmp_path))
    with pytest.raises(ProtocolError, match="cannot be resumed"):
        run(
            suite,
            repo_root=Path(__file__).parents[1],
            endpoint="http://127.0.0.1/target",
            model_label="target",
            expected_model="target",
            model_revision="revision",
            request_model=None,
            judge_endpoint="http://127.0.0.1/judge",
            judge_model="judge",
            expected_judge_model="judge",
            judge_revision="revision",
            target_key_env="MISSING_TARGET_KEY",
            judge_key_env="MISSING_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=1,
            official=True,
            allow_external_judge=False,
            resume_dir=tmp_path / "interrupted",
        )


def test_official_mutable_revisions_are_rejected_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = load_suite(_suite(tmp_path))
    monkeypatch.setattr("cavada_eval.runner.call_target", lambda *_args, **_kwargs: pytest.fail("network contacted"))
    with pytest.raises(ProtocolError, match="full lowercase commit/content hash"):
        run(
            suite,
            repo_root=Path(__file__).parents[1],
            endpoint="http://127.0.0.1/target",
            model_label="target",
            expected_model="target",
            model_revision="main",
            request_model=None,
            judge_endpoint="http://127.0.0.1/judge",
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
    _official_revision("opaque-immutable:provider-release-2026-08-07", "target")
    with pytest.raises(ProtocolError):
        _official_revision("opaque-immutable:latest", "target")


def test_authorization_is_exact_secret_free_and_reconciled(tmp_path: Path) -> None:
    record = {
        "authorization_id": "authorization-1",
        "approver": "owner",
        "purpose": "evaluation",
        "destinations": [{"host": "target.example", "region": "EU", "purpose": "target"}],
        "expires_at": "2099-01-01T00:00:00Z",
    }
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps(record))
    loaded, digest = _external_authorization(str(path))
    assert loaded == record and len(digest) == 64
    record["extra"] = "not allowed"
    path.write_text(json.dumps(record))
    with pytest.raises(ProtocolError, match="exactly"):
        _external_authorization(str(path))


def test_json_evidence_hashes_the_same_bytes_it_parses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "evidence.json"
    original = b'{"record_id":"record-a"}\n'
    replacement = '{"record_id":"record-b"}\n'
    path.write_bytes(original)
    real_read_bytes = Path.read_bytes
    real_read_text = Path.read_text

    def read_bytes_then_replace(candidate: Path) -> bytes:
        raw = real_read_bytes(candidate)
        if candidate == path:
            candidate.write_text(replacement, encoding="utf-8")
        return raw

    def read_text_then_replace(candidate: Path, *args: object, **kwargs: object) -> str:
        text = real_read_text(candidate, *args, **kwargs)
        if candidate == path:
            candidate.write_text(replacement, encoding="utf-8")
        return text

    monkeypatch.setattr(Path, "read_bytes", read_bytes_then_replace)
    monkeypatch.setattr(Path, "read_text", read_text_then_replace)
    _, value, digest = _evidence_object(str(path), "test evidence", {"record_id"})

    assert value == {"record_id": "record-a"}
    assert digest == sha256_bytes(original)
    assert json.loads(path.read_text(encoding="utf-8"))["record_id"] == "record-b"


@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("mutation", "external authorization changed before dispatch"),
        ("expiry", "external authorization expired before dispatch"),
    ],
)
def test_development_external_authorization_remains_current_before_each_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    message: str,
) -> None:
    root = _suite(tmp_path)
    suite_config = root / "suite.toml"
    suite_config.write_text(
        suite_config.read_text(encoding="utf-8").replace('data_classification = "synthetic"', 'data_classification = "restricted"'),
        encoding="utf-8",
    )
    suite = load_suite(root)
    authorization = tmp_path / "authorization.json"
    authorization.write_text(
        json.dumps(
            {
                "authorization_id": "authorization",
                "approver": "owner",
                "purpose": "evaluation",
                "destinations": [
                    {"host": "target.example", "region": "EU", "purpose": "target"},
                    {"host": "judge.example", "region": "EU", "purpose": "judge"},
                ],
                "expires_at": "2099-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    dispatches = {"target": 0, "judge": 0}

    def target(*_args: object, **_kwargs: object) -> tuple[str, dict[str, object], str, dict[str, object], dict[str, object]]:
        dispatches["target"] += 1
        if scenario == "mutation":
            authorization.write_text(authorization.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        raw: dict[str, object] = {"model": "target-real", "answer": "Answer"}
        return "Answer", raw, "target-real", {"input": "Question"}, {"request_id": "target", "attempts": 1}

    def judge(*_args: object, **_kwargs: object) -> None:
        dispatches["judge"] += 1
        pytest.fail("stale authorization allowed a judge dispatch")

    evidence_times = iter(
        (
            datetime(2098, 12, 31, 23, 59, tzinfo=timezone.utc),
            datetime(2099, 1, 1, 0, 1, tzinfo=timezone.utc),
        )
    )
    monkeypatch.setattr("cavada_eval.runner._evidence_now", lambda: next(evidence_times))
    monkeypatch.setattr("cavada_eval.runner.call_target", target)
    monkeypatch.setattr("cavada_eval.runner.call_judge", judge)

    output = run(
        suite,
        repo_root=tmp_path,
        endpoint="https://target.example/v1",
        model_label="target",
        expected_model="target-real",
        model_revision="target-revision",
        request_model=None,
        judge_endpoint="https://judge.example/v1",
        judge_model="judge-real",
        expected_judge_model="judge-real",
        judge_revision="judge-revision",
        target_key_env="MISSING_TARGET_KEY",
        judge_key_env="MISSING_JUDGE_KEY",
        repetitions=1,
        judge_repetitions=1,
        max_cases=0,
        timeout=1,
        official=False,
        allow_external_judge=False,
        external_authorization=str(authorization),
    )

    result = json.loads((output / "case_results.jsonl").read_text(encoding="utf-8"))
    assert dispatches == {"target": 1, "judge": 0}
    assert result["status"] == "error" and message in result["reason"]


@pytest.mark.parametrize(
    ("scenario", "expected_abort"),
    [
        ("expiry", "engagement expired before dispatch"),
        ("mutation", "external authorization changed before dispatch"),
    ],
)
def test_official_evidence_change_between_target_and_judge_stops_next_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    expected_abort: str,
) -> None:
    loaded = load_suite(_suite(tmp_path))
    suite = Suite(loaded.root, {**loaded.config, "status": "approved", "gates": []}, loaded.cases, loaded.rubric, loaded.dataset_path, loaded.rubric_path)
    qualification = tmp_path / "qualification.json"
    qualification.write_text("{}")
    approver_evidence = tmp_path / "judge-approver.txt"
    approver_evidence.write_text("independent judge approver evidence", encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text(
        json.dumps(
            {
                "approval_id": "judge-approval",
                "approver_id": "reviewer",
                "approved_at": "2026-08-01T00:00:00Z",
                "expires_at": "2026-09-01T00:00:00Z",
                "approver_qualification_evidence": approver_evidence.name,
                "approver_qualification_evidence_sha256": sha256_file(approver_evidence),
            }
        )
    )
    engagement = tmp_path / "engagement.json"
    engagement.write_text("{}")
    engagement_summary = {
        "engagement_id": "engagement",
        "sha256": sha256_file(engagement),
        "approved_at": "2026-08-01T00:00:00Z",
        "expires_at": "2026-08-05T12:00:00Z",
    }
    authorization = tmp_path / "authorization.json"
    authorization.write_text(
        json.dumps(
            {
                "authorization_id": "authorization",
                "approver": "owner",
                "purpose": "evaluation",
                "destinations": [{"host": "target.example", "region": "EU", "purpose": "target"}],
                "expires_at": "2026-09-01T00:00:00Z",
            }
        )
    )
    source = {"commit": "c" * 40, "dirty": False, "status_sha256": "d" * 64}
    dispatches = {"target": 0, "judge": 0}

    def target(*_args: object, **_kwargs: object) -> tuple[str, dict[str, object], str, dict[str, object], dict[str, object]]:
        dispatches["target"] += 1
        if scenario == "mutation":
            authorization.write_text(authorization.read_text() + "\n")
        raw: dict[str, object] = {"model": "target-real", "answer": "Answer"}
        return "Answer", raw, "target-real", {"input": "Question"}, {"request_id": "target", "attempts": 1}

    def judge(*_args: object, **_kwargs: object) -> None:
        dispatches["judge"] += 1
        pytest.fail("expired evidence allowed a judge dispatch")

    evidence_times = iter(
        (datetime(2026, 8, 5, 11, 59, tzinfo=timezone.utc),) * 2
        if scenario == "mutation"
        else (
            datetime(2026, 8, 5, 11, 59, tzinfo=timezone.utc),
            datetime(2026, 8, 5, 12, 1, tzinfo=timezone.utc),
        )
    )
    monkeypatch.setattr("cavada_eval.runner.require_matching_source_checkout", lambda *_args: None)
    monkeypatch.setattr("cavada_eval.runner.load_suite", lambda *_args, **_kwargs: suite)
    monkeypatch.setattr("cavada_eval.runner.git_evidence", lambda *_args: source)
    monkeypatch.setattr("cavada_eval.runner.judge_evidence_errors", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("cavada_eval.runner.verified_engagement", lambda *_args, **_kwargs: engagement_summary)
    monkeypatch.setattr("cavada_eval.runner._evidence_now", lambda: next(evidence_times))
    monkeypatch.setattr("cavada_eval.runner.call_target", target)
    monkeypatch.setattr("cavada_eval.runner.call_judge", judge)

    output = run(
        suite,
        repo_root=tmp_path,
        endpoint="https://target.example/v1" if scenario == "mutation" else "http://127.0.0.1/target",
        model_label="target",
        expected_model="target-real",
        model_revision="a" * 40,
        request_model=None,
        judge_endpoint="http://127.0.0.1/judge",
        judge_model="judge-real",
        expected_judge_model="judge-real",
        judge_revision="b" * 40,
        target_key_env="MISSING_TARGET_KEY",
        judge_key_env="MISSING_JUDGE_KEY",
        repetitions=1,
        judge_repetitions=1,
        max_cases=0,
        timeout=1,
        official=True,
        allow_external_judge=False,
        judge_qualification=str(qualification),
        judge_approval=str(approval),
        engagement=str(engagement),
        external_authorization=str(authorization) if scenario == "mutation" else "",
    )

    assert dispatches == {"target": 1, "judge": 0}
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["official"] is False
    assert expected_abort in manifest["abort_reason"]


def test_official_gates_and_provider_evidence_are_fail_closed(tmp_path: Path) -> None:
    suite = load_suite(_suite(tmp_path))
    assert any("confidence-interval lower bound" in error for error in validate_suite(suite, official=True))
    with pytest.raises(ProtocolError, match="provider usage"):
        _usage_tokens({"usage": {"prompt_tokens": "one", "completion_tokens": 1}})
    with pytest.raises(ProtocolError, match="non-negative integer"):
        _usage_tokens({"usage": {"prompt_tokens": 0.5, "completion_tokens": 1}})
    with pytest.raises(ProtocolError, match="required by the configured token or cost budget"):
        _usage_tokens({}, required=True)
    cases = ({"id": "one", "review": {"status": "approved"}},)
    reconciliation = _behavior_reconciliation(
        cases,
        1,
        [{"kind": "target", "case_id": "one", "repetition": 1}],
        [{"case_id": "one", "repetition": 1}],
        [],
        [{"case_id": "one", "repetition": 1}, {"case_id": "one", "repetition": 1}],
    )
    assert reconciliation["valid"] is False
    assert any("duplicate observation" in error for error in reconciliation["errors"])

    semantic = _behavior_reconciliation(
        cases,
        1,
        [
            {"kind": "target", "case_id": "one", "repetition": 1},
            {"kind": "judge", "case_id": "one", "repetition": 1, "judge_repetition": 1},
        ],
        [{"case_id": "one", "repetition": 1}],
        [{"case_id": "one", "repetition": 1, "judge_repetition": 1, "judgment": {"verdict": "fail"}}],
        [{"case_id": "one", "repetition": 1, "status": "pass", "reason": "judge majority"}],
        expected_judgments_per_observation=1,
    )
    assert semantic["valid"] is False
    assert any("disagrees with preserved judge evidence" in error for error in semantic["errors"])


@pytest.mark.parametrize("requirement", ["budget", "pricing"])
def test_configured_usage_accounting_requires_provider_usage_before_judge_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requirement: str,
) -> None:
    suite_root = _suite(tmp_path)
    if requirement == "pricing":
        with (suite_root / "suite.toml").open("a", encoding="utf-8") as suite_file:
            suite_file.write(
                '\n[pricing]\ncurrency = "USD"\nsource = "test"\neffective_at = "2026-01-01"\n'
                "input_per_million = 1\noutput_per_million = 1\n"
            )
    suite = load_suite(suite_root)
    judge_calls = 0

    def target(*_args: object, **_kwargs: object) -> tuple[str, dict[str, object], str, dict[str, object], dict[str, object]]:
        raw: dict[str, object] = {"model": "target-real", "answer": "Answer"}
        return "Answer", raw, "target-real", {"input": "Question"}, {"request_id": "target", "attempts": 1}

    def judge(*_args: object, **_kwargs: object) -> None:
        nonlocal judge_calls
        judge_calls += 1
        pytest.fail("missing usage evidence allowed a judge dispatch")

    monkeypatch.setattr("cavada_eval.runner.call_target", target)
    monkeypatch.setattr("cavada_eval.runner.call_judge", judge)
    output = run(
        suite,
        repo_root=tmp_path,
        endpoint="http://127.0.0.1/target",
        model_label="target",
        expected_model="target-real",
        model_revision="target-revision",
        request_model=None,
        judge_endpoint="http://127.0.0.1/judge",
        judge_model="judge-real",
        expected_judge_model="judge-real",
        judge_revision="judge-revision",
        target_key_env="MISSING_TARGET_KEY",
        judge_key_env="MISSING_JUDGE_KEY",
        repetitions=1,
        judge_repetitions=1,
        max_cases=0,
        timeout=1,
        official=False,
        allow_external_judge=False,
        max_total_tokens=1 if requirement == "budget" else 0,
    )

    assert judge_calls == 0
    result = json.loads((output / "case_results.jsonl").read_text())
    manifest = json.loads((output / "manifest.json").read_text())
    assert result["status"] == "error"
    assert "provider usage is required" in result["reason"]
    assert "provider usage is required" in manifest["abort_reason"]


def test_official_multi_construct_suite_rejects_overall_gate(tmp_path: Path) -> None:
    suite = load_suite(_suite(tmp_path))
    cases = (suite.cases[0], {**suite.cases[0], "id": "two", "category": "security"})
    config = {**suite.config, "gates": [{"metric": "pass_rate_ci.lower", "min": 0.5}]}
    errors = validate_suite(type(suite)(suite.root, config, cases, suite.rubric, suite.dataset_path, suite.rubric_path), official=True)
    assert any("cannot aggregate multiple constructs" in error for error in errors)


def test_malformed_target_identity_is_preserved_and_takes_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = load_suite(_suite(tmp_path))

    def target(*_args: object, **_kwargs: object) -> None:
        raise _ResponseError(
            "target returned no configured response string",
            request={"message": "Question"},
            raw={"model": "wrong-target", "answer": 7},
            transport={"request_id": "target-request", "attempts": 1},
        )

    monkeypatch.setattr("cavada_eval.runner.call_target", target)
    monkeypatch.setattr("cavada_eval.runner.call_judge", lambda *_args, **_kwargs: pytest.fail("judge contacted"))
    output = _candidate_run(suite, tmp_path)

    response = json.loads((output / "raw_responses.jsonl").read_text())
    result = json.loads((output / "case_results.jsonl").read_text())
    assert response["response"]["model"] == "wrong-target"
    assert result["status"] == "error" and "identity mismatch" in result["reason"]


@pytest.mark.parametrize(
    ("answer", "model_label"),
    (("I am TARGET-REAL", "target"), ("Built by PRIVATE-TARGET-LABEL", "private-target-label")),
)
def test_candidate_target_identity_is_blocked_before_judge_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: str, model_label: str
) -> None:
    suite = load_suite(_suite(tmp_path))
    judge_calls = 0

    def target(*_args: object, **_kwargs: object) -> tuple[str, dict[str, object], str, dict[str, object], dict[str, object]]:
        return answer, {"model": "target-real", "answer": answer}, "target-real", {"input": "Question"}, {"request_id": "target", "attempts": 1}

    def judge(*_args: object, **_kwargs: object) -> None:
        nonlocal judge_calls
        judge_calls += 1
        pytest.fail("target identity reached the judge")

    monkeypatch.setattr("cavada_eval.runner.call_target", target)
    monkeypatch.setattr("cavada_eval.runner.call_judge", judge)

    output = _candidate_run(suite, tmp_path, model_label=model_label)

    result = json.loads((output / "case_results.jsonl").read_text(encoding="utf-8"))
    assert judge_calls == 0
    assert result["status"] == "error"
    assert result["reason"] == "Judge payload exposes a target identity; dispatch blocked"


@pytest.mark.parametrize("identity_failure", ["reported", "partial-stream", "self-reveal", "label-reveal"])
def test_official_identity_abort_prevents_waiting_concurrent_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, identity_failure: str
) -> None:
    root = _suite(tmp_path)
    first_case = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    second_case = {**first_case, "id": "two", "input": "Second question"}
    (root / "dataset.jsonl").write_text(
        "".join(json.dumps(case) + "\n" for case in (first_case, second_case)),
        encoding="utf-8",
    )
    loaded = load_suite(root)
    suite = Suite(
        loaded.root,
        {**loaded.config, "status": "approved", "gates": []},
        loaded.cases,
        loaded.rubric,
        loaded.dataset_path,
        loaded.rubric_path,
    )
    qualification = tmp_path / "qualification.json"
    qualification.write_text("{}", encoding="utf-8")
    approver_evidence = tmp_path / "judge-approver.txt"
    approver_evidence.write_text("independent judge approver evidence", encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text(
        json.dumps(
            {
                "approval_id": "judge-approval",
                "approver_id": "reviewer",
                "approved_at": "2026-08-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "approver_qualification_evidence": approver_evidence.name,
                "approver_qualification_evidence_sha256": sha256_file(approver_evidence),
            }
        ),
        encoding="utf-8",
    )
    engagement = tmp_path / "engagement.json"
    engagement.write_text("{}", encoding="utf-8")
    engagement_summary = {
        "engagement_id": "engagement",
        "sha256": sha256_file(engagement),
        "approved_at": "2026-08-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    source = {"commit": "c" * 40, "dirty": False, "status_sha256": "d" * 64}
    dispatches = {"target": 0, "judge": 0}
    dispatch_lock = threading.Lock()
    second_waiting = threading.Event()
    real_sleep = time.sleep

    def rate_sleep(seconds: float) -> None:
        second_waiting.set()
        real_sleep(seconds)

    def target(*_args: object, **_kwargs: object) -> tuple[str, dict[str, object], str, dict[str, object], dict[str, object]]:
        with dispatch_lock:
            dispatches["target"] += 1
            assert dispatches["target"] == 1, "a target dispatch occurred after the identity abort"
        assert second_waiting.wait(1), "the concurrent observation did not enter rate-limit wait"
        if identity_failure == "partial-stream":
            raise _ResponseError(
                "OpenAI stream contains inconsistent model identities",
                request={"model": "target"},
                raw={
                    "model": "target-real",
                    "stream_events": [{"model": "wrong-target"}, {"model": "target-real"}],
                },
                transport={"request_id": "target", "attempts": 1},
            )
        if identity_failure in {"self-reveal", "label-reveal"}:
            answer = "I am TARGET-REAL" if identity_failure == "self-reveal" else "Built by PRIVATE-TARGET-LABEL"
            self_reveal_raw: dict[str, object] = {"model": "target-real", "answer": answer}
            return answer, self_reveal_raw, "target-real", {"input": "Question"}, {"request_id": "target", "attempts": 1}
        raw: dict[str, object] = {"model": "wrong-target", "answer": "Answer"}
        return "Answer", raw, "wrong-target", {"input": "Question"}, {"request_id": "target", "attempts": 1}

    def judge(*_args: object, **_kwargs: object) -> None:
        dispatches["judge"] += 1
        pytest.fail("identity abort allowed a judge dispatch")

    monkeypatch.setattr("cavada_eval.runner.require_matching_source_checkout", lambda *_args: None)
    monkeypatch.setattr("cavada_eval.runner.load_suite", lambda *_args, **_kwargs: suite)
    monkeypatch.setattr("cavada_eval.runner.git_evidence", lambda *_args: source)
    monkeypatch.setattr("cavada_eval.runner.judge_evidence_errors", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("cavada_eval.runner.verified_engagement", lambda *_args, **_kwargs: engagement_summary)
    monkeypatch.setattr("cavada_eval.runner.call_target", target)
    monkeypatch.setattr("cavada_eval.runner.call_judge", judge)
    monkeypatch.setattr("cavada_eval.runner.time.sleep", rate_sleep)

    output = run(
        suite,
        repo_root=tmp_path,
        endpoint="http://127.0.0.1/target",
        model_label="private-target-label" if identity_failure == "label-reveal" else "target",
        expected_model="target-real",
        model_revision="a" * 40,
        request_model=None,
        judge_endpoint="http://127.0.0.1/judge",
        judge_model="judge-real",
        expected_judge_model="judge-real",
        judge_revision="b" * 40,
        target_key_env="MISSING_TARGET_KEY",
        judge_key_env="MISSING_JUDGE_KEY",
        repetitions=1,
        judge_repetitions=1,
        max_cases=0,
        timeout=1,
        official=True,
        allow_external_judge=False,
        judge_qualification=str(qualification),
        judge_approval=str(approval),
        engagement=str(engagement),
        concurrency=2,
        requests_per_second=5,
    )

    results = [json.loads(line) for line in (output / "case_results.jsonl").read_text(encoding="utf-8").splitlines()]
    assert dispatches == {"target": 1, "judge": 0}
    assert {row["status"] for row in results} == {"error", "skipped"}
    assert any("identity" in row["reason"].casefold() for row in results)
    assert any(row["reason"] == "run aborted by a prior observation" for row in results)
    if identity_failure in {"self-reveal", "label-reveal"}:
        response = json.loads((output / "raw_responses.jsonl").read_text(encoding="utf-8"))
        requests = [json.loads(line) for line in (output / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
        expected_answer = "I am TARGET-REAL" if identity_failure == "self-reveal" else "Built by PRIVATE-TARGET-LABEL"
        assert response["response"]["answer"] == expected_answer
        assert [request["kind"] for request in requests] == ["target"]


def test_malformed_judge_usage_is_counted_once_as_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = load_suite(_suite(tmp_path))
    target_raw = {"model": "target-real", "answer": "Answer"}
    judgment = {"verdict": "pass", "score": 5, "reason": "ok", "criteria": {}}
    judge_raw = {
        "model": "judge-real",
        "choices": [{"message": {"content": json.dumps(judgment)}}],
        "usage": {"prompt_tokens": "bad", "completion_tokens": 1},
    }
    monkeypatch.setattr(
        "cavada_eval.runner.call_target",
        lambda *_args, **_kwargs: (
            "Answer",
            target_raw,
            "target-real",
            {"message": "Question"},
            {"request_id": "target-request", "attempts": 1},
        ),
    )
    monkeypatch.setattr(
        "cavada_eval.runner.call_judge",
        lambda *_args, **_kwargs: (
            judgment,
            judge_raw,
            json.dumps(judgment),
            {"model": "judge"},
            {"request_id": "judge-request", "attempts": 1},
        ),
    )
    output = _candidate_run(suite, tmp_path)

    judgments = [json.loads(line) for line in (output / "judgments.jsonl").read_text().splitlines()]
    result = json.loads((output / "case_results.jsonl").read_text())
    assert len(judgments) == 1 and judgments[0]["status"] == "invalid"
    assert "provider usage" in judgments[0]["error"]
    assert result["status"] == "invalid"


@pytest.mark.parametrize("reported_model", ["wrong-judge", ""])
def test_malformed_judge_identity_is_invalid_evidence_and_an_execution_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reported_model: str
) -> None:
    suite = load_suite(_suite(tmp_path))
    monkeypatch.setattr(
        "cavada_eval.runner.call_target",
        lambda *_args, **_kwargs: (
            "Answer",
            {"model": "target-real", "answer": "Answer"},
            "target-real",
            {"message": "Question"},
            {"request_id": "target-request", "attempts": 1},
        ),
    )

    def malformed_judge(*_args: object, **_kwargs: object) -> None:
        raise _JudgeOutputError(
            "judge output is malformed",
            request={"model": "judge"},
            raw={"model": reported_model, "choices": []},
            transport={"request_id": "judge-request", "attempts": 1},
        )

    monkeypatch.setattr("cavada_eval.runner.call_judge", malformed_judge)
    output = _candidate_run(suite, tmp_path)

    judgment = json.loads((output / "judgments.jsonl").read_text(encoding="utf-8"))
    result = json.loads((output / "case_results.jsonl").read_text(encoding="utf-8"))
    assert judgment["status"] == "invalid"
    assert judgment["reported_model"] == reported_model
    assert result["status"] == "error"
    assert "identity mismatch" in result["reason"].casefold()


def test_elapsed_budget_is_rechecked_after_the_last_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite = load_suite(_suite(tmp_path))
    judgment = {"verdict": "pass", "score": 1, "reason": "ok", "criteria": {}}
    monkeypatch.setattr(
        "cavada_eval.runner.call_target",
        lambda *_args, **_kwargs: (
            "Answer",
            {"model": "target-real", "answer": "Answer"},
            "target-real",
            {"message": "Question"},
            {"request_id": "target-request", "attempts": 1},
        ),
    )

    def slow_judge(*_args: object, **_kwargs: object) -> tuple[dict[str, object], dict[str, object], str, dict[str, object], dict[str, object]]:
        time.sleep(0.02)
        raw: dict[str, object] = {"model": "judge-real", "choices": [{"message": {"content": json.dumps(judgment)}}]}
        return judgment, raw, json.dumps(judgment), {"model": "judge"}, {"request_id": "judge-request", "attempts": 1}

    monkeypatch.setattr("cavada_eval.runner.call_judge", slow_judge)
    output = run(
        suite,
        repo_root=tmp_path,
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
        timeout=1,
        official=False,
        allow_external_judge=False,
        max_elapsed_seconds=0.005,
    )

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    metrics = json.loads((output / "metrics.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["abort_reason"] == "budget exhausted: elapsed time"
    assert metrics["budgets"]["exhausted"] is True
