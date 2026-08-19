from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.error
import urllib.parse
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from cavada_eval import private_ai
from cavada_eval.artifacts import verify_bundle
from cavada_eval.metrics import metric_config_errors
from cavada_eval.private_ai import PrivateAIAdapterError, PrivateAIContext, call, preflight_errors
from cavada_eval.protocol import ProtocolError, Suite, load_suite, validate_suite
from cavada_eval.runner import call_target, run


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def private_ai_suite(tmp_path: Path) -> Path:
    root = tmp_path / "suite"
    documents = root / "documents"
    documents.mkdir(parents=True)
    policy = b"The approved retention period is 42 months."
    (documents / "policy.txt").write_bytes(policy)
    corpus = (
        json.dumps(
            {
                "id": "policy",
                "source": "approved",
                "path": "documents/policy.txt",
                "sha256": sha256(policy),
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()
    (root / "corpus.jsonl").write_bytes(corpus)
    case = {
        "id": "retention",
        "input": "What is the approved retention period?",
        "category": "retrieval",
        "risk_domain": "quality",
        "severity": "high",
        "expected_behavior": "answer",
        "expected_behavior_reason": "Answer from the indexed policy.",
        "required_terms": ["42 months"],
        "expected_retrieval_ids": ["policy"],
        "retrieval_recall_min": 1.0,
        "language": "en",
        "locale": "en-US",
        "split": "practice",
        "review": {"status": "approved", "method": "test fixture"},
        "source": {"origin": "synthetic test"},
    }
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    (root / "rubric.md").write_text("Pass when the answer states 42 months and cites the policy.", encoding="utf-8")
    (root / "suite.toml").write_text(
        f'''protocol_version = "1.0.0"
name = "private-ai-adapter-test"
version = "0.1.0"
status = "candidate"
description = "Private AI adapter integration fixture"
profile = "text-generation"
data_classification = "synthetic"
dataset = "dataset.jsonl"
rubric = "rubric.md"

[[gates]]
metric = "pass_rate"
min = 1.0

[target]
kind = "private-ai"
capabilities = ["text"]
corpus = "corpus.jsonl"
corpus_sha256 = "{sha256(corpus)}"
workspace_id_env = "PRIVATE_AI_TEST_WORKSPACE"
reasoning_mode = "instant"
retrieval_limit = 5
''',
        encoding="utf-8",
    )
    return root


class PrivateAIHandler(BaseHTTPRequestHandler):
    authorization = ""
    workspace = ""
    uploaded = b""
    chat_payload: dict[str, object] = {}
    terminal_status = "answer_done"
    after_terminal_event: dict[str, object] | None = None
    job_status = "complete"
    citation_source_id = "source-1"
    citation_path = "documents/policy.txt"

    def _capture_headers(self) -> None:
        type(self).authorization = str(self.headers.get("Authorization", ""))
        type(self).workspace = str(self.headers.get("X-Workspace-Id", ""))

    def _json(self, value: object, status: int = 200) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self._capture_headers()
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if parsed.path == "/v1/sources/browser-folder":
            payload = json.loads(body)
            assert payload["shared"] is False and payload["file_count"] == 1
            self._json({"source": {"id": "source-1"}, "upload_id": "upload-1"}, 201)
            return
        if parsed.path.endswith("/commit"):
            self._json({"id": "job-1", "status": "queued"})
            return
        if parsed.path == "/v1/chat/rag":
            type(self).chat_payload = json.loads(body)
            events = [
                {"type": "thread", "thread_id": "thread-1"},
                {"type": "status", "status": "searching"},
                {
                    "type": "citation",
                    "citation": {
                        "id": "cite-1",
                        "source_id": type(self).citation_source_id,
                        "document_id": "document-1",
                        "chunk_id": "chunk-1",
                        "title": "policy.txt",
                        "path": type(self).citation_path,
                        "quote": "The approved retention period is 42 months.",
                        "offset_start": 0,
                        "offset_end": 44,
                    },
                },
                {"type": "status", "status": "streaming"},
                {"type": "token", "text": "The approved period is 42 months. [1]"},
                {
                    "type": "usage",
                    "final": True,
                    "usage": {
                        "prompt_tokens": 20,
                        "completion_tokens": 9,
                        "total_tokens": 29,
                        "context_window": 32768,
                        "remaining_tokens": 32739,
                        "model_label": "Qwen Test",
                    },
                },
                {"type": "status", "status": type(self).terminal_status},
            ]
            if type(self).after_terminal_event is not None:
                events.append(type(self).after_terminal_event)
            events.append({"type": "done"})
            response = b"".join(json.dumps(event).encode() + b"\n" for event in events)
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            return
        self._json({"detail": "not found"}, 404)

    def do_PUT(self) -> None:  # noqa: N802
        self._capture_headers()
        parsed = urllib.parse.urlsplit(self.path)
        type(self).uploaded = self.rfile.read(int(self.headers["Content-Length"]))
        self._json({"path": urllib.parse.parse_qs(parsed.query)["path"][0], "size_bytes": len(type(self).uploaded)})

    def do_GET(self) -> None:  # noqa: N802
        self._capture_headers()
        if self.path == "/v1/jobs/job-1":
            self._json({"id": "job-1", "status": type(self).job_status, "raw_detail": "fixture job evidence"})
            return
        if self.path == "/v1/sources":
            self._json(
                [
                    {
                        "id": "source-1",
                        "sync_status": "complete",
                        "documents_total": 1,
                        "documents_indexed": 1,
                        "documents_failed": 0,
                    },
                    {
                        "id": "foreign-source",
                        "name": "do-not-leak-foreign-source",
                        "sync_status": "complete",
                        "documents_total": 99,
                        "documents_indexed": 99,
                        "documents_failed": 0,
                    },
                ]
            )
            return
        self._json({"detail": "not found"}, 404)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


@pytest.fixture
def private_ai_server() -> Iterator[tuple[str, type[PrivateAIHandler]]]:
    PrivateAIHandler.authorization = ""
    PrivateAIHandler.workspace = ""
    PrivateAIHandler.uploaded = b""
    PrivateAIHandler.chat_payload = {}
    PrivateAIHandler.terminal_status = "answer_done"
    PrivateAIHandler.after_terminal_event = None
    PrivateAIHandler.job_status = "complete"
    PrivateAIHandler.citation_source_id = "source-1"
    PrivateAIHandler.citation_path = "documents/policy.txt"
    server = ThreadingHTTPServer(("127.0.0.1", 0), PrivateAIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", PrivateAIHandler
    finally:
        server.shutdown()
        thread.join()


def run_private_ai_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
    suite: Suite,
    *,
    max_cases: int = 0,
) -> Path:
    monkeypatch.setenv("PRIVATE_AI_TEST_TOKEN", "secret-token")
    monkeypatch.setenv("PRIVATE_AI_TEST_WORKSPACE", "workspace-1")

    def judge_stub(*_args: object, **_kwargs: object) -> tuple[object, ...]:
        judgment = {"verdict": "pass", "score": 5, "reason": "grounded", "criteria": {}}
        raw = {"model": "Judge Test", "choices": [{"message": {"content": json.dumps(judgment)}}]}
        return (
            judgment,
            raw,
            json.dumps(judgment),
            {"model": "judge"},
            {
                "request_id": "judge-request",
                "total_ms": 1.0,
                "headers_ms": 0.5,
                "response_bytes": 64,
            },
        )

    monkeypatch.setattr("cavada_eval.runner.call_judge", judge_stub)
    return run(
        suite,
        repo_root=tmp_path,
        endpoint=endpoint,
        model_label="Private AI",
        expected_model="Qwen Test",
        model_revision="test-qwen-revision",
        request_model=None,
        judge_endpoint="http://127.0.0.1:9/v1",
        judge_model="judge-request",
        expected_judge_model="Judge Test",
        judge_revision="test-judge-revision",
        target_key_env="PRIVATE_AI_TEST_TOKEN",
        judge_key_env="MISSING_JUDGE_TOKEN",
        repetitions=1,
        judge_repetitions=1,
        max_cases=max_cases,
        timeout=5,
        official=False,
        allow_external_judge=False,
        output_root=tmp_path,
    )


def test_private_ai_target_runs_ingestion_chat_and_verified_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    private_ai_server: tuple[str, type[PrivateAIHandler]],
) -> None:
    endpoint, handler = private_ai_server
    suite = load_suite(private_ai_suite(tmp_path))
    run_dir = run_private_ai_fixture(tmp_path, monkeypatch, endpoint, suite)

    setup = json.loads((run_dir / "target_setup.json").read_text())
    raw_response = json.loads((run_dir / "raw_responses.jsonl").read_text())["response"]
    assert setup["status"] == "ready" and setup["source_ids"] == ["source-1"]
    setup_text = (run_dir / "target_setup.json").read_text()
    assert "secret-token" not in setup_text and "do-not-leak-foreign-source" not in setup_text
    assert handler.authorization == "Bearer secret-token" and handler.workspace == "workspace-1"
    assert handler.uploaded == b"The approved retention period is 42 months."
    assert handler.chat_payload["acl"] == {"source_ids": ["source-1"], "document_ids": []}
    assert raw_response["retrieved_ids"] == ["policy"]
    assert raw_response["sources"][0]["chunk_id"] == "chunk-1"
    assert verify_bundle(run_dir)["valid"] is True


def test_private_ai_corpus_is_validated_before_network(tmp_path: Path) -> None:
    root = private_ai_suite(tmp_path)
    (root / "documents/policy.txt").write_text("mutated", encoding="utf-8")
    with pytest.raises(ProtocolError, match="corpus asset hash mismatch"):
        load_suite(root)


def test_private_ai_expected_retrieval_ids_must_exist_in_corpus(tmp_path: Path) -> None:
    root = private_ai_suite(tmp_path)
    case = json.loads((root / "dataset.jsonl").read_text(encoding="utf-8"))
    case["expected_retrieval_ids"] = ["typo-not-in-corpus"]
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="unknown corpus document IDs"):
        load_suite(root)


def test_private_ai_official_run_fails_closed(tmp_path: Path) -> None:
    suite = load_suite(private_ai_suite(tmp_path))
    errors = validate_suite(suite, official=True)
    assert any("candidate-only" in error for error in errors)
    assert "official retrieval metrics require a qualified retrieval-evidence adapter" in errors


def test_official_retrieval_metrics_fail_closed_for_generic_targets(tmp_path: Path) -> None:
    suite = load_suite(private_ai_suite(tmp_path))
    suite.config["target"] = {"kind": "json", "capabilities": ["text"]}
    assert "official retrieval metrics require a qualified retrieval-evidence adapter" in validate_suite(suite, official=True)


def test_retrieval_threshold_requires_expected_ids() -> None:
    assert "retrieval_recall_min requires non-empty expected_retrieval_ids" in metric_config_errors({"retrieval_recall_min": 0.9})


def test_private_ai_does_not_follow_cross_origin_redirects_or_forward_credentials(tmp_path: Path) -> None:
    sink_requests: list[dict[str, str]] = []

    class SinkHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            sink_requests.append(
                {
                    "authorization": str(self.headers.get("Authorization", "")),
                    "workspace": str(self.headers.get("X-Workspace-Id", "")),
                }
            )
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    class RedirectHandler(BaseHTTPRequestHandler):
        location = ""
        authorization = ""
        workspace = ""

        def do_POST(self) -> None:  # noqa: N802
            type(self).authorization = str(self.headers.get("Authorization", ""))
            type(self).workspace = str(self.headers.get("X-Workspace-Id", ""))
            self.send_response(307)
            self.send_header("Location", type(self).location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
    redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    RedirectHandler.location = f"http://127.0.0.1:{sink.server_port}/capture"
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (sink, redirect)]
    for thread in threads:
        thread.start()
    try:
        suite = load_suite(private_ai_suite(tmp_path))
        target = suite.config["target"]
        snapshot = private_ai.snapshot_corpus(suite.root, target)
        with pytest.raises(PrivateAIAdapterError):
            private_ai.prepare(
                suite.root,
                target,
                f"http://127.0.0.1:{redirect.server_port}",
                "secret-token",
                "workspace-1",
                5,
                "redirect-test",
                corpus_snapshot=snapshot,
            )
        context = PrivateAIContext(
            f"http://127.0.0.1:{redirect.server_port}",
            "secret-token",
            "workspace-1",
            ("source-1",),
            (),
            "0" * 64,
            "instant",
            5,
        )
        with pytest.raises(PrivateAIAdapterError, match="HTTP 307"):
            call(context, "Question", 5)
    finally:
        for server in (redirect, sink):
            server.shutdown()
        for thread in threads:
            thread.join()
    assert RedirectHandler.authorization == "Bearer secret-token"
    assert RedirectHandler.workspace == "workspace-1"
    assert sink_requests == []


def test_private_ai_preflights_every_case_and_capability_before_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = private_ai_suite(tmp_path)
    dataset_path = root / "dataset.jsonl"
    case = json.loads(dataset_path.read_text())
    unsupported = {**case, "id": "second", "input": "A second question"}
    unsupported["messages"] = [{"role": "user", "content": unsupported["input"]}]
    dataset_path.write_text(json.dumps(case) + "\n" + json.dumps(unsupported) + "\n", encoding="utf-8")
    suite = load_suite(root)
    assert preflight_errors(suite.cases, {"capabilities": ["text", "image"]})

    def forbidden_network(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("network was contacted before private-ai case preflight")

    monkeypatch.setattr(private_ai, "_urlopen", forbidden_network)
    with pytest.raises(ProtocolError, match=r"case\[2\] conversations are not supported"):
        run_private_ai_fixture(tmp_path, monkeypatch, "http://127.0.0.1:9", suite, max_cases=1)


def test_private_ai_rejects_intermediate_corpus_symlinks(tmp_path: Path) -> None:
    root = private_ai_suite(tmp_path)
    external_documents = tmp_path / "external-documents"
    (root / "documents").rename(external_documents)
    (root / "documents").symlink_to(external_documents, target_is_directory=True)
    with pytest.raises(ProtocolError, match="symlink-free"):
        load_suite(root)


def test_private_ai_uploads_the_exact_snapshotted_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    private_ai_server: tuple[str, type[PrivateAIHandler]],
) -> None:
    endpoint, handler = private_ai_server
    root = private_ai_suite(tmp_path)
    suite = load_suite(root)
    expected = (root / "documents/policy.txt").read_bytes()
    original_prepare = private_ai.prepare

    def mutate_after_snapshot(
        suite_root: Path,
        target: dict[str, Any],
        target_endpoint: str,
        token: str,
        workspace_id: str,
        timeout: float,
        run_id: str,
        *,
        corpus_snapshot: private_ai.CorpusSnapshot | None = None,
    ) -> tuple[PrivateAIContext, dict[str, Any]]:
        (suite_root / "documents/policy.txt").write_bytes(b"mutated after snapshot")
        return original_prepare(
            suite_root,
            target,
            target_endpoint,
            token,
            workspace_id,
            timeout,
            run_id,
            corpus_snapshot=corpus_snapshot,
        )

    monkeypatch.setattr(private_ai, "prepare", mutate_after_snapshot)
    run_dir = run_private_ai_fixture(tmp_path, monkeypatch, endpoint, suite)
    digest = sha256(expected)
    assert handler.uploaded == expected
    assert (run_dir / "corpus_assets" / digest).read_bytes() == expected
    assert json.loads((run_dir / "target_setup.json").read_text())["documents"][0]["snapshot"] == f"corpus_assets/{digest}"


def test_private_ai_setup_failure_is_finalized_with_raw_identifiers_and_no_fake_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    private_ai_server: tuple[str, type[PrivateAIHandler]],
) -> None:
    endpoint, handler = private_ai_server
    handler.job_status = "failed"
    suite = load_suite(private_ai_suite(tmp_path))
    run_dir = run_private_ai_fixture(tmp_path, monkeypatch, endpoint, suite)

    setup = json.loads((run_dir / "target_setup.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    setup_text = (run_dir / "target_setup.json").read_text()
    assert setup["status"] == "error"
    assert setup["source_ids"] == ["source-1"]
    assert setup["upload_ids"] == ["upload-1"]
    assert setup["job_ids"] == ["job-1"]
    assert setup["raw"] == {"id": "job-1", "raw_detail": "fixture job evidence", "status": "failed"}
    assert setup["cleanup"]["status"] == "not_attempted"
    assert all("response_body_base64" in request for request in setup["requests"])
    assert "secret-token" not in setup_text and "workspace-1" not in setup_text
    assert manifest["status"] == "failed" and "setup failed" in manifest["abort_reason"]
    assert "target_setup.json" in manifest["artifacts"]
    assert verify_bundle(run_dir)["valid"] is True


def test_private_ai_chat_network_error_has_real_adapter_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter((10.0, 10.125))

    def fail_network(*_args: object, **_kwargs: object) -> Any:
        raise urllib.error.URLError("fixture network failure")

    monkeypatch.setattr(private_ai, "_urlopen", fail_network)
    monkeypatch.setattr("cavada_eval.private_ai.time.perf_counter", lambda: next(ticks))
    context = PrivateAIContext("http://127.0.0.1:9", "", "", ("source-1",), (), "0" * 64, "instant", 5)
    with pytest.raises(PrivateAIAdapterError, match="chat request failed") as raised:
        call(context, "Question", 5)
    assert len(raised.value.transport["request_id"]) == 32
    assert raised.value.transport["total_ms"] == 125.0
    assert raised.value.transport["attempts"] == 1


def test_private_ai_stream_read_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    limits: list[int] = []

    class Response:
        status = 200
        headers = type("Headers", (), {"get_content_type": lambda self: "application/x-ndjson"})()

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read1(self, limit: int) -> bytes:
            limits.append(limit)
            return b"x" * limit

    monkeypatch.setattr(private_ai, "MAX_RESPONSE_BYTES", 8)
    monkeypatch.setattr(private_ai, "_urlopen", lambda *_args, **_kwargs: Response())
    context = PrivateAIContext("http://127.0.0.1:9", "", "", ("source-1",), (), "0" * 64, "instant", 5)
    with pytest.raises(PrivateAIAdapterError, match="response exceeded") as raised:
        call(context, "Question", 5)
    assert limits == [9]
    assert raised.value.raw is not None
    assert base64.b64decode(raised.value.raw["wire_response"]["body_base64"]) == b"x" * 8
    assert raised.value.raw["wire_response"]["body_truncated"] is True


@pytest.mark.parametrize(
    "invalid_body",
    [
        b'{"type":"usage","usage":{"prompt_tokens":NaN}}\n',
        b'{"type":"usage","usage":{"prompt_tokens":1e999}}\n',
        b'{"type":"done","type":"token","text":"ambiguous"}\n',
        b'{"type":"usage","usage":' + b"[" * 600 + b"0" + b"]" * 600 + b"}\n",
    ],
)
def test_private_ai_preserves_malformed_wire_response_and_rejects_non_strict_json(
    monkeypatch: pytest.MonkeyPatch, invalid_body: bytes
) -> None:
    body = invalid_body

    class Response:
        status = 200
        headers = type("Headers", (), {"get_content_type": lambda self: "application/x-ndjson"})()

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read1(self, _limit: int) -> bytes:
            nonlocal body
            value, body = body, b""
            return value

    expected = body
    monkeypatch.setattr(private_ai, "_urlopen", lambda *_args, **_kwargs: Response())
    context = PrivateAIContext("http://127.0.0.1:9", "", "", ("source-1",), (), "0" * 64, "instant", 5)
    with pytest.raises(PrivateAIAdapterError, match="invalid JSON") as raised:
        call(context, "Question", 5)
    assert raised.value.raw is not None
    assert base64.b64decode(raised.value.raw["wire_response"]["body_base64"]) == expected


def test_private_ai_preserves_unsupported_content_type_body(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"unexpected upstream response"
    remaining = body

    class Response:
        status = 200
        headers = type("Headers", (), {"get_content_type": lambda self: "text/html"})()

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            nonlocal remaining
            value, remaining = remaining[:limit], remaining[limit:]
            return value

    monkeypatch.setattr(private_ai, "_urlopen", lambda *_args, **_kwargs: Response())
    context = PrivateAIContext("http://127.0.0.1:9", "", "", ("source-1",), (), "0" * 64, "instant", 5)
    with pytest.raises(PrivateAIAdapterError, match="unsupported content type") as raised:
        call(context, "Question", 5)
    assert raised.value.raw is not None
    assert base64.b64decode(raised.value.raw["wire_response"]["body_base64"]) == body


@pytest.mark.parametrize(
    "body",
    [b'{"x":1e999}', b'{"x":1,"x":2}', b'{"x":' + b"[" * 600 + b"0" + b"]" * 600 + b"}"],
)
def test_private_ai_setup_rejects_non_strict_json_and_preserves_raw(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    remaining = body

    class Headers:
        def get_content_type(self) -> str:
            return "application/json"

        def get(self, _name: str) -> None:
            return None

    class Response:
        status = 200
        headers = Headers()

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read1(self, limit: int) -> bytes:
            nonlocal remaining
            value, remaining = remaining[:limit], remaining[limit:]
            return value

    monkeypatch.setattr(private_ai, "_urlopen", lambda *_args, **_kwargs: Response())
    evidence: list[dict[str, Any]] = []
    with pytest.raises(PrivateAIAdapterError, match="non-JSON setup data"):
        private_ai._request_json("GET", "http://127.0.0.1:9/v1/test", "", "", time.monotonic() + 5, evidence)
    assert base64.b64decode(evidence[-1]["response_body_base64"]) == body


def test_private_ai_stream_timeout_is_a_total_deadline() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            try:
                for byte in b'{"type":"status","status":"answer_done"}\n{"type":"done"}\n':
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.03)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        context = PrivateAIContext(f"http://127.0.0.1:{server.server_port}", "", "", ("source-1",), (), "0" * 64, "instant", 5)
        with pytest.raises(PrivateAIAdapterError, match="TimeoutError") as raised:
            call(context, "Question", 0.1)
        elapsed = time.monotonic() - started
    finally:
        server.shutdown()
        thread.join()
    assert elapsed < 0.3
    assert raised.value.transport["request_id"]
    assert raised.value.raw is not None
    assert len(base64.b64decode(raised.value.raw["wire_response"]["body_base64"])) > 0
    assert raised.value.transport["response_bytes"] > 0


def test_private_ai_setup_timeout_preserves_partial_body() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                for byte in b'{"status":"complete"}':
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.03)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    evidence: list[dict[str, Any]] = []
    try:
        with pytest.raises(PrivateAIAdapterError, match="TimeoutError"):
            private_ai._request_json(
                "GET",
                f"http://127.0.0.1:{server.server_port}/v1/test",
                "",
                "",
                time.monotonic() + 0.1,
                evidence,
            )
    finally:
        server.shutdown()
        thread.join()
    assert evidence[-1]["response_bytes"] > 0
    assert base64.b64decode(evidence[-1]["response_body_base64"])


def test_private_ai_runner_refuses_to_fabricate_missing_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite = load_suite(private_ai_suite(tmp_path))
    context = PrivateAIContext("http://127.0.0.1:9", "", "", ("source-1",), (), "0" * 64, "instant", 5)

    def missing_transport(*_args: object, **_kwargs: object) -> tuple[str, dict[str, Any], str, dict[str, Any], dict[str, Any]]:
        raise PrivateAIAdapterError("missing transport", request={"message": "Question"})

    monkeypatch.setattr(private_ai, "call", missing_transport)
    with pytest.raises(ProtocolError, match="omitted real transport evidence"):
        call_target(suite, context.endpoint, "", "Question", None, 5, private_ai_context=context)


@pytest.mark.parametrize(
    "terminal_status",
    ["runtime_unavailable", "no_sources", "no_indexed_documents", "retrieval_no_results"],
)
def test_private_ai_runtime_failure_is_not_scored_as_an_answer(
    private_ai_server: tuple[str, type[PrivateAIHandler]],
    terminal_status: str,
) -> None:
    endpoint, handler = private_ai_server
    handler.terminal_status = terminal_status
    context = PrivateAIContext(endpoint, "", "", ("source-1",), (), "0" * 64, "instant", 5)
    with pytest.raises(PrivateAIAdapterError, match=terminal_status) as raised:
        call(context, "Question", 5)
    assert raised.value.raw is not None
    assert raised.value.raw["private_ai"]["events"][-1] == {"type": "done"}


def test_private_ai_rejects_citations_outside_the_request_acl(
    private_ai_server: tuple[str, type[PrivateAIHandler]],
) -> None:
    endpoint, handler = private_ai_server
    handler.citation_source_id = "source-outside-acl"
    context = PrivateAIContext(endpoint, "", "", ("source-1",), (("documents/policy.txt", "policy"),), "0" * 64, "instant", 5)
    with pytest.raises(PrivateAIAdapterError, match="outside the request ACL") as raised:
        call(context, "Question", 5)
    assert raised.value.raw is not None
    assert raised.value.raw["sources"][0]["source_id"] == "source-outside-acl"
    assert raised.value.raw["retrieved_ids"] == []


def test_private_ai_unknown_citation_path_is_preserved_as_unexpected(
    private_ai_server: tuple[str, type[PrivateAIHandler]],
) -> None:
    endpoint, handler = private_ai_server
    handler.citation_path = "documents/not-in-corpus.txt"
    context = PrivateAIContext(endpoint, "", "", ("source-1",), (("documents/policy.txt", "policy"),), "0" * 64, "instant", 5)
    _, raw, _, _, _ = call(context, "Question", 5)
    assert len(raw["retrieved_ids"]) == 1 and raw["retrieved_ids"][0].startswith("unexpected:")


def test_private_ai_success_requires_answer_done_immediately_before_done(
    private_ai_server: tuple[str, type[PrivateAIHandler]],
) -> None:
    endpoint, handler = private_ai_server
    handler.after_terminal_event = {"type": "token", "text": "late"}
    context = PrivateAIContext(endpoint, "", "", ("source-1",), (), "0" * 64, "instant", 5)
    with pytest.raises(PrivateAIAdapterError, match="answer_done immediately followed by done") as raised:
        call(context, "Question", 5)
    assert raised.value.transport["request_id"]
