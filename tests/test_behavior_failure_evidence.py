from __future__ import annotations

import base64
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cavada_eval.behavior_verify import verify_behavior_run
from cavada_eval.demo import JUDGE_MODEL, TARGET_MODEL, _JudgeHandler
from cavada_eval.protocol import load_suite, sha256_file
from cavada_eval.runner import run


def _serve(handler: type[BaseHTTPRequestHandler]) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join()


def _run_recorded(suite_root: Path, artifact_root: Path, judge_endpoint: str, *, max_cases: int = 1, preset: str = "") -> Path:
    artifact_root.mkdir(parents=True, exist_ok=True)
    suite = load_suite(suite_root)
    return run(
        suite,
        repo_root=artifact_root,
        endpoint="recorded://local",
        model_label=TARGET_MODEL,
        expected_model=TARGET_MODEL,
        model_revision=sha256_file(suite.root / "recorded_responses.jsonl"),
        request_model=None,
        judge_endpoint=judge_endpoint,
        judge_model=JUDGE_MODEL,
        expected_judge_model=JUDGE_MODEL,
        judge_revision="synthetic-failure-evidence-test",
        target_key_env="CAVADA_TEST_UNUSED_TARGET_KEY",
        judge_key_env="CAVADA_TEST_UNUSED_JUDGE_KEY",
        repetitions=1,
        judge_repetitions=1,
        max_cases=max_cases,
        timeout=5,
        official=False,
        allow_external_judge=False,
        mode="offline",
        preset=preset,
    )


def _json_target_suite(tmp_path: Path) -> Path:
    suite_root = tmp_path / "json-suite"
    shutil.copytree(Path("suites/demo-v1"), suite_root)
    config = (suite_root / "suite.toml").read_text(encoding="utf-8")
    config = config.replace(
        'kind = "recorded"\nresponses = "recorded_responses.jsonl"\nresponse_field = "answer"\nreported_model_field = "model"',
        'kind = "json"\nrequest_field = "message"\nresponse_field = "answer"\nreported_model_field = "model"',
    )
    (suite_root / "suite.toml").write_text(config, encoding="utf-8")
    return suite_root


def _openai_stream_suite(tmp_path: Path) -> Path:
    suite_root = tmp_path / "openai-stream-suite"
    shutil.copytree(Path("suites/demo-v1"), suite_root)
    config = (suite_root / "suite.toml").read_text(encoding="utf-8")
    config = config.replace(
        'kind = "recorded"\nresponses = "recorded_responses.jsonl"',
        'kind = "openai"\nstream = true',
    )
    (suite_root / "suite.toml").write_text(config, encoding="utf-8")
    return suite_root


def test_invalid_judge_wire_body_is_preserved_and_semantically_valid(tmp_path: Path) -> None:
    class InvalidJudge(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            body = b"not-json"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server, thread = _serve(InvalidJudge)
    try:
        output = _run_recorded(Path("suites/demo-v1"), tmp_path, f"http://127.0.0.1:{server.server_port}/v1")
    finally:
        _stop(server, thread)
    verification = verify_behavior_run(output)
    judgment = json.loads((output / "judgments.jsonl").read_text(encoding="utf-8"))
    assert verification["valid"] is True and verification["semantic_valid"] is True
    assert judgment["status"] == "invalid" and judgment["error_stage"] == "decode"
    assert judgment["wire_body_base64"] == "bm90LWpzb24=" and judgment["wire_body_truncated"] is False
    assert judgment["transport"]["request_id"]


def test_target_projection_error_preserves_request_raw_and_transport(tmp_path: Path) -> None:
    class MissingAnswer(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps({"model": TARGET_MODEL, "usage": {"prompt_tokens": 2, "completion_tokens": 0}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    suite_root = _json_target_suite(tmp_path)
    suite = load_suite(suite_root)
    server, thread = _serve(MissingAnswer)
    try:
        output = run(
            suite,
            repo_root=tmp_path,
            endpoint=f"http://127.0.0.1:{server.server_port}/target",
            model_label=TARGET_MODEL,
            expected_model=TARGET_MODEL,
            model_revision="synthetic-target-projection-test",
            request_model=None,
            judge_endpoint=f"http://127.0.0.1:{server.server_port}/judge",
            judge_model=JUDGE_MODEL,
            expected_judge_model=JUDGE_MODEL,
            judge_revision="unused-judge",
            target_key_env="CAVADA_TEST_UNUSED_TARGET_KEY",
            judge_key_env="CAVADA_TEST_UNUSED_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=1,
            timeout=5,
            official=False,
            allow_external_judge=False,
            mode="offline",
        )
    finally:
        _stop(server, thread)
    verification = verify_behavior_run(output)
    response = json.loads((output / "raw_responses.jsonl").read_text(encoding="utf-8"))
    result = json.loads((output / "case_results.jsonl").read_text(encoding="utf-8"))
    assert verification["valid"] is True and verification["semantic_valid"] is True
    assert response["status"] == "error" and response["error_stage"] == "projection"
    assert response["wire_body_sha256"] and response["transport"]["request_id"]
    assert result["status"] == "error" and result["reason"] == response["error"]


def test_openai_stream_error_preserves_partial_wire_evidence(tmp_path: Path) -> None:
    class InvalidStream(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            body = b"data: not-json\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    suite = load_suite(_openai_stream_suite(tmp_path))
    server, thread = _serve(InvalidStream)
    try:
        output = run(
            suite,
            repo_root=tmp_path,
            endpoint=f"http://127.0.0.1:{server.server_port}/v1",
            model_label=TARGET_MODEL,
            expected_model=TARGET_MODEL,
            model_revision="synthetic-stream-evidence-test",
            request_model="synthetic-request-model",
            judge_endpoint=f"http://127.0.0.1:{server.server_port}/judge",
            judge_model=JUDGE_MODEL,
            expected_judge_model=JUDGE_MODEL,
            judge_revision="unused-judge",
            target_key_env="CAVADA_TEST_UNUSED_TARGET_KEY",
            judge_key_env="CAVADA_TEST_UNUSED_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=1,
            timeout=5,
            official=False,
            allow_external_judge=False,
            mode="offline",
        )
    finally:
        _stop(server, thread)
    verification = verify_behavior_run(output)
    response = json.loads((output / "raw_responses.jsonl").read_text(encoding="utf-8"))
    assert verification["valid"] is True and verification["semantic_valid"] is True
    assert response["status"] == "error" and response["error_stage"] == "decode"
    assert response["wire_body_base64"] == "ZGF0YTogbm90LWpzb24KCg=="
    assert response["wire_body_truncated"] is False and response["transport"]["streaming"] is True


def test_successful_openai_stream_preserves_exact_wire_bytes(tmp_path: Path) -> None:
    target_event = json.dumps(
        {"model": TARGET_MODEL, "choices": [{"delta": {"content": "4"}}]}, separators=(",", ":")
    )
    usage_event = json.dumps(
        {
            "model": TARGET_MODEL,
            "choices": [],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        },
        separators=(",", ":"),
    )
    stream_body = f"data: {target_event}\n\ndata: {usage_event}\n\ndata: [DONE]\n\n".encode()

    class TargetAndJudge(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if request.get("model") == "synthetic-request-model":
                body = stream_body
                content_type = "text/event-stream"
            else:
                judgment = {"verdict": "pass", "score": 5, "reason": "exact", "criteria": {}}
                body = json.dumps(
                    {
                        "model": JUDGE_MODEL,
                        "choices": [{"message": {"content": json.dumps(judgment)}}],
                        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                    }
                ).encode()
                content_type = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    suite = load_suite(_openai_stream_suite(tmp_path))
    server, thread = _serve(TargetAndJudge)
    try:
        output = run(
            suite,
            repo_root=tmp_path,
            endpoint=f"http://127.0.0.1:{server.server_port}/v1",
            model_label=TARGET_MODEL,
            expected_model=TARGET_MODEL,
            model_revision="synthetic-stream-success-test",
            request_model="synthetic-request-model",
            judge_endpoint=f"http://127.0.0.1:{server.server_port}/v1",
            judge_model=JUDGE_MODEL,
            expected_judge_model=JUDGE_MODEL,
            judge_revision="synthetic-stream-judge",
            target_key_env="CAVADA_TEST_UNUSED_TARGET_KEY",
            judge_key_env="CAVADA_TEST_UNUSED_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=1,
            timeout=5,
            official=False,
            allow_external_judge=False,
            mode="offline",
        )
    finally:
        _stop(server, thread)
    verification = verify_behavior_run(output)
    response = json.loads((output / "raw_responses.jsonl").read_text(encoding="utf-8"))
    judgment = json.loads((output / "judgments.jsonl").read_text(encoding="utf-8"))
    assert verification["valid"] is True and verification["semantic_valid"] is True
    assert base64.b64decode(response["wire_body_base64"]) == stream_body
    assert response["wire_body_truncated"] is False
    assert judgment["wire_body_sha256"] and judgment["wire_body_truncated"] is False


def test_preset_selection_and_truthful_abort_reconstruct(tmp_path: Path) -> None:
    valid_server, valid_thread = _serve(_JudgeHandler)
    try:
        selected = _run_recorded(
            Path("suites/demo-v1"),
            tmp_path / "selected",
            f"http://127.0.0.1:{valid_server.server_port}/v1",
            max_cases=1,
            preset="smoke",
        )
    finally:
        _stop(valid_server, valid_thread)
    selected_manifest = json.loads((selected / "manifest.json").read_text(encoding="utf-8"))
    assert selected_manifest["parameters"]["selected_cases"] == 1
    assert verify_behavior_run(selected)["semantic_valid"] is True

    class TokenHeavyTarget(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps(
                {"answer": "4", "model": TARGET_MODEL, "usage": {"prompt_tokens": 2, "completion_tokens": 2}}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    suite = load_suite(_json_target_suite(tmp_path))
    (tmp_path / "aborted").mkdir()
    abort_server, abort_thread = _serve(TokenHeavyTarget)
    try:
        aborted = run(
            suite,
            repo_root=tmp_path / "aborted",
            endpoint=f"http://127.0.0.1:{abort_server.server_port}/target",
            model_label=TARGET_MODEL,
            expected_model=TARGET_MODEL,
            model_revision="synthetic-budget-abort-test",
            request_model=None,
            judge_endpoint=f"http://127.0.0.1:{abort_server.server_port}/judge",
            judge_model=JUDGE_MODEL,
            expected_judge_model=JUDGE_MODEL,
            judge_revision="unused-judge",
            target_key_env="CAVADA_TEST_UNUSED_TARGET_KEY",
            judge_key_env="CAVADA_TEST_UNUSED_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=5,
            official=False,
            allow_external_judge=False,
            mode="offline",
            concurrency=1,
            max_total_tokens=1,
        )
    finally:
        _stop(abort_server, abort_thread)
    statuses = [json.loads(line)["status"] for line in (aborted / "case_results.jsonl").read_text(encoding="utf-8").splitlines()]
    verification = verify_behavior_run(aborted)
    assert statuses == ["error", "skipped", "skipped"]
    assert verification["valid"] is True and verification["semantic_valid"] is True
