from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle
from .protocol import ProtocolError, load_suite, sha256_file
from .runner import run

TARGET_MODEL = "cavadalabs-demo-recorded-v1"
JUDGE_MODEL = "cavadalabs-demo-judge-v1"


class _JudgeHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if self.path != "/v1/chat/completions" or not 0 < length <= 1_000_000:
            self.send_error(400)
            return
        try:
            request = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400)
            return
        if not isinstance(request, dict) or request.get("model") != JUDGE_MODEL:
            self.send_error(400)
            return
        judgment = {"verdict": "pass", "score": 5, "reason": "The recorded response satisfies the demo case.", "criteria": {"demo": True}}
        body = json.dumps(
            {
                "model": JUDGE_MODEL,
                "choices": [{"message": {"content": json.dumps(judgment)}}],
                "usage": {"prompt_tokens": 64, "completion_tokens": 20, "total_tokens": 84},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def run_demo(repo_root: Path, *, artifact_root: Path | None = None) -> dict[str, Any]:
    suite_path = repo_root / "suites" / "demo-v1"
    if not suite_path.is_dir():
        suite_path = Path(__file__).with_name("demo_suite")
    suite = load_suite(suite_path)
    responses = suite.root / "recorded_responses.jsonl"
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JudgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        run_dir = run(
            suite,
            repo_root=artifact_root or repo_root,
            endpoint="recorded://local",
            model_label=TARGET_MODEL,
            expected_model=TARGET_MODEL,
            model_revision=sha256_file(responses),
            request_model=None,
            judge_endpoint=f"http://127.0.0.1:{server.server_port}/v1",
            judge_model=JUDGE_MODEL,
            expected_judge_model=JUDGE_MODEL,
            judge_revision="builtin-demo-judge-1.0.0",
            target_key_env="CAVADA_DEMO_UNUSED_TARGET_KEY",
            judge_key_env="CAVADA_DEMO_UNUSED_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=10,
            official=False,
            allow_external_judge=False,
            mode="offline",
            max_target_calls=len(suite.cases),
            max_judge_calls=len(suite.cases),
            max_total_tokens=10_000,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    verification = verify_bundle(run_dir)
    if manifest.get("status") != "passed" or not verification["valid"]:
        raise ProtocolError("offline demo did not produce a passing verified bundle")
    return {
        "status": "passed",
        "official": False,
        "external_network_used": False,
        "run": str(run_dir),
        "report": str(run_dir / "report_public.html"),
        "metrics": str(run_dir / "metrics.json"),
        "failures": str(run_dir / "failures.jsonl"),
        "verification": verification,
    }
