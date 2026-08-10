#!/usr/bin/env python3
"""Produce a local development bundle without credentials or external network."""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cavada_eval.artifacts import verify_bundle
from cavada_eval.protocol import load_suite
from cavada_eval.runner import run


class DemoHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload: dict[str, Any] = json.loads(self.rfile.read(length))
        model = str(payload.get("model", ""))
        if model == "demo-target":
            content = "4"
        elif model == "demo-judge":
            content = json.dumps({"verdict": "pass", "score": 5, "reason": "Local fixture matched.", "criteria": {"demo": True}})
        else:
            self.send_error(400, "unknown demo model")
            return
        body = json.dumps({"model": model, "choices": [{"message": {"content": content}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=Path.cwd(), help="Root that will receive runs/ (default: current directory)")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/v1"
        run_dir = run(
            load_suite(repository / "suites" / "template"),
            repo_root=args.output_root.resolve(),
            endpoint=endpoint,
            model_label="offline-protocol-demo",
            expected_model="demo-target",
            model_revision="fixture-1",
            request_model="demo-target",
            judge_endpoint=endpoint,
            judge_model="demo-judge",
            expected_judge_model="demo-judge",
            judge_revision="fixture-1",
            target_key_env="CAVADA_DEMO_UNUSED_TARGET_KEY",
            judge_key_env="CAVADA_DEMO_UNUSED_JUDGE_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=1,
            timeout=5,
            official=False,
            allow_external_judge=False,
            mode="offline",
            max_target_calls=1,
            max_judge_calls=1,
        )
    finally:
        server.shutdown()
        thread.join()
    verification = verify_bundle(run_dir)
    print(json.dumps({"run": str(run_dir), "bundle_valid": verification["valid"], "claim": "protocol transport demo only"}, indent=2))
    return 0 if verification["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
