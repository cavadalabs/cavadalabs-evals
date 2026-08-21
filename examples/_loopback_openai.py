"""Tiny synthetic OpenAI-compatible fixture shared by client examples."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ANSWERS = {
    "What is the support code?": "SUPPORT-001",
    "What is the billing code?": "BILLING-002",
    "Reply with READY.": "READY",
    "Count to two.": "one two",
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        try:
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            messages = payload.get("messages", [])
            prompt = next(message["content"] for message in reversed(messages) if message.get("role") == "user")
            answer = ANSWERS.get(prompt, "unknown")
            model = payload["model"]
        except (KeyError, TypeError, ValueError, StopIteration):
            self._reply(400, {"error": {"message": "invalid synthetic request"}})
            return
        if payload.get("stream"):
            events = (
                {"model": model, "choices": [{"delta": {"content": "one "}}]},
                {"model": model, "choices": [{"delta": {"content": "two"}}]},
                {
                    "model": model,
                    "choices": [],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                    "timings": {"prompt_n": 8, "prompt_ms": 8, "predicted_n": 2, "predicted_ms": 2},
                },
            )
            body = b"".join(f"data: {json.dumps(event)}\n\n".encode() for event in events) + b"data: [DONE]\n\n"
            self._reply_bytes(200, body, "text/event-stream")
            return
        self._reply(
            200,
            {
                "id": "synthetic-completion",
                "object": "chat.completion",
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 2},
            },
        )

    def _reply(self, status: int, value: dict[str, Any]) -> None:
        self._reply_bytes(status, json.dumps(value, separators=(",", ":")).encode(), "application/json")

    def _reply_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    port = parser.parse_args().port
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"synthetic loopback listening on http://127.0.0.1:{port}/v1", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
