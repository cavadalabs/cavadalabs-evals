from __future__ import annotations

import asyncio
import inspect
import json
import threading
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Protocol, TypeAlias, TypedDict, TypeVar, cast, runtime_checkable

from .protocol import _strict_json_loads

JSONValue: TypeAlias = str | int | float | bool | None | list["JSONValue"] | dict[str, "JSONValue"]


class TargetResponse(TypedDict, total=False):
    answer: str
    model: str
    output: JSONValue
    structured_output: JSONValue
    usage: JSONValue
    latency: JSONValue
    citations: JSONValue
    retrieval: JSONValue
    tool_calls: JSONValue
    trace: JSONValue
    metadata: JSONValue
    raw: JSONValue


TargetOutput: TypeAlias = str | Mapping[str, JSONValue]
TargetCallable: TypeAlias = Callable[[Mapping[str, JSONValue]], TargetOutput | Awaitable[TargetOutput]]
T = TypeVar("T")


class TargetInvocationError(RuntimeError):
    """A target failed without exposing provider or callable internals."""


@runtime_checkable
class Target(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def revision(self) -> str: ...

    @property
    def capabilities(self) -> tuple[str, ...]: ...

    def __call__(self, client_case: Mapping[str, JSONValue]) -> TargetResponse | Awaitable[TargetResponse]: ...


def _resolve(value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        async def wait() -> T:
            return await value

        return asyncio.run(wait())
    return value


def _json_clone(value: object) -> JSONValue:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        return cast(JSONValue, _strict_json_loads(encoded))
    except (TypeError, ValueError, RecursionError):
        raise TargetInvocationError("target returned invalid JSON evidence") from None


def _chat_content(raw: Mapping[str, JSONValue]) -> tuple[str | None, Mapping[str, JSONValue] | None]:
    choices = raw.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None, None
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return None, None
    content = message.get("content")
    return (content if isinstance(content, str) else None), message


def _normalize_target_response(value: TargetOutput | TargetResponse, fallback_model: str) -> TargetResponse:
    cloned = _json_clone(value)
    if isinstance(cloned, str):
        return {"answer": cloned, "model": fallback_model, "output": cloned, "raw": cloned}
    if not isinstance(cloned, dict):
        raise TargetInvocationError("target returned invalid JSON evidence")
    chat_answer, message = _chat_content(cloned)
    answer_value = cloned.get("answer")
    output_value = cloned.get("output")
    answer = answer_value if isinstance(answer_value, str) else output_value if isinstance(output_value, str) else chat_answer
    if answer is None and isinstance(output_value, (dict, list)):
        answer = json.dumps(output_value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    if not isinstance(answer, str):
        raise TargetInvocationError("target returned no answer")
    model_value = cloned.get("model")
    model = model_value if isinstance(model_value, str) and model_value else fallback_model
    response: TargetResponse = {
        "answer": answer,
        "model": model,
        "output": output_value if output_value is not None else answer,
        "raw": cloned.get("raw", cloned),
    }
    response_values = cast(dict[str, JSONValue], response)
    if isinstance(output_value, (dict, list)):
        response["structured_output"] = output_value
    for key in ("structured_output", "usage", "latency", "citations", "retrieval", "tool_calls", "trace", "metadata"):
        if key in cloned:
            response_values[key] = cloned[key]
    if "retrieval" not in response and "retrieved_ids" in cloned:
        response["retrieval"] = cloned["retrieved_ids"]
    if isinstance(message, Mapping):
        for key in ("citations", "tool_calls"):
            if key not in response and key in message:
                response_values[key] = message[key]
    return response


def _with_metadata(response: TargetResponse, **metadata: JSONValue) -> TargetResponse:
    existing = response.get("metadata")
    merged = dict(existing) if isinstance(existing, dict) else {}
    merged.update(metadata)
    return {**response, "metadata": merged}


@dataclass(frozen=True)
class CallableTarget:
    name: str
    callable: TargetCallable
    model: str
    revision: str = ""
    capabilities: tuple[str, ...] = ("text",)

    def __call__(self, client_case: Mapping[str, JSONValue]) -> TargetResponse | Awaitable[TargetResponse]:
        try:
            value = self.callable(client_case)
        except Exception:
            raise TargetInvocationError("target invocation failed") from None
        if inspect.isawaitable(value):
            return self._await(value)
        return _normalize_target_response(value, self.model)

    async def _await(self, value: Awaitable[TargetOutput]) -> TargetResponse:
        try:
            resolved = await value
            return _normalize_target_response(resolved, self.model)
        except TargetInvocationError:
            raise
        except Exception:
            raise TargetInvocationError("target invocation failed") from None


@dataclass(frozen=True)
class OpenAICompatibleTarget:
    base_url: str
    model: str
    name: str = ""
    api_key_env: str = ""
    revision: str = ""
    capabilities: tuple[str, ...] = ("text",)
    stream: bool = False
    pricing: Mapping[str, JSONValue] | None = None

    def __post_init__(self) -> None:
        if not self.name:
            object.__setattr__(self, "name", self.model)

    def __call__(self, client_case: Mapping[str, JSONValue]) -> TargetResponse:
        raise TargetInvocationError("OpenAI-compatible targets must run through the canonical evaluator transport")


@dataclass(frozen=True)
class RecordedTarget:
    name: str
    path: Path
    model: str
    revision: str = ""
    capabilities: tuple[str, ...] = ("text",)

    def __call__(self, client_case: Mapping[str, JSONValue]) -> TargetResponse:
        identifier = client_case.get("case_id", client_case.get("id"))
        if not isinstance(identifier, str) or not identifier:
            raise TargetInvocationError("recorded target requires a case ID")
        try:
            rows = self.path.read_text(encoding="utf-8").splitlines()
            matches: list[Mapping[str, JSONValue]] = []
            for line in rows:
                if not line.strip():
                    continue
                row = _strict_json_loads(line)
                if not isinstance(row, dict):
                    raise ValueError("invalid row")
                if row.get("case_id", row.get("id")) == identifier:
                    matches.append(cast(Mapping[str, JSONValue], row))
            if len(matches) != 1:
                raise ValueError("missing or duplicate row")
            value = matches[0].get("response", matches[0])
            if not isinstance(value, (str, dict)):
                raise ValueError("invalid response")
            return _with_metadata(_normalize_target_response(cast(TargetOutput, value), self.model), target=self.name, revision=self.revision, recorded=True)
        except (OSError, UnicodeDecodeError, ValueError, TargetInvocationError):
            raise TargetInvocationError("recorded target evidence is unavailable") from None


LoopbackCallable: TypeAlias = Callable[[dict[str, JSONValue]], JSONValue | Awaitable[JSONValue]]


@contextmanager
def _serve_json(callback: LoopbackCallable) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 2 * 1024 * 1024:
                    raise ValueError("invalid length")
                request = _strict_json_loads(self.rfile.read(length))
                if not isinstance(request, dict):
                    raise ValueError("request is not an object")
            except (UnicodeDecodeError, ValueError):
                self._reply(400, {"error": {"type": "invalid_request", "message": "request rejected"}})
                return
            try:
                response = _resolve(callback(cast(dict[str, JSONValue], request)))
                body = json.dumps(response, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
            except Exception:
                self._reply(500, {"error": {"type": "invocation_error", "message": "invocation failed"}})
                return
            self._reply_bytes(200, body)

        def _reply(self, status: int, value: JSONValue) -> None:
            self._reply_bytes(status, json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode())

        def _reply_bytes(self, status: int, body: bytes) -> None:
            self.send_response(status)
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
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@contextmanager
def serve_target(target: Target) -> Iterator[str]:
    def invoke(request: dict[str, JSONValue]) -> JSONValue | Awaitable[JSONValue]:
        client_case = request.get("client_case", request)
        if not isinstance(client_case, dict):
            raise TargetInvocationError("client case must be an object")
        result = target(client_case)
        if inspect.isawaitable(result):
            async def normalized() -> JSONValue:
                value = await result
                return cast(JSONValue, _normalize_target_response(value, target.model))

            return normalized()
        return cast(JSONValue, _normalize_target_response(result, target.model))

    with _serve_json(invoke) as endpoint:
        yield endpoint
