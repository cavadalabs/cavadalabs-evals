from __future__ import annotations

import base64
import http.client
import io
import json
import math
import os
import shlex
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from .artifacts import verify_bundle, write_bundle
from .assets import asset_inventory, content_text, encoded_content, encoded_messages, openai_content
from .calibration import judge_evidence_errors
from .metrics import METRIC_VERSION, deterministic_evaluation
from .profiles import ADAPTER_CONTRACT_VERSION, BENCHMARK_PRESET_VERSION, canonical_preset, stratified_cases
from .protocol import (
    PROTOCOL_VERSION,
    REPORT_VERSION,
    SCHEMA_VERSION,
    ProtocolError,
    Suite,
    _read_jsonl,
    append_jsonl,
    apply_gates,
    atomic_json,
    atomic_text,
    canonical_host,
    contains_secret_like,
    dataset_card,
    environment_evidence,
    git_evidence,
    load_suite,
    new_run_dir,
    require_matching_source_checkout,
    sha256_bytes,
    sha256_file,
    summarize,
    wilson_interval,
    write_category_csv,
)
from .release import canonical_protocol_path, suite_governance_snapshots, verified_engagement
from .release import official_revision as _official_revision
from .release import parse_judgment as _judge_result
from .release import reconcile_behavior_evidence as _behavior_reconciliation
from .reporting import generate_reports
from .statistics import bootstrap_mean_interval, distribution, paired_binary_comparison, stratified_bootstrap_mean_interval

JUDGE_MAX_TOKENS = 600


def _evidence_now() -> datetime:
    return datetime.now(timezone.utc)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _enforce_http_deadline(stream: Any, deadline: float, message: str) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(message)
    pending = [stream]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        setter = getattr(current, "settimeout", None)
        if callable(setter):
            setter(max(remaining, 0.001))
            return
        pending.extend(getattr(current, name, None) for name in ("fp", "raw", "_sock"))


class _DeadlineReader(io.RawIOBase):
    def __init__(self, raw: io.RawIOBase, sock: socket.socket, deadline: float) -> None:
        self._raw = raw
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int | None:
        _enforce_http_deadline(self._sock, self._deadline, "response exceeded the total request timeout")
        return self._raw.readinto(buffer)

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


class _DeadlineSocket:
    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self._sock = sock
        self._deadline = deadline

    def makefile(self, *_args: Any, **_kwargs: Any) -> io.BufferedReader:
        raw = cast(io.RawIOBase, self._sock.makefile("rb", buffering=0))
        return io.BufferedReader(_DeadlineReader(raw, self._sock, self._deadline))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sock, name)


class _DeadlineHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, *, timeout: float, **kwargs: Any) -> None:
        self._deadline = time.monotonic() + timeout
        super().__init__(host, timeout=timeout, **kwargs)

    def getresponse(self) -> http.client.HTTPResponse:
        if self.sock is not None:
            self.sock = cast(Any, _DeadlineSocket(self.sock, self._deadline))
        return super().getresponse()


class _DeadlineHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, *, timeout: float, **kwargs: Any) -> None:
        self._deadline = time.monotonic() + timeout
        super().__init__(host, timeout=timeout, **kwargs)

    def getresponse(self) -> http.client.HTTPResponse:
        if self.sock is not None:
            self.sock = cast(Any, _DeadlineSocket(self.sock, self._deadline))
        return super().getresponse()


class _DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, request: urllib.request.Request) -> Any:
        return self.do_open(cast(Any, _DeadlineHTTPConnection), request)


class _DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request: urllib.request.Request) -> Any:
        return self.do_open(
            cast(Any, _DeadlineHTTPSConnection),
            request,
            context=getattr(self, "_context", None),
            check_hostname=getattr(self, "_check_hostname", None),
        )


def _urlopen(request: urllib.request.Request, timeout: float) -> Any:
    opener = urllib.request.build_opener(
        _NoRedirectHandler(),
        _DeadlineHTTPHandler(),
        _DeadlineHTTPSHandler(context=ssl.create_default_context()),
    )
    return opener.open(request, timeout=timeout)  # noqa: S310 -- the caller validates the scheme.


class _CallEvidenceError(ProtocolError):
    def __init__(
        self,
        message: str,
        *,
        request: dict[str, Any],
        raw: dict[str, Any] | None,
        transport: dict[str, Any],
    ) -> None:
        super().__init__(message)
        self.request = request
        self.raw = raw
        self.transport = transport


class _TransportError(_CallEvidenceError):
    pass


class _ResponseError(_CallEvidenceError):
    pass


class _RunAborted(ProtocolError):
    pass


def _stream_model_identities(raw: dict[str, Any]) -> set[str]:
    identities = {str(raw.get("model"))} if raw.get("model") else set()
    events = raw.get("stream_events")
    if isinstance(events, list):
        identities.update(str(event["model"]) for event in events if isinstance(event, dict) and event.get("model"))
    return identities


class _JudgeOutputError(_CallEvidenceError):
    pass


def _http_response_evidence(
    body: bytes,
    *,
    status: int | None,
    content_type: str,
    truncated: bool,
) -> dict[str, Any]:
    return {
        "http_status": status,
        "content_type": content_type,
        "body_base64": base64.b64encode(body).decode("ascii"),
        "body_sha256": sha256_bytes(body),
        "body_truncated": truncated,
    }


def _read_http_body(stream: Any, body: bytearray, max_body_bytes: int, deadline: float, message: str) -> None:
    read = getattr(stream, "read1", stream.read)
    while len(body) <= max_body_bytes:
        _enforce_http_deadline(stream, deadline, message)
        chunk = read(min(64 * 1024, max_body_bytes + 1 - len(body)))
        if not chunk:
            return
        body.extend(chunk)
        if time.monotonic() > deadline:
            raise TimeoutError(message)


def _scenario_analysis_rows(
    rows: list[dict[str, Any]], cases: tuple[dict[str, Any], ...]
) -> list[dict[str, Any]] | None:
    if not cases or not all(case.get("scenario_role") in {"primary", "variant"} for case in cases):
        return None
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row.get("scenario_id", "")), []).append(row)
    primaries = {str(case["scenario_group_id"]): case for case in cases if case["scenario_role"] == "primary"}
    aggregated: list[dict[str, Any]] = []
    for group_id, primary in sorted(primaries.items()):
        selected = groups.get(group_id, [])
        statuses = {str(row.get("status")) for row in selected}
        if "error" in statuses:
            status = "error"
        elif "invalid" in statuses or not selected:
            status = "invalid"
        elif "skipped" in statuses:
            status = "skipped"
        elif "fail" in statuses:
            status = "fail"
        elif statuses == {"pass"}:
            status = "pass"
        else:
            status = "invalid"
        aggregated.append(
            {
                "case_id": group_id,
                "scenario_id": group_id,
                "category": primary["category"],
                "risk_domain": primary["risk_domain"],
                "severity": primary["severity"],
                "language": primary.get("language", "missing"),
                "locale": primary.get("locale", "missing"),
                "split": primary.get("split", "missing"),
                "operating_condition": primary.get("operating_condition", "missing"),
                "status": status,
                "reason": "all scenario cases passed" if status == "pass" else f"scenario evidence contains {sorted(statuses)}",
            }
        )
    return aggregated


def _distribution_shift_summary(
    rows: list[dict[str, Any]],
    cases: tuple[dict[str, Any], ...],
    *,
    confidence: float,
    samples: int,
    seed: int,
) -> dict[str, Any] | None:
    shift_cases = [case for case in cases if case.get("operating_condition") == "distribution-shift"]
    if not shift_cases:
        return None
    statuses: dict[str, set[str]] = {}
    for row in rows:
        statuses.setdefault(str(row["case_id"]), set()).add(str(row["status"]))

    def outcome(case_id: str) -> bool | None:
        values = statuses.get(case_id, set())
        if values == {"pass"}:
            return True
        if values and values <= {"pass", "fail"}:
            return False
        return None

    baseline: dict[str, bool] = {}
    shifted: dict[str, bool] = {}
    categories: dict[str, tuple[dict[str, bool], dict[str, bool]]] = {}
    for case in shift_cases:
        pair_id = str(case["id"])
        left = outcome(str(case["distribution_shift_reference_id"]))
        right = outcome(pair_id)
        if left is None or right is None:
            continue
        baseline[pair_id] = left
        shifted[pair_id] = right
        category = str(case["category"])
        category_pair = categories.setdefault(category, ({}, {}))
        category_pair[0][pair_id] = left
        category_pair[1][pair_id] = right
    comparison = (
        paired_binary_comparison(baseline, shifted, confidence=confidence, samples=samples, seed=seed)
        if baseline
        else None
    )
    return {
        "declared_pairs": len(shift_cases),
        "valid_pairs": len(baseline),
        "invalid_pairs": len(shift_cases) - len(baseline),
        "comparison": comparison,
        "by_category": {
            category: paired_binary_comparison(left, right, confidence=confidence, samples=samples, seed=seed)
            for category, (left, right) in sorted(categories.items())
        },
    }


def _get(value: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _reject_non_finite_json(constant: str) -> Any:
    raise ValueError(f"non-finite JSON constant: {constant}")


def _strict_json_loads(value: str | bytes) -> Any:
    return json.loads(value, parse_constant=_reject_non_finite_json)


def _usage_tokens(raw: dict[str, Any], *, required: bool = False) -> tuple[float, float]:
    usage = raw.get("usage")
    if usage is None:
        if required:
            raise ProtocolError("provider usage is required by the configured token or cost budget")
        return 0.0, 0.0
    if not isinstance(usage, dict):
        raise ProtocolError("provider usage evidence must be an object")
    input_tokens = usage.get("prompt_tokens")
    output_tokens = usage.get("completion_tokens")
    if required and (input_tokens is None or output_tokens is None):
        raise ProtocolError("provider usage prompt_tokens and completion_tokens are required by the configured token or cost budget")
    for field, value in (("prompt_tokens", input_tokens), ("completion_tokens", output_tokens)):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            raise ProtocolError(f"provider usage {field} must be a non-negative integer")
    return (
        float(input_tokens) if isinstance(input_tokens, int) else 0.0,
        float(output_tokens) if isinstance(output_tokens, int) else 0.0,
    )


def _completion_url(endpoint: str) -> str:
    clean = endpoint.rstrip("/")
    return clean if clean.endswith("/chat/completions") else clean + "/chat/completions"


def _post_json(
    url: str,
    payload: dict[str, Any],
    api_key: str,
    timeout: float,
    *,
    request_id: str,
    retries: int = 0,
    max_body_bytes: int = 10 * 1024 * 1024,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if urllib.parse.urlparse(url).scheme not in {"http", "https"}:
        raise ProtocolError("HTTP adapter accepts http or https URLs only")
    if retries < 0:
        raise ProtocolError("HTTP adapter retries cannot be negative")
    safe_url = _manifest_endpoint(url)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers["X-Cavada-Eval-Request-ID"] = request_id
    headers["Idempotency-Key"] = request_id
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    encoded_payload = json.dumps(payload, ensure_ascii=False).encode()
    attempt_errors: list[dict[str, Any]] = []
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, data=encoded_payload, headers=headers, method="POST")  # noqa: S310 -- scheme is validated above.
        started = time.perf_counter()
        deadline = time.monotonic() + timeout
        received = bytearray()
        http_status: int | None = None
        content_type = ""
        headers_ms: float | None = None
        http_error: urllib.error.HTTPError | None = None
        try:
            try:
                response = _urlopen(request, timeout)
            except urllib.error.HTTPError as exc:
                response = exc
                http_error = exc
            with response:
                headers_ms = (time.perf_counter() - started) * 1000
                content_type = response.headers.get_content_type()
                http_status = http_error.code if http_error is not None else response.status
                _read_http_body(response, received, max_body_bytes, deadline, "response exceeded the total request timeout")
                total_ms = (time.perf_counter() - started) * 1000
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            kind = "timeout" if isinstance(reason, TimeoutError) else "network"
            error_body = received[:max_body_bytes]
            raw = (
                _http_response_evidence(
                    bytes(error_body),
                    status=http_status,
                    content_type=content_type,
                    truncated=len(received) > max_body_bytes,
                )
                if http_status is not None
                else None
            )
            error = {
                "attempt": attempt + 1,
                "kind": kind,
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "error_type": type(reason).__name__,
                "error": str(reason),
            }
            if raw is not None:
                error.update(
                    {
                        "http_status": http_status,
                        "response_bytes": len(error_body),
                        "response_sha256": raw["body_sha256"],
                    }
                )
            attempt_errors.append(error)
            if attempt == retries:
                transport = {
                    "request_id": request_id,
                    "attempts": attempt + 1,
                    "request_bytes": len(encoded_payload),
                    "response_bytes": len(error_body),
                    "total_ms": attempt_errors[-1]["duration_ms"],
                    "attempt_errors": attempt_errors,
                }
                if headers_ms is not None:
                    transport["headers_ms"] = round(headers_ms, 3)
                raise _TransportError(
                    f"Cannot reach {safe_url}: {reason}",
                    request=payload,
                    raw=raw,
                    transport=transport,
                ) from exc
        else:
            body_bytes = bytes(received[:max_body_bytes])
            body_truncated = len(received) > max_body_bytes
            if http_error is None:
                break
            raw = _http_response_evidence(
                body_bytes,
                status=http_error.code,
                content_type=content_type,
                truncated=body_truncated,
            )
            attempt_errors.append(
                {
                    "attempt": attempt + 1,
                    "kind": "http",
                    "http_status": http_error.code,
                    "duration_ms": round(total_ms, 3),
                    "response_bytes": len(body_bytes),
                    "response_sha256": raw["body_sha256"],
                }
            )
            if http_error.code not in {408, 425, 429, 500, 502, 503, 504} or attempt == retries:
                message = f"HTTP {http_error.code} from {safe_url}; body_sha256={raw['body_sha256']}"
                raise _TransportError(
                    message,
                    request=payload,
                    raw=raw,
                    transport={
                        "request_id": request_id,
                        "attempts": attempt + 1,
                        "request_bytes": len(encoded_payload),
                        "response_bytes": len(body_bytes),
                        "total_ms": attempt_errors[-1]["duration_ms"],
                        "attempt_errors": attempt_errors,
                    },
                ) from http_error
        if attempt < retries:
            time.sleep(min(2.0, 0.25 * (2**attempt)))
    else:  # pragma: no cover - loop always breaks or raises
        raise AssertionError("unreachable HTTP adapter state")
    transport = {
        "request_id": request_id,
        "attempts": attempt + 1,
        "request_bytes": len(encoded_payload),
        "response_bytes": len(body_bytes),
        "headers_ms": round(headers_ms, 3),
        "total_ms": round(total_ms, 3),
        "attempt_errors": attempt_errors,
    }
    raw_response = _http_response_evidence(
        body_bytes,
        status=http_status,
        content_type=content_type,
        truncated=body_truncated,
    )
    if body_truncated:
        raise _ResponseError(
            f"Response from {safe_url} exceeds {max_body_bytes} bytes",
            request=payload,
            raw=raw_response,
            transport=transport,
        )
    if content_type != "application/json" and not content_type.endswith("+json"):
        raise _ResponseError(
            f"Unexpected response content type from {safe_url}: {content_type}",
            request=payload,
            raw=raw_response,
            transport=transport,
        )
    try:
        parsed = _strict_json_loads(body_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _ResponseError(
            f"Non-JSON response from {safe_url}",
            request=payload,
            raw=raw_response,
            transport=transport,
        ) from exc
    if not isinstance(parsed, dict):
        raise _ResponseError(
            f"Expected JSON object from {safe_url}",
            request=payload,
            raw=raw_response,
            transport=transport,
        )
    return parsed, transport


def _post_openai_stream(
    url: str,
    payload: dict[str, Any],
    api_key: str,
    timeout: float,
    *,
    request_id: str,
    max_body_bytes: int = 25 * 1024 * 1024,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if urllib.parse.urlparse(url).scheme not in {"http", "https"}:
        raise ProtocolError("streaming adapter accepts http or https URLs only")
    safe_url = _manifest_endpoint(url)
    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "X-Cavada-Eval-Request-ID": request_id,
        "Idempotency-Key": request_id,
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    encoded_payload = json.dumps(payload, ensure_ascii=False).encode()
    request = urllib.request.Request(url, data=encoded_payload, headers=headers, method="POST")  # noqa: S310 -- scheme is validated above.
    started_ns = time.perf_counter_ns()
    deadline = time.monotonic() + timeout
    try:
        response = _urlopen(request, timeout)
    except urllib.error.HTTPError as exc:
        received = bytearray()
        try:
            with exc:
                _read_http_body(exc, received, max_body_bytes, deadline, "streaming response exceeded the total request timeout")
        except (urllib.error.URLError, TimeoutError, OSError) as read_exc:
            reason = read_exc.reason if isinstance(read_exc, urllib.error.URLError) else read_exc
            body = bytes(received[:max_body_bytes])
            raw = _http_response_evidence(
                body,
                status=exc.code,
                content_type=exc.headers.get_content_type() if exc.headers else "",
                truncated=len(received) > max_body_bytes,
            )
            finished_ns = time.perf_counter_ns()
            duration_ms = round((finished_ns - started_ns) / 1_000_000, 3)
            error = {
                "attempt": 1,
                "kind": "timeout" if isinstance(reason, TimeoutError) else "network",
                "http_status": exc.code,
                "duration_ms": duration_ms,
                "response_bytes": len(body),
                "response_sha256": raw["body_sha256"],
                "error_type": type(reason).__name__,
                "error": str(reason),
            }
            raise _TransportError(
                f"HTTP error response from {safe_url} failed: {reason}",
                request=payload,
                raw=raw,
                transport={
                    "request_id": request_id,
                    "attempts": 1,
                    "request_bytes": len(encoded_payload),
                    "response_bytes": len(body),
                    "total_ms": duration_ms,
                    "streaming": True,
                    "started_monotonic_ns": started_ns,
                    "headers_monotonic_ns": finished_ns,
                    "first_content_monotonic_ns": None,
                    "finished_monotonic_ns": finished_ns,
                    "event_monotonic_ns": [],
                    "attempt_errors": [error],
                },
            ) from read_exc
        body = bytes(received[:max_body_bytes])
        raw = _http_response_evidence(
            body,
            status=exc.code,
            content_type=exc.headers.get_content_type() if exc.headers else "",
            truncated=len(received) > max_body_bytes,
        )
        finished_ns = time.perf_counter_ns()
        duration_ms = round((finished_ns - started_ns) / 1_000_000, 3)
        raise _TransportError(
            f"HTTP {exc.code} from {safe_url}; body_sha256={raw['body_sha256']}",
            request=payload,
            raw=raw,
            transport={
                "request_id": request_id,
                "attempts": 1,
                "request_bytes": len(encoded_payload),
                "response_bytes": len(body),
                "total_ms": duration_ms,
                "streaming": True,
                "started_monotonic_ns": started_ns,
                "headers_monotonic_ns": finished_ns,
                "first_content_monotonic_ns": None,
                "finished_monotonic_ns": finished_ns,
                "event_monotonic_ns": [],
                "attempt_errors": [
                    {
                        "attempt": 1,
                        "kind": "http",
                        "http_status": exc.code,
                        "duration_ms": duration_ms,
                        "response_bytes": len(body),
                        "response_sha256": raw["body_sha256"],
                    }
                ],
            },
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        kind = "timeout" if isinstance(reason, TimeoutError) else "network"
        finished_ns = time.perf_counter_ns()
        duration_ms = round((finished_ns - started_ns) / 1_000_000, 3)
        raise _TransportError(
            f"Cannot start stream from {safe_url}: {reason}",
            request=payload,
            raw=None,
            transport={
                "request_id": request_id,
                "attempts": 1,
                "request_bytes": len(encoded_payload),
                "response_bytes": 0,
                "total_ms": duration_ms,
                "streaming": True,
                "started_monotonic_ns": started_ns,
                "headers_monotonic_ns": None,
                "first_content_monotonic_ns": None,
                "finished_monotonic_ns": finished_ns,
                "event_monotonic_ns": [],
                "attempt_errors": [
                    {
                        "attempt": 1,
                        "kind": kind,
                        "duration_ms": duration_ms,
                        "error_type": type(reason).__name__,
                        "error": str(reason),
                    }
                ],
            },
        ) from exc
    chunks: list[dict[str, Any]] = []
    content: list[str] = []
    event_monotonic_ns: list[int] = []
    content_monotonic_ns: list[int] = []
    usage: dict[str, Any] = {}
    reported_model = ""
    reported_models: set[str] = set()
    total_bytes = 0
    wire_body = bytearray()
    headers_ns: int | None = None

    def partial_raw(*, truncated: bool = False) -> dict[str, Any]:
        wire = bytes(wire_body)
        return {
            "model": reported_model,
            "choices": [{"message": {"content": "".join(content)}}],
            "usage": usage,
            "stream_events": chunks,
            "stream_body_base64": base64.b64encode(wire).decode("ascii"),
            "stream_body_sha256": sha256_bytes(wire),
            "stream_body_truncated": truncated,
        }

    def partial_transport(*, attempt_errors: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        finished_ns = time.perf_counter_ns()
        value: dict[str, Any] = {
            "request_id": request_id,
            "attempts": 1,
            "request_bytes": len(encoded_payload),
            "response_bytes": total_bytes,
            "headers_ms": round((headers_ns - started_ns) / 1_000_000, 3) if headers_ns is not None else None,
            "total_ms": round((finished_ns - started_ns) / 1_000_000, 3),
            "streaming": True,
            "started_monotonic_ns": started_ns,
            "headers_monotonic_ns": headers_ns,
            "first_content_monotonic_ns": content_monotonic_ns[0] if content_monotonic_ns else None,
            "finished_monotonic_ns": finished_ns,
            "event_monotonic_ns": list(event_monotonic_ns),
            "attempt_errors": attempt_errors or [],
        }
        if content_monotonic_ns:
            value["ttft_ms"] = round((content_monotonic_ns[0] - started_ns) / 1_000_000, 3)
            value["inter_chunk_ms"] = distribution(
                [
                    (right - left) / 1_000_000
                    for left, right in zip(content_monotonic_ns, content_monotonic_ns[1:], strict=False)
                ]
            )
        return value

    try:
        with response:
            content_type = response.headers.get_content_type()
            headers_ns = time.perf_counter_ns()
            if content_type != "text/event-stream":
                received = bytearray()
                try:
                    _read_http_body(response, received, max_body_bytes, deadline, "streaming response exceeded the total request timeout")
                finally:
                    body = bytes(received[:max_body_bytes])
                    total_bytes = len(body)
                    wire_body.extend(body)
                raise _ResponseError(
                    f"Unexpected streaming content type from {safe_url}: {content_type}",
                    request=payload,
                    raw=_http_response_evidence(
                        body,
                        status=response.status,
                        content_type=content_type,
                        truncated=len(received) > max_body_bytes,
                    ),
                    transport=partial_transport(),
                )
            while True:
                _enforce_http_deadline(response, deadline, "streaming response exceeded the total request timeout")
                raw_line = response.readline()
                if time.monotonic() > deadline:
                    raise TimeoutError("streaming response exceeded the total request timeout")
                if not raw_line:
                    break
                total_bytes += len(raw_line)
                remaining = max_body_bytes - len(wire_body)
                if remaining > 0:
                    wire_body.extend(raw_line[:remaining])
                if total_bytes > max_body_bytes:
                    raise _ResponseError(
                        f"Streaming response from {safe_url} exceeds {max_body_bytes} bytes",
                        request=payload,
                        raw=partial_raw(truncated=True),
                        transport=partial_transport(),
                    )
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    event = _strict_json_loads(data)
                except ValueError as exc:
                    raise _ResponseError(
                        "OpenAI stream contains invalid JSON",
                        request=payload,
                        raw=partial_raw(),
                        transport=partial_transport(),
                    ) from exc
                if not isinstance(event, dict):
                    raise _ResponseError(
                        "OpenAI stream event must be an object",
                        request=payload,
                        raw=partial_raw(),
                        transport=partial_transport(),
                    )
                event_ns = time.perf_counter_ns()
                chunks.append(event)
                event_monotonic_ns.append(event_ns)
                event_model = str(event.get("model") or "")
                if event_model:
                    reported_models.add(event_model)
                    reported_model = event_model
                    if len(reported_models) > 1:
                        raise _ResponseError(
                            "OpenAI stream contains inconsistent model identities",
                            request=payload,
                            raw=partial_raw(),
                            transport=partial_transport(),
                        )
                if isinstance(event.get("usage"), dict):
                    usage = event["usage"]
                try:
                    delta = event["choices"][0]["delta"].get("content")
                except (KeyError, IndexError, TypeError, AttributeError):
                    delta = None
                if isinstance(delta, str) and delta:
                    content.append(delta)
                    content_monotonic_ns.append(event_ns)
    except _CallEvidenceError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        kind = "timeout" if isinstance(reason, TimeoutError) else "network"
        duration_ms = round((time.perf_counter_ns() - started_ns) / 1_000_000, 3)
        error = {
            "attempt": 1,
            "kind": kind,
            "duration_ms": duration_ms,
            "error_type": type(reason).__name__,
            "error": str(reason),
        }
        raise _TransportError(
            f"Streaming response from {safe_url} failed: {reason}",
            request=payload,
            raw=partial_raw(),
            transport=partial_transport(attempt_errors=[error]),
        ) from exc
    if not content:
        raise _ResponseError(
            "OpenAI stream returned no text content",
            request=payload,
            raw=partial_raw(),
            transport=partial_transport(),
        )
    intervals = [
        (right - left) / 1_000_000
        for left, right in zip(content_monotonic_ns, content_monotonic_ns[1:], strict=False)
    ]
    raw = {
        "model": reported_model,
        "choices": [{"message": {"content": "".join(content)}}],
        "usage": usage,
        "stream_events": chunks,
    }
    transport = partial_transport()
    transport["inter_chunk_ms"] = distribution(intervals)
    return raw, transport


def _secure_endpoint(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname is not None and (parsed.scheme == "https" or parsed.hostname in {"127.0.0.1", "localhost", "::1"})


def _manifest_endpoint(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password:
        raise ProtocolError("Endpoint URLs must not contain credentials")
    query_keys = sorted(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
    safe_query = "&".join(f"{urllib.parse.quote(key)}=[redacted]" for key in query_keys)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, safe_query, ""))


def _official_endpoint(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if "?" in url or "#" in url:
        raise ProtocolError("official endpoint URLs must not contain a query or fragment")
    if not _secure_endpoint(url) or parsed.hostname is None:
        raise ProtocolError("Official runs require HTTPS or loopback endpoints")
    return canonical_host(parsed.hostname)


def _evidence_object(path_value: str, label: str, fields: set[str]) -> tuple[Path, dict[str, Any], str]:
    path = Path(path_value)
    if path.is_symlink() or not path.is_file():
        raise ProtocolError(f"{label} must be a regular JSON file")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"{label} must be a readable JSON object") from exc
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtocolError(f"{label} must contain exactly these fields: {sorted(fields)}")
    if contains_secret_like(value):
        raise ProtocolError(f"{label} contains secret-like material")
    return path, value, sha256_bytes(raw)


def _external_authorization(path_value: str, *, now: datetime | None = None) -> tuple[dict[str, Any], str]:
    fields = {"authorization_id", "approver", "purpose", "destinations", "expires_at"}
    _, record, digest = _evidence_object(path_value, "external authorization", fields)
    if not all(isinstance(record[field], str) and record[field].strip() for field in fields - {"destinations"}):
        raise ProtocolError("external authorization text fields must be non-empty")
    destinations = record["destinations"]
    if not isinstance(destinations, list) or not destinations:
        raise ProtocolError("external authorization requires at least one destination")
    hosts: list[str] = []
    for item in destinations:
        if (
            not isinstance(item, dict)
            or set(item) != {"host", "region", "purpose"}
            or not all(isinstance(item[field], str) and item[field].strip() for field in ("host", "region", "purpose"))
        ):
            raise ProtocolError("external authorization destinations require exactly non-empty host, region, and purpose")
        hosts.append(canonical_host(item["host"]))
    if len(hosts) != len(set(hosts)):
        raise ProtocolError("external authorization destination hosts must be unique")
    try:
        expires = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("external authorization expires_at is invalid") from exc
    if expires.tzinfo is None or expires <= (now or datetime.now(timezone.utc)):
        raise ProtocolError("external authorization is expired or lacks a timezone")
    return record, digest


def _storage_attestation(path_value: str, *, now: datetime | None = None) -> tuple[dict[str, Any], str]:
    fields = {
        "attestation_id",
        "approver",
        "encryption_at_rest",
        "immutability",
        "access_policy_reference",
        "audit_log_reference",
        "retention_policy_reference",
        "backup_restore_reference",
        "effective_at",
        "expires_at",
    }
    _, record, digest = _evidence_object(path_value, "storage attestation", fields)
    text_fields = fields - {"encryption_at_rest", "immutability"}
    if not all(isinstance(record[field], str) and record[field].strip() for field in text_fields):
        raise ProtocolError("storage attestation text fields must be non-empty")
    if not isinstance(record["encryption_at_rest"], bool) or not isinstance(record["immutability"], bool):
        raise ProtocolError("storage attestation encryption and immutability values must be boolean")
    try:
        effective = datetime.fromisoformat(record["effective_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("storage attestation timestamps are invalid") from exc
    current = now or datetime.now(timezone.utc)
    if effective.tzinfo is None or expires.tzinfo is None or not effective <= current < expires:
        raise ProtocolError("storage attestation is not currently effective")
    return record, digest


def target_case_prompt(case: dict[str, Any], kind: str) -> Any:
    if kind == "recorded":
        return {"case_id": case["id"], "input": case["input"], "messages": case.get("messages")}
    return {"input": case["input"], "messages": case["messages"]} if case.get("messages") else case["input"]


def build_target_payload(
    suite: Suite,
    prompt: Any,
    request_model: str | None,
    *,
    recorded_responses_sha256: str | None = None,
) -> dict[str, Any]:
    target = suite.config.get("target") or {}
    kind = target.get("kind", "json")
    if kind == "recorded":
        if not isinstance(prompt, dict) or not isinstance(prompt.get("case_id"), str) or not recorded_responses_sha256:
            raise ProtocolError("recorded target requires a case ID and response-source hash")
        return {"case_id": prompt["case_id"], "source_sha256": recorded_responses_sha256}
    conversation = isinstance(prompt, dict) and isinstance(prompt.get("messages"), list)
    prompt_value = prompt.get("input") if conversation else prompt
    try:
        openai_prompt = openai_content(prompt_value, suite_root=suite.root) if kind == "openai" and not conversation else None
        json_prompt = encoded_content(prompt_value, suite_root=suite.root) if kind == "json" and not conversation else None
        conversation_messages = encoded_messages(prompt["messages"], suite_root=suite.root, openai=kind == "openai") if conversation else None
    except ValueError as exc:
        raise ProtocolError(str(exc)) from exc
    if kind == "openai":
        if not request_model:
            raise ProtocolError("OpenAI target requires --request-model")
        messages = list(conversation_messages or [{"role": "user", "content": openai_prompt}])
        system_prompt = target.get("system_prompt")
        if system_prompt:
            prompt_path = (suite.root / str(system_prompt)).resolve()
            try:
                prompt_path.relative_to(suite.root.resolve())
            except ValueError as exc:
                raise ProtocolError("target.system_prompt escapes the suite") from exc
            prompt_raw = prompt_path.read_bytes()
            expected_hash = target.get("system_prompt_sha256")
            if expected_hash is not None and sha256_bytes(prompt_raw) != expected_hash:
                raise ProtocolError("target system prompt changed after validation")
            try:
                prompt_text = prompt_raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProtocolError("target system prompt must be UTF-8") from exc
            messages.insert(0, {"role": "system", "content": prompt_text})
        payload: dict[str, Any] = {
            "model": request_model,
            "messages": messages,
            "temperature": float(suite.config.get("temperature", 0)),
            "max_tokens": int(suite.config.get("max_tokens", 2048)),
        }
        if target.get("stream"):
            payload["stream"] = True
            payload["stream_options"] = {"include_usage": True}
        return payload
    if kind == "json":
        payload = json.loads(str(target.get("request_defaults_json", "{}")))
        payload[str(target.get("request_field", "message"))] = conversation_messages if conversation else json_prompt
        return payload
    raise ProtocolError(f"Unsupported target kind: {kind}")


def call_target(
    suite: Suite,
    endpoint: str,
    api_key: str,
    prompt: Any,
    request_model: str | None,
    timeout: float,
) -> tuple[str, dict[str, Any], str, dict[str, Any], dict[str, Any]]:
    target = suite.config.get("target") or {}
    kind = target.get("kind", "json")
    if kind == "recorded":
        if not isinstance(prompt, dict) or not isinstance(prompt.get("case_id"), str):
            raise ProtocolError("recorded target requires a case ID")
        relative = str(target.get("responses", ""))
        path = (suite.root / relative).resolve()
        try:
            path.relative_to(suite.root.resolve())
        except ValueError as exc:
            raise ProtocolError("recorded responses path escapes the suite") from exc
        source_raw = path.read_bytes()
        source_sha256 = sha256_bytes(source_raw)
        expected_hash = target.get("responses_sha256")
        if expected_hash is not None and source_sha256 != expected_hash:
            raise ProtocolError("recorded response source changed after validation")
        payload = build_target_payload(suite, prompt, request_model, recorded_responses_sha256=source_sha256)
        for row in _read_jsonl(path, source_raw):
            if row.get("case_id") == prompt["case_id"]:
                response = row.get("response")
                recorded_raw = dict(response) if isinstance(response, dict) else row
                request_id = uuid.uuid4().hex
                transport = {
                    "request_id": request_id,
                    "attempts": 0,
                    "request_bytes": 0,
                    "response_bytes": len(json.dumps(recorded_raw).encode()),
                    "headers_ms": 0.0,
                    "total_ms": 0.0,
                    "recorded": True,
                }
                try:
                    answer, reported_model = _target_answer(suite, recorded_raw)
                except ProtocolError as exc:
                    raise _ResponseError(
                        str(exc),
                        request=payload,
                        raw=recorded_raw,
                        transport=transport,
                    ) from exc
                return answer, recorded_raw, reported_model, payload, transport
        raise ProtocolError(f"recorded target has no response for case {prompt['case_id']}")
    payload = build_target_payload(suite, prompt, request_model)
    if kind == "openai":
        if target.get("stream"):
            raw, transport = _post_openai_stream(_completion_url(endpoint), payload, api_key, timeout, request_id=uuid.uuid4().hex)
        else:
            raw, transport = _post_json(_completion_url(endpoint), payload, api_key, timeout, request_id=uuid.uuid4().hex)
    elif kind == "json":
        raw, transport = _post_json(endpoint, payload, api_key, timeout, request_id=uuid.uuid4().hex)
    else:
        raise ProtocolError(f"Unsupported target kind: {kind}")
    try:
        answer, reported_model = _target_answer(suite, raw)
    except ProtocolError as exc:
        raise _ResponseError(str(exc), request=payload, raw=raw, transport=transport) from exc
    return answer, raw, reported_model, payload, transport


def _target_answer(suite: Suite, raw: dict[str, Any]) -> tuple[str, str]:
    target = suite.config.get("target") or {}
    if target.get("kind", "json") == "openai":
        try:
            answer = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProtocolError("OpenAI target returned no message content") from exc
        reported_model = _target_reported_model(suite, raw)
    else:
        answer = _get(raw, str(target.get("response_field", "answer")))
        reported_model = _target_reported_model(suite, raw)
    if not isinstance(answer, str):
        raise ProtocolError("target returned no configured response string")
    return answer, reported_model


def _target_reported_model(suite: Suite, raw: dict[str, Any]) -> str:
    target = suite.config.get("target") or {}
    value = raw.get("model") if target.get("kind", "json") == "openai" else _get(raw, str(target.get("reported_model_field", "model")))
    return value if isinstance(value, str) else ""


def _judge_system_prompt(suite: Suite) -> str:
    return (
        suite.rubric
        + "\nReturn only strict JSON: "
        + '{"verdict":"pass|fail","score":0,"reason":"concise reason","criteria":{}}. '
        + "The target model identity is intentionally hidden."
    )


def _judge_calibration_summary(rows: list[dict[str, Any]], suite: Suite) -> dict[str, dict[str, Any]]:
    cases = {str(case["id"]): case for case in suite.cases if case.get("judge_gold_verdict") in {"pass", "fail"}}

    def summarize(selected: list[dict[str, Any]]) -> dict[str, Any]:
        by_case: dict[str, list[str | None]] = {}
        for row in selected:
            judgment = row.get("judgment")
            verdict = judgment.get("verdict") if isinstance(judgment, dict) else None
            by_case.setdefault(str(row["case_id"]), []).append(str(verdict) if verdict in {"pass", "fail"} else None)
        confusion = {"true_pass": 0, "true_fail": 0, "false_pass": 0, "false_fail": 0}
        invalid_cases = 0
        repeated_cases = 0
        stable_repeated_cases = 0
        for case_id, verdicts in by_case.items():
            valid = [verdict for verdict in verdicts if verdict is not None]
            if len(verdicts) > 1:
                repeated_cases += 1
                stable_repeated_cases += int(len(valid) == len(verdicts) and len(set(valid)) == 1)
            if len(valid) != len(verdicts) or len(set(valid)) != 1:
                invalid_cases += 1
                continue
            gold = str(cases[case_id]["judge_gold_verdict"])
            predicted = valid[0]
            confusion[f"true_{gold}" if predicted == gold else f"false_{predicted}"] += 1
        samples = sum(confusion.values())
        fail_total = confusion["true_fail"] + confusion["false_pass"]
        pass_total = confusion["true_pass"] + confusion["false_fail"]
        sensitivity = confusion["true_fail"] / fail_total if fail_total else None
        specificity = confusion["true_pass"] / pass_total if pass_total else None
        accuracy_ci = wilson_interval(confusion["true_pass"] + confusion["true_fail"], samples) if samples else None
        sensitivity_ci = wilson_interval(confusion["true_fail"], fail_total) if fail_total else None
        specificity_ci = wilson_interval(confusion["true_pass"], pass_total) if pass_total else None
        return {
            **confusion,
            "cases": len(by_case),
            "samples": samples,
            "invalid_cases": invalid_cases,
            "observations": sum(len(verdicts) for verdicts in by_case.values()),
            "accuracy": (confusion["true_pass"] + confusion["true_fail"]) / samples if samples else 0.0,
            "accuracy_ci": {"lower": accuracy_ci[0], "upper": accuracy_ci[1], "confidence": 0.95} if accuracy_ci else None,
            "failure_sensitivity": sensitivity,
            "failure_sensitivity_ci": (
                {"lower": sensitivity_ci[0], "upper": sensitivity_ci[1], "confidence": 0.95}
                if sensitivity_ci
                else None
            ),
            "pass_specificity": specificity,
            "pass_specificity_ci": (
                {"lower": specificity_ci[0], "upper": specificity_ci[1], "confidence": 0.95}
                if specificity_ci
                else None
            ),
            "false_pass_rate": confusion["false_pass"] / fail_total if fail_total else None,
            "false_fail_rate": confusion["false_fail"] / pass_total if pass_total else None,
            "balanced_accuracy": (sensitivity + specificity) / 2 if sensitivity is not None and specificity is not None else None,
            "repeated_cases": repeated_cases,
            "stable_repeated_case_fraction": stable_repeated_cases / repeated_cases if repeated_cases else None,
        }

    calibration: dict[str, dict[str, Any]] = {}
    judge_ids = sorted({str(row.get("judge_id", "primary")) for row in rows})
    for judge_id in judge_ids:
        judge_rows = [row for row in rows if str(row.get("judge_id", "primary")) == judge_id and str(row.get("case_id")) in cases]
        if not judge_rows:
            continue
        result = summarize(judge_rows)
        dimensions = (
            "category",
            "severity",
            "language",
            "response_length",
            "response_style",
            "probe_type",
            "model_family_alias",
        )
        result["slices"] = {
            dimension: {
                value: summarize([row for row in judge_rows if str(cases[str(row["case_id"])].get(dimension)) == value])
                for value in sorted({str(cases[str(row["case_id"])].get(dimension)) for row in judge_rows})
            }
            for dimension in dimensions
            if any(cases[str(row["case_id"])].get(dimension) is not None for row in judge_rows)
        }
        calibration[judge_id] = result
    return calibration


def build_judge_payload(
    suite: Suite,
    judge_model: str,
    case: dict[str, Any],
    answer: str,
    target_raw: dict[str, Any],
) -> dict[str, Any]:
    target = suite.config.get("target") or {}
    evidence = {
        "sources": _get(target_raw, str(target.get("sources_field", "sources"))) or [],
        "tool_calls": _get(target_raw, str(target.get("tools_field", "tool_calls"))) or [],
    }
    if contains_secret_like(evidence):
        raise ProtocolError("Judge payload blocked: retrieved evidence contains secret-like material")
    user_payload = {
        "input": content_text(case["input"]),
        "conversation": case.get("messages"),
        "expected_behavior": case["expected_behavior"],
        "expected_behavior_reason": case["expected_behavior_reason"],
        "mandatory_criteria": case.get("mandatory_criteria", []),
        "reference_answer": case.get("expected_output"),
        "category": case["category"],
        "risk_domain": case["risk_domain"],
        "severity": case["severity"],
        "answer": answer,
        "evidence": evidence,
    }
    judge_user_content: Any = json.dumps(user_payload, ensure_ascii=False)
    multimodal_inputs = [case.get("input")]
    multimodal_inputs.extend(message.get("content") for message in case.get("messages", []) if isinstance(message, dict))
    media_parts: list[dict[str, Any]] = []
    try:
        for value in multimodal_inputs:
            if not isinstance(value, list):
                continue
            converted = openai_content(value, suite_root=suite.root)
            if isinstance(converted, list):
                media_parts.extend(part for part in converted if part.get("type") != "text")
    except ValueError as exc:
        raise ProtocolError(f"Judge adapter cannot evaluate this modality: {exc}") from exc
    if media_parts:
        unique_media = list({json.dumps(part, sort_keys=True): part for part in media_parts}.values())
        judge_user_content = [{"type": "text", "text": judge_user_content}, *unique_media]
    return {
        "model": judge_model,
        "messages": [
            {"role": "system", "content": _judge_system_prompt(suite)},
            {"role": "user", "content": judge_user_content},
        ],
        "temperature": 0,
        "max_tokens": JUDGE_MAX_TOKENS,
    }


def _target_identity_exposure(payload: dict[str, Any], identities: tuple[str | None, ...]) -> bool:
    visible = json.dumps(payload, ensure_ascii=False).casefold()
    placeholders = {
        "",
        "model",
        "target",
        "unknown",
        "unspecified",
        "none",
        "null",
        "n/a",
        "unavailable",
        "unassigned",
        "unassessed",
        "not-assessed",
        "replace-me",
    }
    return any(
        identity.strip().casefold() not in placeholders and identity.strip().casefold() in visible
        for identity in identities
        if isinstance(identity, str)
    )


def _require_strict_judgment_json(content: str) -> None:
    text = content.strip()
    if text.startswith("```"):
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        _strict_json_loads(text)
    except ValueError as exc:
        raise ProtocolError("Judge output is not valid strict JSON") from exc


def call_judge(
    suite: Suite,
    endpoint: str,
    api_key: str,
    judge_model: str,
    case: dict[str, Any],
    answer: str,
    target_raw: dict[str, Any],
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any], dict[str, Any]]:
    request_payload = build_judge_payload(suite, judge_model, case, answer, target_raw)
    try:
        raw, transport = _post_json(
            _completion_url(endpoint),
            request_payload,
            api_key,
            timeout,
            request_id=uuid.uuid4().hex,
        )
    except _ResponseError as exc:
        raise _JudgeOutputError(
            str(exc),
            request=exc.request,
            raw=exc.raw,
            transport=exc.transport,
        ) from exc
    try:
        parsed, content = _judge_result(raw)
        _require_strict_judgment_json(content)
    except ProtocolError as exc:
        raise _JudgeOutputError(
            str(exc),
            request=request_payload,
            raw=raw,
            transport=transport,
        ) from exc
    return parsed, raw, content, request_payload, transport


def run(
    suite: Suite,
    *,
    repo_root: Path,
    endpoint: str,
    model_label: str,
    expected_model: str,
    model_revision: str,
    request_model: str | None,
    judge_endpoint: str,
    judge_model: str,
    expected_judge_model: str | None,
    judge_revision: str,
    target_key_env: str,
    judge_key_env: str,
    repetitions: int,
    judge_repetitions: int,
    max_cases: int,
    timeout: float,
    official: bool,
    allow_external_judge: bool,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
    signing_key_id: str = "",
    mode: str = "candidate",
    max_target_calls: int = 0,
    max_judge_calls: int = 0,
    max_total_tokens: int = 0,
    max_elapsed_seconds: float = 0,
    max_estimated_cost: float = 0,
    non_inferiority_margin: float | None = None,
    external_authorization: str = "",
    storage_attestation: str = "",
    resume_dir: Path | None = None,
    concurrency: int = 1,
    requests_per_second: float = 0,
    progress: bool = False,
    judge_qualification: str = "",
    judge_approval: str = "",
    engagement: str = "",
    preset: str = "",
    output_root: Path | None = None,
) -> Path:
    try:
        preset = canonical_preset(preset)
    except ValueError as exc:
        raise ProtocolError(str(exc)) from exc
    modes = {"smoke", "regression", "candidate", "official", "redteam", "performance", "load", "soak", "offline", "monitoring"}
    if mode not in modes:
        raise ProtocolError(f"unsupported run mode: {mode}")
    if resume_dir is not None:
        raise ProtocolError("runs are immutable and cannot be resumed; start a new run")
    if official:
        mode = "official"
        require_matching_source_checkout(repo_root, __file__)
        _official_revision(model_revision, "target")
        _official_revision(judge_revision, "judge")
    elif mode == "official":
        raise ProtocolError("official mode requires official integrity validation")
    suite_config_path = suite.root / "suite.toml"
    try:
        suite_config_raw = suite_config_path.read_bytes()
    except OSError as exc:
        raise ProtocolError("suite.toml became unreadable before canonical validation") from exc
    fresh_suite = load_suite(suite.root, official=official)

    def require_unchanged_suite_config() -> None:
        try:
            current = suite_config_path.read_bytes()
        except OSError as exc:
            raise ProtocolError("suite.toml became unreadable after canonical validation") from exc
        if current != suite_config_raw:
            raise ProtocolError("suite.toml changed after canonical validation; no network request was sent")

    require_unchanged_suite_config()
    if suite != fresh_suite:
        raise ProtocolError("provided suite differs from the canonical validated suite on disk")
    suite = fresh_suite
    unresolved = [case["id"] for case in suite.cases if (case.get("review") or {}).get("status") != "approved"]
    if official and unresolved:
        raise ProtocolError(f"official runs require all cases approved; unresolved={len(unresolved)}")
    if (
        not isinstance(repetitions, int)
        or isinstance(repetitions, bool)
        or repetitions < 1
        or not isinstance(judge_repetitions, int)
        or isinstance(judge_repetitions, bool)
        or judge_repetitions < 1
    ):
        raise ProtocolError("Repetitions must be positive")
    float_parameters = {
        "timeout": timeout,
        "requests_per_second": requests_per_second,
        "max_elapsed_seconds": max_elapsed_seconds,
        "max_estimated_cost": max_estimated_cost,
    }
    if any(
        not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value))
        for value in float_parameters.values()
    ):
        raise ProtocolError("runtime floating-point parameters must be finite numbers")
    if timeout <= 0 or max_elapsed_seconds < 0 or max_estimated_cost < 0:
        raise ProtocolError("timeout must be positive; elapsed-time and cost budgets cannot be negative")
    if non_inferiority_margin is not None and (
        isinstance(non_inferiority_margin, bool)
        or not isinstance(non_inferiority_margin, (int, float))
        or not math.isfinite(float(non_inferiority_margin))
        or not 0 <= float(non_inferiority_margin) <= 1
    ):
        raise ProtocolError("non-inferiority margin must be a finite number from 0 to 1")
    if max_estimated_cost and not suite.config.get("pricing"):
        raise ProtocolError("a maximum estimated cost requires a complete suite pricing configuration")
    integer_parameters = (concurrency, max_target_calls, max_judge_calls, max_total_tokens, max_cases)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in integer_parameters):
        raise ProtocolError("runtime counts and budgets must be integers")
    if not 1 <= concurrency <= 64 or requests_per_second < 0 or min(max_target_calls, max_judge_calls, max_total_tokens, max_cases) < 0:
        raise ProtocolError("concurrency must be 1..64; rate, token, and case budgets cannot be negative")
    target_kind = (suite.config.get("target") or {}).get("kind", "json")
    if suite.config["data_classification"] not in {"public", "synthetic"}:
        if target_kind != "recorded" and not _secure_endpoint(endpoint):
            raise ProtocolError("non-public target data requires HTTPS or a loopback endpoint")
        if not _secure_endpoint(judge_endpoint):
            raise ProtocolError("non-public judge data requires HTTPS or a loopback endpoint")
    if official:
        if target_kind != "recorded":
            _official_endpoint(endpoint)
        _official_endpoint(judge_endpoint)
    if official and max_cases > 0:
        raise ProtocolError("Official runs cannot use --max-cases")
    if official and preset and preset != "reference":
        raise ProtocolError("Official runs require the reference preset")
    if official and repetitions < int(suite.config.get("official_min_repetitions", 1)):
        raise ProtocolError("Official run has too few target repetitions")
    if official and judge_repetitions < int(suite.config.get("official_min_judge_repetitions", 1)):
        raise ProtocolError("Official run has too few judge repetitions")
    judge_host = urllib.parse.urlparse(judge_endpoint).hostname
    external_judge = judge_host not in {"127.0.0.1", "localhost", "::1"}
    target_host = "recorded-local" if target_kind == "recorded" else urllib.parse.urlparse(endpoint).hostname
    if mode == "offline" and (external_judge or target_host not in {"127.0.0.1", "localhost", "::1", "recorded-local"}):
        raise ProtocolError("offline mode permits loopback endpoints only")
    allowed_hosts = {canonical_host(host) for host in (suite.config.get("network") or {}).get("allowed_hosts", [])}
    if official and allowed_hosts and ((target_kind != "recorded" and str(target_host) not in allowed_hosts) or str(judge_host) not in allowed_hosts):
        raise ProtocolError("official endpoint host is not in suite.network.allowed_hosts")
    authorization_record: dict[str, Any] | None = None
    authorization_sha256: str | None = None
    if external_authorization:
        authorization_record, authorization_sha256 = _external_authorization(external_authorization)
    external_hosts = {str(host) for host in (target_host, judge_host) if host not in {"127.0.0.1", "localhost", "::1", "recorded-local"}}
    authorized_hosts = {str(item["host"]) for item in (authorization_record or {}).get("destinations", [])}
    if authorization_record is not None and authorized_hosts != external_hosts:
        raise ProtocolError("external authorization destinations must exactly match the external endpoint hosts")
    if external_judge and not allow_external_judge and authorization_record is None:
        raise ProtocolError("external judge requires --allow-external-judge or an authorization record")
    if official and external_hosts and authorization_record is None:
        raise ProtocolError("official external endpoints require an exact authorization record")
    if suite.config["data_classification"] not in {"public", "synthetic"} and not external_hosts <= authorized_hosts:
        raise ProtocolError(f"non-public suite lacks external authorization for hosts: {sorted(external_hosts - authorized_hosts)}")

    storage_record: dict[str, Any] | None = None
    storage_sha256: str | None = None
    if storage_attestation:
        storage_record, storage_sha256 = _storage_attestation(storage_attestation)
    if official and suite.config["data_classification"] not in {"public", "synthetic"}:
        if storage_record is None or storage_record.get("encryption_at_rest") is not True or storage_record.get("immutability") is not True:
            raise ProtocolError("non-public official runs require current encrypted immutable storage attestation")
    if official and not engagement:
        raise ProtocolError("official runs require an approved engagement governance record")
    engagement_evidence = (
        verified_engagement(Path(engagement), suite, expected_model=expected_model, model_revision=model_revision) if engagement else None
    )
    evidence = git_evidence(repo_root)
    current_environment = environment_evidence(repo_root)
    if official and (not evidence["commit"] or evidence["dirty"]):
        raise ProtocolError("Official runs require a committed, clean source tree")
    if official and (not expected_model or not (expected_judge_model or judge_model)):
        raise ProtocolError("Official runs require expected target and judge identities")
    if official and (not model_revision or not judge_revision):
        raise ProtocolError("Official runs require target and judge revisions")

    judge_config = suite.config.get("judge") or {}
    additional_judges = judge_config.get("additional_models", []) if isinstance(judge_config, dict) else []
    if not isinstance(additional_judges, list) or not all(isinstance(item, dict) for item in additional_judges):
        raise ProtocolError("judge.additional_models must be an array of tables")
    judge_specs: list[dict[str, str]] = [
        {"id": "primary", "model": judge_model, "expected_model": expected_judge_model or judge_model, "revision": judge_revision}
    ]
    for index, item in enumerate(additional_judges, 1):
        if not all(isinstance(item.get(field), str) and item[field].strip() for field in ("model", "expected_model", "revision")):
            raise ProtocolError(f"judge.additional_models[{index}] requires model, expected_model, and revision")
        judge_specs.append(
            {"id": f"additional-{index}", "model": str(item["model"]), "expected_model": str(item["expected_model"]), "revision": str(item["revision"])}
        )
        if official:
            _official_revision(str(item["revision"]), f"additional judge {index}")
    consensus = str(judge_config.get("consensus", "unanimous" if official else "majority"))
    if consensus not in {"unanimous", "majority"}:
        raise ProtocolError("judge.consensus must be unanimous or majority")
    minimum_calibration_accuracy = judge_config.get("minimum_calibration_accuracy")
    if minimum_calibration_accuracy is not None and (
        not isinstance(minimum_calibration_accuracy, (int, float))
        or isinstance(minimum_calibration_accuracy, bool)
        or not math.isfinite(float(minimum_calibration_accuracy))
        or not 0 <= float(minimum_calibration_accuracy) <= 1
    ):
        raise ProtocolError("judge.minimum_calibration_accuracy must be from 0 to 1")
    if official and len({item["expected_model"] for item in judge_specs}) != len(judge_specs):
        raise ProtocolError("official additional judges must have distinct expected model identities")

    selected_cases = stratified_cases(suite.cases, max_cases) if preset else (suite.cases[:max_cases] if max_cases > 0 else suite.cases)
    selection_policy = "deterministic stratified scenario groups" if preset and max_cases > 0 else "dataset order"
    case_order_sha256 = sha256_bytes("\n".join(str(case["id"]) for case in selected_cases).encode("utf-8"))
    planned_target_calls = sum((case.get("review") or {}).get("status") != "rejected" for case in selected_cases) * repetitions
    planned_judge_calls = planned_target_calls * judge_repetitions * len(judge_specs)
    if official and max_target_calls and max_target_calls < planned_target_calls:
        raise ProtocolError("official target-call budget is lower than the complete suite plan")
    if official and max_judge_calls and max_judge_calls < planned_judge_calls:
        raise ProtocolError("official judge-call budget is lower than the complete suite plan")

    safe_target_endpoint = _manifest_endpoint(endpoint)
    safe_judge_endpoint = _manifest_endpoint(judge_endpoint)
    judge_manifest = {
        "requested_model": judge_model,
        "expected_reported_model": expected_judge_model or judge_model,
        "revision": judge_revision,
        "endpoint": safe_judge_endpoint,
        "prompt_sha256": sha256_bytes(_judge_system_prompt(suite).encode("utf-8")),
        "response_schema": "judgment.schema.json@1.0.0",
        "temperature": 0,
        "max_tokens": JUDGE_MAX_TOKENS,
        "judge_repetitions": judge_repetitions,
        "models": judge_specs,
        "consensus": consensus,
    }
    judge_evidence: dict[str, Any] | None = None
    qualification_record: dict[str, Any] | None = None
    approval_record: dict[str, Any] | None = None
    qualification_raw: bytes | None = None
    approval_raw: bytes | None = None
    judge_approver_evidence_raw: bytes | None = None
    qualification_sha256: str | None = None
    approval_sha256: str | None = None
    if official and (not judge_qualification or not judge_approval):
        raise ProtocolError("official runs require judge qualification and independent approval evidence")
    if judge_qualification or judge_approval:
        if not judge_qualification or not judge_approval:
            raise ProtocolError("judge qualification and independent approval must be supplied together")
        qualification_path = Path(judge_qualification)
        approval_path = Path(judge_approval)
        if qualification_path.is_symlink() or approval_path.is_symlink():
            raise ProtocolError("judge qualification and approval must be regular files")
        try:
            qualification_raw = qualification_path.read_bytes()
            approval_raw = approval_path.read_bytes()
            qualification_record = json.loads(qualification_raw)
            approval_record = json.loads(approval_raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError("judge qualification and approval must be readable JSON objects") from exc
        qualification_sha256 = sha256_bytes(qualification_raw)
        approval_sha256 = sha256_bytes(approval_raw)
        evidence_errors = judge_evidence_errors(
            qualification_record,
            approval_record,
            qualification_sha256=qualification_sha256,
            expected_judge=judge_manifest,
            rubric_sha256=sha256_file(suite.rubric_path),
            approval_root=Path(judge_approval).parent,
        )
        if evidence_errors:
            raise ProtocolError("invalid judge qualification evidence:\n" + "\n".join(evidence_errors))
        judge_approver_evidence_path = (approval_path.parent / str(approval_record["approver_qualification_evidence"])).resolve()
        try:
            judge_approver_evidence_raw = judge_approver_evidence_path.read_bytes()
        except OSError as exc:
            raise ProtocolError("judge approver qualification evidence became unreadable during preflight") from exc
        if sha256_bytes(judge_approver_evidence_raw) != approval_record["approver_qualification_evidence_sha256"]:
            raise ProtocolError("judge approver qualification evidence changed during preflight")
        judge_evidence = {
            "qualification_sha256": qualification_sha256,
            "approval_sha256": approval_sha256,
            "approval_id": approval_record["approval_id"],
            "approver_id": approval_record["approver_id"],
            "approved_at": approval_record["approved_at"],
            "expires_at": approval_record["expires_at"],
            "approver_qualification_evidence_sha256": approval_record["approver_qualification_evidence_sha256"],
        }
        if official and engagement_evidence is not None and approval_record["approver_id"] in {
            engagement_evidence.get("execution_owner_id"),
            engagement_evidence.get("commercial_owner_id"),
        }:
            raise ProtocolError("judge approval must be independent of the engagement execution and commercial owners")

    target_key = os.getenv(target_key_env, "")
    judge_key = os.getenv(judge_key_env, "")
    if target_key and target_kind != "recorded" and not _secure_endpoint(endpoint):
        raise ProtocolError("target credentials require HTTPS or a loopback endpoint")
    if judge_key and not _secure_endpoint(judge_endpoint):
        raise ProtocolError("judge credentials require HTTPS or a loopback endpoint")
    protocol_source = repo_root / "PROTOCOL.md"
    if not protocol_source.is_file() or protocol_source.is_symlink():
        protocol_source = canonical_protocol_path()
    protocol_raw = protocol_source.read_bytes()
    dataset_raw = suite.dataset_path.read_bytes()
    rubric_raw = suite.rubric_path.read_bytes()
    suite_evidence_raw = suite_governance_snapshots(suite.root, suite.config) if official else {}
    suite_evidence_manifest = {relative: sha256_bytes(raw_bytes) for relative, raw_bytes in suite_evidence_raw.items()}
    suite_manifest = {
        "name": suite.name,
        "version": suite.version,
        "status": suite.status,
        "dataset_sha256": sha256_bytes(dataset_raw),
        "rubric_sha256": sha256_bytes(rubric_raw),
        "suite_config_sha256": sha256_bytes(suite_config_raw),
        "data_classification": suite.config["data_classification"],
        "profile": suite.config.get("profile", "text-generation"),
    }
    target_manifest = {
        "label": model_label,
        "expected_reported_model": expected_model,
        "revision": model_revision,
        "endpoint": safe_target_endpoint,
        "request_model": request_model,
        "api_key_env": target_key_env,
        "kind": target_kind,
        "capabilities": (suite.config.get("target") or {}).get("capabilities", []),
        "recorded_responses_sha256": (
            sha256_file(suite.root / str((suite.config.get("target") or {}).get("responses"))) if target_kind == "recorded" else None
        ),
    }
    judge_manifest["api_key_env"] = judge_key_env
    authorization_evidence = (
        {
            **{key: authorization_record[key] for key in ("authorization_id", "approver", "purpose", "destinations", "expires_at")},
            "sha256": authorization_sha256,
        }
        if authorization_record
        else None
    )
    storage_evidence = (
        {
            **{
                key: storage_record[key]
                for key in ("attestation_id", "approver", "encryption_at_rest", "immutability", "effective_at", "expires_at")
            },
            "sha256": storage_sha256,
        }
        if storage_record
        else None
    )
    artifact_security = {
        "classification": suite.config["data_classification"],
        "retention": (suite.config.get("governance") or {}).get("retention"),
        "storage_attestation": storage_evidence,
        "encryption_state": "attested" if storage_record and storage_record.get("encryption_at_rest") else "not-attested",
        "immutability_state": "attested" if storage_record and storage_record.get("immutability") else "not-attested",
    }
    parameters_manifest = {
        "mode": mode,
        "case_review_policy": "approved-only" if official else "approved-and-needs-review",
        "preset": preset,
        "preset_version": BENCHMARK_PRESET_VERSION if preset else None,
        "repetitions": repetitions,
        "judge_repetitions": judge_repetitions,
        "max_cases": max_cases,
        "selected_cases": len(selected_cases),
        "timeout_seconds": timeout,
        "max_target_calls": max_target_calls,
        "max_judge_calls": max_judge_calls,
        "max_total_tokens": max_total_tokens,
        "max_elapsed_seconds": max_elapsed_seconds,
        "max_estimated_cost": max_estimated_cost,
        "non_inferiority_margin": non_inferiority_margin,
        "concurrency": concurrency,
        "requests_per_second": requests_per_second,
        "progress_events": progress,
        "case_order_policy": selection_policy,
        "case_order_sha256": case_order_sha256,
        "cache": {"target": "disabled", "judge": "disabled"},
    }
    execution_contract = {
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": sha256_bytes(protocol_raw),
        "schema_version": SCHEMA_VERSION,
        "report_version": REPORT_VERSION,
        "metric_version": METRIC_VERSION,
        "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
        "official_requested": official,
        "suite": suite_manifest,
        "target": target_manifest,
        "judge": judge_manifest,
        "judge_qualification": judge_evidence,
        "engagement": engagement_evidence,
        "external_judge_authorized": bool(authorization_record) or bool(allow_external_judge and not official),
        "external_authorization": authorization_evidence,
        "artifact_security": artifact_security,
        "parameters": parameters_manifest,
        "pricing": suite.config.get("pricing") or None,
        "source": evidence,
        "environment": current_environment,
        "signing": {"key_env": signing_key_env, "key_id": signing_key_id},
    }

    def require_current_official_evidence() -> None:
        if not official:
            return
        current_suite = load_suite(suite.root, official=True)
        current_suite_manifest = {
            "name": current_suite.name,
            "version": current_suite.version,
            "status": current_suite.status,
            "dataset_sha256": sha256_file(current_suite.dataset_path),
            "rubric_sha256": sha256_file(current_suite.rubric_path),
            "suite_config_sha256": sha256_file(current_suite.root / "suite.toml"),
            "data_classification": current_suite.config["data_classification"],
            "profile": current_suite.config.get("profile", "text-generation"),
        }
        if current_suite_manifest != suite_manifest or current_suite.cases != suite.cases or current_suite.rubric != suite.rubric:
            raise ProtocolError("official suite changed after canonical validation")
        if git_evidence(repo_root) != evidence:
            raise ProtocolError("official source tree changed after preflight")
        if authorization_record is not None:
            current, digest = _external_authorization(external_authorization)
            if current != authorization_record or digest != authorization_sha256:
                raise ProtocolError("external authorization changed after preflight")
        if storage_record is not None:
            current, digest = _storage_attestation(storage_attestation)
            if current != storage_record or digest != storage_sha256:
                raise ProtocolError("storage attestation changed after preflight")
        if qualification_record is not None and approval_record is not None:
            qualification_path = Path(judge_qualification)
            approval_path = Path(judge_approval)
            if (
                qualification_path.is_symlink()
                or approval_path.is_symlink()
                or not qualification_path.is_file()
                or not approval_path.is_file()
                or sha256_file(qualification_path) != qualification_sha256
                or sha256_file(approval_path) != approval_sha256
                or judge_evidence_errors(
                    qualification_record,
                    approval_record,
                    qualification_sha256=str(qualification_sha256),
                    expected_judge=judge_manifest,
                    rubric_sha256=sha256_file(suite.rubric_path),
                    approval_root=approval_path.parent,
                )
            ):
                raise ProtocolError("judge qualification or approval changed, expired, or became invalid")
        if engagement_evidence is not None:
            current_engagement = verified_engagement(
                Path(engagement), suite, expected_model=expected_model, model_revision=model_revision
            )
            if current_engagement != engagement_evidence:
                raise ProtocolError("engagement governance evidence changed after preflight")

    require_unchanged_suite_config()
    require_current_official_evidence()
    manifest: dict[str, Any]
    if resume_dir is None:  # Checked above; retained only to keep the new-run assembly scoped.
        run_id, run_dir = new_run_dir(output_root or repo_root, suite, model_label)
        started = datetime.now(timezone.utc)
        reproduction = [
            "cavada-eval",
            "run",
            str(suite.root),
            "--endpoint",
            safe_target_endpoint,
            "--model-label",
            model_label,
            "--expected-model",
            expected_model,
            "--model-revision",
            model_revision,
            "--judge-endpoint",
            safe_judge_endpoint,
            "--judge-model",
            judge_model,
            "--expected-judge-model",
            expected_judge_model or judge_model,
            "--judge-revision",
            judge_revision,
            "--target-key-env",
            target_key_env,
            "--judge-key-env",
            judge_key_env,
            "--repetitions",
            str(repetitions),
            "--judge-repetitions",
            str(judge_repetitions),
            "--max-cases",
            str(max_cases),
            "--timeout",
            str(timeout),
            "--mode",
            mode,
            "--max-target-calls",
            str(max_target_calls),
            "--max-judge-calls",
            str(max_judge_calls),
            "--max-total-tokens",
            str(max_total_tokens),
            "--max-elapsed-seconds",
            str(max_elapsed_seconds),
            "--max-estimated-cost",
            str(max_estimated_cost),
            "--concurrency",
            str(concurrency),
            "--requests-per-second",
            str(requests_per_second),
            "--signing-key-env",
            signing_key_env,
        ]
        if non_inferiority_margin is not None:
            reproduction.extend(["--non-inferiority-margin", str(non_inferiority_margin)])
        if request_model:
            reproduction.extend(["--request-model", request_model])
        for option, value, safe_reference in (
            ("--external-authorization", external_authorization, "PATH_TO_EXTERNAL_AUTHORIZATION_JSON"),
            ("--storage-attestation", storage_attestation, "PATH_TO_STORAGE_ATTESTATION_JSON"),
            ("--judge-qualification", judge_qualification, "PATH_TO_JUDGE_QUALIFICATION_JSON"),
            ("--judge-approval", judge_approval, "PATH_TO_JUDGE_APPROVAL_JSON"),
            ("--engagement", engagement, "PATH_TO_ENGAGEMENT_JSON"),
            ("--signing-key-id", signing_key_id, signing_key_id),
        ):
            if value:
                reproduction.extend([option, safe_reference])
        if allow_external_judge:
            reproduction.append("--allow-external-judge")
        if progress:
            reproduction.append("--progress")
        if official:
            reproduction.append("--official")
        if preset:
            reproduction.extend(["--preset", preset])
        public_reproduction = [
            "cavada-eval",
            "run",
            "SUITE",
            "--model-label",
            "MODEL_LABEL",
            "--expected-model",
            "EXPECTED_MODEL",
            "--model-revision",
            "IMMUTABLE_MODEL_REVISION",
            "--judge-model",
            "JUDGE_MODEL",
            "--expected-judge-model",
            "EXPECTED_JUDGE_MODEL",
            "--judge-revision",
            "IMMUTABLE_JUDGE_REVISION",
            "--repetitions",
            str(repetitions),
            "--judge-repetitions",
            str(judge_repetitions),
            "--max-cases",
            str(max_cases),
            "--timeout",
            str(timeout),
            "--mode",
            mode,
        ]
        if non_inferiority_margin is not None:
            public_reproduction.extend(["--non-inferiority-margin", str(non_inferiority_margin)])
        if official:
            public_reproduction.append("--official")
        if preset:
            public_reproduction.extend(["--preset", preset])
        manifest = {
            **execution_contract,
            "run_id": run_id,
            "status": "running",
            "started_at": started.isoformat(),
            "reproduction_command": shlex.join(reproduction),
            "public_reproduction_command": shlex.join(public_reproduction),
        }
    run_perf_started = time.perf_counter()
    atomic_json(run_dir / "manifest.json", manifest)
    if resume_dir is None:
        atomic_json(run_dir / "environment.json", manifest["environment"])
        atomic_json(run_dir / "asset_inventory.json", asset_inventory(selected_cases, suite_root=suite.root, snapshot_dir=run_dir / "assets"))
        snapshots = {
            "protocol_snapshot.md": (protocol_raw, manifest["protocol_sha256"]),
            "suite_snapshot.toml": (suite_config_raw, suite_manifest["suite_config_sha256"]),
            "dataset_snapshot.jsonl": (dataset_raw, suite_manifest["dataset_sha256"]),
            "rubric_snapshot.md": (rubric_raw, suite_manifest["rubric_sha256"]),
        }
        for name, (snapshot_raw, expected_hash) in snapshots.items():
            path = run_dir / name
            path.write_bytes(snapshot_raw)
            os.chmod(path, 0o600)
            if sha256_file(path) != expected_hash:
                raise ProtocolError("behavior input snapshot hash mismatch; no network request was sent")
        atomic_json(run_dir / "suite_evidence_manifest.json", suite_evidence_manifest)
        suite_evidence_dir = run_dir / "suite_evidence"
        for raw_bytes in suite_evidence_raw.values():
            digest = sha256_bytes(raw_bytes)
            path = suite_evidence_dir / digest
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(raw_bytes)
                os.chmod(path, 0o600)
            if sha256_file(path) != digest:
                raise ProtocolError("suite governance snapshot hash mismatch; no network request was sent")
        if qualification_raw is not None and approval_raw is not None and judge_approver_evidence_raw is not None:
            judge_snapshots = {
                "judge_qualification_snapshot.json": (qualification_raw, qualification_sha256),
                "judge_approval_snapshot.json": (approval_raw, approval_sha256),
                f"judge_evidence/{sha256_bytes(judge_approver_evidence_raw)}": (
                    judge_approver_evidence_raw,
                    sha256_bytes(judge_approver_evidence_raw),
                ),
            }
            for name, (snapshot_raw, expected_hash) in judge_snapshots.items():
                path = run_dir / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(snapshot_raw)
                os.chmod(path, 0o600)
                if expected_hash is None or sha256_file(path) != expected_hash:
                    raise ProtocolError("judge evidence snapshot hash mismatch; no network request was sent")
        (run_dir / "dataset_card.md").write_text(dataset_card(suite), encoding="utf-8")
        os.chmod(run_dir / "dataset_card.md", 0o600)
        require_current_official_evidence()
        for name in ("requests.jsonl", "raw_responses.jsonl", "judgments.jsonl", "case_results.jsonl", "failures.jsonl", "events.jsonl"):
            (run_dir / name).touch(mode=0o600, exist_ok=False)
    result_rows: list[dict[str, Any]] = []
    pricing_config = suite.config.get("pricing") or {}
    usage_required = bool(pricing_config or max_total_tokens or max_estimated_cost)
    target_calls = 0
    judge_calls = 0
    token_totals = {"target_input": 0.0, "target_output": 0.0, "judge_input": 0.0, "judge_output": 0.0}
    total_tokens = 0.0
    def current_estimated_cost() -> float:
        return sum(
            token_totals[f"{kind}_{direction}"] * float(pricing_config.get(f"{prefix}_per_million", 0)) / 1_000_000
            for kind, direction, prefix in (
                ("target", "input", "input"),
                ("target", "output", "output"),
                ("judge", "input", "judge_input"),
                ("judge", "output", "judge_output"),
            )
        )

    write_lock = threading.Lock()
    budget_lock = threading.Lock()
    rate_lock = threading.Lock()
    abort_event = threading.Event()
    abort_reasons: list[str] = []
    next_request_at = 0.0

    def require_current_official_timestamps() -> None:
        def unchanged(path_value: str, expected_hash: str | None, label: str) -> None:
            path = Path(path_value)
            if path.is_symlink() or not path.is_file() or expected_hash is None or sha256_file(path) != expected_hash:
                raise ProtocolError(f"official evidence is no longer effective: {label} changed before dispatch")

        if authorization_record is not None:
            unchanged(external_authorization, authorization_sha256, "external authorization")
        current = _evidence_now()

        def timestamp(record: dict[str, Any], field: str, label: str) -> datetime:
            value = record.get(field)
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ProtocolError(f"official evidence is no longer effective: invalid {label} {field}") from exc
            if parsed.tzinfo is None:
                raise ProtocolError(f"official evidence is no longer effective: {label} {field} lacks timezone")
            return parsed

        if authorization_record is not None and current >= timestamp(authorization_record, "expires_at", "external authorization"):
            raise ProtocolError("official evidence is no longer effective: external authorization expired before dispatch")
        if not official:
            return
        if storage_record is not None:
            unchanged(storage_attestation, storage_sha256, "storage attestation")
        if qualification_record is not None:
            unchanged(judge_qualification, qualification_sha256, "judge qualification")
        if approval_record is not None:
            unchanged(judge_approval, approval_sha256, "judge approval")
        if engagement_evidence is not None:
            unchanged(engagement, str(engagement_evidence.get("sha256") or ""), "engagement")
        if storage_record is not None and not (
            timestamp(storage_record, "effective_at", "storage attestation")
            <= current
            < timestamp(storage_record, "expires_at", "storage attestation")
        ):
            raise ProtocolError("official evidence is no longer effective: storage attestation expired before dispatch")
        if approval_record is not None and not (
            timestamp(approval_record, "approved_at", "judge approval")
            <= current
            < timestamp(approval_record, "expires_at", "judge approval")
        ):
            raise ProtocolError("official evidence is no longer effective: judge approval expired before dispatch")
        if qualification_record is not None and qualification_record.get("completed_at") is not None:
            if timestamp(qualification_record, "completed_at", "judge qualification") > current:
                raise ProtocolError("official evidence is no longer effective: judge qualification is future-dated")
        if engagement_evidence is not None and not (
            timestamp(engagement_evidence, "approved_at", "engagement")
            <= current
            < timestamp(engagement_evidence, "expires_at", "engagement")
        ):
            raise ProtocolError("official evidence is no longer effective: engagement expired before dispatch")

    def record(name: str, value: dict[str, Any]) -> None:
        with write_lock:
            append_jsonl(run_dir / name, value)

    def emit_event(event: str, **fields: Any) -> None:
        value = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        record("events.jsonl", value)
        if progress:
            print(json.dumps(value, sort_keys=True), file=sys.stderr, flush=True)

    def wait_for_rate_limit() -> None:
        nonlocal next_request_at
        if not requests_per_second:
            return
        with rate_lock:
            now = time.monotonic()
            reserved = max(now, next_request_at)
            next_request_at = reserved + 1 / requests_per_second
        delay = reserved - now
        if delay > 0:
            time.sleep(delay)

    def enforce_budget(kind: str) -> None:
        nonlocal target_calls, judge_calls
        require_current_official_timestamps()
        with budget_lock:
            if max_elapsed_seconds and time.perf_counter() - run_perf_started >= max_elapsed_seconds:
                raise ProtocolError("budget exhausted: elapsed time")
            if kind == "target":
                if max_target_calls and target_calls >= max_target_calls:
                    raise ProtocolError("budget exhausted: target calls")
                target_calls += 1
            else:
                if max_judge_calls and judge_calls >= max_judge_calls:
                    raise ProtocolError("budget exhausted: judge calls")
                judge_calls += 1

    def consume_tokens(raw: dict[str, Any], kind: str) -> None:
        nonlocal total_tokens
        input_tokens, output_tokens = _usage_tokens(raw, required=usage_required)
        with budget_lock:
            token_totals[f"{kind}_input"] += input_tokens
            token_totals[f"{kind}_output"] += output_tokens
            total_tokens += input_tokens + output_tokens
            if max_total_tokens and total_tokens > max_total_tokens:
                raise ProtocolError("budget exhausted: total tokens")
            if max_estimated_cost and current_estimated_cost() > max_estimated_cost:
                raise ProtocolError("budget exhausted: estimated cost")

    def evaluate_observation(task: tuple[dict[str, Any], int]) -> dict[str, Any]:
        case, repetition = task
        base = {
            "case_id": case["id"],
            "category": case["category"],
            "risk_domain": case["risk_domain"],
            "severity": case["severity"],
            "language": case.get("language", "missing"),
            "locale": case.get("locale", "missing"),
            "split": case.get("split", "missing"),
            "operating_condition": case.get("operating_condition", "missing"),
            "distribution_shift_reference_id": case.get("distribution_shift_reference_id"),
            "scenario_id": case.get("scenario_group_id") or case.get("scenario_id"),
            "case_review_status": case["review"]["status"],
            "performance_phase": case.get("performance_phase", "steady"),
            "repetition": repetition,
        }
        if abort_event.is_set():
            result = {**base, "status": "skipped", "reason": "run aborted by a prior observation"}
            record("case_results.jsonl", result)
            return result
        started_case_ns = time.perf_counter_ns()
        emit_event("observation_started", case_id=case["id"], repetition=repetition, monotonic_ns=started_case_ns)
        target_transport: dict[str, Any] | None = None
        target_raw: dict[str, Any] = {}

        def finish_result(result: dict[str, Any]) -> dict[str, Any]:
            finished_case_ns = time.perf_counter_ns()
            result["duration_ms"] = round((finished_case_ns - started_case_ns) / 1_000_000, 1)
            if target_transport is not None:
                result.update(
                    {
                        "target_latency_ms": target_transport.get("total_ms"),
                        "target_headers_ms": target_transport.get("headers_ms"),
                        "target_response_bytes": target_transport.get("response_bytes"),
                    }
                )
                if "ttft_ms" in target_transport:
                    result["ttft_ms"] = target_transport["ttft_ms"]
                if isinstance(target_transport.get("inter_chunk_ms"), dict):
                    result["inter_chunk_ms"] = target_transport["inter_chunk_ms"]
                usage = target_raw.get("usage") if isinstance(target_raw, dict) else None
                if isinstance(usage, dict):
                    result["input_tokens"] = usage.get("prompt_tokens")
                    result["output_tokens"] = usage.get("completion_tokens")
                    output_tokens = usage.get("completion_tokens")
                    latency_ms = target_transport.get("total_ms")
                    if isinstance(output_tokens, (int, float)) and isinstance(latency_ms, (int, float)) and latency_ms > 0:
                        result["output_tokens_per_second"] = float(output_tokens) / (float(latency_ms) / 1000)
            record("case_results.jsonl", result)
            emit_event(
                "observation_finished",
                case_id=case["id"],
                repetition=repetition,
                status=result["status"],
                monotonic_ns=finished_case_ns,
            )
            return result

        try:
            wait_for_rate_limit()
            if abort_event.is_set():
                raise _RunAborted("run aborted by a prior observation")
            enforce_budget("target")
            if abort_event.is_set():
                raise _RunAborted("run aborted by a prior observation")
            target_input = target_case_prompt(case, target_kind)
            try:
                answer, target_raw, reported_model, target_request, target_transport = call_target(
                    suite, endpoint, target_key, target_input, request_model, timeout
                )
            except _CallEvidenceError as exc:
                target_raw = dict(exc.raw) if isinstance(exc.raw, dict) else {}
                target_transport = exc.transport
                reported_model = _target_reported_model(suite, target_raw)
                record(
                    "requests.jsonl",
                    {
                        **base,
                        "kind": "target",
                        "request_id": exc.transport["request_id"],
                        "payload": exc.request,
                        "status": "error",
                        "error": str(exc),
                        "transport": exc.transport,
                    },
                )
                record(
                    "raw_responses.jsonl",
                    {
                        **base,
                        "reported_model": reported_model,
                        "response": exc.raw,
                        "transport": exc.transport,
                        "status": "error",
                        "error": str(exc),
                    },
                )
                stream_identities = _stream_model_identities(target_raw)
                if (stream_identities and stream_identities != {expected_model}) or (reported_model and reported_model != expected_model):
                    observed: object = sorted(stream_identities) if stream_identities else reported_model
                    raise ProtocolError(f"Target identity mismatch: expected {expected_model!r}, got {observed!r}") from exc
                if exc.raw is not None:
                    consume_tokens(target_raw, "target")
                raise
            record("requests.jsonl", {**base, "kind": "target", "request_id": target_transport["request_id"], "payload": target_request})
            record("raw_responses.jsonl", {**base, "reported_model": reported_model, "response": target_raw, "transport": target_transport})
            if reported_model != expected_model:
                raise ProtocolError(f"Target identity mismatch: expected {expected_model!r}, got {reported_model!r}")
            consume_tokens(target_raw, "target")
            target = suite.config.get("target") or {}
            tools = _get(target_raw, str(target.get("tools_field", "tool_calls"))) or []
            deterministic = deterministic_evaluation(case, answer, tool_calls=tools)
            if not deterministic["hard_pass"]:
                result = {**base, "status": "fail", "reason": "deterministic check failed", "deterministic": deterministic}
            else:
                verdicts: list[dict[str, Any]] = []
                for judge_index, judge_spec in enumerate(judge_specs):
                    for model_repetition in range(1, judge_repetitions + 1):
                        judge_repetition = judge_index * judge_repetitions + model_repetition
                        evidence_fields = {
                            "judge_id": judge_spec["id"],
                            "requested_model": judge_spec["model"],
                            "judge_revision": judge_spec["revision"],
                            "judge_repetition": judge_repetition,
                            "model_repetition": model_repetition,
                        }
                        try:
                            if _target_identity_exposure(
                                build_judge_payload(suite, judge_spec["model"], case, answer, target_raw),
                                (model_label, expected_model, model_revision, request_model),
                            ):
                                raise ProtocolError("Judge payload exposes a target identity; dispatch blocked")
                            wait_for_rate_limit()
                            if abort_event.is_set():
                                raise _RunAborted("run aborted by a prior observation")
                            enforce_budget("judge")
                            if abort_event.is_set():
                                raise _RunAborted("run aborted by a prior observation")
                            judgment, judge_raw, judge_content, judge_request, judge_transport = call_judge(
                                suite, judge_endpoint, judge_key, judge_spec["model"], case, answer, target_raw, timeout
                            )
                            reported_judge = str(judge_raw.get("model") or "")
                            try:
                                _usage_tokens(judge_raw, required=usage_required)
                            except ProtocolError as exc:
                                usage_error = str(exc)
                            else:
                                usage_error = ""
                            record(
                                "requests.jsonl",
                                {**base, **evidence_fields, "kind": "judge", "request_id": judge_transport["request_id"], "payload": judge_request},
                            )
                            record(
                                "judgments.jsonl",
                                {
                                    **base,
                                    **evidence_fields,
                                    "reported_model": reported_judge,
                                    "judgment": judgment,
                                    "raw": judge_raw,
                                    "raw_content": judge_content,
                                    "transport": judge_transport,
                                    **({"status": "invalid", "error": usage_error} if usage_error else {}),
                                },
                            )
                            if reported_judge != judge_spec["expected_model"]:
                                raise ProtocolError(f"Judge identity mismatch: expected {judge_spec['expected_model']!r}, got {reported_judge!r}")
                            if usage_error:
                                if usage_required:
                                    raise ProtocolError(usage_error)
                                continue
                            consume_tokens(judge_raw, "judge")
                            verdicts.append(judgment)
                        except _TransportError as exc:
                            record(
                                "requests.jsonl",
                                {
                                    **base,
                                    **evidence_fields,
                                    "kind": "judge",
                                    "request_id": exc.transport["request_id"],
                                    "payload": exc.request,
                                    "status": "error",
                                    "error": str(exc),
                                    "transport": exc.transport,
                                },
                            )
                            record(
                                "judgments.jsonl",
                                {
                                    **base,
                                    **evidence_fields,
                                    "status": "error",
                                    "error": str(exc),
                                    "raw": exc.raw,
                                    "transport": exc.transport,
                                },
                            )
                            raise
                        except _JudgeOutputError as exc:
                            reported_judge = str((exc.raw or {}).get("model") or "")
                            identity_mismatch = reported_judge != judge_spec["expected_model"]
                            usage_error = ""
                            if exc.raw is not None:
                                try:
                                    _usage_tokens(exc.raw, required=usage_required)
                                except ProtocolError as usage_exc:
                                    usage_error = str(usage_exc)
                            record(
                                "requests.jsonl",
                                {
                                    **base,
                                    **evidence_fields,
                                    "kind": "judge",
                                    "request_id": exc.transport["request_id"],
                                    "payload": exc.request,
                                },
                            )
                            record(
                                "judgments.jsonl",
                                {
                                    **base,
                                    **evidence_fields,
                                    "reported_model": reported_judge,
                                    "status": "invalid",
                                    "error": "; ".join(filter(None, (str(exc), usage_error))),
                                    "raw": exc.raw,
                                    "transport": exc.transport,
                                },
                            )
                            if identity_mismatch:
                                raise ProtocolError(
                                    f"Judge identity mismatch: expected {judge_spec['expected_model']!r}, got {reported_judge!r}"
                                ) from exc
                            if usage_error and usage_required:
                                raise ProtocolError(usage_error) from exc
                            if exc.raw is not None and not usage_error:
                                consume_tokens(exc.raw, "judge")
                        except _RunAborted:
                            raise
                        except ProtocolError as exc:
                            if any(
                                fragment in str(exc).casefold()
                                for fragment in (
                                    "identity mismatch",
                                    "target identity",
                                    "budget exhausted",
                                    "official evidence is no longer effective",
                                )
                            ):
                                raise
                            if usage_required and "provider usage" in str(exc).casefold():
                                raise
                            record("judgments.jsonl", {**base, **evidence_fields, "status": "invalid", "error": str(exc)})
                passes = sum(item["verdict"] == "pass" for item in verdicts)
                fails = sum(item["verdict"] == "fail" for item in verdicts)
                expected_verdicts = judge_repetitions * len(judge_specs)
                if len(verdicts) != expected_verdicts:
                    result = {**base, "status": "invalid", "reason": "one or more judge outputs were invalid", "deterministic": deterministic}
                elif passes == fails or (consensus == "unanimous" and passes and fails):
                    result = {**base, "status": "invalid", "reason": "judge disagreement", "deterministic": deterministic}
                else:
                    result = {
                        **base,
                        "status": "pass" if passes > fails else "fail",
                        "reason": f"judge {consensus}",
                        "score": sum(item["score"] for item in verdicts) / len(verdicts),
                        "judge_agreement": max(passes, fails) / len(verdicts),
                        "deterministic": deterministic,
                    }
        except _RunAborted as exc:
            result = {**base, "status": "skipped", "reason": str(exc)}
        except ProtocolError as exc:
            result = {**base, "status": "error", "reason": str(exc)}
            if (
                (
                    official
                    and any(
                        fragment in str(exc).casefold()
                        for fragment in ("identity mismatch", "target identity", "official evidence is no longer effective")
                    )
                )
                or "budget exhausted" in str(exc).casefold()
                or (usage_required and "provider usage" in str(exc).casefold())
            ):
                with budget_lock:
                    if not abort_reasons:
                        abort_reasons.append(str(exc))
                abort_event.set()
        return finish_result(result)

    tasks: list[tuple[dict[str, Any], int]] = []
    for case in selected_cases:
        if case["review"]["status"] == "rejected":
            result = {
                "case_id": case["id"],
                "category": case["category"],
                "risk_domain": case["risk_domain"],
                "severity": case["severity"],
                "language": case.get("language", "missing"),
                "locale": case.get("locale", "missing"),
                "split": case.get("split", "missing"),
                "scenario_id": case.get("scenario_group_id") or case.get("scenario_id"),
                "case_review_status": case["review"]["status"],
                "performance_phase": case.get("performance_phase", "steady"),
                "status": "skipped",
                "reason": "case rejected",
            }
            result_rows.append(result)
            record("case_results.jsonl", result)
            continue
        tasks.extend((case, repetition) for repetition in range(1, repetitions + 1))
    try:
        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="cavada-eval") as executor:
            result_rows.extend(executor.map(evaluate_observation, tasks))
    except KeyboardInterrupt:
        abort_event.set()
        manifest["status"] = "cancelled"
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        manifest["abort_reason"] = "operator cancellation"
        atomic_json(run_dir / "manifest.json", manifest)
        raise
    try:
        require_current_official_evidence()
    except ProtocolError as exc:
        abort_reasons.append(str(exc))
    if max_elapsed_seconds and time.perf_counter() - run_perf_started >= max_elapsed_seconds:
        elapsed_reason = "budget exhausted: elapsed time"
        if elapsed_reason not in abort_reasons:
            abort_reasons.append(elapsed_reason)
    reconciliation = _behavior_reconciliation(
        selected_cases,
        repetitions,
        _read_jsonl(run_dir / "requests.jsonl"),
        _read_jsonl(run_dir / "raw_responses.jsonl"),
        _read_jsonl(run_dir / "judgments.jsonl"),
        _read_jsonl(run_dir / "case_results.jsonl"),
        expected_judgments_per_observation=judge_repetitions * len(judge_specs),
        consensus=consensus,
    )
    if official and not reconciliation["valid"]:
        abort_reasons.append("official evidence reconciliation failed")
    abort_reason = abort_reasons[0] if abort_reasons else ""

    statistics_config = suite.config.get("statistics") or {}
    confidence = float(statistics_config.get("confidence", 0.95))
    bootstrap_samples = int(statistics_config.get("bootstrap_samples", 10_000))
    bootstrap_seed = int(statistics_config.get("seed", 0))
    case_metrics, case_categories = summarize(result_rows, confidence=confidence)
    scenario_rows = _scenario_analysis_rows(result_rows, selected_cases)
    analysis_rows = scenario_rows if scenario_rows is not None else result_rows
    metrics, categories = summarize(analysis_rows, confidence=confidence)
    metrics["analysis_unit"] = "scenario" if scenario_rows is not None else "case"
    metrics["evaluation_cases"] = case_metrics["total"]
    metrics["target_observations"] = case_metrics["observations"]
    metrics["evidence_reconciliation"] = reconciliation
    metrics["constructs"] = sorted(str(row["category"]) for row in categories)
    metrics["aggregate_scope"] = "single-construct" if len(metrics["constructs"]) <= 1 else "not-applicable"
    metrics["legacy_overall_metrics_claimable"] = metrics["aggregate_scope"] == "single-construct"
    if scenario_rows is not None:
        metrics["case_level"] = case_metrics
        metrics["case_categories"] = case_categories
    statuses_by_case: dict[str, list[str]] = {}
    for row in analysis_rows:
        statuses_by_case.setdefault(str(row["case_id"]), []).append(str(row["status"]))
    case_binary = []
    for statuses in statuses_by_case.values():
        if set(statuses) == {"pass"}:
            case_binary.append(1.0)
        elif set(statuses) <= {"pass", "fail"}:
            case_binary.append(0.0)
    metrics["pass_rate_bootstrap_ci"] = (
        bootstrap_mean_interval(case_binary, confidence=confidence, samples=bootstrap_samples, seed=bootstrap_seed)
        if case_binary
        else {"lower": 0.0, "upper": 0.0, "confidence": confidence, "samples": bootstrap_samples, "seed": bootstrap_seed}
    )
    category_binary: dict[str, list[float]] = {}
    for case_id, statuses in statuses_by_case.items():
        case_rows = [row for row in analysis_rows if str(row["case_id"]) == case_id]
        if set(statuses) == {"pass"}:
            category_binary.setdefault(str(case_rows[0]["category"]), []).append(1.0)
        elif set(statuses) <= {"pass", "fail"}:
            category_binary.setdefault(str(case_rows[0]["category"]), []).append(0.0)
    metrics["pass_rate_stratified_bootstrap_ci"] = stratified_bootstrap_mean_interval(
        category_binary, confidence=confidence, samples=bootstrap_samples, seed=bootstrap_seed
    )
    distribution_shift = _distribution_shift_summary(
        result_rows,
        selected_cases,
        confidence=confidence,
        samples=bootstrap_samples,
        seed=bootstrap_seed,
    )
    if distribution_shift is not None:
        metrics["distribution_shift"] = distribution_shift
    slices: dict[str, dict[str, Any]] = {}
    for dimension in ("risk_domain", "severity", "language", "locale", "split", "operating_condition"):
        values: dict[str, Any] = {}
        for value in sorted({str(row.get(dimension, "missing")) for row in analysis_rows}):
            subset = [row for row in analysis_rows if str(row.get(dimension, "missing")) == value]
            values[value] = summarize(subset, confidence=confidence)[0]
        slices[dimension] = values
    metrics["slices"] = slices
    metrics["slice_disparities"] = {
        dimension: max((float(item["pass_rate"]) for item in values.values()), default=0.0)
        - min((float(item["pass_rate"]) for item in values.values()), default=0.0)
        for dimension, values in slices.items()
    }
    case_statuses: dict[str, list[str]] = {}
    for row in result_rows:
        case_statuses.setdefault(str(row["case_id"]), []).append(str(row["status"]))
    repetition_pass_rates = []
    for statuses in case_statuses.values():
        valid = [status for status in statuses if status in {"pass", "fail"}]
        if valid:
            repetition_pass_rates.append(sum(status == "pass" for status in valid) / len(valid))
    metrics["stability"] = {
        "case_pass_fraction": distribution(repetition_pass_rates),
        "stable_case_fraction": sum(value in {0.0, 1.0} for value in repetition_pass_rates) / len(repetition_pass_rates) if repetition_pass_rates else 0.0,
        "judge_agreement": distribution(row["judge_agreement"] for row in result_rows if isinstance(row.get("judge_agreement"), (int, float))),
        "judge_score": distribution(row["score"] for row in result_rows if isinstance(row.get("score"), (int, float))),
    }
    calibration_rows = _read_jsonl(run_dir / "judgments.jsonl")
    calibration = _judge_calibration_summary(calibration_rows, suite)
    metrics["judge_calibration"] = calibration
    metrics["performance"] = {
        "target_latency_ms": distribution(row["target_latency_ms"] for row in result_rows if isinstance(row.get("target_latency_ms"), (int, float))),
        "evaluation_duration_ms": distribution(row["duration_ms"] for row in result_rows if isinstance(row.get("duration_ms"), (int, float))),
        "target_response_bytes": distribution(
            row["target_response_bytes"] for row in result_rows if isinstance(row.get("target_response_bytes"), (int, float))
        ),
        "input_tokens": distribution(row["input_tokens"] for row in result_rows if isinstance(row.get("input_tokens"), (int, float))),
        "output_tokens": distribution(row["output_tokens"] for row in result_rows if isinstance(row.get("output_tokens"), (int, float))),
        "ttft_ms": distribution(row["ttft_ms"] for row in result_rows if isinstance(row.get("ttft_ms"), (int, float))),
        "output_tokens_per_second": distribution(
            row["output_tokens_per_second"] for row in result_rows if isinstance(row.get("output_tokens_per_second"), (int, float))
        ),
    }
    elapsed_seconds = time.perf_counter() - run_perf_started
    metrics["performance"]["elapsed_seconds"] = elapsed_seconds
    metrics["performance"]["observations_per_second"] = len(result_rows) / elapsed_seconds if elapsed_seconds else 0.0
    metrics["performance"]["target_calls_per_second"] = target_calls / elapsed_seconds if elapsed_seconds else 0.0
    metrics["performance"]["observation_success_rate"] = (
        sum(row.get("status") in {"pass", "fail"} for row in result_rows) / len(result_rows) if result_rows else 0.0
    )
    metrics["performance"]["observation_error_rate"] = sum(row.get("status") == "error" for row in result_rows) / len(result_rows) if result_rows else 0.0
    metrics["performance_by_phase"] = {
        phase: distribution(
            row["target_latency_ms"] for row in result_rows if row.get("performance_phase") == phase and isinstance(row.get("target_latency_ms"), (int, float))
        )
        for phase in ("cold", "warmup", "steady", "soak")
    }
    metrics["budgets"] = {
        "target_calls": target_calls,
        "judge_calls": judge_calls,
        "total_tokens": total_tokens,
        "exhausted": abort_reason.startswith("budget exhausted"),
    }
    pricing = pricing_config
    input_tokens = token_totals["target_input"]
    output_tokens = token_totals["target_output"]
    if pricing:
        metrics["cost"] = {
            "currency": pricing.get("currency"),
            "source": pricing.get("source"),
            "effective_at": pricing.get("effective_at"),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "judge_input_tokens": token_totals["judge_input"],
            "judge_output_tokens": token_totals["judge_output"],
            "estimated_total": current_estimated_cost(),
        }
    gate_failures = apply_gates(suite, metrics, categories)
    if minimum_calibration_accuracy is not None:
        if not calibration:
            gate_failures.append(
                {"category": "judge-calibration", "metric": "accuracy_ci.lower", "minimum": float(minimum_calibration_accuracy), "actual": None}
            )
        for judge_id, calibration_result in calibration.items():
            accuracy_ci = calibration_result.get("accuracy_ci")
            accuracy_lower = accuracy_ci.get("lower") if isinstance(accuracy_ci, dict) else None
            if not isinstance(accuracy_lower, (int, float)) or float(accuracy_lower) < float(minimum_calibration_accuracy):
                gate_failures.append(
                    {
                        "category": f"judge-calibration:{judge_id}",
                        "metric": "accuracy_ci.lower",
                        "minimum": float(minimum_calibration_accuracy),
                        "actual": accuracy_lower,
                    }
                )
    metrics["gate_failures"] = gate_failures
    metrics["aborted"] = bool(abort_reason)
    atomic_json(run_dir / "metrics.json", metrics)
    if scenario_rows is not None:
        atomic_text(run_dir / "scenario_results.jsonl", "")
        for row in scenario_rows:
            append_jsonl(run_dir / "scenario_results.jsonl", row)
    write_category_csv(run_dir / "category_results.csv", categories)
    failures_path = run_dir / "failures.jsonl"
    atomic_text(failures_path, "")
    for row in result_rows:
        if row["status"] != "pass":
            append_jsonl(failures_path, row)
    adjudication_path = run_dir / "adjudication_queue.jsonl"
    atomic_text(adjudication_path, "")
    for row in result_rows:
        if row.get("status") == "invalid" and row.get("severity") == "critical":
            append_jsonl(adjudication_path, row)

    artifact_names = [
        "requests.jsonl",
        "raw_responses.jsonl",
        "judgments.jsonl",
        "case_results.jsonl",
        "scenario_results.jsonl",
        "metrics.json",
        "category_results.csv",
        "failures.jsonl",
        "events.jsonl",
        "adjudication_queue.jsonl",
        "environment.json",
        "asset_inventory.json",
        "protocol_snapshot.md",
        "suite_snapshot.toml",
        "dataset_snapshot.jsonl",
        "rubric_snapshot.md",
        "suite_evidence_manifest.json",
        "judge_qualification_snapshot.json",
        "judge_approval_snapshot.json",
        "dataset_card.md",
    ]
    artifact_names.extend(path.relative_to(run_dir).as_posix() for path in sorted((run_dir / "assets").glob("*")) if path.is_file())
    artifact_names.extend(path.relative_to(run_dir).as_posix() for path in sorted((run_dir / "suite_evidence").glob("*")) if path.is_file())
    artifact_names.extend(path.relative_to(run_dir).as_posix() for path in sorted((run_dir / "judge_evidence").glob("*")) if path.is_file())
    try:
        require_current_official_evidence()
    except ProtocolError as exc:
        if not abort_reason:
            abort_reason = str(exc)
        metrics["aborted"] = True
        atomic_json(run_dir / "metrics.json", metrics)
    manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
    manifest["abort_reason"] = abort_reason
    manifest["metrics"] = metrics
    manifest["artifacts"] = {name: sha256_file(run_dir / name) for name in artifact_names if (run_dir / name).is_file()}
    manifest["status"] = "passed" if not abort_reason and metrics["officially_valid"] and not gate_failures else "failed"
    manifest["official"] = bool(official and manifest["status"] == "passed")
    report_names = generate_reports(run_dir, manifest, metrics, categories, result_rows)
    for name in report_names:
        manifest["artifacts"][name] = sha256_file(run_dir / name)
    atomic_json(run_dir / "manifest.json", manifest)
    write_bundle(run_dir, signing_key_env=signing_key_env, key_id=signing_key_id)
    verification = verify_bundle(run_dir, signing_key_env=signing_key_env, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("generated artifact bundle failed verification")
    return run_dir
