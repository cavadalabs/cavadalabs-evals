from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .artifacts import _read_regular

ADAPTER_VERSION = "1.0.0"
MAX_RESPONSE_BYTES = 25 * 1024 * 1024


class PrivateAIAdapterError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        request: dict[str, Any] | None = None,
        raw: dict[str, Any] | None = None,
        transport: dict[str, Any] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        setup_evidence: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.request = request or {}
        self.raw = raw
        self.transport = transport or {}
        self.evidence = evidence or []
        self.setup_evidence = setup_evidence or {}


@dataclass(frozen=True)
class CorpusDocument:
    id: str
    source: str
    path: str
    sha256: str
    size_bytes: int
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class CorpusSnapshot:
    raw: bytes = field(repr=False)
    sha256: str
    documents: tuple[CorpusDocument, ...]


@dataclass(frozen=True)
class PrivateAIContext:
    endpoint: str
    token: str
    workspace_id: str
    source_ids: tuple[str, ...]
    document_ids_by_path: tuple[tuple[str, str], ...]
    corpus_sha256: str
    reasoning_mode: str
    retrieval_limit: int

    def public_evidence(self) -> dict[str, Any]:
        return {
            "adapter_version": ADAPTER_VERSION,
            "endpoint": _safe_endpoint(self.endpoint),
            "workspace_header_present": bool(self.workspace_id),
            "source_ids": list(self.source_ids),
            "corpus_sha256": self.corpus_sha256,
            "reasoning_mode": self.reasoning_mode,
            "retrieval_limit": self.retrieval_limit,
        }


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_suite_file(root: Path, relative: str, label: str) -> bytes:
    try:
        return _read_regular(root, Path(relative))
    except OSError as exc:
        raise ValueError(f"private-ai {label} must be a regular, symlink-free in-suite file: {relative}") from exc


def _target_corpus(target: dict[str, Any]) -> tuple[str, str]:
    relative = target.get("corpus")
    digest = target.get("corpus_sha256")
    if not isinstance(relative, str) or not relative:
        raise ValueError("private-ai target requires target.corpus")
    if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("private-ai target requires a lowercase SHA-256 target.corpus_sha256")
    return relative, digest


def snapshot_corpus(root: Path, target: dict[str, Any]) -> CorpusSnapshot:
    relative, expected_digest = _target_corpus(target)
    raw = _read_suite_file(root, relative, "corpus")
    if _sha256(raw) != expected_digest:
        raise ValueError("private-ai corpus hash mismatch")

    documents: list[CorpusDocument] = []
    ids: set[str] = set()
    paths: set[str] = set()
    for line_number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid private-ai corpus line {line_number}") from exc
        if not isinstance(row, dict) or set(row) != {"id", "source", "path", "sha256"}:
            raise ValueError(f"private-ai corpus line {line_number} must contain id, source, path, and sha256")
        document_id, source, relative_asset, digest = (row[name] for name in ("id", "source", "path", "sha256"))
        if not all(isinstance(value, str) and value for value in (document_id, source, relative_asset, digest)):
            raise ValueError(f"private-ai corpus line {line_number} contains an empty field")
        if document_id in ids or relative_asset in paths:
            raise ValueError(f"private-ai corpus line {line_number} duplicates an id or path")
        if len(source) > 64:
            raise ValueError(f"private-ai corpus line {line_number} source is too long")
        asset_raw = _read_suite_file(root, relative_asset, "corpus asset")
        if _sha256(asset_raw) != digest:
            raise ValueError(f"private-ai corpus asset hash mismatch: {relative_asset}")
        ids.add(document_id)
        paths.add(relative_asset)
        documents.append(CorpusDocument(document_id, source, relative_asset, digest, len(asset_raw), asset_raw))
    if not documents:
        raise ValueError("private-ai corpus must contain at least one document")
    if len({document.source for document in documents}) > 100:
        raise ValueError("private-ai corpus exceeds the 100-source chat ACL limit")
    return CorpusSnapshot(raw, expected_digest, tuple(documents))


def load_corpus(root: Path, target: dict[str, Any]) -> tuple[CorpusDocument, ...]:
    return snapshot_corpus(root, target).documents


def preflight_errors(cases: tuple[dict[str, Any], ...], target: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    capabilities = target.get("capabilities")
    if not isinstance(capabilities, list) or not all(isinstance(value, str) for value in capabilities) or set(capabilities) != {"text"}:
        errors.append("private-ai target.capabilities must declare only text")
    for index, case in enumerate(cases, 1):
        if not isinstance(case.get("input"), str) or not str(case["input"]).strip():
            errors.append(f"private-ai case[{index}] requires a non-empty text input")
        if case.get("messages") is not None:
            errors.append(f"private-ai case[{index}] conversations are not supported")
    return errors


def config_errors(root: Path, target: dict[str, Any], cases: tuple[dict[str, Any], ...] = ()) -> list[str]:
    errors: list[str] = []
    try:
        documents = load_corpus(root, target)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        errors.append(str(exc))
    else:
        document_ids = {document.id for document in documents}
        for index, case in enumerate(cases, 1):
            expected = case.get("expected_retrieval_ids")
            if isinstance(expected, list) and not set(map(str, expected)) <= document_ids:
                errors.append(f"private-ai case[{index}] references unknown corpus document IDs")
    if target.get("reasoning_mode", "instant") not in {"instant", "thinking"}:
        errors.append("private-ai target.reasoning_mode must be instant or thinking")
    limit = target.get("retrieval_limit", 12)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 20:
        errors.append("private-ai target.retrieval_limit must be an integer from 1 to 20")
    workspace_env = target.get("workspace_id_env", "PRIVATE_AI_WORKSPACE_ID")
    if not isinstance(workspace_env, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", workspace_env) is None:
        errors.append("private-ai target.workspace_id_env must be an environment variable name")
    capabilities = target.get("capabilities")
    if not isinstance(capabilities, list) or not all(isinstance(value, str) for value in capabilities) or set(capabilities) != {"text"}:
        errors.append("private-ai target.capabilities must declare only text")
    return errors


def _base_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint)
    try:
        _ = parsed.port
    except ValueError as exc:
        raise PrivateAIAdapterError("private-ai endpoint port is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PrivateAIAdapterError("private-ai endpoint must be an HTTP(S) base URL without credentials, query, or fragment")
    return endpoint.rstrip("/")


def _safe_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint)
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    return urllib.parse.urlunsplit((parsed.scheme, host + port, parsed.path.rstrip("/"), "", ""))


def _headers(token: str, workspace_id: str, *, content_type: str = "application/json") -> dict[str, str]:
    headers = {"Accept": "application/json", "Content-Type": content_type}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if workspace_id:
        headers["X-Workspace-Id"] = workspace_id
    return headers


def _urlopen(request: urllib.request.Request, timeout: float) -> Any:
    from .runner import _urlopen as deadline_urlopen

    return deadline_urlopen(request, timeout)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PrivateAIAdapterError("private-ai operation exceeded its total timeout")
    return remaining


def _response_chunks(stream: Any, deadline: float, limit: int) -> Any:
    from .runner import _enforce_http_deadline

    read = getattr(stream, "read1", None) or stream.read
    remaining = limit
    while remaining:
        _enforce_http_deadline(stream, deadline, "private-ai response exceeded its total timeout")
        chunk = read(min(64 * 1024, remaining))
        if not chunk:
            return
        yield chunk
        remaining -= len(chunk)


def _request_json(
    method: str,
    url: str,
    token: str,
    workspace_id: str,
    deadline: float,
    evidence: list[dict[str, Any]],
    *,
    payload: dict[str, Any] | None = None,
    body: bytes | None = None,
    redact_response: bool = False,
) -> Any:
    request_body = body if body is not None else (json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None)
    request_id = uuid.uuid4().hex
    headers = _headers(token, workspace_id, content_type="application/octet-stream" if body is not None else "application/json")
    headers["X-Cavada-Eval-Request-ID"] = request_id
    request = urllib.request.Request(  # noqa: S310 -- base endpoint is validated before paths are appended.
        url,
        data=request_body,
        headers=headers,
        method=method,
    )
    started = time.perf_counter()
    raw = bytearray()
    status: int | None = None
    content_type = ""
    response_request_id: str | None = None
    try:
        try:
            response = _urlopen(request, _remaining(deadline))
        except urllib.error.HTTPError as exc:
            response = exc
            status = exc.code
        with response:
            if status is None:
                status = response.status
            content_type = response.headers.get_content_type()
            response_request_id = response.headers.get("X-Request-ID") or response.headers.get("X-Request-Id")
            for chunk in _response_chunks(response, deadline, MAX_RESPONSE_BYTES + 1):
                raw.extend(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        stored_raw = bytes(raw[:MAX_RESPONSE_BYTES])
        error_entry: dict[str, Any] = {
            "method": method,
            "url": _safe_endpoint(url),
            "request_id": request_id,
            "request": payload,
            "request_bytes": len(request_body or b""),
            "request_sha256": _sha256(request_body or b""),
            "status": status,
            "content_type": content_type,
            "response_request_id": response_request_id,
            "response_bytes": len(stored_raw),
            "response_sha256": _sha256(stored_raw),
            "response_truncated": len(raw) > MAX_RESPONSE_BYTES,
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "error_type": type(exc).__name__,
        }
        if redact_response:
            error_entry["response_redacted"] = "unselected workspace resources omitted"
        else:
            error_entry["response_body_base64"] = base64.b64encode(stored_raw).decode("ascii")
        evidence.append(error_entry)
        raise PrivateAIAdapterError(f"private-ai request failed: {type(exc).__name__}", evidence=evidence) from exc
    truncated = len(raw) > MAX_RESPONSE_BYTES
    stored_raw = bytes(raw[:MAX_RESPONSE_BYTES])
    entry: dict[str, Any] = {
        "method": method,
        "url": _safe_endpoint(url),
        "request_id": request_id,
        "request": payload,
        "request_bytes": len(request_body or b""),
        "request_sha256": _sha256(request_body or b""),
        "status": status,
        "content_type": content_type,
        "response_request_id": response_request_id,
        "response_bytes": len(stored_raw),
        "response_sha256": _sha256(stored_raw),
        "response_truncated": truncated,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
    }
    if redact_response:
        entry["response_redacted"] = "unselected workspace resources omitted"
    else:
        entry["response_body_base64"] = base64.b64encode(stored_raw).decode("ascii")
    evidence.append(entry)
    if truncated:
        raise PrivateAIAdapterError("private-ai response exceeded the adapter limit", evidence=evidence)
    try:
        from .runner import _strict_json_loads

        parsed = _strict_json_loads(stored_raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise PrivateAIAdapterError("private-ai returned non-JSON setup data", evidence=evidence) from exc
    if not redact_response:
        entry["response"] = parsed
    if status is None or not 200 <= status < 300:
        raise PrivateAIAdapterError(
            f"private-ai setup request returned HTTP {status}",
            raw=parsed if isinstance(parsed, dict) and not redact_response else None,
            evidence=evidence,
        )
    return parsed


def prepare(
    root: Path,
    target: dict[str, Any],
    endpoint: str,
    token: str,
    workspace_id: str,
    timeout: float,
    run_id: str,
    *,
    corpus_snapshot: CorpusSnapshot | None = None,
) -> tuple[PrivateAIContext, dict[str, Any]]:
    base = _base_endpoint(endpoint)
    snapshot = corpus_snapshot or snapshot_corpus(root, target)
    if snapshot.sha256 != target.get("corpus_sha256"):
        raise PrivateAIAdapterError("private-ai corpus snapshot does not match the configured hash")
    documents = snapshot.documents
    deadline = time.monotonic() + timeout
    requests: list[dict[str, Any]] = []
    source_ids: list[str] = []
    upload_ids: list[str] = []
    job_ids: list[str] = []
    by_source: dict[str, list[CorpusDocument]] = {}
    for document in documents:
        by_source.setdefault(document.source, []).append(document)

    def evidence(status: str) -> dict[str, Any]:
        return {
            "adapter_version": ADAPTER_VERSION,
            "endpoint": _safe_endpoint(base),
            "workspace_header_present": bool(workspace_id),
            "status": status,
            "source_ids": source_ids,
            "upload_ids": upload_ids,
            "job_ids": job_ids,
            "corpus_sha256": snapshot.sha256,
            "documents": [
                {
                    "id": document.id,
                    "source": document.source,
                    "path": document.path,
                    "sha256": document.sha256,
                    "snapshot": f"corpus_assets/{document.sha256}",
                }
                for document in documents
            ],
            "requests": requests,
            "cleanup": {
                "status": "not_attempted",
                "reason": "evaluation sources are retained as audit evidence",
            },
        }

    try:
        for source_name, source_documents in sorted(by_source.items()):
            created = _request_json(
                "POST",
                base + "/v1/sources/browser-folder",
                token,
                workspace_id,
                deadline,
                requests,
                payload={
                    "name": f"cavada-eval-{run_id}-{source_name}"[:255],
                    "file_count": len(source_documents),
                    "total_bytes": sum(document.size_bytes for document in source_documents),
                    "shared": False,
                },
            )
            if not isinstance(created, dict) or not isinstance(created.get("source"), dict):
                raise PrivateAIAdapterError("private-ai source creation response is invalid", evidence=requests)
            source_id = created["source"].get("id")
            upload_id = created.get("upload_id")
            if not isinstance(source_id, str) or not isinstance(upload_id, str):
                raise PrivateAIAdapterError("private-ai source creation omitted identifiers", evidence=requests)
            source_ids.append(source_id)
            upload_ids.append(upload_id)
            for document in source_documents:
                uploaded = _request_json(
                    "PUT",
                    base
                    + f"/v1/sources/{urllib.parse.quote(source_id, safe='')}/browser-upload/{urllib.parse.quote(upload_id, safe='')}/file?"
                    + urllib.parse.urlencode({"path": document.path}),
                    token,
                    workspace_id,
                    deadline,
                    requests,
                    body=document.content,
                )
                if not isinstance(uploaded, dict) or uploaded.get("path") != document.path:
                    raise PrivateAIAdapterError("private-ai file upload response is invalid", evidence=requests)
            job = _request_json(
                "POST",
                base + f"/v1/sources/{urllib.parse.quote(source_id, safe='')}/browser-upload/{urllib.parse.quote(upload_id, safe='')}/commit",
                token,
                workspace_id,
                deadline,
                requests,
                payload={},
            )
            job_id = job.get("id") if isinstance(job, dict) else None
            if not isinstance(job_id, str):
                raise PrivateAIAdapterError("private-ai upload commit omitted the job ID", evidence=requests)
            job_ids.append(job_id)
            while True:
                job = _request_json(
                    "GET",
                    base + f"/v1/jobs/{urllib.parse.quote(job_id, safe='')}",
                    token,
                    workspace_id,
                    deadline,
                    requests,
                )
                status = job.get("status") if isinstance(job, dict) else None
                if status == "complete":
                    break
                if status in {"failed", "canceled"}:
                    raise PrivateAIAdapterError(f"private-ai ingestion job {status}", raw=job, evidence=requests)
                if status not in {"queued", "running"}:
                    raise PrivateAIAdapterError("private-ai ingestion job returned an invalid status", evidence=requests)
                time.sleep(min(0.25, _remaining(deadline)))

        while True:
            sources = _request_json(
                "GET", base + "/v1/sources", token, workspace_id, deadline, requests, redact_response=True
            )
            if not isinstance(sources, list):
                raise PrivateAIAdapterError("private-ai source listing response is invalid", evidence=requests)
            selected = [source for source in sources if isinstance(source, dict) and source.get("id") in source_ids]
            requests[-1]["response"] = selected
            if len(selected) != len(source_ids):
                raise PrivateAIAdapterError("private-ai source disappeared after ingestion", evidence=requests)
            if any(source.get("sync_status") in {"error", "degraded"} or int(source.get("documents_failed", 0)) for source in selected):
                raise PrivateAIAdapterError("private-ai source ingestion failed", raw={"sources": selected}, evidence=requests)
            expected_by_id = {source_id: len(by_source[name]) for source_id, name in zip(source_ids, sorted(by_source), strict=True)}
            if all(
                source.get("sync_status") == "complete"
                and int(source.get("documents_total", -1)) == expected_by_id[str(source["id"])]
                and int(source.get("documents_indexed", -1)) == expected_by_id[str(source["id"])]
                for source in selected
            ):
                break
            time.sleep(min(0.25, _remaining(deadline)))
    except PrivateAIAdapterError as exc:
        if not exc.evidence:
            exc.evidence = requests
        exc.setup_evidence = evidence("error")
        raise
    except (TypeError, ValueError) as exc:
        raise PrivateAIAdapterError(
            "private-ai setup response is invalid",
            evidence=requests,
            setup_evidence=evidence("error"),
        ) from exc

    context = PrivateAIContext(
        endpoint=base,
        token=token,
        workspace_id=workspace_id,
        source_ids=tuple(source_ids),
        document_ids_by_path=tuple((document.path, document.id) for document in documents),
        corpus_sha256=str(target["corpus_sha256"]),
        reasoning_mode=str(target.get("reasoning_mode", "instant")),
        retrieval_limit=int(target.get("retrieval_limit", 12)),
    )
    return context, {**evidence("ready"), **context.public_evidence()}


def call(context: PrivateAIContext, prompt: Any, timeout: float) -> tuple[str, dict[str, Any], str, dict[str, Any], dict[str, Any]]:
    if not isinstance(prompt, str) or not prompt.strip():
        raise PrivateAIAdapterError("private-ai adapter currently supports non-empty text inputs only")
    payload = {
        "message": prompt,
        "turn_id": uuid.uuid4().hex,
        "attempt_id": uuid.uuid4().hex,
        "limit": context.retrieval_limit,
        "acl": {"source_ids": list(context.source_ids), "document_ids": []},
        "selected_document_ids": [],
        "reasoning_mode": context.reasoning_mode,
        "images": [],
    }
    request_id = uuid.uuid4().hex
    raw_payload = json.dumps(payload, ensure_ascii=False).encode()
    request = urllib.request.Request(  # noqa: S310 -- context endpoint was validated during preparation.
        context.endpoint + "/v1/chat/rag",
        data=raw_payload,
        headers={
            **_headers(context.token, context.workspace_id),
            "Accept": "application/x-ndjson",
            "X-Cavada-Eval-Request-ID": request_id,
            "Idempotency-Key": str(payload["attempt_id"]),
        },
        method="POST",
    )
    started = time.perf_counter()
    deadline = time.monotonic() + timeout
    events: list[dict[str, Any]] = []
    statuses: list[str] = []
    answer = ""
    citations: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    usage: dict[str, Any] | None = None
    thread_id = ""
    done = False
    response_bytes = 0
    headers_ms: float | None = None
    http_status: int | None = None
    ttft_ms: float | None = None
    response_body = bytearray()
    response_truncated = False
    response_content_type = ""

    def transport_evidence() -> dict[str, Any]:
        transport: dict[str, Any] = {
            "request_id": request_id,
            "attempts": 1,
            "request_bytes": len(raw_payload),
            "response_bytes": response_bytes,
            "total_ms": round((time.perf_counter() - started) * 1000, 3),
            "streaming": True,
        }
        if headers_ms is not None:
            transport["headers_ms"] = round(headers_ms, 3)
        if http_status is not None:
            transport["http_status"] = http_status
        if ttft_ms is not None:
            transport["ttft_ms"] = round(ttft_ms, 3)
        return transport

    def raw_evidence() -> dict[str, Any]:
        normalized_usage = (
            {
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "total_tokens": usage.get("total_tokens"),
            }
            if usage is not None
            else {}
        )
        document_ids = dict(context.document_ids_by_path)
        retrieved_ids: list[str] = []
        for citation in citations:
            if citation.get("source_id") not in context.source_ids:
                continue
            path = citation.get("path")
            if isinstance(path, str) and path in document_ids:
                retrieved_ids.append(document_ids[path])
                continue
            reference = json.dumps(
                {field: citation.get(field) for field in ("id", "source_id", "document_id", "path")},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            retrieved_ids.append(f"unexpected:{_sha256(reference)}")
        return {
            "model": usage.get("model_label", "") if usage else "",
            "answer": answer,
            "sources": citations,
            "retrieved_ids": retrieved_ids,
            "claims": claims,
            "usage": normalized_usage,
            "wire_response": {
                "http_status": http_status,
                "content_type": response_content_type,
                "body_base64": base64.b64encode(response_body).decode("ascii"),
                "body_sha256": _sha256(bytes(response_body)),
                "body_truncated": response_truncated,
            },
            "private_ai": {
                "adapter_version": ADAPTER_VERSION,
                "thread_id": thread_id,
                "terminal_status": statuses[-1] if statuses else "",
                "statuses": statuses,
                "events": events,
                "usage": usage,
            },
        }

    def consume_line(line: bytes) -> None:
        nonlocal answer, done, thread_id, ttft_ms, usage
        if not line.strip():
            return
        from .runner import _strict_json_loads

        try:
            event = _strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            raise PrivateAIAdapterError("private-ai chat stream contains invalid JSON", request=payload) from exc
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise PrivateAIAdapterError("private-ai chat stream contains an invalid event", request=payload)
        events.append(event)
        if done:
            raise PrivateAIAdapterError("private-ai chat stream contains events after done", request=payload)
        event_type = event["type"]
        if event_type == "token" and isinstance(event.get("text"), str):
            if ttft_ms is None:
                ttft_ms = (time.perf_counter() - started) * 1000
            answer += event["text"]
        elif event_type == "replace" and isinstance(event.get("text"), str):
            if ttft_ms is None:
                ttft_ms = (time.perf_counter() - started) * 1000
            answer = event["text"]
        elif event_type == "citation" and isinstance(event.get("citation"), dict):
            citation = event["citation"]
            citations.append(citation)
            if citation.get("source_id") not in context.source_ids:
                raise PrivateAIAdapterError("private-ai citation source is outside the request ACL", request=payload)
        elif event_type == "claim" and isinstance(event.get("claim"), dict):
            claims.append(event["claim"])
        elif event_type == "usage" and event.get("final") is True and isinstance(event.get("usage"), dict):
            usage = event["usage"]
        elif event_type == "thread" and isinstance(event.get("thread_id"), str):
            thread_id = event["thread_id"]
        elif event_type == "status" and isinstance(event.get("status"), str):
            statuses.append(event["status"])
        elif event_type == "done":
            done = True

    try:
        try:
            response = _urlopen(request, _remaining(deadline))
        except urllib.error.HTTPError as exc:
            http_status = exc.code
            response_content_type = exc.headers.get_content_type()
            with exc:
                for chunk in _response_chunks(exc, deadline, MAX_RESPONSE_BYTES + 1):
                    response_bytes += len(chunk)
                    remaining_body = MAX_RESPONSE_BYTES - len(response_body)
                    response_body.extend(chunk[:remaining_body])
                    response_truncated = response_truncated or len(chunk) > remaining_body
            stored_body = bytes(response_body)
            raise PrivateAIAdapterError(
                f"private-ai chat returned HTTP {exc.code}",
                request=payload,
                raw={
                    "http_status": exc.code,
                    "content_type": response_content_type,
                    "body_base64": base64.b64encode(stored_body).decode("ascii"),
                    "body_sha256": _sha256(stored_body),
                    "body_truncated": response_truncated,
                },
                transport=transport_evidence(),
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PrivateAIAdapterError(
                f"private-ai chat request failed: {type(exc).__name__}",
                request=payload,
                transport=transport_evidence(),
            ) from exc
        headers_ms = (time.perf_counter() - started) * 1000
        http_status = response.status
        with response:
            response_content_type = response.headers.get_content_type()
            if response_content_type not in {"application/x-ndjson", "application/json", "text/plain"}:
                for chunk in _response_chunks(response, deadline, MAX_RESPONSE_BYTES + 1):
                    response_bytes += len(chunk)
                    remaining_body = MAX_RESPONSE_BYTES - len(response_body)
                    response_body.extend(chunk[:remaining_body])
                    response_truncated = response_truncated or len(chunk) > remaining_body
                raise PrivateAIAdapterError(
                    f"private-ai chat returned unsupported content type {response_content_type}", request=payload
                )
            pending = bytearray()
            for chunk in _response_chunks(response, deadline, MAX_RESPONSE_BYTES + 1):
                response_bytes += len(chunk)
                remaining_body = MAX_RESPONSE_BYTES - len(response_body)
                response_body.extend(chunk[:remaining_body])
                response_truncated = response_truncated or len(chunk) > remaining_body
                if response_bytes > MAX_RESPONSE_BYTES:
                    raise PrivateAIAdapterError("private-ai chat response exceeded the adapter limit", request=payload)
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    consume_line(bytes(line))
            if pending:
                consume_line(bytes(pending))
    except PrivateAIAdapterError as exc:
        if not exc.transport:
            exc.transport = transport_evidence()
        if exc.raw is None and (events or response_bytes):
            exc.raw = raw_evidence()
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PrivateAIAdapterError(
            f"private-ai chat response failed: {type(exc).__name__}",
            request=payload,
            raw=raw_evidence(),
            transport=transport_evidence(),
        ) from exc

    transport = transport_evidence()
    raw = raw_evidence()
    failure_statuses = {
        "no_indexed_documents",
        "no_sources",
        "permission_denied",
        "retrieval_no_results",
        "retrieval_unavailable",
        "runtime_unavailable",
    }
    failed_status = next((status for status in statuses if status in failure_statuses), None)
    if failed_status is not None:
        raise PrivateAIAdapterError(f"private-ai chat ended with {failed_status}", request=payload, raw=raw, transport=transport)
    if not done:
        raise PrivateAIAdapterError("private-ai chat stream ended without a done event", request=payload, raw=raw, transport=transport)
    if len(events) < 2 or events[-1].get("type") != "done" or events[-2].get("type") != "status" or events[-2].get("status") != "answer_done":
        raise PrivateAIAdapterError("private-ai chat success requires answer_done immediately followed by done", request=payload, raw=raw, transport=transport)
    if not answer.strip():
        raise PrivateAIAdapterError("private-ai chat returned no answer", request=payload, raw=raw, transport=transport)
    return answer, raw, str(raw["model"]), payload, transport
