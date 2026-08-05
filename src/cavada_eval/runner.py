from __future__ import annotations

import json
import os
import shlex
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
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .assets import asset_inventory, content_text, encoded_content, encoded_messages, openai_content
from .deepeval_adapter import evaluate_metrics as evaluate_deepeval_metrics
from .metrics import METRIC_VERSION, deterministic_evaluation
from .profiles import ADAPTER_CONTRACT_VERSION
from .protocol import (
    PROTOCOL_VERSION,
    REPORT_VERSION,
    SCHEMA_VERSION,
    ProtocolError,
    Suite,
    append_jsonl,
    apply_gates,
    atomic_json,
    atomic_text,
    contains_secret_like,
    dataset_card,
    environment_evidence,
    git_evidence,
    new_run_dir,
    sha256_bytes,
    sha256_file,
    summarize,
    write_category_csv,
)
from .reporting import generate_reports
from .statistics import bootstrap_mean_interval, distribution, stratified_bootstrap_mean_interval


def _get(value: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid {path.name} line {line_number}") from exc
        if not isinstance(value, dict):
            raise ProtocolError(f"invalid {path.name} line {line_number}: expected object")
        rows.append(value)
    return rows


def _usage_tokens(raw: dict[str, Any]) -> tuple[float, float]:
    usage = raw.get("usage")
    if not isinstance(usage, dict):
        return 0.0, 0.0
    input_tokens = usage.get("prompt_tokens")
    output_tokens = usage.get("completion_tokens")
    return (
        float(input_tokens) if isinstance(input_tokens, (int, float)) else 0.0,
        float(output_tokens) if isinstance(output_tokens, (int, float)) else 0.0,
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
    retries: int = 2,
    max_body_bytes: int = 10 * 1024 * 1024,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if urllib.parse.urlparse(url).scheme not in {"http", "https"}:
        raise ProtocolError("HTTP adapter accepts http or https URLs only")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers["X-Cavada-Eval-Request-ID"] = request_id
    headers["Idempotency-Key"] = request_id
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    encoded_payload = json.dumps(payload, ensure_ascii=False).encode()
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, data=encoded_payload, headers=headers, method="POST")  # noqa: S310 -- scheme is validated above.
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:  # noqa: S310 -- scheme is validated above.
                headers_ms = (time.perf_counter() - started) * 1000
                content_type = response.headers.get_content_type()
                if content_type != "application/json" and not content_type.endswith("+json"):
                    raise ProtocolError(f"Unexpected response content type from {url}: {content_type}")
                body_bytes = response.read(max_body_bytes + 1)
                if len(body_bytes) > max_body_bytes:
                    raise ProtocolError(f"Response from {url} exceeds {max_body_bytes} bytes")
                body = body_bytes.decode("utf-8", errors="replace")
                total_ms = (time.perf_counter() - started) * 1000
            break
        except urllib.error.HTTPError as exc:
            error_body = exc.read(1024 * 1024)
            last_error = ProtocolError(f"HTTP {exc.code} from {url}; body_sha256={sha256_bytes(error_body)}")
            if exc.code not in {408, 425, 429, 500, 502, 503, 504} or attempt == retries:
                raise last_error from exc
        except urllib.error.URLError as exc:
            last_error = ProtocolError(f"Cannot reach {url}: {exc.reason}")
            if attempt == retries:
                raise last_error from exc
        if attempt < retries:
            time.sleep(min(2.0, 0.25 * (2**attempt)))
    else:  # pragma: no cover - loop always breaks or raises
        raise ProtocolError(str(last_error or "request failed"))
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"Non-JSON response from {url}") from exc
    if not isinstance(parsed, dict):
        raise ProtocolError(f"Expected JSON object from {url}")
    return parsed, {
        "request_id": request_id,
        "attempts": attempt + 1,
        "request_bytes": len(encoded_payload),
        "response_bytes": len(body_bytes),
        "headers_ms": round(headers_ms, 3),
        "total_ms": round(total_ms, 3),
    }


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
    started = time.perf_counter()
    try:
        response = urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context())  # noqa: S310 -- scheme is validated above.
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise ProtocolError(f"Cannot start stream from {url}: {exc}") from exc
    chunks: list[dict[str, Any]] = []
    content: list[str] = []
    event_times: list[float] = []
    usage: dict[str, Any] = {}
    reported_model = ""
    total_bytes = 0
    with response:
        content_type = response.headers.get_content_type()
        if content_type != "text/event-stream":
            raise ProtocolError(f"Unexpected streaming content type from {url}: {content_type}")
        headers_ms = (time.perf_counter() - started) * 1000
        for raw_line in response:
            total_bytes += len(raw_line)
            if total_bytes > max_body_bytes:
                raise ProtocolError(f"Streaming response from {url} exceeds {max_body_bytes} bytes")
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
            except json.JSONDecodeError as exc:
                raise ProtocolError("OpenAI stream contains invalid JSON") from exc
            if not isinstance(event, dict):
                raise ProtocolError("OpenAI stream event must be an object")
            chunks.append(event)
            reported_model = str(event.get("model") or reported_model)
            if isinstance(event.get("usage"), dict):
                usage = event["usage"]
            try:
                delta = event["choices"][0]["delta"].get("content")
            except (KeyError, IndexError, TypeError, AttributeError):
                delta = None
            if isinstance(delta, str) and delta:
                content.append(delta)
                event_times.append(time.perf_counter())
    total_ms = (time.perf_counter() - started) * 1000
    if not content:
        raise ProtocolError("OpenAI stream returned no text content")
    intervals = [(right - left) * 1000 for left, right in zip(event_times, event_times[1:], strict=False)]
    raw = {
        "model": reported_model,
        "choices": [{"message": {"content": "".join(content)}}],
        "usage": usage,
        "stream_events": chunks,
    }
    return raw, {
        "request_id": request_id,
        "attempts": 1,
        "request_bytes": len(encoded_payload),
        "response_bytes": total_bytes,
        "headers_ms": round(headers_ms, 3),
        "ttft_ms": round((event_times[0] - started) * 1000, 3),
        "inter_chunk_ms": distribution(intervals),
        "total_ms": round(total_ms, 3),
        "streaming": True,
    }


def _secure_endpoint(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" or parsed.hostname in {"127.0.0.1", "localhost", "::1"}


def _manifest_endpoint(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password:
        raise ProtocolError("Endpoint URLs must not contain credentials")
    query_keys = sorted(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
    safe_query = "&".join(f"{urllib.parse.quote(key)}=[redacted]" for key in query_keys)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, safe_query, ""))


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
        for row in _read_jsonl(path):
            if row.get("case_id") == prompt["case_id"]:
                response = row.get("response")
                recorded_raw = dict(response) if isinstance(response, dict) else row
                recorded_payload = {"case_id": prompt["case_id"], "source_sha256": sha256_file(path)}
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
                answer, reported_model = _target_answer(suite, recorded_raw)
                return answer, recorded_raw, reported_model, recorded_payload, transport
        raise ProtocolError(f"recorded target has no response for case {prompt['case_id']}")
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
            messages.insert(0, {"role": "system", "content": prompt_path.read_text(encoding="utf-8")})
        payload: dict[str, Any] = {
            "model": request_model,
            "messages": messages,
            "temperature": float(suite.config.get("temperature", 0)),
            "max_tokens": int(suite.config.get("max_tokens", 2048)),
        }
        if target.get("stream"):
            payload["stream"] = True
            payload["stream_options"] = {"include_usage": True}
            raw, transport = _post_openai_stream(_completion_url(endpoint), payload, api_key, timeout, request_id=uuid.uuid4().hex)
        else:
            raw, transport = _post_json(_completion_url(endpoint), payload, api_key, timeout, request_id=uuid.uuid4().hex)
    elif kind == "json":
        request_field = str(target.get("request_field", "message"))
        payload = json.loads(str(target.get("request_defaults_json", "{}")))
        payload[request_field] = conversation_messages if conversation else json_prompt
        raw, transport = _post_json(endpoint, payload, api_key, timeout, request_id=uuid.uuid4().hex)
    else:
        raise ProtocolError(f"Unsupported target kind: {kind}")
    answer, reported_model = _target_answer(suite, raw)
    return answer, raw, reported_model, payload, transport


def _target_answer(suite: Suite, raw: dict[str, Any]) -> tuple[str, str]:
    target = suite.config.get("target") or {}
    if target.get("kind", "json") == "openai":
        try:
            answer = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProtocolError("OpenAI target returned no message content") from exc
        reported_model = str(raw.get("model") or "")
    else:
        answer = _get(raw, str(target.get("response_field", "answer")))
        reported_model = str(_get(raw, str(target.get("reported_model_field", "model"))) or "")
    if not isinstance(answer, str):
        raise ProtocolError("target returned no configured response string")
    return answer, reported_model


def _judge_result(raw: dict[str, Any]) -> tuple[dict[str, Any], str]:
    try:
        content = raw["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ProtocolError("Judge returned no message content") from exc
    if not isinstance(content, str):
        raise ProtocolError("Judge content is not text")
    text = content.strip()
    if text.startswith("```"):
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError("Judge output is not valid JSON") from exc
    if not isinstance(parsed, dict) or parsed.get("verdict") not in {"pass", "fail"}:
        raise ProtocolError("Judge verdict must be pass or fail")
    score = parsed.get("score")
    if not isinstance(score, int) or not 0 <= score <= 5:
        raise ProtocolError("Judge score must be an integer from 0 to 5")
    if not isinstance(parsed.get("reason"), str) or not parsed["reason"].strip():
        raise ProtocolError("Judge reason is required")
    return parsed, content


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
        return {
            **confusion,
            "cases": len(by_case),
            "samples": samples,
            "invalid_cases": invalid_cases,
            "observations": sum(len(verdicts) for verdicts in by_case.values()),
            "accuracy": (confusion["true_pass"] + confusion["true_fail"]) / samples if samples else 0.0,
            "failure_sensitivity": sensitivity,
            "pass_specificity": specificity,
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
        result["slices"] = {
            dimension: {
                value: summarize([row for row in judge_rows if str(cases[str(row["case_id"])].get(dimension)) == value])
                for value in sorted({str(cases[str(row["case_id"])].get(dimension)) for row in judge_rows})
            }
            for dimension in ("category", "severity", "language")
        }
        calibration[judge_id] = result
    return calibration


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
    system = _judge_system_prompt(suite)
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
    request_payload = {
        "model": judge_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": judge_user_content},
        ],
        "temperature": 0,
        "max_tokens": 600,
    }
    raw, transport = _post_json(
        _completion_url(endpoint),
        request_payload,
        api_key,
        timeout,
        request_id=uuid.uuid4().hex,
    )
    parsed, content = _judge_result(raw)
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
    external_authorization: str = "",
    storage_attestation: str = "",
    resume_dir: Path | None = None,
    concurrency: int = 1,
    requests_per_second: float = 0,
    progress: bool = False,
) -> Path:
    modes = {"smoke", "regression", "candidate", "official", "redteam", "performance", "load", "soak", "offline", "monitoring"}
    if mode not in modes:
        raise ProtocolError(f"unsupported run mode: {mode}")
    if official:
        mode = "official"
    elif mode == "official":
        raise ProtocolError("official mode requires official integrity validation")
    if repetitions < 1 or judge_repetitions < 1:
        raise ProtocolError("Repetitions must be positive")
    if not 1 <= concurrency <= 64 or requests_per_second < 0 or max_total_tokens < 0:
        raise ProtocolError("concurrency must be 1..64; rate and token budgets cannot be negative")
    target_kind = (suite.config.get("target") or {}).get("kind", "json")
    if official and ((target_kind != "recorded" and not _secure_endpoint(endpoint)) or not _secure_endpoint(judge_endpoint)):
        raise ProtocolError("Official runs require HTTPS or loopback endpoints")
    if official and max_cases > 0:
        raise ProtocolError("Official runs cannot use --max-cases")
    if official and repetitions < int(suite.config.get("official_min_repetitions", 1)):
        raise ProtocolError("Official run has too few target repetitions")
    if official and judge_repetitions < int(suite.config.get("official_min_judge_repetitions", 1)):
        raise ProtocolError("Official run has too few judge repetitions")
    judge_host = urllib.parse.urlparse(judge_endpoint).hostname
    external_judge = judge_host not in {"127.0.0.1", "localhost", "::1"}
    target_host = "recorded-local" if target_kind == "recorded" else urllib.parse.urlparse(endpoint).hostname
    if mode == "offline" and (external_judge or target_host not in {"127.0.0.1", "localhost", "::1", "recorded-local"}):
        raise ProtocolError("offline mode permits loopback endpoints only")
    allowed_hosts = set(map(str, (suite.config.get("network") or {}).get("allowed_hosts", [])))
    if official and allowed_hosts and ((target_kind != "recorded" and str(target_host) not in allowed_hosts) or str(judge_host) not in allowed_hosts):
        raise ProtocolError("official endpoint host is not in suite.network.allowed_hosts")
    authorization_record: dict[str, Any] | None = None
    if external_authorization:
        try:
            authorization_record = json.loads(Path(external_authorization).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError("external authorization must be a readable JSON object") from exc
        required = {"authorization_id", "approver", "purpose", "expires_at"}
        if not isinstance(authorization_record, dict) or not required <= set(authorization_record):
            raise ProtocolError(f"external authorization is missing fields: {sorted(required - set(authorization_record or {}))}")
        destinations = authorization_record.get("destinations")
        if (
            not isinstance(destinations, list)
            or not destinations
            or not all(
                isinstance(item, dict) and isinstance(item.get("host"), str) and isinstance(item.get("region"), str) and isinstance(item.get("purpose"), str)
                for item in destinations
            )
        ):
            raise ProtocolError("external authorization requires destinations with host, region, and purpose")
        try:
            expires = datetime.fromisoformat(str(authorization_record["expires_at"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ProtocolError("external authorization expires_at is invalid") from exc
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            raise ProtocolError("external authorization is expired or lacks a timezone")
    external_hosts = {str(host) for host in (target_host, judge_host) if host not in {"127.0.0.1", "localhost", "::1", "recorded-local"}}
    authorized_hosts = {str(item["host"]) for item in (authorization_record or {}).get("destinations", [])}
    if external_judge and not allow_external_judge and authorization_record is None:
        raise ProtocolError("external judge requires --allow-external-judge or an authorization record")
    if suite.config["data_classification"] not in {"public", "synthetic"} and not external_hosts <= authorized_hosts:
        raise ProtocolError(f"non-public suite lacks external authorization for hosts: {sorted(external_hosts - authorized_hosts)}")

    storage_record: dict[str, Any] | None = None
    if storage_attestation:
        try:
            storage_record = json.loads(Path(storage_attestation).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError("storage attestation must be a readable JSON object") from exc
        required_storage = {
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
        if not isinstance(storage_record, dict) or not required_storage <= set(storage_record):
            raise ProtocolError(f"storage attestation is missing fields: {sorted(required_storage - set(storage_record or {}))}")
        try:
            storage_expiry = datetime.fromisoformat(str(storage_record["expires_at"]).replace("Z", "+00:00"))
            storage_effective = datetime.fromisoformat(str(storage_record["effective_at"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ProtocolError("storage attestation timestamps are invalid") from exc
        now = datetime.now(timezone.utc)
        if storage_expiry.tzinfo is None or storage_effective.tzinfo is None or not storage_effective <= now < storage_expiry:
            raise ProtocolError("storage attestation is not currently effective")
    if official and suite.config["data_classification"] not in {"public", "synthetic"}:
        if storage_record is None or storage_record.get("encryption_at_rest") is not True or storage_record.get("immutability") is not True:
            raise ProtocolError("non-public official runs require current encrypted immutable storage attestation")
    evidence = git_evidence(repo_root)
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
    consensus = str(judge_config.get("consensus", "unanimous" if official else "majority"))
    if consensus not in {"unanimous", "majority"}:
        raise ProtocolError("judge.consensus must be unanimous or majority")
    minimum_calibration_accuracy = judge_config.get("minimum_calibration_accuracy")
    if minimum_calibration_accuracy is not None and (
        not isinstance(minimum_calibration_accuracy, (int, float))
        or isinstance(minimum_calibration_accuracy, bool)
        or not 0 <= float(minimum_calibration_accuracy) <= 1
    ):
        raise ProtocolError("judge.minimum_calibration_accuracy must be from 0 to 1")
    if official and len({item["expected_model"] for item in judge_specs}) != len(judge_specs):
        raise ProtocolError("official additional judges must have distinct expected model identities")

    planned_target_calls = len(suite.cases) * repetitions
    planned_judge_calls = planned_target_calls * judge_repetitions * len(judge_specs)
    if official and max_target_calls and max_target_calls < planned_target_calls:
        raise ProtocolError("official target-call budget is lower than the complete suite plan")
    if official and max_judge_calls and max_judge_calls < planned_judge_calls:
        raise ProtocolError("official judge-call budget is lower than the complete suite plan")

    safe_target_endpoint = _manifest_endpoint(endpoint)
    safe_judge_endpoint = _manifest_endpoint(judge_endpoint)

    target_key = os.getenv(target_key_env, "")
    judge_key = os.getenv(judge_key_env, "")
    previous_rows: list[dict[str, Any]] = []
    resumed = resume_dir is not None
    if resume_dir is not None:
        run_dir = resume_dir.resolve()
        if (run_dir / "bundle.json").exists():
            raise ProtocolError("a finalized run bundle cannot be resumed")
        try:
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError("resume directory requires a valid manifest.json") from exc
        expected_resume = {
            "protocol_version": PROTOCOL_VERSION,
            "suite.name": suite.name,
            "suite.version": suite.version,
            "suite.dataset_sha256": sha256_file(suite.dataset_path),
            "suite.rubric_sha256": sha256_file(suite.rubric_path),
            "target.expected_reported_model": expected_model,
            "target.revision": model_revision,
            "judge.expected_reported_model": expected_judge_model or judge_model,
            "judge.revision": judge_revision,
            "parameters.repetitions": repetitions,
            "parameters.judge_repetitions": judge_repetitions,
        }
        for dotted, expected_value in expected_resume.items():
            actual = _get(manifest, dotted) if "." in dotted else manifest.get(dotted)
            if actual != expected_value:
                raise ProtocolError(f"resume mismatch for {dotted}: expected {expected_value!r}, found {actual!r}")
        recorded_judges = manifest.get("judge", {}).get("models")
        if recorded_judges is not None and recorded_judges != judge_specs:
            raise ProtocolError("resume mismatch for configured judge models")
        if official and manifest.get("source", {}).get("commit") != evidence.get("commit"):
            raise ProtocolError("official resume requires the original source commit")
        run_id = str(manifest["run_id"])
        manifest.setdefault("resumed_at", []).append(datetime.now(timezone.utc).isoformat())
        manifest["status"] = "running"
        previous_rows = _read_jsonl(run_dir / "case_results.jsonl")
    else:
        run_id, run_dir = new_run_dir(repo_root, suite, model_label)
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
            "--mode",
            mode,
        ]
        if request_model:
            reproduction.extend(["--request-model", request_model])
        if official:
            reproduction.append("--official")
        manifest = {
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "report_version": REPORT_VERSION,
            "metric_version": METRIC_VERSION,
            "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
            "run_id": run_id,
            "status": "running",
            "official_requested": official,
            "started_at": started.isoformat(),
            "reproduction_command": shlex.join(reproduction),
            "suite": {
                "name": suite.name,
                "version": suite.version,
                "status": suite.status,
                "dataset_sha256": sha256_file(suite.dataset_path),
                "rubric_sha256": sha256_file(suite.rubric_path),
                "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
                "data_classification": suite.config["data_classification"],
                "profile": suite.config.get("profile", "text-generation"),
            },
            "target": {
                "label": model_label,
                "expected_reported_model": expected_model,
                "revision": model_revision,
                "endpoint": safe_target_endpoint,
                "request_model": request_model,
                "kind": (suite.config.get("target") or {}).get("kind", "json"),
                "capabilities": (suite.config.get("target") or {}).get("capabilities", []),
                "recorded_responses_sha256": (
                    sha256_file(suite.root / str((suite.config.get("target") or {}).get("responses"))) if target_kind == "recorded" else None
                ),
            },
            "judge": {
                "requested_model": judge_model,
                "expected_reported_model": expected_judge_model or judge_model,
                "revision": judge_revision,
                "endpoint": safe_judge_endpoint,
                "prompt_sha256": sha256_bytes(_judge_system_prompt(suite).encode("utf-8")),
                "response_schema": "judgment.schema.json@1.0.0",
                "temperature": 0,
                "models": judge_specs,
                "consensus": consensus,
            },
            "external_judge_authorized": bool(authorization_record) or bool(allow_external_judge and not official),
            "external_authorization": (
                {key: authorization_record[key] for key in ("authorization_id", "approver", "purpose", "destinations", "expires_at")}
                if authorization_record
                else None
            ),
            "artifact_security": {
                "classification": suite.config["data_classification"],
                "retention": (suite.config.get("governance") or {}).get("retention"),
                "storage_attestation": storage_record,
                "encryption_state": "attested" if storage_record and storage_record.get("encryption_at_rest") else "not-attested",
                "immutability_state": "attested" if storage_record and storage_record.get("immutability") else "not-attested",
            },
            "parameters": {
                "mode": mode,
                "repetitions": repetitions,
                "judge_repetitions": judge_repetitions,
                "max_cases": max_cases,
                "timeout_seconds": timeout,
                "max_target_calls": max_target_calls,
                "max_judge_calls": max_judge_calls,
                "max_total_tokens": max_total_tokens,
                "max_elapsed_seconds": max_elapsed_seconds,
                "max_estimated_cost": max_estimated_cost,
                "concurrency": concurrency,
                "requests_per_second": requests_per_second,
                "progress_events": progress,
                "case_order_policy": "dataset order",
                "case_order_sha256": sha256_bytes("\n".join(str(case["id"]) for case in suite.cases).encode("utf-8")),
                "cache": {"target": "disabled", "judge": "disabled"},
            },
            "pricing": suite.config.get("pricing") or None,
            "source": evidence,
            "environment": environment_evidence(repo_root),
        }
    run_perf_started = time.perf_counter()
    atomic_json(run_dir / "manifest.json", manifest)
    if not resumed:
        atomic_json(run_dir / "environment.json", manifest["environment"])
        atomic_json(run_dir / "asset_inventory.json", asset_inventory(suite.cases, suite_root=suite.root, snapshot_dir=run_dir / "assets"))
        protocol_source = repo_root / "PROTOCOL.md"
        if not protocol_source.is_file():
            protocol_source = Path(__file__).resolve().parents[2] / "PROTOCOL.md"
        (run_dir / "protocol_snapshot.md").write_text(protocol_source.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(run_dir / "protocol_snapshot.md", 0o600)
        (run_dir / "suite_snapshot.toml").write_text((suite.root / "suite.toml").read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(run_dir / "suite_snapshot.toml", 0o600)
        (run_dir / "dataset_card.md").write_text(dataset_card(suite), encoding="utf-8")
        os.chmod(run_dir / "dataset_card.md", 0o600)
        for name in ("requests.jsonl", "raw_responses.jsonl", "judgments.jsonl", "case_results.jsonl", "failures.jsonl", "events.jsonl"):
            (run_dir / name).touch(mode=0o600, exist_ok=False)
        (run_dir / "engine_results.jsonl").touch(mode=0o600, exist_ok=False)
    result_rows: list[dict[str, Any]] = list(previous_rows)
    previous_requests = _read_jsonl(run_dir / "requests.jsonl")
    previous_raw = {(str(row.get("case_id")), int(row.get("repetition", 0))): row for row in _read_jsonl(run_dir / "raw_responses.jsonl")}
    previous_judgments = {
        (str(row.get("case_id")), int(row.get("repetition", 0)), int(row.get("judge_repetition", 0))): row for row in _read_jsonl(run_dir / "judgments.jsonl")
    }
    previous_engine = {(str(row.get("case_id")), int(row.get("repetition", 0))): row for row in _read_jsonl(run_dir / "engine_results.jsonl")}
    target_calls = sum(row.get("kind") == "target" for row in previous_requests)
    judge_calls = sum(row.get("kind") == "judge" for row in previous_requests)
    token_totals = {"target_input": 0.0, "target_output": 0.0, "judge_input": 0.0, "judge_output": 0.0}
    for rows, kind in ((previous_raw.values(), "target"), (previous_judgments.values(), "judge")):
        for row in rows:
            raw = row.get("response") or row.get("raw") or {}
            if isinstance(raw, dict):
                input_tokens, output_tokens = _usage_tokens(raw)
                token_totals[f"{kind}_input"] += input_tokens
                token_totals[f"{kind}_output"] += output_tokens
    total_tokens = sum(token_totals.values())
    pricing_config = suite.config.get("pricing") or {}

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

    completed = {(str(row.get("case_id")), int(row.get("repetition", 0))) for row in previous_rows}
    write_lock = threading.Lock()
    budget_lock = threading.Lock()
    rate_lock = threading.Lock()
    abort_event = threading.Event()
    abort_reasons: list[str] = []
    next_request_at = 0.0

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
        input_tokens, output_tokens = _usage_tokens(raw)
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
            "scenario_id": case.get("scenario_id"),
            "performance_phase": case.get("performance_phase", "steady"),
            "repetition": repetition,
        }
        if abort_event.is_set():
            result = {**base, "status": "skipped", "reason": "run aborted by a prior observation"}
            record("case_results.jsonl", result)
            return result
        emit_event("observation_started", case_id=case["id"], repetition=repetition)
        started_case = time.perf_counter()
        target_transport: dict[str, Any] | None = None
        target_raw: dict[str, Any] = {}
        try:
            observation_key = (str(case["id"]), repetition)
            cached_target = previous_raw.get(observation_key)
            if cached_target:
                cached_response = cached_target.get("response")
                target_raw = dict(cached_response) if isinstance(cached_response, dict) else {}
                answer, reported_model = _target_answer(suite, target_raw)
                cached_transport = cached_target.get("transport")
                target_transport = dict(cached_transport) if isinstance(cached_transport, dict) else {}
            else:
                enforce_budget("target")
                wait_for_rate_limit()
                target_input: Any = (
                    {"case_id": case["id"], "input": case["input"], "messages": case.get("messages")}
                    if target_kind == "recorded"
                    else {"input": case["input"], "messages": case["messages"]}
                    if case.get("messages")
                    else case["input"]
                )
                answer, target_raw, reported_model, target_request, target_transport = call_target(
                    suite, endpoint, target_key, target_input, request_model, timeout
                )
                record("requests.jsonl", {**base, "kind": "target", "request_id": target_transport["request_id"], "payload": target_request})
                record("raw_responses.jsonl", {**base, "reported_model": reported_model, "response": target_raw, "transport": target_transport})
                consume_tokens(target_raw, "target")
            if reported_model != expected_model:
                raise ProtocolError(f"Target identity mismatch: expected {expected_model!r}, got {reported_model!r}")
            target = suite.config.get("target") or {}
            retrieval = _get(target_raw, str(target.get("retrieved_ids_field", "retrieved_ids"))) or []
            tools = _get(target_raw, str(target.get("tools_field", "tool_calls"))) or []
            deterministic = deterministic_evaluation(case, answer, target_raw=target_raw, retrieved_ids=retrieval, tool_calls=tools)
            if not deterministic["hard_pass"]:
                result = {**base, "status": "fail", "reason": "deterministic check failed", "deterministic": deterministic}
            else:
                engine_results: list[dict[str, Any]] = []
                deep_config = (suite.config.get("metrics") or {}).get("deepeval", [])
                if deep_config:
                    if not isinstance(deep_config, list) or not all(isinstance(item, dict) for item in deep_config):
                        raise ProtocolError("metrics.deepeval must be an array of tables")
                    cached_engine = previous_engine.get(observation_key)
                    if cached_engine and isinstance(cached_engine.get("results"), list):
                        engine_results = cached_engine["results"]
                    else:
                        engine_results = evaluate_deepeval_metrics(deep_config, case, answer, official=official)
                        record("engine_results.jsonl", {**base, "results": engine_results})
                if any(item["hard_fail"] and not item["success"] for item in engine_results):
                    result = {
                        **base,
                        "status": "fail",
                        "reason": "metric engine hard check failed",
                        "deterministic": deterministic,
                        "engine_results": engine_results,
                    }
                    record("case_results.jsonl", result)
                    return result
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
                        cached_judgment = previous_judgments.get((str(case["id"]), repetition, judge_repetition))
                        if cached_judgment is not None:
                            judgment = cached_judgment.get("judgment")
                            if isinstance(judgment, dict):
                                reported_judge = str(cached_judgment.get("reported_model") or "")
                                if reported_judge != judge_spec["expected_model"]:
                                    raise ProtocolError(f"Judge identity mismatch: expected {judge_spec['expected_model']!r}, got {reported_judge!r}")
                                verdicts.append(judgment)
                            continue
                        try:
                            enforce_budget("judge")
                            wait_for_rate_limit()
                            judgment, judge_raw, judge_content, judge_request, judge_transport = call_judge(
                                suite, judge_endpoint, judge_key, judge_spec["model"], case, answer, target_raw, timeout
                            )
                            reported_judge = str(judge_raw.get("model") or "")
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
                                },
                            )
                            consume_tokens(judge_raw, "judge")
                            if reported_judge != judge_spec["expected_model"]:
                                raise ProtocolError(f"Judge identity mismatch: expected {judge_spec['expected_model']!r}, got {reported_judge!r}")
                            verdicts.append(judgment)
                        except ProtocolError as exc:
                            if "identity mismatch" in str(exc).casefold() or "budget exhausted" in str(exc).casefold():
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
        except ProtocolError as exc:
            result = {**base, "status": "error", "reason": str(exc)}
            if (official and "identity mismatch" in str(exc).casefold()) or "budget exhausted" in str(exc).casefold():
                with budget_lock:
                    if not abort_reasons:
                        abort_reasons.append(str(exc))
                abort_event.set()
        result["duration_ms"] = round((time.perf_counter() - started_case) * 1000, 1)
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
        emit_event("observation_finished", case_id=case["id"], repetition=repetition, status=result["status"])
        return result

    selected = suite.cases[:max_cases] if max_cases > 0 else suite.cases
    tasks: list[tuple[dict[str, Any], int]] = []
    for case in selected:
        if case["review"]["status"] != "approved":
            result = {
                "case_id": case["id"],
                "category": case["category"],
                "risk_domain": case["risk_domain"],
                "severity": case["severity"],
                "language": case.get("language", "missing"),
                "locale": case.get("locale", "missing"),
                "split": case.get("split", "missing"),
                "scenario_id": case.get("scenario_id"),
                "performance_phase": case.get("performance_phase", "steady"),
                "status": "skipped",
                "reason": "case not approved",
            }
            result_rows.append(result)
            record("case_results.jsonl", result)
            continue
        tasks.extend((case, repetition) for repetition in range(1, repetitions + 1) if (str(case["id"]), repetition) not in completed)
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
    abort_reason = abort_reasons[0] if abort_reasons else ""

    statistics_config = suite.config.get("statistics") or {}
    confidence = float(statistics_config.get("confidence", 0.95))
    bootstrap_samples = int(statistics_config.get("bootstrap_samples", 10_000))
    bootstrap_seed = int(statistics_config.get("seed", 0))
    metrics, categories = summarize(result_rows, confidence=confidence)
    statuses_by_case: dict[str, list[str]] = {}
    for row in result_rows:
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
        case_rows = [row for row in result_rows if str(row["case_id"]) == case_id]
        if set(statuses) == {"pass"}:
            category_binary.setdefault(str(case_rows[0]["category"]), []).append(1.0)
        elif set(statuses) <= {"pass", "fail"}:
            category_binary.setdefault(str(case_rows[0]["category"]), []).append(0.0)
    metrics["pass_rate_stratified_bootstrap_ci"] = stratified_bootstrap_mean_interval(
        category_binary, confidence=confidence, samples=bootstrap_samples, seed=bootstrap_seed
    )
    slices: dict[str, dict[str, Any]] = {}
    for dimension in ("risk_domain", "severity", "language", "locale", "split"):
        values: dict[str, Any] = {}
        for value in sorted({str(row.get(dimension, "missing")) for row in result_rows}):
            subset = [row for row in result_rows if str(row.get(dimension, "missing")) == value]
            values[value] = summarize(subset, confidence=confidence)[0]
        slices[dimension] = values
    metrics["slices"] = slices
    metrics["slice_disparities"] = {
        dimension: max((float(item["pass_rate"]) for item in values.values()), default=0.0)
        - min((float(item["pass_rate"]) for item in values.values()), default=0.0)
        for dimension, values in slices.items()
    }
    repetition_pass_rates = []
    for statuses in statuses_by_case.values():
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
    scenarios: dict[str, set[str]] = {}
    for row in result_rows:
        if row.get("scenario_id"):
            scenarios.setdefault(str(row["scenario_id"]), set()).add(str(row["status"]))
    if scenarios:
        scenario_statuses = {
            scenario: "pass" if statuses == {"pass"} else "fail" if statuses <= {"pass", "fail"} else "invalid" for scenario, statuses in scenarios.items()
        }
        valid_scenarios = [status for status in scenario_statuses.values() if status in {"pass", "fail"}]
        metrics["hierarchical_scenarios"] = {
            "total": len(scenario_statuses),
            "pass": sum(status == "pass" for status in scenario_statuses.values()),
            "fail": sum(status == "fail" for status in scenario_statuses.values()),
            "invalid": sum(status == "invalid" for status in scenario_statuses.values()),
            "pass_rate": sum(status == "pass" for status in valid_scenarios) / len(valid_scenarios) if valid_scenarios else 0.0,
        }
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
            gate_failures.append({"category": "judge-calibration", "metric": "accuracy", "minimum": float(minimum_calibration_accuracy), "actual": None})
        for judge_id, calibration_result in calibration.items():
            if float(calibration_result["accuracy"]) < float(minimum_calibration_accuracy):
                gate_failures.append(
                    {
                        "category": f"judge-calibration:{judge_id}",
                        "metric": "accuracy",
                        "minimum": float(minimum_calibration_accuracy),
                        "actual": calibration_result["accuracy"],
                    }
                )
    metrics["gate_failures"] = gate_failures
    metrics["aborted"] = bool(abort_reason)
    atomic_json(run_dir / "metrics.json", metrics)
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
        "engine_results.jsonl",
        "case_results.jsonl",
        "metrics.json",
        "category_results.csv",
        "failures.jsonl",
        "events.jsonl",
        "adjudication_queue.jsonl",
        "environment.json",
        "asset_inventory.json",
        "protocol_snapshot.md",
        "suite_snapshot.toml",
        "dataset_card.md",
    ]
    artifact_names.extend(path.relative_to(run_dir).as_posix() for path in sorted((run_dir / "assets").glob("*")) if path.is_file())
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
