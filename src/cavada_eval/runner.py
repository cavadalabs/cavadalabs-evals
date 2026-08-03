from __future__ import annotations

import html
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .protocol import (
    PROTOCOL_VERSION,
    ProtocolError,
    Suite,
    append_jsonl,
    apply_gates,
    atomic_json,
    contains_secret_like,
    deterministic_checks,
    environment_evidence,
    git_evidence,
    new_run_dir,
    sha256_file,
    summarize,
    write_category_csv,
)


def _get(value: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _completion_url(endpoint: str) -> str:
    clean = endpoint.rstrip("/")
    return clean if clean.endswith("/chat/completions") else clean + "/chat/completions"


def _post_json(url: str, payload: dict[str, Any], api_key: str, timeout: float) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:1000]
        raise ProtocolError(f"HTTP {exc.code} from {url}: {body}") from exc
    except urllib.error.URLError as exc:
        raise ProtocolError(f"Cannot reach {url}: {exc.reason}") from exc
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"Non-JSON response from {url}") from exc
    if not isinstance(parsed, dict):
        raise ProtocolError(f"Expected JSON object from {url}")
    return parsed


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
    prompt: str,
    request_model: str | None,
    timeout: float,
) -> tuple[str, dict[str, Any], str]:
    target = suite.config.get("target") or {}
    kind = target.get("kind", "json")
    if kind == "openai":
        if not request_model:
            raise ProtocolError("OpenAI target requires --request-model")
        payload = {
            "model": request_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": float(suite.config.get("temperature", 0)),
            "max_tokens": int(suite.config.get("max_tokens", 2048)),
        }
        raw = _post_json(_completion_url(endpoint), payload, api_key, timeout)
        try:
            answer = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProtocolError("OpenAI target returned no message content") from exc
        reported_model = str(raw.get("model") or "")
    elif kind == "json":
        request_field = str(target.get("request_field", "message"))
        payload = json.loads(str(target.get("request_defaults_json", "{}")))
        payload[request_field] = prompt
        raw = _post_json(endpoint, payload, api_key, timeout)
        answer = _get(raw, str(target.get("response_field", "answer")))
        if not isinstance(answer, str):
            raise ProtocolError("JSON target returned no configured response string")
        reported_model = str(_get(raw, str(target.get("reported_model_field", "model"))) or "")
    else:
        raise ProtocolError(f"Unsupported target kind: {kind}")
    return answer, raw, reported_model


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


def call_judge(
    suite: Suite,
    endpoint: str,
    api_key: str,
    judge_model: str,
    case: dict[str, Any],
    answer: str,
    target_raw: dict[str, Any],
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    target = suite.config.get("target") or {}
    evidence = {
        "sources": _get(target_raw, str(target.get("sources_field", "sources"))) or [],
        "tool_calls": _get(target_raw, str(target.get("tools_field", "tool_calls"))) or [],
    }
    if contains_secret_like(evidence):
        raise ProtocolError("Judge payload blocked: retrieved evidence contains secret-like material")
    user_payload = {
        "input": case["input"],
        "expected_behavior": case["expected_behavior"],
        "expected_behavior_reason": case["expected_behavior_reason"],
        "category": case["category"],
        "risk_domain": case["risk_domain"],
        "severity": case["severity"],
        "answer": answer,
        "evidence": evidence,
    }
    system = (
        suite.rubric
        + "\nReturn only strict JSON: "
        + '{"verdict":"pass|fail","score":0,"reason":"concise reason","criteria":{}}. '
        + "The target model identity is intentionally hidden."
    )
    raw = _post_json(
        _completion_url(endpoint),
        {
            "model": judge_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
            "temperature": 0,
            "max_tokens": 600,
        },
        api_key,
        timeout,
    )
    parsed, content = _judge_result(raw)
    return parsed, raw, content


def _report(path: Path, manifest: dict[str, Any], metrics: dict[str, Any], categories: list[dict[str, Any]]) -> None:
    rows = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(row[key]))}</td>" for key in ("category", "total", "pass", "fail", "invalid", "error", "pass_rate", "ci95_lower")) + "</tr>"
        for row in categories
    )
    document = f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(manifest['suite']['name'])}</title>
<style>body{{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#172033}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd3df;padding:8px;text-align:left}}.pass{{color:#08752c}}.fail{{color:#a11616}}code{{background:#eef1f6;padding:2px 5px}}</style></head><body>
<h1>CavadaLabs Evaluation Report</h1><p>Run <code>{html.escape(manifest['run_id'])}</code> · protocol {PROTOCOL_VERSION}</p>
<h2 class="{'pass' if manifest['status'] == 'passed' else 'fail'}">{html.escape(manifest['status'].upper())}</h2>
<p>Pass rate: {metrics['pass_rate']:.3%}; 95% lower bound: {metrics['pass_rate_ci95']['lower']:.3%}; invalid: {metrics['invalid']}; errors: {metrics['error']}.</p>
<table><thead><tr><th>Category</th><th>Total</th><th>Pass</th><th>Fail</th><th>Invalid</th><th>Error</th><th>Pass rate</th><th>CI95 lower</th></tr></thead><tbody>{rows}</tbody></table>
<p>This report is protocol evidence, not legal certification or a universal safety guarantee.</p></body></html>"""
    path.write_text(document, encoding="utf-8")
    os.chmod(path, 0o600)


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
) -> Path:
    if repetitions < 1 or judge_repetitions < 1:
        raise ProtocolError("Repetitions must be positive")
    if official and (not _secure_endpoint(endpoint) or not _secure_endpoint(judge_endpoint)):
        raise ProtocolError("Official runs require HTTPS or loopback endpoints")
    if official and max_cases > 0:
        raise ProtocolError("Official runs cannot use --max-cases")
    if official and repetitions < int(suite.config.get("official_min_repetitions", 1)):
        raise ProtocolError("Official run has too few target repetitions")
    if official and judge_repetitions < int(suite.config.get("official_min_judge_repetitions", 1)):
        raise ProtocolError("Official run has too few judge repetitions")
    judge_host = urllib.parse.urlparse(judge_endpoint).hostname
    external_judge = judge_host not in {"127.0.0.1", "localhost", "::1"}
    if official and external_judge and suite.config["data_classification"] not in {"public", "synthetic"} and not allow_external_judge:
        raise ProtocolError("Non-public suite requires --allow-external-judge for an external judge")
    evidence = git_evidence(repo_root)
    if official and (not evidence["commit"] or evidence["dirty"]):
        raise ProtocolError("Official runs require a committed, clean source tree")
    if official and (not expected_model or not (expected_judge_model or judge_model)):
        raise ProtocolError("Official runs require expected target and judge identities")
    if official and (not model_revision or not judge_revision):
        raise ProtocolError("Official runs require target and judge revisions")

    safe_target_endpoint = _manifest_endpoint(endpoint)
    safe_judge_endpoint = _manifest_endpoint(judge_endpoint)

    target_key = os.getenv(target_key_env, "")
    judge_key = os.getenv(judge_key_env, "")
    run_id, run_dir = new_run_dir(repo_root, suite, model_label)
    started = datetime.now(timezone.utc)
    manifest: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "run_id": run_id,
        "status": "running",
        "official_requested": official,
        "started_at": started.isoformat(),
        "suite": {
            "name": suite.name,
            "version": suite.version,
            "status": suite.status,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
            "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
            "data_classification": suite.config["data_classification"],
        },
        "target": {"label": model_label, "expected_reported_model": expected_model, "revision": model_revision, "endpoint": safe_target_endpoint, "request_model": request_model},
        "judge": {"requested_model": judge_model, "expected_reported_model": expected_judge_model or judge_model, "revision": judge_revision, "endpoint": safe_judge_endpoint},
        "external_judge_authorized": bool(allow_external_judge),
        "parameters": {"repetitions": repetitions, "judge_repetitions": judge_repetitions, "max_cases": max_cases, "timeout_seconds": timeout},
        "source": evidence,
        "environment": environment_evidence(repo_root),
    }
    atomic_json(run_dir / "manifest.json", manifest)
    result_rows: list[dict[str, Any]] = []
    abort_reason = ""

    selected = suite.cases[:max_cases] if max_cases > 0 else suite.cases
    try:
        for case in selected:
            if case["review"]["status"] != "approved":
                result = {"case_id": case["id"], "category": case["category"], "status": "skipped", "reason": "case not approved"}
                result_rows.append(result)
                append_jsonl(run_dir / "case_results.jsonl", result)
                continue
            for repetition in range(1, repetitions + 1):
                started_case = time.perf_counter()
                base = {"case_id": case["id"], "category": case["category"], "risk_domain": case["risk_domain"], "severity": case["severity"], "repetition": repetition}
                try:
                    answer, target_raw, reported_model = call_target(suite, endpoint, target_key, case["input"], request_model, timeout)
                    append_jsonl(run_dir / "raw_responses.jsonl", {**base, "reported_model": reported_model, "response": target_raw})
                    if reported_model != expected_model:
                        raise ProtocolError(f"Target identity mismatch: expected {expected_model!r}, got {reported_model!r}")
                    deterministic = deterministic_checks(case, answer)
                    if not all(deterministic.values()):
                        result = {**base, "status": "fail", "reason": "deterministic check failed", "deterministic": deterministic}
                    else:
                        verdicts: list[dict[str, Any]] = []
                        for judge_repetition in range(1, judge_repetitions + 1):
                            try:
                                judgment, judge_raw, judge_content = call_judge(suite, judge_endpoint, judge_key, judge_model, case, answer, target_raw, timeout)
                                reported_judge = str(judge_raw.get("model") or "")
                                if reported_judge != (expected_judge_model or judge_model):
                                    raise ProtocolError(f"Judge identity mismatch: expected {(expected_judge_model or judge_model)!r}, got {reported_judge!r}")
                                verdicts.append(judgment)
                                append_jsonl(run_dir / "judgments.jsonl", {**base, "judge_repetition": judge_repetition, "reported_model": reported_judge, "judgment": judgment, "raw_content": judge_content})
                            except ProtocolError as exc:
                                append_jsonl(run_dir / "judgments.jsonl", {**base, "judge_repetition": judge_repetition, "status": "invalid", "error": str(exc)})
                        passes = sum(item["verdict"] == "pass" for item in verdicts)
                        fails = sum(item["verdict"] == "fail" for item in verdicts)
                        if len(verdicts) != judge_repetitions:
                            result = {**base, "status": "invalid", "reason": "one or more judge outputs were invalid", "deterministic": deterministic}
                        elif passes == fails or (official and passes and fails):
                            result = {**base, "status": "invalid", "reason": "judge disagreement", "deterministic": deterministic}
                        else:
                            result = {
                                **base,
                                "status": "pass" if passes > fails else "fail",
                                "reason": "judge majority",
                                "score": sum(item["score"] for item in verdicts) / len(verdicts),
                                "judge_agreement": max(passes, fails) / len(verdicts),
                                "deterministic": deterministic,
                            }
                except ProtocolError as exc:
                    result = {**base, "status": "error", "reason": str(exc)}
                    if official and "identity mismatch" in str(exc).casefold():
                        abort_reason = str(exc)
                result["duration_ms"] = round((time.perf_counter() - started_case) * 1000, 1)
                result_rows.append(result)
                append_jsonl(run_dir / "case_results.jsonl", result)
                if abort_reason:
                    raise ProtocolError(abort_reason)
    except ProtocolError as exc:
        abort_reason = str(exc)

    metrics, categories = summarize(result_rows)
    gate_failures = apply_gates(suite, metrics, categories)
    metrics["gate_failures"] = gate_failures
    metrics["aborted"] = bool(abort_reason)
    atomic_json(run_dir / "metrics.json", metrics)
    write_category_csv(run_dir / "category_results.csv", categories)
    failures_path = run_dir / "failures.jsonl"
    failures_path.touch(mode=0o600, exist_ok=False)
    for row in result_rows:
        if row["status"] != "pass":
            append_jsonl(failures_path, row)

    artifact_names = ["raw_responses.jsonl", "judgments.jsonl", "case_results.jsonl", "metrics.json", "category_results.csv", "failures.jsonl"]
    manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
    manifest["abort_reason"] = abort_reason
    manifest["metrics"] = metrics
    manifest["artifacts"] = {name: sha256_file(run_dir / name) for name in artifact_names if (run_dir / name).is_file()}
    manifest["status"] = "passed" if not abort_reason and metrics["officially_valid"] and not gate_failures else "failed"
    manifest["official"] = bool(official and manifest["status"] == "passed")
    _report(run_dir / "report.html", manifest, metrics, categories)
    manifest["artifacts"]["report.html"] = sha256_file(run_dir / "report.html")
    atomic_json(run_dir / "manifest.json", manifest)
    return run_dir
