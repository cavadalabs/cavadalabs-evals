from __future__ import annotations

import json
import math
import os
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .comparison import _require_compatible_manifests
from .protocol import ProtocolError, Suite, append_jsonl, atomic_json, atomic_text, load_suite, require_mutable_output_root, sha256_bytes
from .runner import _CallEvidenceError, _completion_url, _manifest_endpoint, _post_json, _secure_endpoint, _TransportError
from .statistics import bootstrap_mean_interval

_IDENTITY_FIELDS = ("label", "expected_reported_model", "revision", "request_model")
_IDENTITY_PLACEHOLDERS = {"", "unavailable", "unassigned", "unassessed", "not-assessed", "replace-me"}


def _target_identities(*manifests: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for manifest in manifests:
        target = manifest.get("target")
        if not isinstance(target, dict):
            continue
        for field in _IDENTITY_FIELDS:
            value = target.get(field)
            if isinstance(value, str) and value.strip().casefold() not in _IDENTITY_PLACEHOLDERS:
                values.add(value.strip().casefold())
    return values


def _contains_identity(value: Any, identities: set[str]) -> bool:
    if isinstance(value, str):
        folded = value.casefold()
        return any(identity in folded for identity in identities)
    if isinstance(value, list):
        return any(_contains_identity(item, identities) for item in value)
    if isinstance(value, dict):
        return any(_contains_identity(item, identities) for item in value.values())
    return False


def _rows(raw: bytes, name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"invalid {name}: expected UTF-8") from exc
    for number, line in enumerate(lines, 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid {name} line {number}") from exc
        if not isinstance(value, dict):
            raise ProtocolError(f"invalid {name} line {number}: expected an object")
        rows.append(value)
    return rows


def _snapshot_run(run_dir: Path) -> tuple[dict[str, bytes], str]:
    try:
        bundle_raw = (run_dir / "bundle.json").read_bytes()
    except OSError as exc:
        raise ProtocolError("pairwise input is missing readable bundle.json") from exc
    if not verify_bundle(run_dir)["valid"] or (run_dir / "bundle.json").read_bytes() != bundle_raw:
        raise ProtocolError("pairwise input run bundle verification failed")
    try:
        bundle = json.loads(bundle_raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - verify_bundle rejects this first
        raise ProtocolError("pairwise input has invalid bundle.json") from exc
    files = bundle.get("files") if isinstance(bundle, dict) else None
    if not isinstance(files, dict):  # pragma: no cover - verify_bundle rejects this first
        raise ProtocolError("pairwise input has malformed bundle.json")
    snapshots: dict[str, bytes] = {}
    for name in ("manifest.json", "case_results.jsonl", "raw_responses.jsonl"):
        try:
            raw = (run_dir / name).read_bytes()
        except OSError as exc:
            raise ProtocolError(f"missing pairwise input artifact: {name}") from exc
        if files.get(name) != sha256_bytes(raw):
            raise ProtocolError(f"pairwise input artifact changed after bundle verification: {name}")
        snapshots[name] = raw
    return snapshots, sha256_bytes(bundle_raw)


def _answers(rows: list[dict[str, Any]], expected_model: str) -> dict[tuple[str, int], str]:
    answers: dict[tuple[str, int], str] = {}
    for number, row in enumerate(rows, 1):
        case_id = row.get("case_id")
        repetition = row.get("repetition")
        if not isinstance(case_id, str) or not case_id or not isinstance(repetition, int) or isinstance(repetition, bool) or repetition < 1:
            raise ProtocolError(f"invalid raw_responses.jsonl line {number}: case_id and repetition are required")
        key = (case_id, repetition)
        if key in answers:
            raise ProtocolError(f"duplicate raw answer: {case_id} repetition {repetition}")
        if row.get("reported_model") != expected_model:
            raise ProtocolError(f"raw target identity mismatch: {case_id} repetition {repetition}")
        raw = row.get("response") or {}
        answer: Any = raw.get("answer") if isinstance(raw, dict) else None
        if answer is None:
            try:
                answer = raw["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError):
                answer = None
        if not isinstance(answer, str):
            raise ProtocolError(f"raw response has no usable answer: {case_id} repetition {repetition}")
        answers[key] = answer
    return answers


def _required_keys(rows: list[dict[str, Any]], manifest: dict[str, Any], suite: Suite) -> set[tuple[str, int]]:
    parameters = manifest["parameters"]
    selected_cases = parameters["selected_cases"]
    repetitions = parameters["repetitions"]
    if not isinstance(selected_cases, int) or isinstance(selected_cases, bool) or selected_cases < 1:
        raise ProtocolError("pairwise comparison requires a positive integer selected_cases")
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        raise ProtocolError("pairwise comparison requires a positive integer repetitions")
    suite_ids = {str(case["id"]) for case in suite.cases}
    keys: set[tuple[str, int]] = set()
    for number, row in enumerate(rows, 1):
        if row.get("status") not in {"pass", "fail"}:
            raise ProtocolError(f"invalid case_results.jsonl line {number}: status must be pass or fail")
        case_id = row.get("case_id")
        repetition = row.get("repetition")
        if not isinstance(case_id, str) or case_id not in suite_ids:
            raise ProtocolError(f"invalid case_results.jsonl line {number}: unknown case_id")
        if not isinstance(repetition, int) or isinstance(repetition, bool) or repetition < 1:
            raise ProtocolError(f"invalid case_results.jsonl line {number}: repetition is required")
        key = (case_id, repetition)
        if key in keys:
            raise ProtocolError(f"duplicate case result: {case_id} repetition {repetition}")
        keys.add(key)
    case_ids = {case_id for case_id, _ in keys}
    expected_repetitions = set(range(1, repetitions + 1))
    if len(case_ids) != selected_cases or any({repetition for observed, repetition in keys if observed == case_id} != expected_repetitions for case_id in case_ids):
        raise ProtocolError("pairwise comparison requires every selected case and repetition")
    return keys


def _require_pairwise_run(manifest: dict[str, Any], label: str) -> str:
    metrics = manifest.get("metrics")
    if (
        manifest.get("status") != "passed"
        or bool(manifest.get("abort_reason"))
        or not isinstance(metrics, dict)
        or metrics.get("officially_valid") is not True
        or metrics.get("aborted") is not False
        or metrics.get("gate_failures") != []
        or any(metrics.get(field) != 0 for field in ("invalid", "error", "skipped"))
    ):
        raise ProtocolError(f"pairwise requires a valid passed behavior run: {label}")
    target = manifest.get("target")
    expected_model = target.get("expected_reported_model") if isinstance(target, dict) else None
    if not isinstance(expected_model, str) or not expected_model:
        raise ProtocolError(f"pairwise requires {label} target expected_reported_model")
    return expected_model


def _winner(raw: dict[str, Any]) -> tuple[str, str, float]:
    try:
        text = raw["choices"][0]["message"]["content"]
        value = json.loads(text)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise ProtocolError("pairwise judge returned malformed JSON") from exc
    winner = value.get("winner") if isinstance(value, dict) else None
    reason = value.get("reason") if isinstance(value, dict) else None
    confidence = value.get("confidence") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"winner", "reason", "confidence"}
        or winner not in {"A", "B", "tie"}
        or not isinstance(reason, str)
        or not reason.strip()
        or not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(float(confidence))
        or not 0 <= float(confidence) <= 1
    ):
        raise ProtocolError("pairwise judge requires winner A|B|tie, reason, and confidence 0..1")
    return winner, reason, float(confidence)


def pairwise_runs(
    baseline_dir: Path,
    candidate_dir: Path,
    suite: Suite,
    output_dir: Path,
    *,
    judge_endpoint: str,
    judge_model: str,
    expected_judge_model: str,
    judge_revision: str,
    judge_key_env: str = "JUDGE_API_KEY",
    timeout: float = 90,
    signing_key_env: str = "CAVADA_EVAL_SIGNING_KEY",
) -> dict[str, Any]:
    fresh_suite = load_suite(suite.root)
    if suite != fresh_suite:
        raise ProtocolError("provided suite differs from the canonical validated suite on disk")
    suite = fresh_suite
    resolved_output = output_dir.resolve()
    if any(
        resolved_output == run_dir.resolve() or resolved_output.is_relative_to(run_dir.resolve())
        for run_dir in (baseline_dir, candidate_dir)
    ):
        raise ProtocolError("pairwise output must be outside the immutable input runs")
    require_mutable_output_root(output_dir)
    if output_dir.exists():
        raise ProtocolError("pairwise output directory already exists")
    baseline_snapshot, baseline_bundle_sha256 = _snapshot_run(baseline_dir)
    candidate_snapshot, candidate_bundle_sha256 = _snapshot_run(candidate_dir)
    if not judge_model or not expected_judge_model or not judge_revision:
        raise ProtocolError("pairwise judge model, expected identity, and revision are required")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(float(timeout)) or timeout <= 0:
        raise ProtocolError("pairwise timeout must be a finite positive number")
    if not _secure_endpoint(judge_endpoint):
        raise ProtocolError("pairwise judging requires HTTPS or a loopback endpoint")
    _manifest_endpoint(judge_endpoint)
    judge_host = urllib.parse.urlparse(judge_endpoint).hostname
    if judge_host not in {"127.0.0.1", "localhost", "::1"} and suite.config.get("data_classification") not in {"public", "synthetic"}:
        raise ProtocolError("non-public pairwise evidence requires a local judge")
    try:
        baseline_manifest = json.loads(baseline_snapshot["manifest.json"])
        candidate_manifest = json.loads(candidate_snapshot["manifest.json"])
    except json.JSONDecodeError as exc:
        raise ProtocolError("both pairwise runs require valid manifest.json") from exc
    if not isinstance(baseline_manifest, dict) or not isinstance(candidate_manifest, dict):
        raise ProtocolError("both pairwise runs require manifest objects")
    _require_compatible_manifests(baseline_manifest, candidate_manifest)
    baseline_model = _require_pairwise_run(baseline_manifest, "baseline")
    candidate_model = _require_pairwise_run(candidate_manifest, "candidate")
    suite_evidence = {
        "name": suite.name,
        "version": suite.version,
        "dataset_sha256": sha256_bytes(suite.dataset_path.read_bytes()),
        "rubric_sha256": sha256_bytes(suite.rubric_path.read_bytes()),
        "suite_config_sha256": sha256_bytes((suite.root / "suite.toml").read_bytes()),
    }
    for field, expected in suite_evidence.items():
        if baseline_manifest["suite"].get(field) != expected:
            raise ProtocolError(f"pairwise suite does not match run suite {field}")
    if load_suite(suite.root) != suite:
        raise ProtocolError("canonical suite changed during pairwise preflight")
    left = _answers(_rows(baseline_snapshot["raw_responses.jsonl"], "raw_responses.jsonl"), baseline_model)
    right = _answers(_rows(candidate_snapshot["raw_responses.jsonl"], "raw_responses.jsonl"), candidate_model)
    baseline_keys = _required_keys(_rows(baseline_snapshot["case_results.jsonl"], "case_results.jsonl"), baseline_manifest, suite)
    candidate_keys = _required_keys(_rows(candidate_snapshot["case_results.jsonl"], "case_results.jsonl"), candidate_manifest, suite)
    if baseline_keys != candidate_keys:
        raise ProtocolError("pairwise runs require identical case and repetition identifiers")
    if set(left) != baseline_keys or set(right) != candidate_keys:
        raise ProtocolError("pairwise runs require one raw answer for every selected case and repetition")
    if _snapshot_run(baseline_dir) != (baseline_snapshot, baseline_bundle_sha256) or _snapshot_run(candidate_dir) != (
        candidate_snapshot,
        candidate_bundle_sha256,
    ):
        raise ProtocolError("pairwise input run changed during preflight")
    pairs = sorted(baseline_keys)
    cases = {str(case["id"]): case for case in suite.cases}
    system = suite.rubric + "\nCompare two anonymous answers. Return strict JSON only: " + '{"winner":"A|B|tie","reason":"concise","confidence":0.0}.'
    identities = _target_identities(baseline_manifest, candidate_manifest)
    planned_requests: dict[tuple[str, int], list[tuple[str, dict[str, Any]]]] = {}
    for case_id, repetition in pairs:
        for order, answer_a, answer_b in (
            ("AB", left[(case_id, repetition)], right[(case_id, repetition)]),
            ("BA", right[(case_id, repetition)], left[(case_id, repetition)]),
        ):
            payload = {
                "model": judge_model,
                "messages": [
                    {"role": "system", "content": system},
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "input": cases[case_id]["input"],
                                "expected_behavior": cases[case_id]["expected_behavior"],
                                "expected_behavior_reason": cases[case_id]["expected_behavior_reason"],
                                "answer_A": answer_a,
                                "answer_B": answer_b,
                            },
                            ensure_ascii=False,
                        ),
                    },
                ],
                "temperature": 0,
                "max_tokens": 500,
            }
            if _contains_identity(payload, identities):
                raise ProtocolError("pairwise judge payload exposes target identity")
            planned_requests.setdefault((case_id, repetition), []).append((order, payload))

    output_dir.mkdir(parents=True, mode=0o700)
    (output_dir / "pairwise_judgments.jsonl").touch(mode=0o600)
    key = os.getenv(judge_key_env, "")
    outcomes_by_case: dict[str, list[str]] = {}
    for (case_id, repetition), requests in planned_requests.items():
        order_results: list[str] = []
        order_statuses: list[str] = []
        for order, payload in requests:
            try:
                raw, transport = _post_json(_completion_url(judge_endpoint), payload, key, timeout, request_id=uuid.uuid4().hex)
            except _CallEvidenceError as exc:
                status = "error" if isinstance(exc, _TransportError) else "invalid"
                order_statuses.append(status)
                append_jsonl(
                    output_dir / "pairwise_judgments.jsonl",
                    {
                        "case_id": case_id,
                        "repetition": repetition,
                        "order": order,
                        "status": status,
                        "request": exc.request,
                        "raw": exc.raw,
                        "transport": exc.transport,
                        "error": str(exc),
                    },
                )
                continue
            reported = str(raw.get("model") or "")
            if reported != expected_judge_model:
                error = f"Judge identity mismatch: expected {expected_judge_model!r}, got {reported!r}"
                append_jsonl(
                    output_dir / "pairwise_judgments.jsonl",
                    {
                        "case_id": case_id,
                        "repetition": repetition,
                        "order": order,
                        "status": "invalid",
                        "request": payload,
                        "reported_judge": reported,
                        "raw": raw,
                        "transport": transport,
                        "error": error,
                    },
                )
                raise ProtocolError(error)
            try:
                winner, reason, confidence = _winner(raw)
            except ProtocolError as exc:
                order_statuses.append("invalid")
                append_jsonl(
                    output_dir / "pairwise_judgments.jsonl",
                    {
                        "case_id": case_id,
                        "repetition": repetition,
                        "order": order,
                        "status": "invalid",
                        "request": payload,
                        "reported_judge": reported,
                        "raw": raw,
                        "transport": transport,
                        "error": str(exc),
                    },
                )
                continue
            mapped = winner if winner == "tie" else ("baseline" if (order == "AB" and winner == "A") or (order == "BA" and winner == "B") else "candidate")
            order_results.append(mapped)
            order_statuses.append("valid")
            append_jsonl(
                output_dir / "pairwise_judgments.jsonl",
                {
                    "case_id": case_id,
                    "repetition": repetition,
                    "order": order,
                    "status": "valid",
                    "winner": mapped,
                    "confidence": confidence,
                    "reason": reason,
                    "request": payload,
                    "reported_judge": reported,
                    "raw": raw,
                    "transport": transport,
                },
            )
        if "error" in order_statuses:
            outcome = "error"
        elif len(order_results) != 2 or order_results[0] != order_results[1]:
            outcome = "invalid"
        else:
            outcome = order_results[0]
        outcomes_by_case.setdefault(case_id, []).append(outcome)
    counts = {"baseline": 0, "candidate": 0, "tie": 0, "invalid": 0, "error": 0}
    valid_scores: list[float] = []
    for outcomes in outcomes_by_case.values():
        if "error" in outcomes:
            outcome = "error"
        elif "invalid" in outcomes or len(set(outcomes)) != 1:
            outcome = "invalid"
        else:
            outcome = outcomes[0]
        counts[outcome] += 1
        if outcome in {"baseline", "candidate", "tie"}:
            valid_scores.append(1.0 if outcome == "candidate" else 0.0 if outcome == "baseline" else 0.5)
    metrics = {
        **counts,
        "total": len(outcomes_by_case),
        "observations": len(pairs),
        "valid": len(valid_scores),
        "candidate_score": sum(valid_scores) / len(valid_scores) if valid_scores else 0.0,
        "candidate_score_ci95": bootstrap_mean_interval(valid_scores, samples=10_000, seed=0) if valid_scores else None,
    }
    manifest = {
        "pairwise_version": "2.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "suite": suite_evidence,
        "baseline_run": {"run_id": baseline_manifest.get("run_id"), "bundle_sha256": baseline_bundle_sha256},
        "candidate_run": {"run_id": candidate_manifest.get("run_id"), "bundle_sha256": candidate_bundle_sha256},
        "judge": {
            "model": judge_model,
            "expected_model": expected_judge_model,
            "revision": judge_revision,
            "endpoint": _manifest_endpoint(judge_endpoint),
            "api_key_env": judge_key_env,
            "timeout_seconds": float(timeout),
            "prompt_sha256": sha256_bytes(system.encode("utf-8")),
            "response_schema": "pairwise-winner@1.0.0",
            "temperature": 0,
            "max_tokens": 500,
        },
        "identity_blinded": True,
        "orders": ["AB", "BA"],
        "metrics": metrics,
    }
    atomic_json(output_dir / "metrics.json", metrics)
    atomic_json(output_dir / "manifest.json", manifest)
    atomic_text(
        output_dir / "report.html",
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'"><title>CavadaLabs pairwise comparison</title><style>body{{font:15px system-ui;max-width:900px;margin:40px auto}}table{{border-collapse:collapse}}th,td{{border:1px solid #bbb;padding:8px}}</style><h1>Blind pairwise comparison</h1><p>Each pair was judged in A/B and B/A order. Target identities were not disclosed.</p><table><tr><th>Baseline wins</th><th>Candidate wins</th><th>Ties</th><th>Invalid</th><th>Errors</th></tr><tr><td>{counts["baseline"]}</td><td>{counts["candidate"]}</td><td>{counts["tie"]}</td><td>{counts["invalid"]}</td><td>{counts["error"]}</td></tr></table><p>Candidate score: {metrics["candidate_score"]:.4f}. Invalid order disagreements and errors are not wins or losses.</p></html>\n',
    )
    write_bundle(output_dir, signing_key_env=signing_key_env)
    verification = verify_bundle(output_dir, signing_key_env=signing_key_env, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("pairwise bundle verification failed")
    return manifest
