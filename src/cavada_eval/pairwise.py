from __future__ import annotations

import json
import os
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .protocol import ProtocolError, Suite, append_jsonl, atomic_json, atomic_text, sha256_file
from .runner import _completion_url, _manifest_endpoint, _post_json, _secure_endpoint
from .statistics import bootstrap_mean_interval


def _rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid {path.name} line {number}") from exc
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _answers(run_dir: Path) -> dict[tuple[str, int], str]:
    answers: dict[tuple[str, int], str] = {}
    for row in _rows(run_dir / "raw_responses.jsonl"):
        raw = row.get("response") or {}
        answer: Any = raw.get("answer") if isinstance(raw, dict) else None
        if answer is None:
            try:
                answer = raw["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError):
                answer = None
        if isinstance(answer, str):
            answers[(str(row.get("case_id")), int(row.get("repetition", 1)))] = answer
    return answers


def _winner(raw: dict[str, Any]) -> tuple[str, str, float]:
    try:
        text = raw["choices"][0]["message"]["content"]
        value = json.loads(text)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise ProtocolError("pairwise judge returned malformed JSON") from exc
    winner = value.get("winner") if isinstance(value, dict) else None
    reason = value.get("reason") if isinstance(value, dict) else None
    confidence = value.get("confidence") if isinstance(value, dict) else None
    if winner not in {"A", "B", "tie"} or not isinstance(reason, str) or not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
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
    if output_dir.exists():
        raise ProtocolError("pairwise output directory already exists")
    if not verify_bundle(baseline_dir)["valid"] or not verify_bundle(candidate_dir)["valid"]:
        raise ProtocolError("pairwise input run bundle verification failed")
    if not _secure_endpoint(judge_endpoint):
        raise ProtocolError("pairwise judging requires HTTPS or a loopback endpoint")
    _manifest_endpoint(judge_endpoint)
    judge_host = urllib.parse.urlparse(judge_endpoint).hostname
    if judge_host not in {"127.0.0.1", "localhost", "::1"} and suite.config.get("data_classification") not in {"public", "synthetic"}:
        raise ProtocolError("non-public pairwise evidence requires a local judge")
    baseline_manifest = json.loads((baseline_dir / "manifest.json").read_text(encoding="utf-8"))
    candidate_manifest = json.loads((candidate_dir / "manifest.json").read_text(encoding="utf-8"))
    for field in ("protocol_version",):
        if baseline_manifest.get(field) != candidate_manifest.get(field):
            raise ProtocolError(f"incompatible {field}")
    for field in ("name", "version", "dataset_sha256", "rubric_sha256"):
        expected = baseline_manifest.get("suite", {}).get(field)
        suite_value = {
            "name": suite.name,
            "version": suite.version,
            "dataset_sha256": sha256_file(suite.dataset_path),
            "rubric_sha256": sha256_file(suite.rubric_path),
        }[field]
        if candidate_manifest.get("suite", {}).get(field) != expected or suite_value != expected:
            raise ProtocolError(f"incompatible suite {field}")
    left = _answers(baseline_dir)
    right = _answers(candidate_dir)
    shared = sorted(set(left) & set(right))
    if not shared:
        raise ProtocolError("runs have no shared raw answers")
    output_dir.mkdir(parents=True, mode=0o700)
    (output_dir / "pairwise_judgments.jsonl").touch(mode=0o600)
    key = os.getenv(judge_key_env, "")
    counts = {"baseline": 0, "candidate": 0, "tie": 0, "invalid": 0}
    valid_scores: list[float] = []
    cases = {str(case["id"]): case for case in suite.cases}
    system = suite.rubric + "\nCompare two anonymous answers. Return strict JSON only: " + '{"winner":"A|B|tie","reason":"concise","confidence":0.0}.'
    for case_id, repetition in shared:
        order_results: list[str] = []
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
            try:
                raw, transport = _post_json(_completion_url(judge_endpoint), payload, key, timeout, request_id=uuid.uuid4().hex)
                reported = str(raw.get("model") or "")
                if reported != expected_judge_model:
                    raise ProtocolError(f"Judge identity mismatch: expected {expected_judge_model!r}, got {reported!r}")
                winner, reason, confidence = _winner(raw)
                mapped = winner if winner == "tie" else ("baseline" if (order == "AB" and winner == "A") or (order == "BA" and winner == "B") else "candidate")
                order_results.append(mapped)
                append_jsonl(
                    output_dir / "pairwise_judgments.jsonl",
                    {
                        "case_id": case_id,
                        "repetition": repetition,
                        "order": order,
                        "winner": mapped,
                        "confidence": confidence,
                        "reason": reason,
                        "reported_judge": reported,
                        "raw": raw,
                        "transport": transport,
                    },
                )
            except ProtocolError as exc:
                append_jsonl(
                    output_dir / "pairwise_judgments.jsonl",
                    {"case_id": case_id, "repetition": repetition, "order": order, "status": "invalid", "error": str(exc)},
                )
                if "identity mismatch" in str(exc).casefold():
                    raise
        if len(order_results) != 2 or order_results[0] != order_results[1]:
            counts["invalid"] += 1
        else:
            counts[order_results[0]] += 1
            valid_scores.append(1.0 if order_results[0] == "candidate" else 0.0 if order_results[0] == "baseline" else 0.5)
    metrics = {
        **counts,
        "total": len(shared),
        "valid": len(valid_scores),
        "candidate_score": sum(valid_scores) / len(valid_scores) if valid_scores else 0.0,
        "candidate_score_ci95": bootstrap_mean_interval(valid_scores, samples=10_000, seed=0) if valid_scores else None,
    }
    manifest = {
        "pairwise_version": "1.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "suite": {"name": suite.name, "version": suite.version},
        "baseline_run": baseline_manifest.get("run_id"),
        "candidate_run": candidate_manifest.get("run_id"),
        "judge": {"model": judge_model, "expected_model": expected_judge_model, "revision": judge_revision},
        "identity_blinded": True,
        "orders": ["AB", "BA"],
        "metrics": metrics,
    }
    atomic_json(output_dir / "metrics.json", metrics)
    atomic_json(output_dir / "manifest.json", manifest)
    atomic_text(
        output_dir / "report.html",
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'"><title>CavadaLabs pairwise comparison</title><style>body{{font:15px system-ui;max-width:900px;margin:40px auto}}table{{border-collapse:collapse}}th,td{{border:1px solid #bbb;padding:8px}}</style><h1>Blind pairwise comparison</h1><p>Each pair was judged in A/B and B/A order. Target identities were not disclosed.</p><table><tr><th>Baseline wins</th><th>Candidate wins</th><th>Ties</th><th>Invalid</th></tr><tr><td>{counts["baseline"]}</td><td>{counts["candidate"]}</td><td>{counts["tie"]}</td><td>{counts["invalid"]}</td></tr></table><p>Candidate score: {metrics["candidate_score"]:.4f}. Invalid order disagreements are not wins or losses.</p></html>\n',
    )
    write_bundle(output_dir, signing_key_env=signing_key_env)
    verification = verify_bundle(output_dir, signing_key_env=signing_key_env, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("pairwise bundle verification failed")
    return manifest
