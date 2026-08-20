from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .behavior_verify import verify_behavior_run
from .protocol import ProtocolError, atomic_json, atomic_text
from .statistics import holm_adjust, paired_binary_comparison


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise ProtocolError(f"missing comparison artifact: {path.name}")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid {path.name} line {number}") from exc
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _outcomes(rows: list[dict[str, Any]], category: str | None = None) -> dict[str, bool]:
    grouped: dict[str, list[str]] = {}
    for row in rows:
        if category is not None and row.get("category") != category:
            continue
        grouped.setdefault(str(row.get("case_id")), []).append(str(row.get("status")))
    result: dict[str, bool] = {}
    for case_id, statuses in grouped.items():
        observed = set(statuses)
        if observed == {"pass"}:
            result[case_id] = True
        elif observed <= {"pass", "fail"}:
            result[case_id] = False
    return result


def _analysis_rows(run_dir: Path, manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    unit = str((manifest.get("metrics") or {}).get("analysis_unit", "case"))
    if unit not in {"case", "scenario"}:
        raise ProtocolError(f"unsupported comparison analysis unit: {unit}")
    name = "scenario_results.jsonl" if unit == "scenario" else "case_results.jsonl"
    return _jsonl(run_dir / name), unit


def compare_runs(
    baseline_dir: Path,
    candidate_dir: Path,
    output_dir: Path,
    *,
    confidence: float = 0.95,
    samples: int = 10_000,
    seed: int = 0,
    non_inferiority_margin: float | None = None,
) -> dict[str, Any]:
    if not verify_behavior_run(baseline_dir)["valid"] or not verify_behavior_run(candidate_dir)["valid"]:
        raise ProtocolError("comparison input run bundle verification failed")
    try:
        baseline_manifest = json.loads((baseline_dir / "manifest.json").read_text(encoding="utf-8"))
        candidate_manifest = json.loads((candidate_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError("both runs require valid manifest.json") from exc
    for field in ("protocol_version", "schema_version"):
        if baseline_manifest.get(field) != candidate_manifest.get(field):
            raise ProtocolError(f"incompatible {field}")
    for field in ("name", "version", "dataset_sha256", "rubric_sha256"):
        if baseline_manifest.get("suite", {}).get(field) != candidate_manifest.get("suite", {}).get(field):
            raise ProtocolError(f"incompatible suite {field}")

    baseline_rows, baseline_unit = _analysis_rows(baseline_dir, baseline_manifest)
    candidate_rows, candidate_unit = _analysis_rows(candidate_dir, candidate_manifest)
    if baseline_unit != candidate_unit:
        raise ProtocolError("incompatible comparison analysis units")
    overall = paired_binary_comparison(
        _outcomes(baseline_rows),
        _outcomes(candidate_rows),
        confidence=confidence,
        samples=samples,
        seed=seed,
    )
    if non_inferiority_margin is not None:
        if not 0 <= non_inferiority_margin <= 1:
            raise ProtocolError("non-inferiority margin must be from 0 to 1")
        overall["non_inferiority"] = {
            "margin": non_inferiority_margin,
            "passed": float(overall["delta_ci"]["lower"]) >= -non_inferiority_margin,
        }
    overall["minimum_detectable_effect_approx"] = 1.96 * (0.5 / float(overall["cases"])) ** 0.5
    categories = sorted({str(row.get("category")) for row in baseline_rows + candidate_rows})
    category_results: list[dict[str, Any]] = []
    for category in categories:
        left = _outcomes(baseline_rows, category)
        right = _outcomes(candidate_rows, category)
        if set(left) & set(right):
            category_results.append({"category": category, **paired_binary_comparison(left, right, confidence=confidence, samples=samples, seed=seed)})
    adjusted = holm_adjust([float(row["mcnemar"]["p_value"]) for row in category_results])
    for row, value in zip(category_results, adjusted, strict=True):
        row["mcnemar"]["holm_adjusted_p_value"] = value

    result = {
        "comparison_version": "1.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "protocol_version": baseline_manifest.get("protocol_version"),
        "suite": baseline_manifest.get("suite"),
        "baseline": {"run_id": baseline_manifest.get("run_id"), "target": baseline_manifest.get("target")},
        "candidate": {"run_id": candidate_manifest.get("run_id"), "target": candidate_manifest.get("target")},
        "parameters": {"confidence": confidence, "bootstrap_samples": samples, "seed": seed, "multiple_comparison": "Holm"},
        "analysis_unit": baseline_unit,
        "overall": overall,
        "categories": category_results,
        "quality_latency_cost": [
            {
                "name": "baseline",
                "pass_rate": overall["baseline_pass_rate"],
                "latency_p50_ms": baseline_manifest.get("metrics", {}).get("performance", {}).get("target_latency_ms", {}).get("p50"),
                "estimated_cost": baseline_manifest.get("metrics", {}).get("cost", {}).get("estimated_total"),
            },
            {
                "name": "candidate",
                "pass_rate": overall["candidate_pass_rate"],
                "latency_p50_ms": candidate_manifest.get("metrics", {}).get("performance", {}).get("target_latency_ms", {}).get("p50"),
                "estimated_cost": candidate_manifest.get("metrics", {}).get("cost", {}).get("estimated_total"),
            },
        ],
        "limitations": [f"paired valid {baseline_unit}s only", "no causal claim", "compatible frozen suite required"],
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    atomic_json(output_dir / "comparison.json", result)
    rows = "".join(
        f"<tr><td>{html.escape(row['category'])}</td><td>{row['cases']}</td><td>{row['baseline_pass_rate']:.4f}</td><td>{row['candidate_pass_rate']:.4f}</td><td>{row['absolute_delta']:.4f}</td><td>{row['mcnemar']['holm_adjusted_p_value']:.4g}</td></tr>"
        for row in category_results
    )
    tradeoff_rows = "".join(
        f"<tr><td>{html.escape(str(point['name']))}</td><td>{point['pass_rate']:.4f}</td><td>{html.escape(str(point['latency_p50_ms']))}</td><td>{html.escape(str(point['estimated_cost']))}</td></tr>"
        for point in result["quality_latency_cost"]
    )
    atomic_text(
        output_dir / "comparison.html",
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'"><title>CavadaLabs paired comparison</title><style>body{{font:15px system-ui;max-width:1100px;margin:40px auto}}table{{border-collapse:collapse}}th,td{{border:1px solid #bbb;padding:8px}}</style><h1>Paired run comparison</h1><p>Analysis unit: {baseline_unit}. Units: {overall["cases"]}; delta: {overall["absolute_delta"]:.4f}; 95% bootstrap CI: {overall["delta_ci"]["lower"]:.4f} to {overall["delta_ci"]["upper"]:.4f}; McNemar p: {overall["mcnemar"]["p_value"]:.4g}.</p><table><tr><th>Category</th><th>Units</th><th>Baseline</th><th>Candidate</th><th>Delta</th><th>Holm p</th></tr>{rows}</table><h2>Quality, latency and cost</h2><table><tr><th>Run</th><th>Pass rate</th><th>Latency p50 ms</th><th>Estimated cost</th></tr>{tradeoff_rows}</table><p>Only paired valid analysis units are included. This is not a causal or universal claim.</p></html>\n',
    )
    write_bundle(output_dir)
    verification = verify_bundle(output_dir, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("comparison bundle verification failed")
    return result
