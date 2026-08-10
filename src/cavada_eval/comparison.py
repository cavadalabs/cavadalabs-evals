from __future__ import annotations

import html
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from shutil import copyfile as _snapshot_copyfile
from tempfile import TemporaryDirectory
from typing import Any

from .artifacts import verify_bundle, write_bundle
from .protocol import ProtocolError, atomic_json, atomic_text, require_mutable_output_root, sha256_file
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
        if not isinstance(value, dict):
            raise ProtocolError(f"invalid {path.name} line {number}: expected an object")
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
    unit = (manifest.get("metrics") or {}).get("analysis_unit")
    if unit not in {"case", "scenario"}:
        raise ProtocolError(f"unsupported comparison analysis unit: {unit}")
    name = "scenario_results.jsonl" if unit == "scenario" else "case_results.jsonl"
    return _jsonl(run_dir / name), str(unit)


def _require_compatible_manifests(baseline: dict[str, Any], candidate: dict[str, Any]) -> None:
    for label, manifest in (("baseline", baseline), ("candidate", candidate)):
        if manifest.get("status") not in {"passed", "failed"}:
            raise ProtocolError(f"comparison requires a finalized behavior run (passed or failed): {label}")
        if not isinstance(manifest.get("official_requested"), bool):
            raise ProtocolError(f"comparison requires {label} to declare official_requested")
    for field in ("protocol_version", "schema_version", "metric_version", "adapter_contract_version"):
        left = baseline.get(field)
        right = candidate.get(field)
        if not isinstance(left, str) or not left or not isinstance(right, str) or not right:
            raise ProtocolError(f"comparison requires both manifests to declare {field}")
        if left != right:
            raise ProtocolError(f"incompatible {field}")

    baseline_suite = baseline.get("suite")
    candidate_suite = candidate.get("suite")
    if not isinstance(baseline_suite, dict) or not isinstance(candidate_suite, dict):
        raise ProtocolError("comparison requires suite evidence in both manifests")
    for field in ("name", "version", "dataset_sha256", "rubric_sha256", "suite_config_sha256"):
        left = baseline_suite.get(field)
        right = candidate_suite.get(field)
        if not isinstance(left, str) or not left or not isinstance(right, str) or not right:
            raise ProtocolError(f"comparison requires both manifests to declare suite {field}")
        if left != right:
            raise ProtocolError(f"incompatible suite {field}")

    baseline_judge = baseline.get("judge")
    candidate_judge = candidate.get("judge")
    if not isinstance(baseline_judge, dict) or not isinstance(candidate_judge, dict):
        raise ProtocolError("comparison requires judge configuration in both manifests")
    judge_fields = (
        "requested_model",
        "expected_reported_model",
        "revision",
        "prompt_sha256",
        "response_schema",
        "temperature",
        "max_tokens",
        "models",
        "consensus",
    )
    for field in judge_fields:
        if field not in baseline_judge or field not in candidate_judge:
            raise ProtocolError(f"comparison requires both manifests to declare judge {field}")
        if baseline_judge[field] != candidate_judge[field]:
            raise ProtocolError(f"incompatible judge {field}")

    baseline_parameters = baseline.get("parameters")
    candidate_parameters = candidate.get("parameters")
    if not isinstance(baseline_parameters, dict) or not isinstance(candidate_parameters, dict):
        raise ProtocolError("comparison requires execution parameters in both manifests")
    required_parameters = (
        "mode",
        "preset",
        "preset_version",
        "repetitions",
        "judge_repetitions",
        "max_cases",
        "selected_cases",
        "case_order_policy",
        "case_order_sha256",
        "cache",
    )
    missing = [field for field in required_parameters if field not in baseline_parameters or field not in candidate_parameters]
    if missing:
        raise ProtocolError(f"comparison requires execution parameters: {', '.join(missing)}")
    ignored_parameters = {"progress_events", "non_inferiority_margin"}
    parameter_names = (set(baseline_parameters) | set(candidate_parameters)) - ignored_parameters
    absent = object()
    mismatched = sorted(
        field for field in parameter_names if baseline_parameters.get(field, absent) != candidate_parameters.get(field, absent)
    )
    if mismatched:
        raise ProtocolError(f"incompatible execution parameters: {', '.join(mismatched)}")
    if baseline.get("official_requested") != candidate.get("official_requested"):
        raise ProtocolError("incompatible official_requested")


def _coverage(
    manifest: dict[str, Any],
    case_rows: list[dict[str, Any]],
    analysis_rows: list[dict[str, Any]],
    unit: str,
) -> tuple[set[str], set[str], dict[str, list[str]]]:
    parameters = manifest["parameters"]
    selected_cases = parameters["selected_cases"]
    repetitions = parameters["repetitions"]
    if not isinstance(selected_cases, int) or isinstance(selected_cases, bool) or selected_cases < 1:
        raise ProtocolError("comparison requires a positive integer selected_cases")
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        raise ProtocolError("comparison requires a positive integer repetitions")

    issues: dict[str, list[str]] = {name: [] for name in ("missing", "invalid", "error", "skipped", "malformed", "extra")}
    repetitions_by_case: dict[str, list[int]] = {}
    scenarios: set[str] = set()
    for number, row in enumerate(case_rows, 1):
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            issues["malformed"].append(f"case_results.jsonl:{number}:case_id")
            continue
        status = row.get("status")
        if status in {"invalid", "error", "skipped"}:
            issues[str(status)].append(case_id)
        elif status not in {"pass", "fail"}:
            issues["malformed"].append(f"{case_id}:status={status!r}")
        repetition = row.get("repetition")
        if not isinstance(repetition, int) or isinstance(repetition, bool):
            issues["malformed"].append(f"{case_id}:repetition={repetition!r}")
        else:
            repetitions_by_case.setdefault(case_id, []).append(repetition)
        if unit == "scenario":
            scenario_id = row.get("scenario_id")
            if not isinstance(scenario_id, str) or not scenario_id:
                issues["malformed"].append(f"{case_id}:scenario_id={scenario_id!r}")
            else:
                scenarios.add(scenario_id)

    case_ids = set(repetitions_by_case)
    missing_case_count = selected_cases - len(case_ids)
    if missing_case_count > 0:
        issues["missing"].append(f"{missing_case_count} unrecorded selected case(s)")
    elif missing_case_count < 0:
        issues["extra"].append(f"{-missing_case_count} case(s) beyond selected_cases")
    expected_repetitions = list(range(1, repetitions + 1))
    for case_id, observed in sorted(repetitions_by_case.items()):
        if sorted(observed) != expected_repetitions:
            issues["missing"].append(f"{case_id}:expected repetitions {expected_repetitions}, found {sorted(observed)}")

    analysis_ids: set[str] = set()
    analysis_counts: dict[str, int] = {}
    for number, row in enumerate(analysis_rows, 1):
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            issues["malformed"].append(f"analysis:{number}:case_id")
            continue
        analysis_ids.add(case_id)
        analysis_counts[case_id] = analysis_counts.get(case_id, 0) + 1
        if not isinstance(row.get("category"), str) or not row["category"]:
            issues["malformed"].append(f"analysis:{case_id}:category")
        status = row.get("status")
        if status in {"invalid", "error", "skipped"}:
            issues[str(status)].append(case_id)
        elif status not in {"pass", "fail"}:
            issues["malformed"].append(f"analysis:{case_id}:status={status!r}")

    expected_analysis_ids = scenarios if unit == "scenario" else case_ids
    issues["missing"].extend(sorted(expected_analysis_ids - analysis_ids))
    issues["extra"].extend(sorted(analysis_ids - expected_analysis_ids))
    expected_observations = 1 if unit == "scenario" else repetitions
    for case_id, count in sorted(analysis_counts.items()):
        if count != expected_observations:
            issues["malformed"].append(f"analysis:{case_id}:expected {expected_observations} row(s), found {count}")
    for values in issues.values():
        values[:] = sorted(set(values))
    return case_ids, analysis_ids, issues


def _require_complete_pairs(
    baseline_manifest: dict[str, Any],
    candidate_manifest: dict[str, Any],
    baseline_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    unit: str,
    baseline_dir: Path,
    candidate_dir: Path,
) -> None:
    baseline_cases, baseline_units, baseline_issues = _coverage(
        baseline_manifest, _jsonl(baseline_dir / "case_results.jsonl"), baseline_rows, unit
    )
    candidate_cases, candidate_units, candidate_issues = _coverage(
        candidate_manifest, _jsonl(candidate_dir / "case_results.jsonl"), candidate_rows, unit
    )
    baseline_issues["missing"].extend(sorted(candidate_cases - baseline_cases))
    candidate_issues["missing"].extend(sorted(baseline_cases - candidate_cases))
    baseline_issues["missing"].extend(sorted(candidate_units - baseline_units))
    candidate_issues["missing"].extend(sorted(baseline_units - candidate_units))
    for issues in (baseline_issues, candidate_issues):
        for values in issues.values():
            values[:] = sorted(set(values))
    if any(baseline_issues.values()) or any(candidate_issues.values()):
        details = json.dumps({"baseline": baseline_issues, "candidate": candidate_issues}, sort_keys=True)
        raise ProtocolError(f"comparison requires identical complete preregistered units: {details}")
    if baseline_cases != candidate_cases or baseline_units != candidate_units:
        raise ProtocolError("comparison requires identical case and analysis-unit identifiers")
    baseline_categories = {str(row["case_id"]): row.get("category") for row in baseline_rows}
    candidate_categories = {str(row["case_id"]): row.get("category") for row in candidate_rows}
    if baseline_categories != candidate_categories:
        raise ProtocolError("comparison requires identical analysis-unit categories")


def _preregistered_non_inferiority_margin(
    baseline: dict[str, Any], candidate: dict[str, Any], requested: float | None
) -> float | None:
    if requested is None:
        return None
    if isinstance(requested, bool) or not 0 <= requested <= 1:
        raise ProtocolError("non-inferiority margin must be from 0 to 1")
    left = baseline["parameters"].get("non_inferiority_margin")
    right = candidate["parameters"].get("non_inferiority_margin")
    if (
        not isinstance(left, (int, float))
        or isinstance(left, bool)
        or not isinstance(right, (int, float))
        or isinstance(right, bool)
        or float(left) != float(right)
        or float(left) != requested
    ):
        raise ProtocolError("non-inferiority margin must be identically preregistered in both run manifests")
    return requested


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
    resolved_output = output_dir.resolve()
    if any(
        resolved_output == run_dir.resolve() or resolved_output.is_relative_to(run_dir.resolve())
        for run_dir in (baseline_dir, candidate_dir)
    ):
        raise ProtocolError("comparison output must be outside the immutable input runs")
    require_mutable_output_root(output_dir)
    if any(run_dir.is_symlink() or not run_dir.is_dir() for run_dir in (baseline_dir, candidate_dir)):
        raise ProtocolError("comparison inputs must be regular run directories")
    with TemporaryDirectory(prefix="cavada-comparison-") as temporary:
        root = Path(temporary)
        baseline_snapshot = root / "baseline"
        candidate_snapshot = root / "candidate"
        shutil.copytree(baseline_dir, baseline_snapshot, symlinks=True, copy_function=_snapshot_copyfile)
        shutil.copytree(candidate_dir, candidate_snapshot, symlinks=True, copy_function=_snapshot_copyfile)
        return _compare_runs_snapshot(
            baseline_snapshot,
            candidate_snapshot,
            output_dir,
            confidence=confidence,
            samples=samples,
            seed=seed,
            non_inferiority_margin=non_inferiority_margin,
        )


def _compare_runs_snapshot(
    baseline_dir: Path,
    candidate_dir: Path,
    output_dir: Path,
    *,
    confidence: float,
    samples: int,
    seed: int,
    non_inferiority_margin: float | None,
) -> dict[str, Any]:
    if not verify_bundle(baseline_dir)["valid"] or not verify_bundle(candidate_dir)["valid"]:
        raise ProtocolError("comparison input run bundle verification failed")
    baseline_bundle_sha256 = sha256_file(baseline_dir / "bundle.json")
    candidate_bundle_sha256 = sha256_file(candidate_dir / "bundle.json")
    try:
        baseline_manifest = json.loads((baseline_dir / "manifest.json").read_text(encoding="utf-8"))
        candidate_manifest = json.loads((candidate_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError("both runs require valid manifest.json") from exc
    if not isinstance(baseline_manifest, dict) or not isinstance(candidate_manifest, dict):
        raise ProtocolError("both runs require manifest objects")
    _require_compatible_manifests(baseline_manifest, candidate_manifest)

    baseline_rows, baseline_unit = _analysis_rows(baseline_dir, baseline_manifest)
    candidate_rows, candidate_unit = _analysis_rows(candidate_dir, candidate_manifest)
    if baseline_unit != candidate_unit:
        raise ProtocolError("incompatible comparison analysis units")
    _require_complete_pairs(
        baseline_manifest,
        candidate_manifest,
        baseline_rows,
        candidate_rows,
        baseline_unit,
        baseline_dir,
        candidate_dir,
    )
    non_inferiority_margin = _preregistered_non_inferiority_margin(
        baseline_manifest, candidate_manifest, non_inferiority_margin
    )
    categories = sorted({str(row.get("category")) for row in baseline_rows + candidate_rows})
    baseline_scope = (baseline_manifest.get("metrics") or {}).get("aggregate_scope")
    candidate_scope = (candidate_manifest.get("metrics") or {}).get("aggregate_scope")
    if baseline_scope not in {"single-construct", "not-applicable"} or candidate_scope != baseline_scope:
        raise ProtocolError("comparison requires identical declared aggregate_scope")
    expected_scope = "single-construct" if len(categories) <= 1 else "not-applicable"
    if baseline_scope != expected_scope:
        raise ProtocolError("comparison aggregate_scope does not match the preserved constructs")
    category_confidence = (
        1 - (1 - confidence) / len(categories) if baseline_scope == "not-applicable" else confidence
    )
    category_results: list[dict[str, Any]] = []
    for category in categories:
        left = _outcomes(baseline_rows, category)
        right = _outcomes(candidate_rows, category)
        if set(left) & set(right):
            comparison = paired_binary_comparison(
                left, right, confidence=category_confidence, samples=samples, seed=seed
            )
            comparison["minimum_detectable_effect_approx"] = 1.96 * (0.5 / float(comparison["cases"])) ** 0.5
            if non_inferiority_margin is not None:
                comparison["non_inferiority"] = {
                    "margin": non_inferiority_margin,
                    "passed": float(comparison["delta_ci"]["lower"]) >= -non_inferiority_margin,
                }
            category_results.append({"category": category, **comparison})
    adjusted = holm_adjust([float(row["mcnemar"]["p_value"]) for row in category_results])
    for row, value in zip(category_results, adjusted, strict=True):
        row["mcnemar"]["holm_adjusted_p_value"] = value

    overall: dict[str, Any] | None = None
    if baseline_scope == "single-construct":
        overall = paired_binary_comparison(
            _outcomes(baseline_rows),
            _outcomes(candidate_rows),
            confidence=confidence,
            samples=samples,
            seed=seed,
        )
        overall["minimum_detectable_effect_approx"] = 1.96 * (0.5 / float(overall["cases"])) ** 0.5
        if non_inferiority_margin is not None:
            overall["non_inferiority"] = category_results[0]["non_inferiority"]

    result: dict[str, Any] = {
        "comparison_version": "2.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "protocol_version": baseline_manifest.get("protocol_version"),
        "suite": baseline_manifest.get("suite"),
        "baseline": {
            "run_id": baseline_manifest.get("run_id"),
            "target": baseline_manifest.get("target"),
            "bundle_sha256": baseline_bundle_sha256,
        },
        "candidate": {
            "run_id": candidate_manifest.get("run_id"),
            "target": candidate_manifest.get("target"),
            "bundle_sha256": candidate_bundle_sha256,
        },
        "parameters": {
            "confidence": confidence,
            "bootstrap_samples": samples,
            "seed": seed,
            "multiple_comparison": "Holm",
            "non_inferiority_margin": non_inferiority_margin,
            "interval_multiplicity": {
                "method": "Bonferroni" if baseline_scope == "not-applicable" else "none",
                "family_confidence": confidence,
                "per_construct_confidence": category_confidence,
                "constructs": len(categories),
            },
        },
        "analysis_unit": baseline_unit,
        "aggregate_scope": baseline_scope,
        "categories": category_results,
        "quality_latency_cost": [
            {
                "name": "baseline",
                "latency_p50_ms": baseline_manifest.get("metrics", {}).get("performance", {}).get("target_latency_ms", {}).get("p50"),
                "estimated_cost": baseline_manifest.get("metrics", {}).get("cost", {}).get("estimated_total"),
                **({"pass_rate": overall["baseline_pass_rate"]} if overall is not None else {}),
            },
            {
                "name": "candidate",
                "latency_p50_ms": candidate_manifest.get("metrics", {}).get("performance", {}).get("target_latency_ms", {}).get("p50"),
                "estimated_cost": candidate_manifest.get("metrics", {}).get("cost", {}).get("estimated_total"),
                **({"pass_rate": overall["candidate_pass_rate"]} if overall is not None else {}),
            },
        ],
        "limitations": [f"paired valid {baseline_unit}s only", "no causal claim", "compatible frozen suite required"],
        **({"overall": overall} if overall is not None else {}),
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    atomic_json(output_dir / "comparison.json", result)
    rows = "".join(
        f"<tr><td>{html.escape(row['category'])}</td><td>{row['cases']}</td><td>{row['baseline_pass_rate']:.4f}</td><td>{row['candidate_pass_rate']:.4f}</td><td>{row['absolute_delta']:.4f}</td><td>{row['mcnemar']['holm_adjusted_p_value']:.4g}</td></tr>"
        for row in category_results
    )
    if overall is not None:
        headline = f'<p>Analysis unit: {baseline_unit}. Units: {overall["cases"]}; delta: {overall["absolute_delta"]:.4f}; 95% bootstrap CI: {overall["delta_ci"]["lower"]:.4f} to {overall["delta_ci"]["upper"]:.4f}; McNemar p: {overall["mcnemar"]["p_value"]:.4g}.</p>'
        tradeoff_header = "<tr><th>Run</th><th>Pass rate</th><th>Latency p50 ms</th><th>Estimated cost</th></tr>"
        tradeoff_rows = "".join(
            f"<tr><td>{html.escape(str(point['name']))}</td><td>{point['pass_rate']:.4f}</td><td>{html.escape(str(point['latency_p50_ms']))}</td><td>{html.escape(str(point['estimated_cost']))}</td></tr>"
            for point in result["quality_latency_cost"]
        )
    else:
        headline = f"<p>Analysis unit: {html.escape(baseline_unit)}. No suite-wide delta combines distinct constructs.</p>"
        tradeoff_header = "<tr><th>Run</th><th>Latency p50 ms</th><th>Estimated cost</th></tr>"
        tradeoff_rows = "".join(
            f"<tr><td>{html.escape(str(point['name']))}</td><td>{html.escape(str(point['latency_p50_ms']))}</td><td>{html.escape(str(point['estimated_cost']))}</td></tr>"
            for point in result["quality_latency_cost"]
        )
    atomic_text(
        output_dir / "comparison.html",
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'"><title>CavadaLabs paired comparison</title><style>body{{font:15px system-ui;max-width:1100px;margin:40px auto}}table{{border-collapse:collapse}}th,td{{border:1px solid #bbb;padding:8px}}</style><h1>Paired run comparison</h1>{headline}<table><tr><th>Category</th><th>Units</th><th>Baseline</th><th>Candidate</th><th>Delta</th><th>Holm p</th></tr>{rows}</table><h2>Quality, latency and cost</h2><table>{tradeoff_header}{tradeoff_rows}</table><p>Only paired valid analysis units are included. This is not a causal or universal claim.</p></html>\n',
    )
    write_bundle(output_dir)
    verification = verify_bundle(output_dir, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("comparison bundle verification failed")
    return result
