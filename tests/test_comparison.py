from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.comparison import compare_runs
from cavada_eval.protocol import ProtocolError, sha256_file


def _manifest(name: str, selected_cases: int, *, margin: float | None = None) -> dict[str, Any]:
    parameters: dict[str, Any] = {
        "mode": "candidate",
        "preset": "reference",
        "preset_version": "1.0.0",
        "repetitions": 2,
        "judge_repetitions": 3,
        "max_cases": 0,
        "selected_cases": selected_cases,
        "timeout_seconds": 90,
        "max_target_calls": 0,
        "max_judge_calls": 0,
        "max_total_tokens": 0,
        "max_elapsed_seconds": 0,
        "max_estimated_cost": 0,
        "non_inferiority_margin": margin,
        "concurrency": 1,
        "requests_per_second": 0,
        "progress_events": False,
        "case_order_policy": "dataset order",
        "case_order_sha256": "e" * 64,
        "cache": {"target": "disabled", "judge": "disabled"},
    }
    return {
        "protocol_version": "1.0.0",
        "schema_version": "1.0.0",
        "report_version": "1.0.0",
        "metric_version": "1.0.0",
        "adapter_contract_version": "1.0.0",
        "run_id": name,
        "status": "passed",
        "official_requested": False,
        "suite": {
            "name": "suite",
            "version": "1.0.0",
            "dataset_sha256": "a" * 64,
            "rubric_sha256": "b" * 64,
            "suite_config_sha256": "c" * 64,
        },
        "target": {"label": name, "expected_reported_model": name, "revision": f"{name}-revision"},
        "judge": {
            "requested_model": "judge",
            "expected_reported_model": "judge-real",
            "revision": "judge-revision",
            "prompt_sha256": "d" * 64,
            "response_schema": "judgment.schema.json@1.0.0",
            "temperature": 0,
            "max_tokens": 600,
            "models": [{"id": "primary", "model": "judge", "expected_model": "judge-real", "revision": "judge-revision"}],
            "consensus": "majority",
        },
        "parameters": parameters,
        "metrics": {"analysis_unit": "case", "aggregate_scope": "single-construct"},
    }


def _run(
    path: Path,
    statuses: dict[str, str],
    *,
    selected_cases: int | None = None,
    margin: float | None = None,
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> Path:
    path.mkdir()
    manifest = _manifest(path.name, selected_cases if selected_cases is not None else len(statuses), margin=margin)
    if mutate is not None:
        mutate(manifest)
    rows = [
        {"case_id": case_id, "category": "quality", "status": status, "repetition": repetition}
        for case_id, status in statuses.items()
        for repetition in (1, 2)
    ]
    (path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (path / "case_results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    write_bundle(path)
    return path


def _set(path: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(manifest: dict[str, Any]) -> None:
        target: dict[str, Any] = manifest
        parts = path.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value

    return mutate


def test_comparison_accepts_only_exact_complete_contract(tmp_path: Path) -> None:
    baseline = _run(tmp_path / "baseline", {"a": "pass", "b": "fail"})
    candidate = _run(tmp_path / "candidate", {"a": "pass", "b": "pass"})

    result = compare_runs(baseline, candidate, tmp_path / "comparison", samples=100)

    assert result["overall"]["cases"] == 2
    assert result["overall"]["absolute_delta"] == 0.5
    assert verify_bundle(tmp_path / "comparison")["valid"] is True


def test_comparison_reads_only_verified_input_snapshots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    baseline = _run(tmp_path / "baseline", {"a": "pass"})
    candidate = _run(tmp_path / "candidate", {"a": "pass"})
    original_bundle_sha256 = sha256_file(baseline / "bundle.json")
    real_verify = verify_bundle
    changed = False

    def verify_then_replace_source(path: Path, **kwargs: Any) -> dict[str, Any]:
        nonlocal changed
        result = real_verify(path, **kwargs)
        if path.name == "baseline" and not changed:
            changed = True
            manifest = json.loads((baseline / "manifest.json").read_text(encoding="utf-8"))
            manifest["run_id"] = "forged-after-verification"
            (baseline / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            write_bundle(baseline)
        return result

    monkeypatch.setattr("cavada_eval.comparison.verify_bundle", verify_then_replace_source)
    result = compare_runs(baseline, candidate, tmp_path / "comparison", samples=100)

    assert result["baseline"]["run_id"] == "baseline"
    assert result["baseline"]["bundle_sha256"] == original_bundle_sha256
    assert json.loads((baseline / "manifest.json").read_text(encoding="utf-8"))["run_id"] == "forged-after-verification"


def test_comparison_rejects_output_inside_input_run(tmp_path: Path) -> None:
    baseline = _run(tmp_path / "baseline", {"a": "pass"})
    candidate = _run(tmp_path / "candidate", {"a": "pass"})

    with pytest.raises(ProtocolError, match="outside the immutable input runs"):
        compare_runs(baseline, candidate, baseline / "comparison", samples=100)
    assert verify_bundle(baseline)["valid"] is True


def test_comparison_rejects_output_inside_any_finalized_bundle(tmp_path: Path) -> None:
    baseline = _run(tmp_path / "baseline", {"a": "pass"})
    candidate = _run(tmp_path / "candidate", {"a": "pass"})
    unrelated = _run(tmp_path / "unrelated", {"a": "pass"})

    with pytest.raises(ProtocolError, match="outside finalized run bundles"):
        compare_runs(baseline, candidate, unrelated / "comparison", samples=100)
    assert verify_bundle(unrelated)["valid"] is True


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("metric_version", "2.0.0", "incompatible metric_version"),
        ("adapter_contract_version", "2.0.0", "incompatible adapter_contract_version"),
        ("suite.suite_config_sha256", "f" * 64, "incompatible suite suite_config_sha256"),
        ("judge.temperature", 0.5, "incompatible judge temperature"),
        ("parameters.timeout_seconds", 30, "incompatible execution parameters: timeout_seconds"),
        ("parameters.case_order_sha256", "f" * 64, "incompatible execution parameters: case_order_sha256"),
        ("parameters.sampling_seed", None, "incompatible execution parameters: sampling_seed"),
    ],
)
def test_comparison_rejects_incompatible_effective_contract(
    tmp_path: Path, field: str, value: Any, message: str
) -> None:
    baseline = _run(tmp_path / "baseline", {"a": "pass"})
    candidate = _run(tmp_path / "candidate", {"a": "pass"}, mutate=_set(field, value))

    with pytest.raises(ProtocolError, match=message):
        compare_runs(baseline, candidate, tmp_path / "comparison", samples=100)
    assert not (tmp_path / "comparison").exists()


def test_comparison_lists_and_rejects_incomplete_or_invalid_units(tmp_path: Path) -> None:
    baseline = _run(tmp_path / "baseline", {"valid": "pass", "bad": "invalid", "broken": "error", "omitted": "skipped"})
    candidate = _run(tmp_path / "candidate", {"valid": "pass"}, selected_cases=4)

    with pytest.raises(ProtocolError) as caught:
        compare_runs(baseline, candidate, tmp_path / "comparison", samples=100)

    message = str(caught.value)
    assert all(value in message for value in ('"missing"', '"invalid": ["bad"]', '"error": ["broken"]', '"skipped": ["omitted"]'))
    assert all(case_id in message for case_id in ("bad", "broken", "omitted"))
    assert not (tmp_path / "comparison").exists()


def test_comparison_rejects_different_analysis_units(tmp_path: Path) -> None:
    baseline = _run(tmp_path / "baseline", {"a": "pass"})
    candidate = _run(tmp_path / "candidate", {"a": "pass"}, mutate=_set("metrics.analysis_unit", "scenario"))
    (candidate / "scenario_results.jsonl").write_text(
        json.dumps({"case_id": "scenario-a", "category": "quality", "status": "pass"}) + "\n",
        encoding="utf-8",
    )
    write_bundle(candidate)

    with pytest.raises(ProtocolError, match="incompatible comparison analysis units"):
        compare_runs(baseline, candidate, tmp_path / "comparison", samples=100)
    assert not (tmp_path / "comparison").exists()


def test_non_inferiority_requires_matching_preregistered_margins(tmp_path: Path) -> None:
    baseline = _run(tmp_path / "baseline", {"a": "pass"})
    candidate = _run(tmp_path / "candidate", {"a": "pass"})
    with pytest.raises(ProtocolError, match="identically preregistered"):
        compare_runs(baseline, candidate, tmp_path / "rejected", samples=100, non_inferiority_margin=0.05)

    registered_baseline = _run(tmp_path / "registered-baseline", {"a": "pass"}, margin=0.05)
    registered_candidate = _run(tmp_path / "registered-candidate", {"a": "pass"}, margin=0.05)
    result = compare_runs(
        registered_baseline,
        registered_candidate,
        tmp_path / "accepted",
        samples=100,
        non_inferiority_margin=0.05,
    )
    assert result["overall"]["non_inferiority"]["margin"] == 0.05


def test_multi_construct_comparison_has_no_combined_delta_or_non_inferiority(tmp_path: Path) -> None:
    baseline = _run(tmp_path / "baseline", {"quality": "pass", "security": "pass"}, margin=0.05)
    candidate = _run(tmp_path / "candidate", {"quality": "pass", "security": "fail"}, margin=0.05)
    for run_dir in (baseline, candidate):
        manifest = json.loads((run_dir / "manifest.json").read_text())
        manifest["metrics"]["aggregate_scope"] = "not-applicable"
        (run_dir / "manifest.json").write_text(json.dumps(manifest))
        rows = [json.loads(line) for line in (run_dir / "case_results.jsonl").read_text().splitlines()]
        for row in rows:
            row["category"] = row["case_id"]
        (run_dir / "case_results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        write_bundle(run_dir)

    result = compare_runs(
        baseline,
        candidate,
        tmp_path / "comparison",
        samples=100,
        non_inferiority_margin=0.05,
    )

    assert result["aggregate_scope"] == "not-applicable" and "overall" not in result
    assert {row["category"] for row in result["categories"]} == {"quality", "security"}
    assert all("non_inferiority" in row for row in result["categories"])
    assert all(row["delta_ci"]["confidence"] == pytest.approx(0.975) for row in result["categories"])
    assert result["parameters"]["interval_multiplicity"] == {
        "method": "Bonferroni",
        "family_confidence": 0.95,
        "per_construct_confidence": pytest.approx(0.975),
        "constructs": 2,
    }
    assert all("pass_rate" not in point for point in result["quality_latency_cost"])
    assert "No suite-wide delta" in (tmp_path / "comparison" / "comparison.html").read_text()
