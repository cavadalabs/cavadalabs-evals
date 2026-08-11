from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from cavada_eval.performance import PERFORMANCE_PROTOCOL_VERSION, PERFORMANCE_REPORT_VERSION, _campaign_summary, _line_svg, _performance_reports


def _distribution(value: float, *, count: int = 1, samples: int = 200) -> dict[str, Any]:
    return {
        "count": count,
        "min": value,
        "max": value,
        "mean": value,
        "median": value,
        "stdev": 0.0,
        "p50": value,
        "p90": value,
        "p95": value,
        "p99": value,
        "p95_ci": {"lower": value * 0.9, "upper": value * 1.1, "confidence": 0.95, "samples": samples, "seed": 1},
        "p99_ci": {"lower": value * 0.8, "upper": value * 1.2, "confidence": 0.95, "samples": samples, "seed": 2},
    }


def _cell(*, cell_key: str, concurrency: int, successes: int, errors: int) -> dict[str, Any]:
    available = successes > 0
    value = 10.0 if available else 0.0
    return {
        "block": 1,
        "cell_key": cell_key,
        "scenario_id": "closed-load",
        "arrival": "closed-loop",
        "context_tokens": 128,
        "output_tokens": 64,
        "concurrency": concurrency,
        "request_rate": None,
        "status": "completed" if not errors else "completed-with-errors",
        "observations": successes + errors,
        "successes": successes,
        "errors": errors,
        "error_types": {"timeout": errors} if errors else {},
        "error_rate": errors / (successes + errors),
        "slo_passed": available and not errors,
        "goodput_requests_per_second": 0.5 if available else 0.0,
        "requests_per_second": 1.0 if available else 0.0,
        "input_tokens_per_second": 128.0 if available else 0.0,
        "output_tokens_per_second": 64.0 if available else 0.0,
        "estimated_cost": None,
        "ttft_ms": _distribution(value, count=successes),
        "e2e_ms": _distribution(value * 2, count=successes),
        "tpot_ms": _distribution(value / 2, count=successes),
        "p99_resolution": {"successful_observations": successes, "minimum": 2, "resolved": successes >= 2},
        "warnings": [f"p99 gate unresolved: {successes} successful observations; 2 required"],
    }


def _v2_manifest(*, run_id: str, status: str, cells: dict[str, int]) -> dict[str, Any]:
    return {
        "performance_protocol_version": PERFORMANCE_PROTOCOL_VERSION,
        "report_version": PERFORMANCE_REPORT_VERSION,
        "run_id": run_id,
        "status": status,
        "officially_valid": False,
        "finished_at": "2026-08-10T12:00:00+00:00",
        "plan": {"name": "test-v2", "revision": "2.0.0", "sha256": "a" * 64},
        "workload": {"id": "test-workload", "revision": "2.0.0", "sha256": "b" * 64},
        "runtime": {
            "id": "runtime-a",
            "engine": "test-engine",
            "model_revision": "c" * 40,
            "gpu_count": 1,
            "gpu_model": "test-gpu",
            "dtype": "fp16",
            "quantization": "none",
            "pricing": None,
        },
        "system_evidence": None,
        "cells": cells,
        "warmups": {"total": 0, "successes": 0, "errors": 0},
    }


def test_v2_summary_best_cell_excludes_invalid_and_error_capacity_points() -> None:
    valid = _cell(cell_key="valid", concurrency=1, successes=1, errors=0)
    valid["goodput_requests_per_second"] = 0.1
    errored = {**_cell(cell_key="errored", concurrency=2, successes=1, errors=1), "goodput_requests_per_second": 10.0}
    invalid = {**_cell(cell_key="invalid", concurrency=3, successes=2, errors=0), "status": "invalid-loadgen", "goodput_requests_per_second": 20.0}
    manifest = _v2_manifest(run_id="best-cell-v2", status="invalid-loadgen", cells={"total": 3})
    manifest.update({"token_usage": {}, "estimated_cost": None})

    summary = _campaign_summary(manifest, [valid, errored, invalid], [])

    assert summary["best_goodput_cell"] == valid


def test_line_svg_has_axes_markers_and_does_not_bridge_missing_values(tmp_path: Path) -> None:
    chart = tmp_path / "chart.svg"
    _line_svg(
        "Comparable load family",
        [("block 1", [1.0, math.nan, 3.0, 4.0])],
        chart,
        "Latency (ms)",
        x_labels=["1", "2", "4", "8"],
        x_label="Concurrency (users)",
    )

    svg = chart.read_text(encoding="utf-8")
    assert svg.count('class="x-tick"') == 4
    assert svg.count('class="data-point"') == 3
    assert svg.count('class="data-line"') == 1
    assert "Concurrency (users)" in svg and "Latency (ms)" in svg
    assert "Missing values are omitted and never connected" in svg
    assert "nan" not in svg.casefold() and "inf" not in svg.casefold()

    marker = tmp_path / "marker.svg"
    _line_svg("One point", [("block 1", [2.0])], marker, "Latency (ms)", x_labels=["1"], x_label="Concurrency (users)")
    marker_svg = marker.read_text(encoding="utf-8")
    assert marker_svg.count('class="data-point"') == 1
    assert 'class="data-line"' not in marker_svg


def test_performance_report_preserves_uncertainty_errors_and_na_cells(tmp_path: Path) -> None:
    successful = _cell(cell_key="closed__ctx128__out64__c1", concurrency=1, successes=1, errors=0)
    failed = _cell(cell_key="closed__ctx128__out64__c2", concurrency=2, successes=0, errors=1)
    skipped = {
        "block": 1,
        "cell_key": "open__ctx128__out64__rps1",
        "scenario_id": "open-load",
        "arrival": "open-loop",
        "context_tokens": 128,
        "output_tokens": 64,
        "concurrency": None,
        "request_rate": 1.0,
        "status": "skipped",
        "reason": "context plus requested output exceeds runtime max_context_tokens",
    }
    manifest = {
        "performance_protocol_version": PERFORMANCE_PROTOCOL_VERSION,
        "report_version": PERFORMANCE_REPORT_VERSION,
        "run_id": "run-report-test",
        "status": "completed-with-errors",
        "officially_valid": False,
        "finished_at": "2026-08-07T12:00:00+00:00",
        "plan": {"name": "test-plan", "revision": "2.0.0", "sha256": "a" * 64},
        "workload": {"id": "test-workload", "revision": "2.0.0", "sha256": "b" * 64},
        "runtime": {
            "id": "runtime-a",
            "engine": "test-engine",
            "model_revision": "c" * 40,
            "gpu_count": 1,
            "gpu_model": "test-gpu",
            "dtype": "fp16",
            "quantization": "none",
            "pricing": None,
        },
        "system_evidence": None,
        "cells": {"total": 3, "completed": 1, "with_errors": 1, "invalid_loadgen": 0, "skipped": 1, "slo_passed": 1, "slo_failed": 1},
        "warmups": {"total": 2, "successes": 1, "errors": 1},
    }
    summary = {
        "observations": 2,
        "successes": 1,
        "errors": 1,
        "limitations": ["Client-side measurements include network transport.", "Performance does not establish response quality."],
    }

    _performance_reports(tmp_path, manifest, summary, [successful, failed, skipped])

    report = (tmp_path / "report.html").read_text(encoding="utf-8")
    chart = (tmp_path / "figures" / "ttft.svg").read_text(encoding="utf-8")
    assert "N/A" in report and "closed__ctx128__out64__c2" in report
    assert "9.00–11.00 (95%)" in report and "200" in report
    assert "1/2 · unresolved" in report and "0/2 · unresolved" in report
    assert "p99 gate unresolved" in report
    assert "timeout: 1" in report and "context plus requested output exceeds" in report
    assert "Cell outcome matrix" in report and "Completed, errored, invalid-loadgen, and skipped cells remain distinct" in report
    assert '<main id="main">' in report and "Skip to report content" in report
    assert "<caption>" in report and 'scope="col"' in report and 'scope="row"' in report
    assert "<script" not in report.casefold() and "default-src 'none'" in report
    assert "Plotted points: 1 of 2" in report
    assert chart.count('class="data-point"') == 1 and 'class="data-line"' not in chart
    assert "nan" not in chart.casefold()
    assert (tmp_path / "figures" / "e2e.svg").is_file()
    assert (tmp_path / "figures" / "throughput.svg").is_file()
    assert (tmp_path / "figures" / "goodput.svg").is_file()
    pdf = (tmp_path / "report.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-")
    assert b"TABLE 1. MEASURED CELLS" in pdf and b"LIMITATIONS" in pdf
    assert b"Page 1 of" in pdf and b"CavadaLabs Evaluation Protocol" in pdf


def test_open_loop_report_exposes_invalid_load_generator_evidence(tmp_path: Path) -> None:
    invalid = _cell(cell_key="open__ctx128__out64__rps20", concurrency=1, successes=100, errors=0)
    invalid.update(
        {
            "arrival": "open-loop",
            "concurrency": None,
            "request_rate": 20.0,
            "status": "invalid-loadgen",
            "slo_passed": False,
            "serving_slo_passed": True,
            "goodput_requests": 0,
            "goodput_requests_per_second": 0.0,
            "offered_requests": 100,
            "dispatched_requests": 5,
            "completed_requests": 4,
            "offered_requests_per_second": 20.0,
            "dispatched_requests_per_second": 1.0,
            "completed_requests_per_second": 0.8,
            "dispatch_rate_fidelity": 0.05,
            "measurement_window_seconds": 5.0,
            "throughput_window_seconds": 65.0,
            "client_queue_ms": _distribution(59_950.0, count=100),
            "dispatch_lag_ms": _distribution(60_000.0, count=100),
            "scheduled_ttft_ms": _distribution(60_010.0, count=100),
            "scheduled_e2e_ms": _distribution(60_020.0, count=100),
            "load_generator_valid": False,
            "load_generator_gates": {"dispatch_rate_fidelity": False, "dispatch_lag_p95": False},
            "load_generator_invalid_reasons": [
                "dispatch rate fidelity 0.0500 is below preregistered minimum 0.9800",
                "dispatch lag p95 60000.000 ms exceeds preregistered maximum 100.000 ms",
            ],
        }
    )
    errored = _cell(cell_key="closed__ctx128__out64__c2", concurrency=2, successes=0, errors=1)
    skipped = {
        "block": 1,
        "cell_key": "open__ctx128__out64__rps40",
        "scenario_id": "open-load",
        "arrival": "open-loop",
        "context_tokens": 128,
        "output_tokens": 64,
        "concurrency": None,
        "request_rate": 40.0,
        "status": "skipped",
        "reason": "runtime context limit",
    }
    manifest = _v2_manifest(
        run_id="run-invalid-loadgen-report",
        status="invalid-loadgen",
        cells={
            "total": 3,
            "completed": 0,
            "with_errors": 1,
            "invalid_loadgen": 1,
            "skipped": 1,
            "slo_passed": 0,
            "slo_failed": 2,
        },
    )
    summary = {
        "observations": 101,
        "successes": 100,
        "errors": 1,
        "limitations": ["Invalid load-generator cells are not serving-system measurements."],
    }

    _performance_reports(tmp_path, manifest, summary, [invalid, errored, skipped])

    report = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert all(
        label in report
        for label in (
            "Offered req/s",
            "Dispatched req/s",
            "Completed req/s",
            "Rate fidelity",
            "Client queue p95 ms",
            "Dispatch lag p95 ms",
            "Arrival window s",
            "Throughput window s",
        )
    )
    assert all(value in report for value in ("20.000", "1.000", "0.800", "0.0500", "59,950.00", "60,000.00", "5.000", "65.000"))
    assert "invalid-loadgen" in report.casefold()
    assert "dispatch rate fidelity 0.0500 is below preregistered minimum 0.9800" in report
    assert "dispatch lag p95 60000.000 ms exceeds preregistered maximum 100.000 ms" in report
    assert "timeout: 1" in report and "runtime context limit" in report
    assert "Completed, errored, invalid-loadgen, and skipped cells remain distinct" in report
    assert "Contact SLO" in report and "Final SLO" in report
    assert not list((tmp_path / "figures").glob("*.svg"))
    assert "No valid completed cells are available for serving curves." in report
    pdf = (tmp_path / "report.pdf").read_bytes()
    assert b"arrival window 5.000" in pdf and b"throughput window 65.000 s" in pdf


def test_v2_closed_loop_report_marks_open_loop_fields_na_and_names_denominators(tmp_path: Path) -> None:
    closed = _cell(cell_key="closed__ctx128__out64__c100", concurrency=100, successes=100, errors=0)
    closed.update(
        {
            "serving_slo_passed": True,
            "goodput_requests": 100,
            "measurement_window_seconds": 2.0,
            "throughput_window_seconds": 2.0,
            "offered_requests": None,
            "dispatched_requests": None,
            "completed_requests": None,
            "offered_requests_per_second": None,
            "dispatched_requests_per_second": None,
            "completed_requests_per_second": None,
            "dispatch_rate_fidelity": None,
            "load_generator_valid": None,
            "load_generator_gates": {},
            "load_generator_invalid_reasons": [],
            "client_queue_ms": _distribution(0.0, count=100),
            "dispatch_lag_ms": None,
            "scheduled_ttft_ms": None,
            "scheduled_e2e_ms": None,
            "warnings": [],
        }
    )
    manifest = _v2_manifest(
        run_id="run-closed-loop-report",
        status="completed",
        cells={
            "total": 1,
            "completed": 1,
            "with_errors": 0,
            "invalid_loadgen": 0,
            "skipped": 0,
            "slo_passed": 1,
            "slo_failed": 0,
        },
    )
    manifest.update(
        {
            "publication_version": "2.0.0",
            "release": {"release_id": "release-report-test"},
            "assurance": "approved",
            "official": True,
            "rankable": True,
            "semantic_valid": True,
            "authenticity": "unverified",
        }
    )
    summary = {
        "observations": 100,
        "successes": 100,
        "errors": 0,
        "limitations": ["Client-side serving measurements only."],
    }

    _performance_reports(tmp_path, manifest, summary, [closed])

    report = (tmp_path / "report.html").read_text(encoding="utf-8")
    row = next(part.partition("</tr>")[0] for part in report.split("<tr>") if "closed__ctx128__out64__c100" in part.partition("</tr>")[0])
    columns = [re.sub(r"<[^>]+>", "", value).strip() for value in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.DOTALL)]
    assert columns[5:12] == ["N/A"] * 7
    assert columns[12] == "2.000"
    assert "Arrival window s" in report and "Throughput window s" in report
    assert "N/A means the field is not applicable or its evidence is unavailable" in report
    assert "N/A means no successful observation" not in report
    assert all(value in report for value in ("release-report-test", "approved", "yes / yes", "valid / unverified"))
    pdf = (tmp_path / "report.pdf").read_bytes()
    assert b"offered N/A req/s" in pdf
    assert b"arrival window N/A s" in pdf
    assert b"throughput window 2.000 s" in pdf
    assert b"N/A = NOT APPLICABLE OR UNAVAILABLE" in pdf
    assert b"CavadaLabs Evaluation Protocol - report 2.0.0" in pdf
    assert b"CavadaLabs Evaluation Protocol - report 1.0.0" not in pdf
