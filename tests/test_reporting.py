from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from cavada_eval.reporting import _pdf, generate_reports


def _manifest() -> dict[str, Any]:
    return {
        "protocol_version": "1.0.0",
        "run_id": "run-report-test",
        "status": "failed",
        "suite": {"name": "report-test", "version": "1.0.0"},
        "target": {"label": "target-under-test", "revision": "a" * 40},
        "reproduction_command": "cavada-eval run --endpoint https://private.invalid/v1 --target-key-env PRIVATE_KEY",
        "public_reproduction_command": "cavada-eval verify-public public-bundle",
    }


def _distribution(count: int = 0, value: float = 0.0) -> dict[str, Any]:
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
    }


def _category(name: str, passed: int, failed: int, lower: float, upper: float) -> dict[str, Any]:
    total = passed + failed
    rate = passed / total if total else 0.0
    return {
        "category": name,
        "total": total,
        "observations": total,
        "pass": passed,
        "fail": failed,
        "invalid": 0,
        "error": 0,
        "skipped": 0,
        "pass_rate": rate,
        "pass_rate_ci": {"lower": lower, "upper": upper, "confidence": 0.95},
        "pass_rate_ci95": {"lower": lower, "upper": upper},
        "ci95_lower": lower,
        "ci95_upper": upper,
        "confidence": 0.95,
    }


def _metrics(categories: list[dict[str, Any]], *, aggregate_scope: str) -> dict[str, Any]:
    totals = {name: sum(int(row[name]) for row in categories) for name in ("total", "observations", "pass", "fail", "invalid", "error", "skipped")}
    judged = totals["pass"] + totals["fail"]
    return {
        **totals,
        "pass_rate": totals["pass"] / judged if judged else 0.0,
        "pass_rate_ci": {"lower": 0.30001234, "upper": 0.94998766, "confidence": 0.95},
        "analysis_unit": "case",
        "evaluation_cases": totals["total"],
        "target_observations": totals["observations"],
        "aggregate_scope": aggregate_scope,
        "constructs": [row["category"] for row in categories],
        "gate_failures": [],
        "performance": {"target_latency_ms": _distribution()},
        "stability": {"case_pass_fraction": _distribution(), "judge_agreement": _distribution(), "stable_case_fraction": 0.0},
        "judge_calibration": {},
        "slices": {},
        "slice_disparities": {},
    }


def test_multi_construct_reports_are_category_first_public_and_data_backed(tmp_path: Path) -> None:
    categories = [
        _category("Accuracy", 2, 0, 0.34237195, 1.0),
        _category("Safety", 1, 1, 0.09453121, 0.90546879),
    ]
    metrics = _metrics(categories, aggregate_scope="not-applicable")
    metrics["gate_failures"] = [{"category": "Safety", "metric": "pass_rate_ci.lower", "minimum": 0.2, "actual": 0.09453121}]
    (tmp_path / "suite_snapshot.toml").write_text(
        """[statistics]
confidence = 0.95

[[gates]]
category = "Accuracy"
metric = "pass_rate_ci.lower"
min = 0.3

[[gates]]
category = "Safety"
metric = "pass_rate_ci.lower"
min = 0.2
""",
        encoding="utf-8",
    )
    rows = [
        {"case_id": "a", "repetition": 1, "category": "Accuracy", "severity": "low", "status": "pass"},
        {"case_id": "b", "repetition": 1, "category": "Accuracy", "severity": "low", "status": "pass"},
        {"case_id": "c", "repetition": 1, "category": "Safety", "severity": "high", "status": "pass"},
        {"case_id": "d", "repetition": 1, "category": "Safety", "severity": "high", "status": "fail", "reason": "unsafe answer"},
    ]

    names = generate_reports(tmp_path, _manifest(), metrics, categories, rows)

    public_html = (tmp_path / "report_public.html").read_text(encoding="utf-8")
    assert "cavada-eval verify-public public-bundle" in public_html
    assert "private.invalid" not in public_html and "PRIVATE_KEY" not in public_html
    assert public_html.index("Results by construct") < public_html.index("Run evidence")
    assert "Overall result" not in public_html and "Overall pass rate" not in public_html
    assert "No suite-wide pass rate or headline score combines them" in public_html
    assert "100.0%" in public_html and "34.2%" in public_html and "34.237195" not in public_html
    assert "Safety</th>" in public_html and "Failed</td>" in public_html
    assert "<main id=\"main\">" in public_html and "scope=\"col\"" in public_html and "<caption>" in public_html
    assert "<script" not in public_html and "img-src data:" in public_html
    assert "data:image/svg+xml;base64," in public_html

    assert not (tmp_path / "figures/overall_scores.svg").exists()
    assert not (tmp_path / "figures/latency.svg").exists()
    assert not (tmp_path / "figures/latency_cdf.svg").exists()
    assert "figures/overall_scores.svg" not in names
    assert "figures/category_scores.svg" in names

    public_pdf = (tmp_path / "report_public.pdf").read_bytes()
    assert b"cavada-eval verify-public public-bundle" in public_pdf
    assert b"private.invalid" not in public_pdf and b"PRIVATE_KEY" not in public_pdf
    assert b"Results by construct" in public_pdf and b"Gate decisions" in public_pdf and b"Limitations" in public_pdf
    assert b"Page 1 of" in public_pdf

    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["gates"] == [
        {"category": "Accuracy", "metric": "pass_rate_ci.lower", "min": 0.3, "confidence": 0.95},
        {"category": "Safety", "metric": "pass_rate_ci.lower", "min": 0.2, "confidence": 0.95},
    ]


def test_single_construct_explains_lower_bound_gate_at_perfect_point_rate(tmp_path: Path) -> None:
    categories = [_category("Quality", 1, 0, 0.20654931, 1.0)]
    metrics = _metrics(categories, aggregate_scope="single-construct")
    metrics["pass_rate_ci"] = {"lower": 0.20654931, "upper": 1.0, "confidence": 0.95}
    metrics["gate_failures"] = [{"category": "overall", "metric": "pass_rate_ci.lower", "minimum": 0.8, "actual": 0.20654931}]
    metrics["performance"]["target_latency_ms"] = _distribution(1, 10.0)
    (tmp_path / "suite_snapshot.toml").write_text(
        """[[gates]]
metric = "pass_rate_ci.lower"
min = 0.8
""",
        encoding="utf-8",
    )

    generate_reports(
        tmp_path,
        _manifest(),
        metrics,
        categories,
        [{"case_id": "one", "repetition": 1, "category": "Quality", "severity": "low", "status": "pass", "target_latency_ms": 10.0}],
    )

    report = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "Observed pass rate: 100.0%" in report
    assert "95.0% Wilson interval: 20.7%-100.0%" in report
    assert "confidence-interval lower bound, not the observed point estimate" in report
    assert "80.0%</td><td>20.7%</td><td>Failed" in report
    assert (tmp_path / "figures/overall_scores.svg").is_file()
    assert (tmp_path / "figures/latency.svg").is_file()
    assert not (tmp_path / "figures/latency_cdf.svg").exists()


def test_junit_identifies_repetitions_and_separates_all_outcomes(tmp_path: Path) -> None:
    categories = [_category("Quality", 1, 1, 0.1, 0.9)]
    metrics = _metrics(categories, aggregate_scope="single-construct")
    rows = [
        {"case_id": "same", "repetition": 1, "category": "Quality", "status": "pass"},
        {"case_id": "same", "repetition": 2, "category": "Quality", "status": "fail", "reason": "assertion failed"},
        {"case_id": "invalid", "repetition": 1, "category": "Quality", "status": "invalid", "reason": 'bad "judge"\x01'},
        {"case_id": "transport", "repetition": 3, "category": "Quality", "status": "error", "reason": "timeout"},
        {"case_id": "later", "repetition": 4, "category": "Quality", "status": "skipped", "reason": "prior abort"},
    ]

    generate_reports(tmp_path, _manifest(), metrics, categories, rows)

    suite = ET.parse(tmp_path / "junit.xml").getroot()  # noqa: S314 - parses only the report generated above
    assert suite.attrib == {"name": "cavada-eval", "tests": "5", "failures": "1", "errors": "2", "skipped": "1"}
    tests = {case.attrib["name"]: case for case in suite.findall("testcase")}
    assert {"same [repetition=1]", "same [repetition=2]"} <= tests.keys()
    assert tests["same [repetition=2]"].find("failure") is not None
    assert tests["invalid [repetition=1]"].find("error").attrib["type"] == "invalid"  # type: ignore[union-attr]
    assert tests["transport [repetition=3]"].find("error").attrib["type"] == "error"  # type: ignore[union-attr]
    assert tests["later [repetition=4]"].find("skipped") is not None


def test_empty_measurements_do_not_create_empty_figures(tmp_path: Path) -> None:
    names = generate_reports(tmp_path, _manifest(), _metrics([], aggregate_scope="single-construct"), [], [])

    assert not any(name.startswith("figures/") for name in names)
    assert list((tmp_path / "figures").iterdir()) == []
    assert "<img" not in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_pdf_keeps_indented_record_details_on_the_same_page(tmp_path: Path) -> None:
    path = tmp_path / "report.pdf"
    _pdf(path, "Grouped rows", [*(f"line {index}" for index in range(52)), "| row |", "  Cell: kept", "  Detail: together"])

    streams = [part.split(b"\nendstream", 1)[0] for part in path.read_bytes().split(b">>\nstream\n")[1:]]
    assert len(streams) == 2
    assert b"| row |" not in streams[0]
    assert all(value in streams[1] for value in (b"| row |", b"Cell: kept", b"Detail: together"))
