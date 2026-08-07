from __future__ import annotations

import base64
import html
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

from .pdf_report import render_pdf, require_pdf_support
from .protocol import REPORT_VERSION, atomic_json, atomic_text


def _bar_svg(title: str, rows: list[tuple[str, float]], path: Path, *, maximum: float = 1.0) -> None:
    width = 900
    row_height = 38
    height = 70 + row_height * max(1, len(rows))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<title id="title">{html.escape(title)}</title>',
        '<desc id="desc">Horizontal bar chart. Exact values are printed beside each bar and in the report table.</desc>',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="20" y="30" font-family="system-ui" font-size="20" font-weight="700">{html.escape(title)}</text>',
    ]
    scale = 580 / maximum if maximum > 0 else 0
    for index, (label, value) in enumerate(rows):
        y = 55 + index * row_height
        parts.append(f'<text x="20" y="{y + 18}" font-family="system-ui" font-size="13">{html.escape(label[:42])}</text>')
        parts.append(f'<rect x="290" y="{y}" width="{max(0, min(580, value * scale)):.2f}" height="22" fill="#1769aa"/>')
        parts.append(f'<text x="880" y="{y + 17}" text-anchor="end" font-family="system-ui" font-size="13">{value:.4f}</text>')
    parts.append("</svg>\n")
    atomic_text(path, "".join(parts))


def _cdf_svg(title: str, values: list[float], path: Path) -> None:
    ordered = sorted(values)
    maximum = max(ordered, default=1.0) or 1.0
    points = " ".join(f"{50 + value / maximum * 800:.2f},{320 - (index + 1) / len(ordered) * 270:.2f}" for index, value in enumerate(ordered))
    atomic_text(
        path,
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="900" height="360" viewBox="0 0 900 360"><title id="title">{html.escape(title)}</title><desc id="desc">Empirical cumulative distribution; exact latency percentiles are provided in the report table.</desc><rect width="100%" height="100%" fill="white"/><line x1="50" y1="320" x2="850" y2="320" stroke="#172033"/><line x1="50" y1="50" x2="50" y2="320" stroke="#172033"/><polyline points="{points}" fill="none" stroke="#1769aa" stroke-width="3"/><text x="450" y="350" text-anchor="middle" font-family="system-ui">Latency ms (max {maximum:.2f})</text><text x="15" y="185" text-anchor="middle" transform="rotate(-90 15 185)" font-family="system-ui">Cumulative fraction</text></svg>\n',
    )


def _html_document(
    manifest: dict[str, Any],
    metrics: dict[str, Any],
    categories: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    public: bool,
    figures: dict[str, str],
) -> str:
    category_rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(row.get(key, '')))}</td>"
            for key in ("category", "total", "pass", "fail", "invalid", "error", "pass_rate", "ci95_lower", "ci95_upper")
        )
        + "</tr>"
        for row in categories
    )
    failure_section = ""
    if not public:
        failure_rows = "".join(
            f"<tr><td>{html.escape(str(row.get('case_id', '')))}</td><td>{html.escape(str(row.get('status', '')))}</td><td>{html.escape(str(row.get('reason', '')))}</td></tr>"
            for row in failures[:200]
        )
        failure_section = f"<h2>Failures and invalid evidence</h2><table><thead><tr><th>Case</th><th>Status</th><th>Reason</th></tr></thead><tbody>{failure_rows}</tbody></table>"
    target = manifest.get("target", {})
    sut = html.escape(str(target.get("label", "redacted") if not public else target.get("label", "system-under-test")))
    status = html.escape(str(manifest.get("status", "unknown")).upper())
    analysis_unit = html.escape(str(metrics.get("analysis_unit", "case")))
    performance = metrics.get("performance", {}).get("target_latency_ms", {})
    interval = metrics.get("pass_rate_ci", {})
    confidence = float(interval.get("confidence", 0.95))
    slice_rows = "".join(
        f"<tr><td>{html.escape(dimension)}</td><td>{html.escape(value)}</td><td>{summary.get('total', 0)}</td><td>{summary.get('pass_rate', 0):.4f}</td><td>{summary.get('invalid', 0)}</td><td>{summary.get('error', 0)}</td></tr>"
        for dimension, values in metrics.get("slices", {}).items()
        for value, summary in values.items()
    )
    gate_rows = "".join(
        f"<tr><td>{html.escape(str(row.get('category')))}</td><td>{html.escape(str(row.get('metric')))}</td><td>{html.escape(str(row.get('minimum')))}</td><td>{html.escape(str(row.get('actual')))}</td></tr>"
        for row in metrics.get("gate_failures", [])
    )
    gate_section = (
        f"<h2>Gate failures</h2><table><thead><tr><th>Scope</th><th>Metric</th><th>Minimum</th><th>Actual</th></tr></thead><tbody>{gate_rows}</tbody></table>"
        if gate_rows
        else "<h2>Gates</h2><p>No declared gate failed.</p>"
    )
    shift = metrics.get("distribution_shift", {})
    shift_comparison = shift.get("comparison") if isinstance(shift, dict) else None
    shift_section = ""
    if isinstance(shift_comparison, dict):
        shift_interval = shift_comparison.get("delta_ci", {})
        shift_section = (
            f'<h2>Distribution-shift pairs</h2><img src="{figures["distribution_shift"]}" '
            'alt="Paired in-distribution and shifted pass rates">'
            f'<p>Valid pairs: {shift.get("valid_pairs", 0)}/{shift.get("declared_pairs", 0)}; '
            f'shift-minus-baseline delta: {float(shift_comparison.get("absolute_delta", 0)):.3%}; '
            f'bootstrap interval: {float(shift_interval.get("lower", 0)):.3%}–'
            f'{float(shift_interval.get("upper", 0)):.3%}; '
            f'invalid pairs: {shift.get("invalid_pairs", 0)}.</p>'
        )
    reproduction = html.escape(str(manifest.get("reproduction_command", "Unavailable; see manifest parameters.")))
    critical = ((metrics.get("slices") or {}).get("severity") or {}).get("critical") or {}
    critical_non_pass = sum(int(critical.get(name, 0)) for name in ("fail", "invalid", "error"))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CavadaLabs Evaluation Report</title><style>body{{font:15px system-ui;max-width:1180px;margin:0 auto;padding:40px 24px;color:#172033;background:#f4f7fb;line-height:1.5}}header,section{{background:white;border:1px solid #dce3ec;border-radius:14px;padding:24px;margin-bottom:20px;box-shadow:0 6px 22px #1720330a}}h1{{margin:6px 0 4px;font-size:30px}}h2{{margin-top:26px}}header h2{{margin:0}}table{{border-collapse:collapse;width:100%;display:block;overflow:auto;font-variant-numeric:tabular-nums}}th,td{{border-bottom:1px solid #ccd3df;padding:8px;text-align:left;white-space:nowrap}}th{{background:#eef3f8}}.pass{{color:#08752c}}.fail{{color:#a11616}}.status{{display:inline-block;border-radius:999px;padding:5px 10px;background:#eef3f8;font-weight:700}}.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px;margin-top:22px}}.kpi{{border:1px solid #dce3ec;border-radius:10px;padding:14px}}.kpi strong{{display:block;font-size:23px}}.muted{{color:#5d697b}}code{{background:#eef1f6;padding:2px 5px;overflow-wrap:anywhere}}img{{max-width:100%;height:auto;display:block}}.notice{{border-left:5px solid #b26a00;padding:12px 16px;background:#fff6df}}@media(max-width:700px){{body{{padding:16px 10px}}}}@media print{{body{{background:white;padding:0}}header,section{{box-shadow:none}}}}</style></head><body>
<header><span class="status {"pass" if manifest.get("status") == "passed" else "fail"}">{status}</span><h1>AI evaluation result</h1><p class="muted">Suite {html.escape(str(manifest.get("suite", {}).get("name")))}@{html.escape(str(manifest.get("suite", {}).get("version")))} · Protocol {html.escape(str(manifest.get("protocol_version")))} · Report {REPORT_VERSION}</p><p>System under test: <code>{sut}</code></p><div class="kpis"><div class="kpi"><span>Pass rate</span><strong>{metrics.get("pass_rate", 0):.1%}</strong><small>{metrics.get("pass", 0)} pass / {metrics.get("fail", 0)} fail</small></div><div class="kpi"><span>{confidence:.0%} interval</span><strong>{interval.get("lower", 0):.1%}–{interval.get("upper", 0):.1%}</strong><small>Wilson interval</small></div><div class="kpi"><span>Independent units</span><strong>{metrics.get("total", 0)}</strong><small>{analysis_unit}</small></div><div class="kpi"><span>Critical non-pass</span><strong>{critical_non_pass}</strong><small>fail + invalid + error</small></div><div class="kpi"><span>Gate failures</span><strong>{len(metrics.get("gate_failures", []))}</strong><small>declared gates</small></div><div class="kpi"><span>Latency p95</span><strong>{performance.get("p95", 0):.1f} ms</strong><small>target response</small></div></div></header><section>
<div class="notice"><strong>Scope:</strong> This report is protocol evidence, not legal certification, universal correctness, or a universal safety guarantee.</div>
<h2>Overall and category results</h2><img src="{figures["overall"]}" alt="Overall pass-rate bar chart"><img src="{figures["category"]}" alt="Pass rate by category bar chart">
<table><thead><tr><th>Category</th><th>Total</th><th>Pass</th><th>Fail</th><th>Invalid</th><th>Error</th><th>Pass rate</th><th>CI95 lower</th><th>CI95 upper</th></tr></thead><tbody>{category_rows}</tbody></table>
	<h2>Status distribution</h2><img src="{figures["status"]}" alt="Pass, fail, invalid, error, and skipped counts">
	<h2>Failure severity</h2><img src="{figures["failure_severity"]}" alt="Non-pass cases grouped by severity">
	<h2>Performance</h2><img src="{figures["latency"]}" alt="Target latency percentile chart"><img src="{figures["latency_cdf"]}" alt="Target latency cumulative distribution">
	<h2>Stability, judge agreement and calibration</h2><img src="{figures["stability"]}" alt="Stability and judge agreement values"><img src="{figures["calibration"]}" alt="Judge calibration accuracy by judge">
	<h2>Slice disparity</h2><img src="{figures["disparity"]}" alt="Maximum pass-rate disparity by slice dimension">
{shift_section}
<h2>Result slices</h2><table><thead><tr><th>Dimension</th><th>Value</th><th>Cases</th><th>Pass rate</th><th>Invalid</th><th>Error</th></tr></thead><tbody>{slice_rows}</tbody></table>
{gate_section}
<h2>Methodology</h2><p>Cases were validated before execution. Deterministic hard checks ran before LLM judges. Repetitions were aggregated at distinct-case level. Invalid, error, and skipped cases were excluded from pass-rate denominators and remain visible.</p>
<h2>Limitations</h2><p>Finite test data cannot cover future inputs. Judge models may be biased or wrong. Public datasets may be contaminated. Confidence intervals characterize the sampled cases, not every possible use.</p>
<h2>Reproduction</h2><pre><code>{reproduction}</code></pre>
{failure_section}</section></body></html>"""


def _data_uri(path: Path) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def _evaluation_pdf(
    path: Path,
    manifest: dict[str, Any],
    metrics: dict[str, Any],
    categories: list[dict[str, Any]],
    result_rows: list[dict[str, Any]],
    *,
    public: bool,
) -> None:
    interval = metrics.get("pass_rate_ci") or {}
    performance = (metrics.get("performance") or {}).get("target_latency_ms") or {}
    failures = [row for row in result_rows if row.get("status") != "pass"]
    target = manifest.get("target") or {}
    suite = manifest.get("suite") or {}
    total = int(metrics.get("total", 0))
    confidence = float(interval.get("confidence", 0.95))
    status = str(manifest.get("status", "unknown"))
    target_label = "system-under-test" if public else str(target.get("label", "redacted"))
    gate_failures = metrics.get("gate_failures") or []
    critical = ((metrics.get("slices") or {}).get("severity") or {}).get("critical") or {}
    critical_non_pass = sum(int(critical.get(name, 0)) for name in ("fail", "invalid", "error"))
    category_rows = [
        [
            row.get("category", ""),
            row.get("total", 0),
            row.get("pass", 0),
            row.get("fail", 0),
            row.get("invalid", 0),
            row.get("error", 0),
            f"{float(row.get('pass_rate', 0)):.1%}",
            f"{float(row.get('ci95_lower', 0)):.1%} - {float(row.get('ci95_upper', 0)):.1%}",
        ]
        for row in categories
    ]
    slice_rows = [
        [dimension, value, summary.get("total", 0), f"{float(summary.get('pass_rate', 0)):.1%}", summary.get("invalid", 0), summary.get("error", 0)]
        for dimension, values in (metrics.get("slices") or {}).items()
        for value, summary in values.items()
    ]
    sections: list[dict[str, Any]] = [
        {
            "title": "Executive interpretation",
            "paragraphs": [
                f"The evaluated system finished with status {status.upper()}. The pass rate is {float(metrics.get('pass_rate', 0)):.1%} across {total} independent {metrics.get('analysis_unit', 'case')} units.",
                "A passing protocol gate is evidence only for the declared suite, model revision, configuration, and sampled cases. It is not universal correctness, safety, compliance, or legal certification.",
            ],
            "warning": f"Sample size: {total}. The {confidence:.0%} interval is {float(interval.get('lower', 0)):.1%} to {float(interval.get('upper', 0)):.1%}; conclusions outside the sampled scope require additional evidence.",
            "key_values": [
                ("System under test", target_label),
                ("Suite", f"{suite.get('name', 'unknown')}@{suite.get('version', 'unknown')}"),
                ("Analysis unit", metrics.get("analysis_unit", "case")),
                ("Evaluation cases", metrics.get("evaluation_cases", total)),
                ("Target observations", metrics.get("target_observations", metrics.get("observations", 0))),
                ("Run mode", manifest.get("mode", "candidate")),
            ],
        },
        {
            "title": "Category results",
            "table": {
                "headers": ["Category", "N", "Pass", "Fail", "Invalid", "Error", "Rate", "95% interval"],
                "rows": category_rows,
                "widths": [47, 12, 14, 14, 15, 14, 18, 45],
            },
            "charts": [
                {
                    "title": "Pass rate by category",
                    "rows": [(str(row.get("category", "unknown")), 100 * float(row.get("pass_rate", 0))) for row in categories],
                    "unit": "%",
                },
                {
                    "title": "Case status distribution",
                    "rows": [(name.title(), float(metrics.get(name, 0))) for name in ("pass", "fail", "invalid", "error", "skipped")],
                    "unit": "cases",
                },
            ],
        },
        {
            "title": "Gates and slices",
            "paragraphs": ["No declared gate failed." if not gate_failures else f"{len(gate_failures)} declared gate(s) failed."],
            "table": {
                "headers": ["Scope", "Metric", "Minimum", "Actual"],
                "rows": [[row.get("category"), row.get("metric"), row.get("minimum"), row.get("actual")] for row in gate_failures] or [["All", "Declared gates", "-", "No failures"]],
                "widths": [50, 50, 35, 44],
            },
        },
    ]
    if slice_rows:
        sections.append(
            {
                "title": "Result slices",
                "table": {"headers": ["Dimension", "Value", "Cases", "Pass rate", "Invalid", "Error"], "rows": slice_rows, "widths": [35, 55, 20, 29, 20, 20]},
            }
        )
    sections.extend(
        [
            {
                "title": "Methodology and limitations",
                "paragraphs": [
                    "The suite was validated before execution. Deterministic hard checks ran before LLM judges. Repetitions were aggregated at distinct-case level; invalid, error, and skipped evidence remains separate from pass-rate denominators.",
                    "Finite datasets cannot cover future inputs. Judge models may be biased or wrong, public data may be contaminated, and confidence intervals characterize sampled cases rather than every deployment condition.",
                ],
                "key_values": [
                    ("Protocol", manifest.get("protocol_version", "unknown")),
                    ("Report version", REPORT_VERSION),
                    ("Latency p50 / p95 / p99", f"{float(performance.get('p50', 0)):.1f} / {float(performance.get('p95', 0)):.1f} / {float(performance.get('p99', 0)):.1f} ms"),
                    ("Reproduction", "Restricted in public report" if public else manifest.get("reproduction_command", "See manifest parameters")),
                ],
            }
        ]
    )
    if failures and not public:
        sections.append(
            {
                "title": "Failure and invalid evidence",
                "page_break": True,
                "warning": f"{len(failures)} non-pass result(s) are preserved. Review these rows before making any release decision.",
                "table": {
                    "headers": ["Case", "Status", "Severity", "Reason"],
                    "rows": [[row.get("case_id", ""), row.get("status", ""), row.get("severity", "missing"), row.get("reason", "No reason recorded")] for row in failures[:200]],
                    "widths": [38, 22, 24, 95],
                },
            }
        )
    metadata = {
        "Run ID": str(manifest.get("run_id", "unknown")),
        "Status": status,
        "Protocol": str(manifest.get("protocol_version", "unknown")),
        "Suite": f"{suite.get('name', 'unknown')}@{suite.get('version', 'unknown')}",
        "Target revision": "restricted" if public else str(target.get("revision", "unknown")),
        "Started": str(manifest.get("started_at", "unknown")),
        "Finished": str(manifest.get("finished_at", "unknown")),
    }
    render_pdf(
        path,
        title="Public AI Evaluation Report" if public else "AI Evaluation Report",
        subtitle=f"{suite.get('name', 'unknown')}@{suite.get('version', 'unknown')} / {target_label}",
        status=status,
        report_id=str(manifest.get("run_id", "unknown")),
        classification="PUBLIC" if public else str(manifest.get("data_classification", "RESTRICTED")),
        scope="Protocol evidence for the declared suite and system revision; not legal certification or a universal safety guarantee.",
        kpis=[
            ("Pass rate", f"{float(metrics.get('pass_rate', 0)):.1%}", f"{metrics.get('pass', 0)} pass / {metrics.get('fail', 0)} fail"),
            (f"{confidence:.0%} interval", f"{float(interval.get('lower', 0)):.1%} - {float(interval.get('upper', 0)):.1%}", "Wilson interval"),
            ("Independent units", f"{total:,}", str(metrics.get("analysis_unit", "case"))),
            ("Invalid + errors", f"{int(metrics.get('invalid', 0)) + int(metrics.get('error', 0)):,}", "reported separately"),
            ("Gate failures", f"{len(gate_failures):,}", "declared protocol gates"),
            ("Critical non-pass", f"{critical_non_pass:,}", "fail + invalid + error"),
        ],
        sections=sections,
        metadata=metadata,
    )


def generate_reports(
    run_dir: Path,
    manifest: dict[str, Any],
    metrics: dict[str, Any],
    categories: list[dict[str, Any]],
    result_rows: list[dict[str, Any]],
) -> list[str]:
    require_pdf_support()
    figures = run_dir / "figures"
    figures.mkdir(mode=0o700, exist_ok=True)
    _bar_svg("Overall pass rate", [("Pass rate", float(metrics.get("pass_rate", 0)))], figures / "overall_scores.svg")
    _bar_svg("Pass rate by category", [(str(row["category"]), float(row["pass_rate"])) for row in categories], figures / "category_scores.svg")
    latency = metrics.get("performance", {}).get("target_latency_ms", {})
    latency_rows = [(key.upper(), float(latency.get(key, 0))) for key in ("p50", "p90", "p95", "p99")]
    _bar_svg("Target latency percentiles (ms)", latency_rows, figures / "latency.svg", maximum=max([value for _, value in latency_rows] + [1.0]))
    status_rows = [(name.title(), float(metrics.get(name, 0))) for name in ("pass", "fail", "invalid", "error", "skipped")]
    _bar_svg("Case status distribution", status_rows, figures / "status_distribution.svg", maximum=max([value for _, value in status_rows] + [1.0]))
    stability = metrics.get("stability", {})
    stability_rows = [
        ("Stable case fraction", float(stability.get("stable_case_fraction", 0))),
        ("Mean judge agreement", float((stability.get("judge_agreement") or {}).get("mean", 0))),
    ]
    _bar_svg("Stability and judge agreement", stability_rows, figures / "stability.svg")
    failure_rows = [
        (severity.title(), float(sum(row.get("status") != "pass" and str(row.get("severity", "missing")) == severity for row in result_rows)))
        for severity in ("low", "medium", "high", "critical", "missing")
    ]
    _bar_svg("Non-pass evidence by severity", failure_rows, figures / "failure_severity.svg", maximum=max([value for _, value in failure_rows] + [1.0]))
    _bar_svg(
        "Maximum pass-rate disparity by slice",
        [(str(name), float(value)) for name, value in metrics.get("slice_disparities", {}).items()],
        figures / "slice_disparity.svg",
    )
    calibration_rows = [(str(name), float(value.get("accuracy", 0))) for name, value in metrics.get("judge_calibration", {}).items()]
    _bar_svg("Judge calibration accuracy", calibration_rows, figures / "judge_calibration.svg")
    _cdf_svg(
        "Target latency empirical CDF",
        [float(row["target_latency_ms"]) for row in result_rows if isinstance(row.get("target_latency_ms"), (int, float))],
        figures / "latency_cdf.svg",
    )
    shift_comparison = (metrics.get("distribution_shift") or {}).get("comparison") or {}
    _bar_svg(
        "Paired distribution-shift pass rates",
        [
            ("In-distribution reference", float(shift_comparison.get("baseline_pass_rate", 0))),
            ("Shift probe", float(shift_comparison.get("candidate_pass_rate", 0))),
        ],
        figures / "distribution_shift.svg",
    )

    figure_uris = {
        "overall": _data_uri(figures / "overall_scores.svg"),
        "category": _data_uri(figures / "category_scores.svg"),
        "latency": _data_uri(figures / "latency.svg"),
        "status": _data_uri(figures / "status_distribution.svg"),
        "stability": _data_uri(figures / "stability.svg"),
        "failure_severity": _data_uri(figures / "failure_severity.svg"),
        "disparity": _data_uri(figures / "slice_disparity.svg"),
        "calibration": _data_uri(figures / "judge_calibration.svg"),
        "latency_cdf": _data_uri(figures / "latency_cdf.svg"),
        "distribution_shift": _data_uri(figures / "distribution_shift.svg"),
    }

    failures = [row for row in result_rows if row.get("status") != "pass"]
    atomic_text(run_dir / "report.html", _html_document(manifest, metrics, categories, failures, public=False, figures=figure_uris))
    atomic_text(run_dir / "report_public.html", _html_document(manifest, metrics, categories, [], public=True, figures=figure_uris))
    summary = {
        "protocol_version": manifest.get("protocol_version"),
        "report_version": REPORT_VERSION,
        "run_id": manifest.get("run_id"),
        "status": manifest.get("status"),
        "suite": manifest.get("suite"),
        "target": {"label": manifest.get("target", {}).get("label"), "revision": manifest.get("target", {}).get("revision")},
        "metrics": metrics,
        "categories": categories,
        "limitations": ["finite sampled scope", "judge uncertainty", "possible benchmark contamination"],
    }
    atomic_json(run_dir / "summary.json", summary)

    _evaluation_pdf(run_dir / "report.pdf", manifest, metrics, categories, result_rows, public=False)
    _evaluation_pdf(run_dir / "report_public.pdf", manifest, metrics, categories, result_rows, public=True)

    tests = []
    for row in result_rows:
        name = xml_escape(str(row.get("case_id", "unknown")))
        if row.get("status") == "pass":
            tests.append(f'<testcase classname="cavada-eval" name="{name}"/>')
        elif row.get("status") == "fail":
            tests.append(f'<testcase classname="cavada-eval" name="{name}"><failure message="{xml_escape(str(row.get("reason", "failed")))}"/></testcase>')
        else:
            tests.append(
                f'<testcase classname="cavada-eval" name="{name}"><error message="{xml_escape(str(row.get("reason", row.get("status", "invalid"))))}"/></testcase>'
            )
    atomic_text(
        run_dir / "junit.xml", f'<?xml version="1.0" encoding="UTF-8"?><testsuite name="cavada-eval" tests="{len(tests)}">{"".join(tests)}</testsuite>\n'
    )
    return [
        "report.html",
        "report_public.html",
        "report.pdf",
        "report_public.pdf",
        "summary.json",
        "junit.xml",
        "figures/overall_scores.svg",
        "figures/category_scores.svg",
        "figures/latency.svg",
        "figures/status_distribution.svg",
        "figures/stability.svg",
        "figures/failure_severity.svg",
        "figures/slice_disparity.svg",
        "figures/judge_calibration.svg",
        "figures/latency_cdf.svg",
        "figures/distribution_shift.svg",
    ]
