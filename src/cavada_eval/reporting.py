from __future__ import annotations

import base64
import html
import os
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

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


def _pdf(path: Path, title: str, lines: list[str]) -> None:
    pages = [lines[index : index + 42] for index in range(0, len(lines), 42)] or [[]]
    objects: list[bytes] = []
    page_ids: list[int] = []

    # Object 1 is catalog, object 2 is pages, object 3 is font.
    objects.extend([b"", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"])
    for page_lines in pages:
        content = ["BT /F1 11 Tf 50 790 Td 14 TL"]
        for index, line in enumerate([title, ""] + page_lines):
            safe = line.encode("latin-1", errors="replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            content.append(f"({safe}) Tj" if index == 0 else f"T* ({safe}) Tj")
        content.append("ET")
        stream = "\n".join(content).encode("latin-1")
        content_id = len(objects) + 1
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
        page_id = len(objects) + 1
        page_ids.append(page_id)
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>".encode())
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{item} 0 R" for item in page_ids)
    objects[1] = f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode()

    data = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for identifier, value in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(f"{identifier} 0 obj\n".encode() + value + b"\nendobj\n")
    xref = len(data)
    data.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        data.extend(f"{offset:010d} 00000 n \n".encode())
    data.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    path.write_bytes(data)
    os.chmod(path, 0o600)


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
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CavadaLabs Evaluation Report</title><style>body{{font:15px system-ui;max-width:1180px;margin:40px auto;padding:0 20px;color:#172033;line-height:1.45}}table{{border-collapse:collapse;width:100%;display:block;overflow:auto}}th,td{{border:1px solid #ccd3df;padding:8px;text-align:left}}th{{background:#eef3f8}}.pass{{color:#08752c}}.fail{{color:#a11616}}code{{background:#eef1f6;padding:2px 5px}}img{{max-width:100%;height:auto}}.notice{{border-left:5px solid #b26a00;padding:10px;background:#fff6df}}@media print{{body{{margin:10mm}}}}</style></head><body>
<h1>CavadaLabs Evaluation Report</h1><p>Report {REPORT_VERSION} · Protocol {html.escape(str(manifest.get("protocol_version")))} · Suite {html.escape(str(manifest.get("suite", {}).get("name")))}@{html.escape(str(manifest.get("suite", {}).get("version")))}</p>
<h2 class="{"pass" if manifest.get("status") == "passed" else "fail"}">{status}</h2>
<p>System under test: <code>{sut}</code>. Distinct cases: {metrics.get("total", 0)}. Observations: {metrics.get("observations", 0)}.</p>
<p>Pass rate: {metrics.get("pass_rate", 0):.3%}; {confidence:.1%} Wilson interval: {interval.get("lower", 0):.3%}–{interval.get("upper", 0):.3%}. Invalid: {metrics.get("invalid", 0)}; errors: {metrics.get("error", 0)}; skipped: {metrics.get("skipped", 0)}.</p>
<p>Target latency p50/p95/p99: {performance.get("p50", 0):.1f}/{performance.get("p95", 0):.1f}/{performance.get("p99", 0):.1f} ms.</p>
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
{failure_section}</body></html>"""


def _data_uri(path: Path) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def generate_reports(
    run_dir: Path,
    manifest: dict[str, Any],
    metrics: dict[str, Any],
    categories: list[dict[str, Any]],
    result_rows: list[dict[str, Any]],
) -> list[str]:
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

    lines = (
        [
            f"Status: {manifest.get('status', 'unknown').upper()}",
            f"Protocol: {manifest.get('protocol_version')}",
            f"Suite: {manifest.get('suite', {}).get('name')}@{manifest.get('suite', {}).get('version')}",
            f"Run: {manifest.get('run_id')}",
            f"Cases: {metrics.get('total', 0)}; observations: {metrics.get('observations', 0)}",
            f"Pass rate: {metrics.get('pass_rate', 0):.4f}",
            f"Confidence interval: {metrics.get('pass_rate_ci', {}).get('lower', 0):.4f} - {metrics.get('pass_rate_ci', {}).get('upper', 0):.4f}",
            "",
            "Categories:",
        ]
        + [f"- {row['category']}: {row['pass_rate']:.4f} ({row['pass']}/{row['pass'] + row['fail']})" for row in categories]
        + (
            [
                "",
                f"Distribution-shift valid pairs: {metrics['distribution_shift']['valid_pairs']}/{metrics['distribution_shift']['declared_pairs']}",
                f"Distribution-shift delta: {metrics['distribution_shift']['comparison']['absolute_delta']:.4f}",
            ]
            if (metrics.get("distribution_shift") or {}).get("comparison")
            else []
        )
        + ["", "Not legal certification or a universal safety guarantee."]
    )
    _pdf(run_dir / "report.pdf", "CavadaLabs Evaluation Report", lines)
    _pdf(run_dir / "report_public.pdf", "CavadaLabs Public Evaluation Report", lines)

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
