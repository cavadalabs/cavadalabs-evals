from __future__ import annotations

import base64
import html
import os
import textwrap
import tomllib
from pathlib import Path
from typing import Any
from xml.sax.saxutils import quoteattr

from .protocol import REPORT_VERSION, atomic_json, atomic_text

_LIMITATIONS = (
    "Finite test data cannot cover future inputs or every use context.",
    "Judge models may be biased, inconsistent, or wrong.",
    "Public evaluation data may have been seen during model development.",
    "Confidence intervals describe the sampled analysis units, not universal behavior.",
)


def _as_float(value: Any) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def _percent(value: Any) -> str:
    return f"{_as_float(value):.1%}"


def _interval(row: dict[str, Any]) -> tuple[float, float, float]:
    value = row.get("pass_rate_ci")
    if isinstance(value, dict):
        return _as_float(value.get("lower")), _as_float(value.get("upper")), _as_float(value.get("confidence"))
    return _as_float(row.get("ci95_lower")), _as_float(row.get("ci95_upper")), _as_float(row.get("confidence", 0.95))


def _bar_svg(
    title: str,
    rows: list[tuple[str, float]],
    path: Path,
    *,
    maximum: float = 1.0,
    value_kind: str = "rate",
) -> None:
    width = 900
    row_height = 38
    height = 70 + row_height * len(rows)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<title id="title">{html.escape(title)}</title>',
        '<desc id="desc">Horizontal bar chart. Rounded values are printed beside each bar and in the report table.</desc>',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="20" y="30" font-family="system-ui" font-size="20" font-weight="700">{html.escape(title)}</text>',
    ]
    scale = 580 / maximum if maximum > 0 else 0
    for index, (label, value) in enumerate(rows):
        y = 55 + index * row_height
        shown = f"{value:.1%}" if value_kind == "rate" else f"{value:.1f}" if value_kind == "decimal" else f"{value:.0f}"
        parts.append(f'<text x="20" y="{y + 18}" font-family="system-ui" font-size="13">{html.escape(label[:42])}</text>')
        parts.append(f'<rect x="290" y="{y}" width="{max(0, min(580, value * scale)):.2f}" height="22" fill="#1769aa"/>')
        parts.append(f'<text x="880" y="{y + 17}" text-anchor="end" font-family="system-ui" font-size="13">{shown}</text>')
    parts.append("</svg>\n")
    atomic_text(path, "".join(parts))


def _pdf_escape(value: str) -> str:
    value = value.translate(str.maketrans("–—−‑•·×“”‘’", "----;;x\"\"''"))
    return value.encode("latin-1", errors="replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf(path: Path, title: str, lines: list[str], *, report_version: str = REPORT_VERSION) -> None:
    """Write a dependency-free, paginated text report.

    Lines beginning with ``# `` are section headings, ``## `` are subheadings,
    and ``|`` lines are rendered in a compact monospaced table style.
    """

    groups: list[list[tuple[str, float, float, float, str]]] = []
    for raw in lines:
        if not raw:
            groups.append([("F1", 10, 0, 8, "")])
            continue
        if raw.startswith("# "):
            text, font, size, indent, leading, width = raw[2:], "F2", 13.0, 0.0, 22.0, 72
        elif raw.startswith("## "):
            text, font, size, indent, leading, width = raw[3:], "F2", 11.0, 0.0, 17.0, 86
        elif raw.startswith("|"):
            text, font, size, indent, leading, width = raw, "F3", 7.5, 0.0, 11.0, 108
        elif raw.startswith("- "):
            text, font, size, indent, leading, width = "- " + raw[2:], "F1", 9.5, 12.0, 13.0, 90
        else:
            text, font, size, indent, leading, width = raw, "F1", 9.5, 0.0, 13.0, 94
        wrapped = textwrap.wrap(text, width=width, break_long_words=True, break_on_hyphens=False, subsequent_indent="  ") or [""]
        laid_out = [(font, size, indent, leading, item) for item in wrapped]
        if raw.startswith("  ") and groups:
            groups[-1].extend(laid_out)
        else:
            groups.append(laid_out)

    pages: list[list[tuple[str, float, float, float, str]]] = [[]]
    used = 0.0
    for group in groups:
        height = sum(item[3] for item in group)
        if used + height > 700 and pages[-1]:
            pages.append([])
            used = 0.0
        for item in group:
            if used + item[3] > 700 and pages[-1]:
                pages.append([])
                used = 0.0
            pages[-1].append(item)
            used += item[3]

    objects: list[bytes] = [
        b"",
        b"",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    page_ids: list[int] = []
    page_count = len(pages)
    for page_number, page_lines in enumerate(pages, 1):
        content = [
            "0.12 0.17 0.27 rg",
            f"BT /F2 16 Tf 50 800 Td ({_pdf_escape(title)}) Tj ET",
            "0.76 0.80 0.86 RG 0.6 w 50 783 m 545 783 l S",
            "0.12 0.17 0.27 rg",
        ]
        y = 760.0
        for font, size, indent, leading, line in page_lines:
            if line:
                content.append(f"BT /{font} {size:g} Tf {50 + indent:g} {y:g} Td ({_pdf_escape(line)}) Tj ET")
            y -= leading
        footer = f"CavadaLabs Evaluation Protocol - report {report_version}"
        content.extend(
            [
                "0.76 0.80 0.86 RG 0.6 w 50 48 m 545 48 l S",
                "0.30 0.34 0.42 rg",
                f"BT /F1 8 Tf 50 31 Td ({_pdf_escape(footer)}) Tj ET",
                f"BT /F1 8 Tf 485 31 Td (Page {page_number} of {page_count}) Tj ET",
            ]
        )
        stream = "\n".join(content).encode("latin-1")
        content_id = len(objects) + 1
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
        page_id = len(objects) + 1
        page_ids.append(page_id)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {content_id} 0 R >>".encode()
        )
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
    maximum = max(ordered) or 1.0
    points = " ".join(f"{50 + value / maximum * 800:.2f},{320 - (index + 1) / len(ordered) * 270:.2f}" for index, value in enumerate(ordered))
    atomic_text(
        path,
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="900" height="360" viewBox="0 0 900 360"><title id="title">{html.escape(title)}</title><desc id="desc">Empirical cumulative distribution; rounded latency percentiles are provided in the report table.</desc><rect width="100%" height="100%" fill="white"/><line x1="50" y1="320" x2="850" y2="320" stroke="#172033"/><line x1="50" y1="50" x2="50" y2="320" stroke="#172033"/><polyline points="{points}" fill="none" stroke="#1769aa" stroke-width="3"/><text x="450" y="350" text-anchor="middle" font-family="system-ui">Latency ms (max {maximum:.1f})</text><text x="15" y="185" text-anchor="middle" transform="rotate(-90 15 185)" font-family="system-ui">Cumulative fraction</text></svg>\n',
    )


def _table(caption: str, headers: list[str], rows: list[list[Any]]) -> str:
    headings = "".join(f'<th scope="col">{html.escape(value)}</th>' for value in headers)
    body = "".join(
        "<tr>"
        + "".join(
            f'<th scope="row">{html.escape(str(value))}</th>' if index == 0 else f"<td>{html.escape(str(value))}</td>"
            for index, value in enumerate(row)
        )
        + "</tr>"
        for row in rows
    )
    label = html.escape(caption)
    return f'<div class="table-wrap" role="region" aria-label="{label}" tabindex="0"><table><caption>{label}</caption><thead><tr>{headings}</tr></thead><tbody>{body}</tbody></table></div>'


def _figure(figures: dict[str, str], key: str, alt: str, caption: str) -> str:
    source = figures.get(key)
    if source is None:
        return ""
    return f'<figure><img src="{source}" alt="{html.escape(alt)}"><figcaption>{html.escape(caption)}</figcaption></figure>'


def _metric(source: dict[str, Any], name: str) -> Any:
    value: Any = source
    for part in name.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def _gate_results(run_dir: Path, metrics: dict[str, Any], categories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    config: dict[str, Any] = {}
    try:
        loaded = tomllib.loads((run_dir / "suite_snapshot.toml").read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            config = loaded
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        pass
    statistics = config.get("statistics")
    confidence = _as_float(statistics.get("confidence", 0.95)) if isinstance(statistics, dict) else 0.95
    by_category = {str(row.get("category")): row for row in categories}
    results: list[dict[str, Any]] = []
    configured = config.get("gates")
    if isinstance(configured, list):
        for value in configured:
            if not isinstance(value, dict):
                continue
            category_value = value.get("category")
            category = str(category_value) if category_value is not None else None
            metric = str(value.get("metric", "pass_rate_ci.lower"))
            minimum = value.get("min")
            source = by_category.get(category, {}) if category is not None else metrics
            actual = _metric(source, metric)
            passed = isinstance(actual, (int, float)) and not isinstance(actual, bool) and isinstance(minimum, (int, float)) and float(actual) >= float(minimum)
            results.append(
                {
                    "category": category,
                    "metric": metric,
                    "minimum": minimum,
                    "actual": actual,
                    "confidence": confidence,
                    "status": "passed" if passed else "failed",
                    "declared": True,
                }
            )
    known = {(row["category"] or "overall", row["metric"]) for row in results}
    failures = metrics.get("gate_failures")
    if isinstance(failures, list):
        for value in failures:
            if not isinstance(value, dict):
                continue
            category = str(value.get("category", "overall"))
            metric = str(value.get("metric", "unknown"))
            if (category, metric) in known:
                continue
            results.append(
                {
                    "category": None if category == "overall" else category,
                    "metric": metric,
                    "minimum": value.get("minimum"),
                    "actual": value.get("actual"),
                    "confidence": confidence,
                    "status": "failed",
                    "declared": False,
                }
            )
    return results


def _format_gate_value(value: Any, metric: str) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "Unavailable"
    return _percent(value) if "rate" in metric or "accuracy" in metric else f"{float(value):.2f}"


def _gate_scope(value: Any, *, multi_construct: bool) -> str:
    if value is not None:
        return str(value)
    return "Suite-wide (not a combined construct score)" if multi_construct else "Overall"


def _category_gate_status(category: str, gates: list[dict[str, Any]]) -> str:
    matching = [row for row in gates if row.get("category") == category]
    if any(row.get("status") == "failed" for row in matching):
        return "Failed"
    return "Passed" if matching else "No category gate"


def _html_document(
    manifest: dict[str, Any],
    metrics: dict[str, Any],
    categories: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    public: bool,
    figures: dict[str, str],
    gates: list[dict[str, Any]] | None = None,
) -> str:
    gates = gates or []
    multi_construct = metrics.get("aggregate_scope") == "not-applicable" or len(categories) > 1
    category_rows: list[list[Any]] = []
    for row in categories:
        lower, upper, confidence = _interval(row)
        category = str(row.get("category", ""))
        category_rows.append(
            [
                category,
                row.get("total", 0),
                row.get("pass", 0),
                row.get("fail", 0),
                row.get("invalid", 0),
                row.get("error", 0),
                row.get("skipped", 0),
                _percent(row.get("pass_rate")),
                f"{_percent(confidence)} Wilson: {_percent(lower)}-{_percent(upper)}",
                _category_gate_status(category, gates),
            ]
        )
    category_table = _table(
        "Results by construct",
        ["Construct", "Units", "Pass", "Fail", "Invalid", "Error", "Skipped", "Pass rate", "Confidence interval", "Category gate"],
        category_rows,
    )
    category_result = (
        '<h2 id="results">Results by construct</h2>'
        + (
            '<p class="notice"><strong>Interpretation:</strong> Distinct constructs are reported separately. No suite-wide pass rate or headline score combines them. '
            'Each pass-rate gate uses that construct\'s confidence-interval lower bound; even a 100.0% observed rate can fail a stricter minimum.</p>'
            if multi_construct
            else ""
        )
        + _figure(figures, "category", "Pass rate by construct", "Rounded pass rates; confidence intervals and exact counts are in the adjacent table.")
        + category_table
    )

    interval = metrics.get("pass_rate_ci")
    interval = interval if isinstance(interval, dict) else {}
    confidence = _as_float(interval.get("confidence", 0.95))
    overall = ""
    if not multi_construct:
        overall = (
            '<h2 id="results">Overall result</h2>'
            f'<p><strong>Observed pass rate: {_percent(metrics.get("pass_rate"))}.</strong> '
            f'{_percent(confidence)} Wilson interval: {_percent(interval.get("lower"))}-{_percent(interval.get("upper"))}.</p>'
            '<p class="notice"><strong>Gate rule:</strong> Official pass-rate gates use the confidence-interval lower bound, not the observed point estimate. A 100.0% observed rate can therefore fail a stricter declared minimum.</p>'
            + _figure(figures, "overall", "Overall pass rate", "Rounded observed pass rate; the confidence interval is stated in text.")
        )

    gate_rows = [
        [
            _gate_scope(row.get("category"), multi_construct=multi_construct),
            row.get("metric", ""),
            _format_gate_value(row.get("minimum"), str(row.get("metric", ""))),
            _format_gate_value(row.get("actual"), str(row.get("metric", ""))),
            str(row.get("status", "unknown")).title(),
        ]
        for row in gates
    ]
    if gate_rows:
        gate_section = '<h2>Gate decisions</h2><p>Each decision compares the declared metric with its minimum. Confidence-interval gates use the displayed lower bound.</p>' + _table(
            "Declared gate decisions", ["Scope", "Metric", "Minimum", "Actual", "Decision"], gate_rows
        )
    else:
        gate_section = '<h2>Gate decisions</h2><p>No declared gates were available in the report evidence, and no gate failures were recorded.</p>'

    status_rows = [[name.title(), metrics.get(name, 0)] for name in ("pass", "fail", "invalid", "error", "skipped")]
    status_section = (
        '<h2>Status distribution</h2>'
        + _figure(figures, "status", "Counts of pass, fail, invalid, error, and skipped results", "Statuses remain separate; invalid and error are not model failures.")
        + _table("Analysis-unit status counts", ["Status", "Count"], status_rows)
    )

    performance = metrics.get("performance")
    performance = performance if isinstance(performance, dict) else {}
    latency = performance.get("target_latency_ms")
    latency = latency if isinstance(latency, dict) else {}
    performance_section = ""
    if int(_as_float(latency.get("count"))) > 0:
        performance_section = (
            '<h2>Observed target latency</h2>'
            + _figure(figures, "latency", "Target latency percentiles", "Client-observed target latency percentiles in milliseconds.")
            + _figure(figures, "latency_cdf", "Target latency empirical cumulative distribution", "Empirical distribution of recorded target latencies.")
            + _table(
                "Target latency percentiles (milliseconds)",
                ["Statistic", "Milliseconds"],
                [[key.upper(), f"{_as_float(latency.get(key)):.1f}"] for key in ("p50", "p90", "p95", "p99")],
            )
        )

    stability = metrics.get("stability")
    stability = stability if isinstance(stability, dict) else {}
    case_fraction = stability.get("case_pass_fraction")
    case_fraction = case_fraction if isinstance(case_fraction, dict) else {}
    agreement = stability.get("judge_agreement")
    agreement = agreement if isinstance(agreement, dict) else {}
    stability_rows: list[list[Any]] = []
    if int(_as_float(case_fraction.get("count"))) > 0:
        stability_rows.append(["Stable case fraction", _percent(stability.get("stable_case_fraction"))])
    if int(_as_float(agreement.get("count"))) > 0:
        stability_rows.append(["Mean judge agreement", _percent(agreement.get("mean"))])
    stability_section = ""
    if stability_rows:
        stability_section = (
            '<h2>Stability and judge agreement</h2>'
            + _figure(figures, "stability", "Stability and judge agreement", "Rounded stability and agreement values.")
            + _table("Stability measures", ["Measure", "Value"], stability_rows)
        )

    calibration = metrics.get("judge_calibration")
    calibration = calibration if isinstance(calibration, dict) else {}
    calibration_rows = [
        [name, _percent(value.get("accuracy"))]
        for name, value in calibration.items()
        if isinstance(value, dict) and isinstance(value.get("accuracy"), (int, float))
    ]
    calibration_section = ""
    if calibration_rows:
        calibration_section = (
            '<h2>Judge calibration</h2>'
            + _figure(figures, "calibration", "Judge calibration accuracy by judge", "Rounded calibration accuracy by judge.")
            + _table("Judge calibration accuracy", ["Judge", "Accuracy"], calibration_rows)
        )

    slices = metrics.get("slices")
    slices = slices if isinstance(slices, dict) else {}
    slice_rows = [
        [dimension, value, summary.get("total", 0), _percent(summary.get("pass_rate")), summary.get("invalid", 0), summary.get("error", 0)]
        for dimension, values in slices.items()
        if isinstance(values, dict)
        for value, summary in values.items()
        if isinstance(summary, dict)
    ]
    disparities = metrics.get("slice_disparities")
    disparities = disparities if isinstance(disparities, dict) else {}
    disparity_rows = [[name, _percent(value)] for name, value in disparities.items() if isinstance(slices.get(name), dict) and slices[name]]
    slice_section = ""
    if slice_rows:
        slice_section = (
            '<h2>Result slices</h2>'
            + _figure(figures, "disparity", "Maximum pass-rate disparity by slice dimension", "Descriptive disparity only; it is not a fairness or causal claim.")
            + (_table("Maximum descriptive slice disparities", ["Dimension", "Maximum disparity"], disparity_rows) if disparity_rows else "")
            + _table("Results by descriptive slice", ["Dimension", "Value", "Units", "Pass rate", "Invalid", "Error"], slice_rows)
        )

    severity_rows: list[list[Any]] = []
    for severity in ("low", "medium", "high", "critical", "missing"):
        count = sum(row.get("status") != "pass" and str(row.get("severity", "missing")) == severity for row in failures)
        if count:
            severity_rows.append([severity.title(), count])
    severity_section = ""
    if severity_rows:
        severity_section = (
            '<h2>Non-pass evidence by severity</h2>'
            + _figure(figures, "failure_severity", "Non-pass evidence grouped by severity", "Counts include fail, invalid, error, and skipped evidence.")
            + _table("Non-pass evidence by severity", ["Severity", "Count"], severity_rows)
        )

    shift = metrics.get("distribution_shift")
    shift = shift if isinstance(shift, dict) else {}
    shift_comparison = shift.get("comparison")
    shift_section = ""
    if isinstance(shift_comparison, dict):
        shift_interval = shift_comparison.get("delta_ci")
        shift_interval = shift_interval if isinstance(shift_interval, dict) else {}
        shift_section = (
            '<h2>Distribution-shift pairs</h2>'
            + _figure(figures, "distribution_shift", "Paired in-distribution and shifted pass rates", "Paired descriptive pass rates; this is not a causal claim.")
            + _table(
                "Distribution-shift comparison",
                ["Valid pairs", "Declared pairs", "Shift minus baseline", "Bootstrap interval", "Invalid pairs"],
                [
                    [
                        shift.get("valid_pairs", 0),
                        shift.get("declared_pairs", 0),
                        _percent(shift_comparison.get("absolute_delta")),
                        f'{_percent(shift_interval.get("lower"))}-{_percent(shift_interval.get("upper"))}',
                        shift.get("invalid_pairs", 0),
                    ]
                ],
            )
        )

    failure_section = ""
    if not public and failures:
        failure_rows = [
            [row.get("case_id", ""), row.get("repetition", "n/a"), row.get("status", ""), row.get("reason", "")]
            for row in failures[:200]
        ]
        failure_section = '<h2>Failure, invalid, error, and skipped evidence</h2>' + _table(
            "Non-pass observation evidence (first 200 rows)", ["Case", "Repetition", "Status", "Reason"], failure_rows
        )

    target = manifest.get("target")
    target = target if isinstance(target, dict) else {}
    suite = manifest.get("suite")
    suite = suite if isinstance(suite, dict) else {}
    analysis_unit = str(metrics.get("analysis_unit", "case"))
    reproduction_key = "public_reproduction_command" if public else "reproduction_command"
    reproduction = html.escape(str(manifest.get(reproduction_key, "Unavailable; see manifest parameters.")))
    limitations = "".join(f"<li>{html.escape(value)}</li>" for value in _LIMITATIONS)
    result_section = category_result if multi_construct else overall + category_result.replace(' id="results"', "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CavadaLabs Evaluation Report</title><style>:root{{--ink:#172033;--muted:#536072;--line:#cbd4df;--paper:#fff;--panel:#f4f7fa;--accent:#075ea8}}*{{box-sizing:border-box}}body{{font:15px/1.55 system-ui,sans-serif;max-width:1180px;margin:0 auto;padding:36px 24px;color:var(--ink);background:var(--paper)}}.skip{{position:absolute;left:-9999px}}.skip:focus{{left:16px;top:12px;background:#fff;padding:8px;z-index:1}}header{{border-bottom:2px solid var(--ink);margin-bottom:28px}}.eyebrow{{color:var(--muted)}}h1{{font-size:2rem;margin:.2rem 0 1rem}}h2{{margin-top:2rem}}code,pre{{background:#eef2f6}}code{{padding:2px 5px}}pre{{padding:14px;overflow:auto;border:1px solid var(--line)}}.table-wrap{{overflow:auto;margin:12px 0 24px}}table{{border-collapse:collapse;width:100%}}caption{{font-weight:700;text-align:left;padding:0 0 7px}}th,td{{border:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}thead th{{background:#eaf0f6}}tbody th{{font-weight:600}}figure{{margin:18px 0}}img{{display:block;max-width:100%;height:auto;border:1px solid var(--line)}}figcaption{{color:var(--muted);font-size:.92rem;margin-top:5px}}.notice{{border-left:5px solid #9a5b00;padding:10px 12px;background:#fff5d9}}footer{{border-top:1px solid var(--line);margin-top:36px;padding-top:12px;color:var(--muted)}}@media print{{body{{padding:0}}.skip{{display:none}}pre,.table-wrap{{overflow:visible}}}}</style></head><body>
<a class="skip" href="#main">Skip to report content</a><header><p class="eyebrow">Report {REPORT_VERSION} · Protocol {html.escape(str(manifest.get("protocol_version", "unknown")))} · Suite {html.escape(str(suite.get("name", "unknown")))}@{html.escape(str(suite.get("version", "unknown")))}</p><h1>CavadaLabs Evaluation Report</h1></header>
<main id="main">{result_section}
<h2>Run evidence</h2><p>Protocol run status: <strong>{html.escape(str(manifest.get("status", "unknown")).upper())}</strong>. System under test: <code>{html.escape(str(target.get("label", "system-under-test")))}</code>. Independent {html.escape(analysis_unit)} units: {metrics.get("total", 0)}; evaluation cases: {metrics.get("evaluation_cases", metrics.get("total", 0))}; target observations: {metrics.get("target_observations", metrics.get("observations", 0))}.</p>
<p class="notice"><strong>Scope:</strong> Protocol evidence only. This is not legal certification, universal correctness, or a universal safety guarantee.</p>
{gate_section}{status_section}{performance_section}{stability_section}{calibration_section}{severity_section}{shift_section}{slice_section}
<h2>Methodology</h2><p>Cases were validated before execution. Deterministic hard checks ran before LLM judges. Repetitions were aggregated at distinct-case level. Invalid, error, and skipped results were excluded from pass-rate denominators and remain separately visible.</p>
<h2>Limitations</h2><ul>{limitations}</ul>
<h2>Reproduction</h2><pre><code>{reproduction}</code></pre>{failure_section}</main>
<footer>CavadaLabs Evaluation Protocol · report {REPORT_VERSION}</footer></body></html>\n"""


def _data_uri(path: Path) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def _pdf_lines(
    manifest: dict[str, Any],
    metrics: dict[str, Any],
    categories: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    gates: list[dict[str, Any]],
    *,
    public: bool,
) -> list[str]:
    suite = manifest.get("suite")
    suite = suite if isinstance(suite, dict) else {}
    target = manifest.get("target")
    target = target if isinstance(target, dict) else {}
    multi_construct = metrics.get("aggregate_scope") == "not-applicable" or len(categories) > 1
    lines = [
        f"Protocol: {manifest.get('protocol_version', 'unknown')}",
        f"Suite: {suite.get('name', 'unknown')}@{suite.get('version', 'unknown')}",
        f"Run: {manifest.get('run_id', 'unknown')}",
        "# Results by construct" if multi_construct else "# Overall result",
    ]
    interval = metrics.get("pass_rate_ci")
    interval = interval if isinstance(interval, dict) else {}
    if multi_construct:
        lines.append("Distinct constructs are reported separately. No suite-wide pass rate or headline score combines them.")
    else:
        lines.extend(
            [
                f"Observed pass rate: {_percent(metrics.get('pass_rate'))}",
                f"{_percent(interval.get('confidence', 0.95))} Wilson interval: {_percent(interval.get('lower'))}-{_percent(interval.get('upper'))}",
                "Gate rule: official pass-rate gates use the confidence-interval lower bound, not the observed point estimate. A 100.0% observed rate can still fail a stricter minimum.",
                "# Results by construct",
            ]
        )
    for row in categories:
        lower, upper, confidence = _interval(row)
        category = str(row.get("category", "unknown"))
        lines.extend(
            [
                f"## {category}",
                "| Units | Pass | Fail | Invalid | Error | Skipped | Pass rate | CI |",
                "|-------|------|------|---------|-------|---------|-----------|----|",
                f"| {row.get('total', 0)} | {row.get('pass', 0)} | {row.get('fail', 0)} | {row.get('invalid', 0)} | {row.get('error', 0)} | {row.get('skipped', 0)} | {_percent(row.get('pass_rate'))} | {_percent(confidence)}: {_percent(lower)}-{_percent(upper)} |",
                f"Category gate: {_category_gate_status(category, gates)}",
            ]
        )
    lines.extend(
        [
            "# Run evidence",
            f"Protocol run status: {str(manifest.get('status', 'unknown')).upper()}",
            f"System under test: {target.get('label', 'system-under-test')}",
            f"Analysis unit: {metrics.get('analysis_unit', 'case')}",
            f"Independent units: {metrics.get('total', 0)}; evaluation cases: {metrics.get('evaluation_cases', metrics.get('total', 0))}; target observations: {metrics.get('target_observations', metrics.get('observations', 0))}",
            "Protocol evidence only; not legal certification, universal correctness, or a universal safety guarantee.",
            "# Gate decisions",
        ]
    )
    if gates:
        for gate in gates:
            metric = str(gate.get("metric", ""))
            lines.extend(
                [
                    f"## {_gate_scope(gate.get('category'), multi_construct=multi_construct)} - {metric}",
                    "| Minimum | Actual | Decision |",
                    "|---------|--------|----------|",
                    f"| {_format_gate_value(gate.get('minimum'), metric)} | {_format_gate_value(gate.get('actual'), metric)} | {str(gate.get('status', 'unknown')).title()} |",
                ]
            )
    else:
        lines.append("No declared gates were available in the report evidence, and no gate failures were recorded.")
    lines.extend(
        [
            "# Status distribution",
            "| Pass | Fail | Invalid | Error | Skipped |",
            "|------|------|---------|-------|---------|",
            f"| {metrics.get('pass', 0)} | {metrics.get('fail', 0)} | {metrics.get('invalid', 0)} | {metrics.get('error', 0)} | {metrics.get('skipped', 0)} |",
        ]
    )
    performance = metrics.get("performance")
    performance = performance if isinstance(performance, dict) else {}
    latency = performance.get("target_latency_ms")
    latency = latency if isinstance(latency, dict) else {}
    if int(_as_float(latency.get("count"))) > 0:
        lines.extend(
            [
                "# Observed target latency",
                "| p50 ms | p90 ms | p95 ms | p99 ms |",
                "|--------|--------|--------|--------|",
                f"| {_as_float(latency.get('p50')):.1f} | {_as_float(latency.get('p90')):.1f} | {_as_float(latency.get('p95')):.1f} | {_as_float(latency.get('p99')):.1f} |",
            ]
        )
    stability = metrics.get("stability")
    stability = stability if isinstance(stability, dict) else {}
    case_fraction = stability.get("case_pass_fraction")
    case_fraction = case_fraction if isinstance(case_fraction, dict) else {}
    agreement = stability.get("judge_agreement")
    agreement = agreement if isinstance(agreement, dict) else {}
    stability_rows: list[tuple[str, str]] = []
    if int(_as_float(case_fraction.get("count"))) > 0:
        stability_rows.append(("Stable case fraction", _percent(stability.get("stable_case_fraction"))))
    if int(_as_float(agreement.get("count"))) > 0:
        stability_rows.append(("Mean judge agreement", _percent(agreement.get("mean"))))
    if stability_rows:
        lines.extend(["# Stability and judge agreement", "| Measure | Value |", "|---------|-------|"])
        lines.extend(f"| {name} | {value} |" for name, value in stability_rows)
    calibration = metrics.get("judge_calibration")
    calibration = calibration if isinstance(calibration, dict) else {}
    calibration_rows = [
        (str(name), _percent(value.get("accuracy")))
        for name, value in calibration.items()
        if isinstance(value, dict) and isinstance(value.get("accuracy"), (int, float))
    ]
    if calibration_rows:
        lines.extend(["# Judge calibration", "| Judge | Accuracy |", "|-------|----------|"])
        lines.extend(f"| {name} | {value} |" for name, value in calibration_rows)
    severity_rows = [
        (severity.title(), sum(str(row.get("severity", "missing")) == severity for row in failures))
        for severity in ("low", "medium", "high", "critical", "missing")
    ]
    severity_rows = [(name, count) for name, count in severity_rows if count]
    if severity_rows:
        lines.extend(["# Non-pass evidence by severity", "| Severity | Count |", "|----------|-------|"])
        lines.extend(f"| {name} | {count} |" for name, count in severity_rows)
    shift = metrics.get("distribution_shift")
    shift = shift if isinstance(shift, dict) else {}
    comparison = shift.get("comparison")
    if isinstance(comparison, dict):
        delta_interval = comparison.get("delta_ci")
        delta_interval = delta_interval if isinstance(delta_interval, dict) else {}
        lines.extend(
            [
                "# Distribution-shift pairs",
                f"Valid pairs: {shift.get('valid_pairs', 0)}/{shift.get('declared_pairs', 0)}; invalid pairs: {shift.get('invalid_pairs', 0)}",
                f"Shift minus baseline: {_percent(comparison.get('absolute_delta'))}; bootstrap interval: {_percent(delta_interval.get('lower'))}-{_percent(delta_interval.get('upper'))}",
            ]
        )
    slices = metrics.get("slices")
    slices = slices if isinstance(slices, dict) else {}
    if any(isinstance(values, dict) and values for values in slices.values()):
        disparities = metrics.get("slice_disparities")
        disparities = disparities if isinstance(disparities, dict) else {}
        disparity_rows = [(str(name), _percent(value)) for name, value in disparities.items() if isinstance(slices.get(name), dict) and slices[name]]
        if disparity_rows:
            lines.extend(["# Maximum descriptive slice disparities", "| Dimension | Maximum disparity |", "|-----------|-------------------|"])
            lines.extend(f"| {name} | {value} |" for name, value in disparity_rows)
        lines.extend(["# Result slices", "| Dimension | Value | Units | Pass rate | Invalid | Error |", "|-----------|-------|-------|-----------|---------|-------|"])
        for dimension, values in slices.items():
            if isinstance(values, dict):
                for value, summary in values.items():
                    if isinstance(summary, dict):
                        lines.append(
                            f"| {dimension} | {value} | {summary.get('total', 0)} | {_percent(summary.get('pass_rate'))} | {summary.get('invalid', 0)} | {summary.get('error', 0)} |"
                        )
    lines.extend(
        [
            "# Methodology",
            "Cases were validated before execution. Deterministic hard checks ran before LLM judges. Repetitions were aggregated at distinct-case level. Invalid, error, and skipped results were excluded from pass-rate denominators and remain separately visible.",
            "# Limitations",
            *[f"- {value}" for value in _LIMITATIONS],
            "# Reproduction",
            str(manifest.get("public_reproduction_command" if public else "reproduction_command", "Unavailable; see manifest parameters.")),
        ]
    )
    if not public and failures:
        lines.extend(["# Failure, invalid, error, and skipped evidence", "| Case | Repetition | Status | Reason |", "|------|------------|--------|--------|"])
        lines.extend(
            f"| {row.get('case_id', '')} | {row.get('repetition', 'n/a')} | {row.get('status', '')} | {row.get('reason', '')} |" for row in failures[:200]
        )
    return lines


def _xml_attribute(value: Any) -> str:
    cleaned = "".join(character if character in "\t\n\r" or ord(character) >= 32 else "\ufffd" for character in str(value))
    return quoteattr(cleaned)


def _junit(result_rows: list[dict[str, Any]]) -> str:
    counts = {name: sum(row.get("status") == name for row in result_rows) for name in ("fail", "error", "invalid", "skipped")}
    tests: list[str] = []
    for row in result_rows:
        status = str(row.get("status", "invalid"))
        identity = f"{row.get('case_id', 'unknown')} [repetition={row.get('repetition', 'n/a')}]"
        opening = f'<testcase classname={_xml_attribute(row.get("category", "cavada-eval"))} name={_xml_attribute(identity)}>'
        reason = _xml_attribute(row.get("reason", status))
        if status == "pass":
            child = ""
        elif status == "fail":
            child = f'<failure type="assertion" message={reason}/>'
        elif status == "skipped":
            child = f'<skipped message={reason}/>'
        else:
            child = f'<error type={_xml_attribute("invalid" if status == "invalid" else "error")} message={reason}/>'
        tests.append(opening + child + "</testcase>")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<testsuite name="cavada-eval" tests="{len(tests)}" failures="{counts["fail"]}" errors="{counts["error"] + counts["invalid"]}" skipped="{counts["skipped"]}">'
        + "".join(tests)
        + "</testsuite>\n"
    )


def generate_reports(
    run_dir: Path,
    manifest: dict[str, Any],
    metrics: dict[str, Any],
    categories: list[dict[str, Any]],
    result_rows: list[dict[str, Any]],
) -> list[str]:
    figures = run_dir / "figures"
    figures.mkdir(mode=0o700, exist_ok=True)
    generated: dict[str, Path] = {}
    multi_construct = metrics.get("aggregate_scope") == "not-applicable" or len(categories) > 1
    valid_total = int(_as_float(metrics.get("pass"))) + int(_as_float(metrics.get("fail")))
    if not multi_construct and valid_total:
        generated["overall"] = figures / "overall_scores.svg"
        _bar_svg("Overall pass rate", [("Pass rate", _as_float(metrics.get("pass_rate")))], generated["overall"])
    if categories:
        generated["category"] = figures / "category_scores.svg"
        _bar_svg("Pass rate by construct", [(str(row.get("category", "unknown")), _as_float(row.get("pass_rate"))) for row in categories], generated["category"])

    performance = metrics.get("performance")
    performance = performance if isinstance(performance, dict) else {}
    latency = performance.get("target_latency_ms")
    latency = latency if isinstance(latency, dict) else {}
    if int(_as_float(latency.get("count"))) > 0:
        latency_rows = [(key.upper(), _as_float(latency.get(key))) for key in ("p50", "p90", "p95", "p99")]
        generated["latency"] = figures / "latency.svg"
        _bar_svg("Target latency percentiles (ms)", latency_rows, generated["latency"], maximum=max(value for _, value in latency_rows) or 1.0, value_kind="decimal")

    status_rows = [(name.title(), _as_float(metrics.get(name))) for name in ("pass", "fail", "invalid", "error", "skipped")]
    if any(value for _, value in status_rows):
        generated["status"] = figures / "status_distribution.svg"
        _bar_svg("Analysis-unit status distribution", status_rows, generated["status"], maximum=max(value for _, value in status_rows), value_kind="count")

    stability = metrics.get("stability")
    stability = stability if isinstance(stability, dict) else {}
    case_fraction = stability.get("case_pass_fraction")
    case_fraction = case_fraction if isinstance(case_fraction, dict) else {}
    agreement = stability.get("judge_agreement")
    agreement = agreement if isinstance(agreement, dict) else {}
    stability_rows: list[tuple[str, float]] = []
    if int(_as_float(case_fraction.get("count"))) > 0:
        stability_rows.append(("Stable case fraction", _as_float(stability.get("stable_case_fraction"))))
    if int(_as_float(agreement.get("count"))) > 0:
        stability_rows.append(("Mean judge agreement", _as_float(agreement.get("mean"))))
    if stability_rows:
        generated["stability"] = figures / "stability.svg"
        _bar_svg("Stability and judge agreement", stability_rows, generated["stability"])

    failures = [row for row in result_rows if row.get("status") != "pass"]
    severity_rows = [
        (severity.title(), float(sum(str(row.get("severity", "missing")) == severity for row in failures)))
        for severity in ("low", "medium", "high", "critical", "missing")
    ]
    severity_rows = [(name, value) for name, value in severity_rows if value]
    if severity_rows:
        generated["failure_severity"] = figures / "failure_severity.svg"
        _bar_svg("Non-pass evidence by severity", severity_rows, generated["failure_severity"], maximum=max(value for _, value in severity_rows), value_kind="count")

    slices = metrics.get("slices")
    slices = slices if isinstance(slices, dict) else {}
    disparities = metrics.get("slice_disparities")
    disparities = disparities if isinstance(disparities, dict) else {}
    disparity_rows = [
        (str(name), _as_float(value)) for name, value in disparities.items() if isinstance(slices.get(name), dict) and slices[name]
    ]
    if disparity_rows:
        generated["disparity"] = figures / "slice_disparity.svg"
        _bar_svg("Maximum pass-rate disparity by slice", disparity_rows, generated["disparity"])

    calibration = metrics.get("judge_calibration")
    calibration = calibration if isinstance(calibration, dict) else {}
    calibration_rows = [(str(name), _as_float(value.get("accuracy"))) for name, value in calibration.items() if isinstance(value, dict) and isinstance(value.get("accuracy"), (int, float))]
    if calibration_rows:
        generated["calibration"] = figures / "judge_calibration.svg"
        _bar_svg("Judge calibration accuracy", calibration_rows, generated["calibration"])

    latency_values = [_as_float(row["target_latency_ms"]) for row in result_rows if isinstance(row.get("target_latency_ms"), (int, float))]
    if len(latency_values) > 1:
        generated["latency_cdf"] = figures / "latency_cdf.svg"
        _cdf_svg("Target latency empirical CDF", latency_values, generated["latency_cdf"])

    shift = metrics.get("distribution_shift")
    shift = shift if isinstance(shift, dict) else {}
    shift_comparison = shift.get("comparison")
    if isinstance(shift_comparison, dict):
        generated["distribution_shift"] = figures / "distribution_shift.svg"
        _bar_svg(
            "Paired distribution-shift pass rates",
            [
                ("In-distribution reference", _as_float(shift_comparison.get("baseline_pass_rate"))),
                ("Shift probe", _as_float(shift_comparison.get("candidate_pass_rate"))),
            ],
            generated["distribution_shift"],
        )

    figure_uris = {key: _data_uri(path) for key, path in generated.items()}
    gates = _gate_results(run_dir, metrics, categories)
    atomic_text(run_dir / "report.html", _html_document(manifest, metrics, categories, failures, public=False, figures=figure_uris, gates=gates))
    atomic_text(run_dir / "report_public.html", _html_document(manifest, metrics, categories, [], public=True, figures=figure_uris, gates=gates))
    summary = {
        "protocol_version": manifest.get("protocol_version"),
        "report_version": REPORT_VERSION,
        "run_id": manifest.get("run_id"),
        "status": manifest.get("status"),
        "suite": manifest.get("suite"),
        "target": {"label": manifest.get("target", {}).get("label"), "revision": manifest.get("target", {}).get("revision")},
        "metrics": metrics,
        "categories": categories,
        "gates": [
            {"category": row["category"], "metric": row["metric"], "min": row["minimum"], "confidence": row["confidence"]}
            for row in gates
            if row.get("declared")
        ],
        "limitations": list(_LIMITATIONS),
    }
    atomic_json(run_dir / "summary.json", summary)
    _pdf(run_dir / "report.pdf", "CavadaLabs Evaluation Report", _pdf_lines(manifest, metrics, categories, failures, gates, public=False))
    _pdf(run_dir / "report_public.pdf", "CavadaLabs Public Evaluation Report", _pdf_lines(manifest, metrics, categories, [], gates, public=True))
    atomic_text(run_dir / "junit.xml", _junit(result_rows))
    return [
        "report.html",
        "report_public.html",
        "report.pdf",
        "report_public.pdf",
        "summary.json",
        "junit.xml",
        *[path.relative_to(run_dir).as_posix() for path in generated.values()],
    ]
