import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cavada_eval.cli import EXIT_CONFIGURATION, EXIT_GATE_FAILURE, EXIT_INTEGRITY, _doctor, main, parser
from cavada_eval.protocol import ProtocolError

ROOT = Path(__file__).resolve().parents[1]


def test_doctor_separates_development_and_official_readiness(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas" / "example.json").write_text("{}", encoding="utf-8")
    (tmp_path / "program").mkdir()
    (tmp_path / "program" / "registry.toml").write_text(
        '[[suites]]\nid = "draft-v1"\nstatus = "draft"\nofficial_capable = false\n',
        encoding="utf-8",
    )
    (tmp_path / "PROTOCOL.md").write_text("# Protocol\n", encoding="utf-8")
    performance_protocol = tmp_path / "PERFORMANCE_PROTOCOL_V2.md"
    performance_protocol.write_text("# Performance protocol\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("", encoding="utf-8")

    result = _doctor(tmp_path)

    assert result["ready"] is True
    assert result["development_ready"] is True
    assert result["official_ready"] is False
    assert result["performance_protocol"] is True
    assert result["program"] == {
        "suites": 1,
        "by_status": {"draft": 1},
        "official_capable": 0,
        "deep_validation": "run `cavada-eval program`",
    }

    performance_protocol.unlink()
    missing_performance_protocol = _doctor(tmp_path)
    assert missing_performance_protocol["development_ready"] is False
    assert missing_performance_protocol["performance_protocol"] is False


def test_list_reads_metadata_without_deep_suite_validation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    suite = tmp_path / "draft"
    suite.mkdir()
    (suite / "suite.toml").write_text('name = "draft-v1"\nversion = "0.1.0"\nstatus = "draft"\n', encoding="utf-8")

    assert main(["list", "--suites-root", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert '"name": "draft-v1"' in output
    assert "metadata-only" in output


def test_list_uses_packaged_suites_outside_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    packaged = tmp_path / "_resources"
    suite = packaged / "suites" / "template"
    suite.mkdir(parents=True)
    (suite / "suite.toml").write_text('name = "template-v1"\nversion = "1.0.0"\nstatus = "draft"\n', encoding="utf-8")
    monkeypatch.setattr("cavada_eval.cli._repository_root", lambda *_args: packaged)

    assert main(["list"]) == 0
    assert '"name": "template-v1"' in capsys.readouterr().out


def test_estimate_matches_development_review_policy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "cavada_eval.cli.load_suite",
        lambda _path: SimpleNamespace(
            cases=(
                {"id": "approved", "review": {"status": "approved"}},
                {"id": "development", "review": {"status": "needs_review"}},
                {"id": "rejected", "review": {"status": "rejected"}},
            )
        ),
    )

    assert main(["estimate", "unused-suite", "--repetitions", "2", "--judge-repetitions", "3"]) == 0
    output = capsys.readouterr().out
    assert '"selected_cases": 3' in output
    assert '"executable_cases": 2' in output
    assert '"skipped_rejected_cases": 1' in output
    assert '"target_calls": 4' in output
    assert '"maximum_judge_calls": 12' in output


def test_estimate_counts_every_configured_judge(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        "cavada_eval.cli.load_suite",
        lambda _path: SimpleNamespace(
            cases=({"id": "one", "review": {"status": "approved"}},),
            config={"judge": {"additional_models": [{"model": "second"}, {"model": "third"}]}},
        ),
    )

    assert main(["estimate", "unused-suite", "--repetitions", "2", "--judge-repetitions", "3"]) == 0
    assert '"maximum_judge_calls": 18' in capsys.readouterr().out


def test_resume_command_fails_closed_without_reading_or_mutating_a_run(capsys: pytest.CaptureFixture[str]) -> None:
    result = main(
        [
            "resume",
            "missing-run",
            "suite",
        ]
    )

    assert result == EXIT_CONFIGURATION
    assert "runs are immutable and cannot be resumed" in capsys.readouterr().err


def test_run_accepts_an_explicit_output_root() -> None:
    args = parser().parse_args(
        [
            "run",
            "suite",
            "--endpoint",
            "http://127.0.0.1:8000/v1",
            "--model-label",
            "model",
            "--expected-model",
            "model",
            "--judge-endpoint",
            "http://127.0.0.1:8001/v1",
            "--judge-model",
            "judge",
            "--output-root",
            "artifacts",
            "--non-inferiority-margin",
            "0.05",
        ]
    )
    assert args.output_root == "artifacts"
    assert args.non_inferiority_margin == 0.05


@pytest.mark.parametrize(
    ("status", "invalid_loadgen", "slo_failed"),
    (("invalid-loadgen", 1, 1), ("completed", 0, 1)),
    ids=("invalid-load-generator", "ordinary-slo-failure"),
)
def test_perf_run_prints_gate_failure_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
    invalid_loadgen: int,
    slo_failed: int,
) -> None:
    run_dir = tmp_path / status
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "status": status,
                "cells": {"invalid_loadgen": invalid_loadgen, "slo_failed": slo_failed},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("cavada_eval.cli.load_performance_plan", lambda _path: object())
    monkeypatch.setattr("cavada_eval.cli.load_performance_runtime", lambda _path: object())
    monkeypatch.setattr("cavada_eval.cli.run_performance_campaign", lambda *_args, **_kwargs: run_dir)

    result = main(["perf", "run", "unused-plan.toml", "unused-runtime.toml"])

    assert result == EXIT_GATE_FAILURE
    assert json.loads(capsys.readouterr().out) == {
        "run_dir": str(run_dir),
        "report_html": str(run_dir / "report.html"),
        "report_pdf": str(run_dir / "report.pdf"),
        "cells_csv": str(run_dir / "cells.csv"),
        "verify_command": f"uv run cavada-eval verify {run_dir}",
        "status": status,
        "invalid_loadgen": invalid_loadgen,
        "slo_failed": slo_failed,
    }


def test_perf_compare_prints_source_bound_verify_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "comparison"
    left = tmp_path / "left"
    right = tmp_path / "right"
    monkeypatch.setattr(
        "cavada_eval.cli.compare_performance_runs",
        lambda *_args, **_kwargs: {"baseline": "runtime-a", "shared_cells": 1},
    )

    assert main(["perf", "compare", str(left), str(right), "--output", str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["verify_command"] == (
        f"uv run cavada-eval verify {output} --source-run {left} --source-run {right}"
    )


def test_verify_routes_comparison_bundles_through_semantic_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    comparison = tmp_path / "comparison"
    comparison.mkdir()
    (comparison / "comparison.json").write_text("{}", encoding="utf-8")
    (comparison / "report.html").write_text("report", encoding="utf-8")
    left = tmp_path / "left"
    right = tmp_path / "right"
    monkeypatch.setattr(
        "cavada_eval.cli.verify_performance_comparison",
        lambda path, source_run_dirs, **_kwargs: {
            "valid": path == comparison,
            "semantic_valid": source_run_dirs == [left, right],
            "type": "performance-comparison",
        },
    )

    assert main(["verify", str(comparison), "--source-run", str(left), "--source-run", str(right)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["semantic_valid"] is True
    assert result["report_html"] == str(comparison / "report.html")

    monkeypatch.setattr(
        "cavada_eval.cli.verify_performance_comparison",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ProtocolError("presentation differs from comparison.json")),
    )
    assert main(["verify", str(comparison)]) == EXIT_INTEGRITY
    rejected = json.loads(capsys.readouterr().out)
    assert rejected["type"] == "performance-comparison"
    assert rejected["semantic_valid"] is False


def test_verify_routes_historical_performance_source_through_its_compatibility_verifier(
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = ROOT / "tests" / "fixtures" / "performance-v1.0-source" / "bundle"

    assert main(["verify", str(source)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "valid": True,
        "semantic_valid": False,
        "type": "performance",
        "performance_protocol_version": "1.0.0",
        "assurance": "legacy-hash-only",
        "official": False,
        "rankable": False,
        "authenticity": "unverified",
        "bundle_signature": "absent",
        "report_html": str(source / "report.html"),
    }


@pytest.mark.parametrize(
    ("document", "target"),
    (
        ("README.md", "PERFORMANCE_PROTOCOL_V2.md"),
        ("docs/README.md", "../PERFORMANCE_PROTOCOL_V2.md"),
        ("docs/PERFORMANCE.md", "../PERFORMANCE_PROTOCOL_V2.md"),
        ("docs/PERFORMANCE_RELEASE.md", "../PERFORMANCE_PROTOCOL_V2.md"),
        ("docs/API.md", "../PERFORMANCE_PROTOCOL_V2.md"),
        ("docs/FINAL_AUDIT.md", "../PERFORMANCE_PROTOCOL_V2.md"),
        ("performance/README.md", "../PERFORMANCE_PROTOCOL_V2.md"),
        ("results/README.md", "../PERFORMANCE_PROTOCOL_V2.md"),
        ("IMPLEMENTATION_CHECKLIST.md", "PERFORMANCE_PROTOCOL_V2.md"),
        ("OFFICIAL_EVALUATION_PROGRAM.md", "PERFORMANCE_PROTOCOL_V2.md"),
    ),
)
def test_current_performance_documentation_links_to_v2(document: str, target: str) -> None:
    source = ROOT / document
    assert f"]({target})" in source.read_text(encoding="utf-8")
    assert (source.parent / target).resolve().is_file()


def test_historical_performance_protocols_and_development_presets_remain_explicit() -> None:
    assert (ROOT / "PERFORMANCE_PROTOCOL.md").is_file()
    assert (ROOT / "PERFORMANCE_PROTOCOL_V1_0.md").is_file()
    assert (ROOT / "PERFORMANCE_PROTOCOL_V1_1.md").is_file()
    docs_index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8").casefold()
    assert "unanchored historical-development" in docs_index and "[v1.1 protocol]" in docs_index
    assert "commit-anchored\n   [v1.0 protocol]" in docs_index

    presets = (ROOT / "performance" / "README.md").read_text(encoding="utf-8").splitlines()
    for preset in ("`smoke`", "`quick`", "`standard`"):
        row = next(line.casefold() for line in presets if line.startswith(f"| {preset}"))
        assert "historical-development v1.1" in row


def test_performance_guide_orders_offline_quick_before_reference_and_states_scope() -> None:
    guide = (ROOT / "docs" / "PERFORMANCE.md").read_text(encoding="utf-8")
    validate_quick = "uv run cavada-eval perf validate --preset quick"
    run_quick = "uv run cavada-eval perf run /secure/path/runtime.toml --preset quick"
    run_reference = "uv run cavada-eval perf run /secure/path/runtime.toml --preset reference"
    assert guide.index(validate_quick) < guide.index(run_quick) < guide.index(run_reference)
    assert "validate locally without contacting the endpoint" in guide

    package_guide = (ROOT / "performance" / "README.md").read_text(encoding="utf-8").casefold()
    for boundary in ("externally managed", "response quality", "hardware utilization", "energy use"):
        assert boundary in package_guide
    assert '"release_version": "2.0.0"' in (ROOT / "docs" / "PERFORMANCE_RELEASE.md").read_text(encoding="utf-8")


def test_performance_release_guide_has_copyable_source_bound_offline_workflow() -> None:
    guide = (ROOT / "docs" / "PERFORMANCE_RELEASE.md").read_text(encoding="utf-8")
    for evidence in (
        "Controlled offline contributor path",
        "--source-run \"$LEFT_RUN\" --source-run \"$RIGHT_RUN\"",
        "test_registry_cli_resolves_the_exact_content_addressed_archive",
        "semantic_valid",
        "invalid-loadgen",
        "N/A",
        "no publishable benchmark result",
    ):
        assert evidence in guide
