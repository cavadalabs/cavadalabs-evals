from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cavada_eval import cli


def test_init_and_plan_client_project_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    project = tmp_path / "customer-eval"
    assert cli.main(["init", str(project)]) == cli.EXIT_PASS
    assert {"eval.toml", "custom.py", "README.md", ".gitignore", "data"} == {path.name for path in project.iterdir()}
    capsys.readouterr()

    monkeypatch.chdir(project)
    assert cli.main(["plan", "eval.toml"]) == cli.EXIT_PASS
    result = json.loads(capsys.readouterr().out)
    assert result["network_used"] is False
    assert result["cell_count"] == 1
    assert result["target_requests"] == 2


def test_client_run_routes_resume_and_progress(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "eval.toml"
    config.write_text('version = "1"\n', encoding="utf-8")
    plan = object()
    output = tmp_path / "run"
    called: dict[str, Any] = {}

    monkeypatch.setattr(cli, "load_experiment_plan", lambda path: plan)

    def fake_run(value: object, *, resume: bool | None, progress: bool) -> SimpleNamespace:
        called.update({"plan": value, "resume": resume, "progress": progress})
        return SimpleNamespace(
            path=output,
            summary={
                "cells": [
                    {
                        "target": "local",
                        "prompt": "baseline",
                        "pass_rate": 1.0,
                        "pass_rate_ci": {"lower": 0.8, "upper": 1.0},
                        "error": 0,
                        "invalid": 0,
                        "p50_latency_ms": 12.5,
                        "cost": None,
                    }
                ]
            },
        )

    monkeypatch.setattr(cli, "run_experiment", fake_run)
    assert cli.main(["run", str(config), "--resume", "--progress"]) == cli.EXIT_PASS
    assert called == {"plan": plan, "resume": True, "progress": True}
    rendered = capsys.readouterr().out
    assert rendered.splitlines()[0] == str(output)
    assert "Target\tPrompt\tPass rate" in rendered and "local\tbaseline\t100.0%" in rendered


@pytest.mark.parametrize(
    "arguments",
    [
        ["--official"],
        ["--allow-external-judge"],
        ["--preset", "reference"],
        ["--mode", "official"],
        ["--external-authorization", "authorization.json"],
        ["--storage-attestation", "storage.json"],
        ["--judge-qualification-package", "qualification"],
        ["--judge-qualification", "qualification.json"],
        ["--judge-approval", "approval.json"],
        ["--engagement", "engagement.json"],
    ],
)
def test_client_run_rejects_legacy_assurance_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    config = tmp_path / "eval.toml"
    config.write_text('version = "1"\n', encoding="utf-8")
    monkeypatch.setattr(cli, "run_experiment", lambda *_args, **_kwargs: pytest.fail("client run must not start"))

    assert cli.main(["run", str(config), *arguments]) == cli.EXIT_CONFIGURATION
    assert arguments[0] in capsys.readouterr().err


def test_legacy_run_still_requires_legacy_connection_flags(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["run", str(tmp_path / "suite")]) == cli.EXIT_CONFIGURATION
    error = capsys.readouterr().err
    assert "legacy suite run requires" in error
    assert "--endpoint" in error and "--judge-endpoint" in error
    assert "Traceback" not in error


def test_client_report_and_verify_resolve_latest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    runs = tmp_path / "runs"
    experiment = runs / "experiment-1"
    experiment.mkdir(parents=True)
    (experiment / "experiment.json").write_text("{}\n", encoding="utf-8")
    (experiment / "report.html").write_text("report", encoding="utf-8")
    (runs / "latest").write_text("experiment-1\n", encoding="utf-8")
    seen: list[Path] = []

    def fake_verify(path: str | Path) -> dict[str, Any]:
        seen.append(Path(path))
        return {"valid": True, "semantic_valid": True}

    monkeypatch.setattr(cli, "verify_experiment", fake_verify)
    assert cli.main(["report", str(runs / "latest")]) == cli.EXIT_PASS
    report = json.loads(capsys.readouterr().out)
    assert report["reports"] == [str(experiment / "report.html")]
    assert cli.main(["verify", str(runs / "latest")]) == cli.EXIT_PASS
    assert json.loads(capsys.readouterr().out)["semantic_valid"] is True
    assert seen == [experiment.resolve(), experiment.resolve()]


def test_benchmark_plan_and_run_route_to_performance_core(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "benchmark.toml"
    config.write_text("benchmark_version = '1.0.0'\n", encoding="utf-8")
    benchmark = SimpleNamespace(sha256="abc", config={"concurrency": [1, 4]})
    loaded: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        cli,
        "load_client_benchmark",
        lambda path, *, trust_factory: loaded.append((str(path), trust_factory)) or benchmark,
    )
    monkeypatch.setattr(
        cli,
        "plan_client_benchmark",
        lambda value, directory: SimpleNamespace(plan=object(), runtime=object()),
    )
    monkeypatch.setattr(cli, "performance_plan_summary", lambda plan, runtime: {"planned_requests": 8})

    assert cli.main(["benchmark", str(config), "--trust-factory", "--plan"]) == cli.EXIT_PASS
    planned = json.loads(capsys.readouterr().out)
    assert planned["planned_requests"] == 8 and planned["network_used"] is False
    assert loaded == [(str(config), True)]

    run_dir = tmp_path / "benchmark-run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text('{"status":"completed","cells":{"slo_failed":0}}\n', encoding="utf-8")
    called: dict[str, Any] = {}

    def fake_run(value: object, **kwargs: Any) -> Path:
        called.update(kwargs)
        assert value is benchmark
        return run_dir

    monkeypatch.setattr(cli, "run_client_benchmark", fake_run)
    output_root = tmp_path / "runs"
    assert cli.main(["benchmark", str(config), "--output-root", str(output_root)]) == cli.EXIT_PASS
    assert capsys.readouterr().out.strip() == str(run_dir)
    assert called["output_root"] == output_root


def test_legacy_suite_init_requires_explicit_suites_root(tmp_path: Path) -> None:
    suites = tmp_path / "suites"
    assert cli.main(["init", "legacy-suite", "--suites-root", str(suites)]) == cli.EXIT_PASS
    assert (suites / "legacy-suite" / "suite.toml").is_file()
