from __future__ import annotations

from pathlib import Path

import pytest

import cavada_eval.cli as cli
from cavada_eval.demo import run_demo


def test_offline_demo_produces_verified_reports(tmp_path: Path) -> None:
    repo = Path(__file__).parents[1]
    result = run_demo(repo, artifact_root=tmp_path)

    assert set(result) == {"status", "official", "external_network_used", "run", "report", "metrics", "failures", "verification"}
    assert set(result["verification"]) == {"valid", "failures", "signature", "files"}
    assert result["status"] == "passed" and result["external_network_used"] is False
    assert result["official"] is False
    assert Path(result["report"]).is_file() and result["verification"]["valid"] is True


def test_demo_can_open_the_generated_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: opened.append(url) or True)

    assert cli.main(["demo", "--open"]) == 0
    assert len(opened) == 1 and opened[0].startswith("file:")
