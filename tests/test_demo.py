from __future__ import annotations

from pathlib import Path

from cavada_eval.demo import run_demo


def test_offline_demo_produces_verified_reports(tmp_path: Path) -> None:
    repo = Path(__file__).parents[1]
    result = run_demo(repo, artifact_root=tmp_path)

    assert result["status"] == "passed" and result["external_network_used"] is False
    assert Path(result["report"]).is_file() and result["verification"]["valid"] is True
