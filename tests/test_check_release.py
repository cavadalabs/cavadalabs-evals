from __future__ import annotations

import runpy
from pathlib import Path
from typing import Callable, cast

ROOT = Path(__file__).parents[1]
validate = cast(Callable[..., list[str]], runpy.run_path(str(ROOT / "scripts" / "check_release.py"))["validate"])


def test_development_release_metadata_is_consistent() -> None:
    assert validate(ROOT) == []
    assert "development version" in "\n".join(validate(ROOT, release=True, tag="v0.4.0.dev0"))


def test_release_check_rejects_version_drift(tmp_path: Path) -> None:
    for relative in (
        "pyproject.toml",
        "src/cavada_eval/__init__.py",
        "CITATION.cff",
        "CHANGELOG.md",
        "README.md",
        "PROTOCOL.md",
        "GOVERNANCE.md",
        "RESULTS_POLICY.md",
        "docs/THREAT_MODEL.md",
        "results/registry.json",
        "results/registry-v2.json",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    init = tmp_path / "src/cavada_eval/__init__.py"
    init.write_text(init.read_text(encoding="utf-8").replace("0.4.0.dev0", "9.9.9"), encoding="utf-8")

    assert "version mismatch" in "\n".join(validate(tmp_path))
