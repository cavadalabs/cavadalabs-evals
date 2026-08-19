from __future__ import annotations

import re
import tomllib
from pathlib import Path

from cavada_eval import __version__


def test_development_version_is_consistent() -> None:
    root = Path(__file__).parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    citation = (root / "CITATION.cff").read_text(encoding="utf-8")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")

    assert project["project"]["version"] == __version__
    assert re.search(rf"^version: ['\"]?{re.escape(__version__)}['\"]?$", citation, re.MULTILINE)
    assert f"## Unreleased ({__version__})" in changelog
