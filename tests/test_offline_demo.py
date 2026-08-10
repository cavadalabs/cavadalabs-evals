from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest


def test_offline_demo_produces_a_verified_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    demo = runpy.run_path("examples/offline_demo.py")
    monkeypatch.setattr(sys, "argv", ["offline_demo.py", "--output-root", str(tmp_path)])

    assert demo["main"]() == 0
    output = capsys.readouterr().out
    assert '"bundle_valid": true' in output
    assert '"claim": "protocol transport demo only"' in output
