from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.protocol import _strict_json_loads


def test_bundle_rejects_hardlinks_and_case_collisions(tmp_path: Path) -> None:
    hardlinked = tmp_path / "hardlinked"
    hardlinked.mkdir()
    artifact = hardlinked / "result.json"
    artifact.write_text("{}\n", encoding="utf-8")
    write_bundle(hardlinked)
    same_bytes = tmp_path / "same-bytes.json"
    same_bytes.write_text("{}\n", encoding="utf-8")
    artifact.unlink()
    os.link(same_bytes, artifact)

    failures = verify_bundle(hardlinked)["failures"]
    assert "unreadable artifact: result.json" in failures
    assert "unsafe hardlinked artifact: result.json" in failures

    colliding = tmp_path / "colliding"
    colliding.mkdir()
    (colliding / "Result.json").write_text("{}\n", encoding="utf-8")
    write_bundle(colliding)
    bundle = json.loads((colliding / "bundle.json").read_text(encoding="utf-8"))
    bundle["files"]["result.json"] = bundle["files"]["Result.json"]
    (colliding / "bundle.json").write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    (colliding / "checksums.txt").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(bundle["files"].items())),
        encoding="utf-8",
    )
    assert any("case-colliding artifact paths" in failure for failure in verify_bundle(colliding)["failures"])


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is not available")
def test_bundle_rejects_unlisted_non_regular_files(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "result.json").write_text("{}\n", encoding="utf-8")
    write_bundle(run_dir)
    os.mkfifo(run_dir / "unexpected.fifo")

    assert "unsafe non-regular artifact: unexpected.fifo" in verify_bundle(run_dir)["failures"]


def test_strict_json_normalizes_excessive_nesting_to_a_validation_error() -> None:
    with pytest.raises(ValueError, match="nesting is too deep"):
        _strict_json_loads("[" * 1_000 + "0" + "]" * 1_000)
