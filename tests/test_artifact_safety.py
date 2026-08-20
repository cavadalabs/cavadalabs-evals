from __future__ import annotations

import json
import os
import unicodedata
from pathlib import Path

import pytest

from cavada_eval.artifacts import snapshot_bundle_files, verify_bundle, write_bundle
from cavada_eval.protocol import ProtocolError, _strict_json_loads


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


def test_bundle_checksums_use_canonical_path_order(tmp_path: Path) -> None:
    (tmp_path / "qualification").mkdir()
    (tmp_path / "qualification-run").mkdir()
    (tmp_path / "qualification" / "report.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "qualification-run" / "manifest.json").write_text("{}\n", encoding="utf-8")

    write_bundle(tmp_path)

    assert verify_bundle(tmp_path)["valid"] is True


def test_bundle_snapshot_hash_binds_each_read_byte(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = tmp_path / "result.json"
    artifact.write_text("{}\n", encoding="utf-8")
    write_bundle(tmp_path)
    from cavada_eval import artifacts

    original = artifacts._read_regular

    def raced(root: Path, relative: Path) -> bytes:
        return b'{"swapped":true}\n' if relative.as_posix() == "result.json" else original(root, relative)

    monkeypatch.setattr(artifacts, "_read_regular", raced)
    with pytest.raises(ProtocolError, match="changed while it was snapshotted"):
        snapshot_bundle_files(tmp_path)


def test_bundle_rejects_noncanonical_unicode_paths(tmp_path: Path) -> None:
    decomposed = unicodedata.normalize("NFD", "évidence.json")
    assert decomposed != unicodedata.normalize("NFC", decomposed)
    (tmp_path / decomposed).write_text("{}\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="Unicode NFC"):
        write_bundle(tmp_path)


def test_bundle_rejects_ambiguous_windows_separator(tmp_path: Path) -> None:
    (tmp_path / "a\\b").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="unambiguous"):
        write_bundle(tmp_path)


def test_bundle_tree_race_is_a_validation_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "result.json").write_text("{}\n", encoding="utf-8")
    write_bundle(tmp_path)
    late = tmp_path / "late.tmp"
    late.write_text("race\n", encoding="utf-8")
    original = Path.lstat

    def raced(path: Path) -> os.stat_result:
        if path == late:
            raise FileNotFoundError(path)
        return original(path)

    monkeypatch.setattr(Path, "lstat", raced)
    assert "bundle tree changed during verification" in verify_bundle(tmp_path)["failures"]


def test_public_snapshot_does_not_depend_on_hmac_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "result.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("TEST_BUNDLE_KEY", "correct")
    write_bundle(tmp_path, signing_key_env="TEST_BUNDLE_KEY")
    assert verify_bundle(tmp_path, signing_key_env="TEST_BUNDLE_KEY")["signature"] == "valid"
    monkeypatch.setenv("TEST_BUNDLE_KEY", "wrong")
    public = verify_bundle(tmp_path, signing_key_env="TEST_BUNDLE_KEY", verify_hmac=False)
    assert public["valid"] is True
    assert public["signature"] == "unverified"
