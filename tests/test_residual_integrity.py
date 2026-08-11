from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import cavada_eval.artifacts as artifacts_module
import cavada_eval.compliance as compliance_module
import cavada_eval.retention as retention_module
from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.assets import asset_inventory
from cavada_eval.compliance import generate_control_report
from cavada_eval.performance import _metric_summary
from cavada_eval.pilot import _evidence
from cavada_eval.protocol import ProtocolError, sha256_bytes, sha256_file
from cavada_eval.retention import retention_record
from cavada_eval.statistics import (
    bootstrap_mean_interval,
    distribution,
    holm_adjust,
    mcnemar_exact,
    paired_binary_comparison,
    percentile,
    stratified_bootstrap_mean_interval,
)


def test_pilot_evidence_parses_the_exact_hashed_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "evidence.json"
    original = b'{"status":"approved"}\n'
    path.write_bytes(original)
    real_read = Path.read_bytes
    real_hash = sha256_file

    def read_then_replace(candidate: Path) -> bytes:
        raw = real_read(candidate)
        if candidate == path:
            candidate.write_text('{"status":"forged"}\n', encoding="utf-8")
        return raw

    def hash_then_replace(candidate: Path) -> str:
        digest = real_hash(candidate)
        if candidate == path:
            candidate.write_text('{"status":"forged"}\n', encoding="utf-8")
        return digest

    monkeypatch.setattr(Path, "read_bytes", read_then_replace)
    monkeypatch.setattr("cavada_eval.pilot.sha256_file", hash_then_replace)
    errors: list[str] = []
    value = _evidence(tmp_path, {"path": path.name, "sha256": sha256_bytes(original)}, "pilot evidence", errors)

    assert value == {"status": "approved"}
    assert errors == []


def test_bundle_verifier_rejects_path_swap_after_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = tmp_path / "run-swap"
    run.mkdir()
    artifact = run / "artifact.json"
    artifact.write_text('{"trusted":true}\n', encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text('{"trusted":false}\n', encoding="utf-8")
    write_bundle(run)
    real_open = artifacts_module.os.open
    swapped = False

    def open_then_swap(path: str | bytes | Path, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        descriptor = real_open(path, flags, *args, **kwargs)
        if Path(path) == artifact and not swapped:
            swapped = True
            artifact.unlink()
            artifact.symlink_to(outside)
        return descriptor

    monkeypatch.setattr(artifacts_module.os, "open", open_then_swap)
    result = verify_bundle(run)

    assert result["valid"] is False
    assert any("artifact.json" in failure for failure in result["failures"])


def test_bundle_verifier_rejects_transient_ancestor_symlink_swap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = tmp_path / "run-ancestor-swap"
    nested = run / "nested"
    nested.mkdir(parents=True)
    artifact = nested / "artifact.json"
    artifact.write_text('{"trusted":true}\n', encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / artifact.name).write_bytes(artifact.read_bytes())
    write_bundle(run)
    backup = run / "nested-original"
    real_hash = artifacts_module._hash_regular
    swapped = False

    def hash_during_swap(root: Path, relative: Path) -> str:
        nonlocal swapped
        if relative.as_posix() == "nested/artifact.json" and not swapped:
            swapped = True
            nested.rename(backup)
            nested.symlink_to(outside, target_is_directory=True)
            try:
                return real_hash(root, relative)
            finally:
                nested.unlink()
                backup.rename(nested)
        return real_hash(root, relative)

    monkeypatch.setattr(artifacts_module, "_hash_regular", hash_during_swap)
    result = verify_bundle(run)

    assert result["valid"] is False
    assert "unreadable artifact: nested/artifact.json" in result["failures"]
    assert artifact.is_file() and not nested.is_symlink()


def test_compliance_report_binds_sources_and_rejects_false_or_unsafe_manual_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "result.json").write_text("{}\n", encoding="utf-8")
    (run_dir / "manifest.json").write_text(
        json.dumps({"run_id": "run-1", "suite": {"name": "suite"}, "artifacts": {"result.json": sha256_file(run_dir / "result.json")}}) + "\n",
        encoding="utf-8",
    )
    write_bundle(run_dir)

    catalog = tmp_path / "controls.toml"
    catalog.write_text(
        'version = "1.0.0"\n'
        '[[controls]]\nid = "AI-ACT-12"\ntitle = "Logging"\nevidence = []\n'
        '[[controls]]\nid = "GDPR-5"\ntitle = "Accountability"\nevidence = []\n',
        encoding="utf-8",
    )
    base = {
        "control_id": "GDPR-5",
        "status": "manual_required",
        "applicability": "operator review",
        "owner": "reviewer",
        "effective_at": "2026-08-07",
        "residual_risk": "requires accountable approval",
    }

    (run_dir / "result.json").write_text('{"tampered":true}\n', encoding="utf-8")
    invalid_output = tmp_path / "invalid-source-output"
    with pytest.raises(ProtocolError, match="source run bundle verification failed"):
        generate_control_report(run_dir, catalog, invalid_output)
    assert not invalid_output.exists()
    (run_dir / "result.json").write_text("{}\n", encoding="utf-8")
    write_bundle(run_dir)

    duplicate = tmp_path / "duplicate.jsonl"
    duplicate.write_text("".join(json.dumps(base) + "\n" for _ in range(2)), encoding="utf-8")
    with pytest.raises(ProtocolError, match="duplicate evidence control_id"):
        generate_control_report(run_dir, catalog, tmp_path / "duplicate-output", records_path=duplicate)

    automated = tmp_path / "automated.jsonl"
    automated.write_text(json.dumps({**base, "status": "automated_pass"}) + "\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="cannot claim an automated status"):
        generate_control_report(run_dir, catalog, tmp_path / "automated-output", records_path=automated)

    metadata_override = tmp_path / "metadata-override.jsonl"
    metadata_override.write_text(json.dumps({**base, "source": "https://untrusted.example"}) + "\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="invalid evidence record"):
        generate_control_report(run_dir, catalog, tmp_path / "metadata-override-output", records_path=metadata_override)

    unsafe_artifacts = (
        str(Path.home() / "private.pdf"),
        "../private.pdf",
        r"..\private.pdf",
        r"C:private.pdf",
        "api_key=" + "a" * 16,
    )
    for index, artifact in enumerate(unsafe_artifacts):
        unsafe = tmp_path / f"unsafe-{index}.jsonl"
        unsafe.write_text(json.dumps({**base, "artifact": artifact}) + "\n", encoding="utf-8")
        with pytest.raises(ProtocolError, match="unsafe evidence artifact"):
            generate_control_report(run_dir, catalog, tmp_path / f"unsafe-output-{index}", records_path=unsafe)

    duplicate_catalog = tmp_path / "duplicate-controls.toml"
    duplicate_catalog.write_text(catalog.read_text(encoding="utf-8") + '[[controls]]\nid = "GDPR-5"\ntitle = "Duplicate"\n', encoding="utf-8")
    with pytest.raises(ProtocolError, match="duplicate control_id"):
        generate_control_report(run_dir, duplicate_catalog, tmp_path / "duplicate-catalog-output")

    records = tmp_path / "records.jsonl"
    records.write_text(json.dumps({**base, "artifact": "DPIA-record-id"}) + "\n", encoding="utf-8")
    manifest_raw = (run_dir / "manifest.json").read_bytes()
    bundle_raw = (run_dir / "bundle.json").read_bytes()
    records_raw = records.read_bytes()
    original_compliance_verify = compliance_module.verify_bundle
    original_records = compliance_module._records
    mutated = False

    def mutate_run_after_verify(path: Path, **kwargs: Any) -> dict[str, Any]:
        nonlocal mutated
        result = original_compliance_verify(path, **kwargs)
        if not mutated:
            mutated = True
            changed = json.loads(manifest_raw)
            changed["run_id"] = "mutated-run"
            (run_dir / "manifest.json").write_text(json.dumps(changed) + "\n", encoding="utf-8")
        return result

    def mutate_records_after_parse(path: Path | None, raw: bytes | None = None) -> dict[str, dict[str, Any]]:
        parsed = original_records(path, raw)
        if path == records:
            records.write_text(json.dumps({**base, "artifact": "changed-record"}) + "\n", encoding="utf-8")
        return parsed

    monkeypatch.setattr(compliance_module, "verify_bundle", mutate_run_after_verify)
    monkeypatch.setattr(compliance_module, "_records", mutate_records_after_parse)
    output = tmp_path / "control-report"
    report = generate_control_report(run_dir, catalog, output, records_path=records)

    assert report["run_id"] == "run-1"
    assert report["source_bundle_sha256"] == sha256_bytes(bundle_raw)
    assert report["source_manifest_sha256"] == sha256_bytes(manifest_raw)
    assert report["control_catalog_sha256"] == sha256_file(catalog)
    assert report["manual_records_sha256"] == sha256_bytes(records_raw)
    automated_record = next(item for item in report["controls"] if item["control_id"] == "AI-ACT-12")
    manual_record = next(item for item in report["controls"] if item["control_id"] == "GDPR-5")
    assert automated_record["artifact"] == "bundle.json"
    assert manual_record["artifact"] == "DPIA-record-id"
    assert str(run_dir) not in json.dumps(report)
    assert verify_bundle(output)["valid"] is True


def test_asset_inventory_rejects_symlink_ancestors_and_copy_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite_root = tmp_path / "suite"
    assets = suite_root / "assets"
    assets.mkdir(parents=True)
    source = assets / "source.txt"
    source.write_text("pinned source\n", encoding="utf-8")
    case = {
        "id": "case-1",
        "input": [{"type": "document", "asset": "assets/source.txt", "mime_type": "text/plain"}],
    }

    linked = suite_root / "linked-assets"
    linked.symlink_to(assets, target_is_directory=True)
    linked_case = {
        "id": "case-linked",
        "input": [{"type": "document", "asset": "linked-assets/source.txt", "mime_type": "text/plain"}],
    }
    with pytest.raises(ValueError, match="symlinks are not allowed"):
        asset_inventory([linked_case], suite_root=suite_root)

    outside = tmp_path / "outside-snapshots"
    outside.mkdir()
    snapshot_parent = tmp_path / "linked-snapshot-parent"
    snapshot_parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="snapshot paths must not traverse symlinks"):
        asset_inventory([case], suite_root=suite_root, snapshot_dir=snapshot_parent / "snapshots")
    assert not (outside / "snapshots").exists()

    def drift_copy(_source: str | Path, destination: str | Path) -> str:
        Path(destination).write_text("changed during copy\n", encoding="utf-8")
        return str(destination)

    monkeypatch.setattr("cavada_eval.assets.shutil.copyfile", drift_copy)
    with pytest.raises(ValueError, match="snapshot hash mismatch"):
        asset_inventory([case], suite_root=suite_root, snapshot_dir=tmp_path / "snapshots")


def test_retention_records_require_object_manifests_and_portable_nonsecret_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "retention-run"
    run_dir.mkdir()
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text("[]\n", encoding="utf-8")
    write_bundle(run_dir)
    with pytest.raises(ProtocolError, match="manifest must be an object"):
        retention_record(run_dir, tmp_path / "list-output", action="legal-hold", actor="operator", evidence="ticket-1")

    manifest_path.write_text('{"run_id":"run-1"}\n', encoding="utf-8")
    write_bundle(run_dir)
    unsafe_references = (str(Path.home() / "evidence.txt"), "../evidence.txt", r"..\evidence.txt", r"C:evidence.txt", "api_key=" + "b" * 16)
    for index, reference in enumerate(unsafe_references):
        output = tmp_path / f"unsafe-retention-{index}"
        with pytest.raises(ProtocolError, match="portable, non-secret reference"):
            retention_record(run_dir, output, action="legal-hold", actor="operator", evidence=reference)
        assert not output.exists()

    bundle_raw = (run_dir / "bundle.json").read_bytes()
    original_retention_verify = retention_module.verify_bundle
    mutated = False

    def mutate_manifest_after_verify(path: Path, **kwargs: Any) -> dict[str, Any]:
        nonlocal mutated
        result = original_retention_verify(path, **kwargs)
        if not mutated:
            mutated = True
            manifest_path.write_text('{"run_id":"mutated-run"}\n', encoding="utf-8")
        return result

    monkeypatch.setattr(retention_module, "verify_bundle", mutate_manifest_after_verify)
    output = tmp_path / "retention-output"
    record = retention_record(run_dir, output, action="legal-hold", actor="operator", evidence="governance/ticket-1")
    assert record["run_id"] == "run-1"
    assert record["source_bundle_sha256"] == sha256_bytes(bundle_raw)
    assert record["evidence"] == "governance/ticket-1"
    assert verify_bundle(output)["valid"] is True


def test_statistics_reject_nonfinite_or_nonboolean_inputs() -> None:
    invalid_calls = (
        lambda: percentile([1.0], float("nan")),
        lambda: percentile([float("inf")], 0.5),
        lambda: distribution([float("-inf")]),
        lambda: bootstrap_mean_interval([float("nan")]),
        lambda: bootstrap_mean_interval([], confidence=float("inf")),
        lambda: stratified_bootstrap_mean_interval({"slice": [float("nan")]}),
        lambda: holm_adjust([0.1, float("inf")]),
        lambda: holm_adjust([-0.1]),
        lambda: mcnemar_exact([float("nan")], [True]),  # type: ignore[list-item]
        lambda: paired_binary_comparison({"case": float("inf")}, {"case": True}),  # type: ignore[dict-item]
    )
    for call in invalid_calls:
        with pytest.raises(ValueError):
            call()


def test_seeded_bootstrap_is_independent_of_completion_order() -> None:
    values = [1.0, 2.0, 3.0, 10.0, 100.0]
    permuted = [1.0, 2.0, 10.0, 3.0, 100.0]
    assert _metric_summary(values, 100, 1) == _metric_summary(permuted, 100, 1)
    assert bootstrap_mean_interval(values, samples=100, seed=7) == bootstrap_mean_interval(list(reversed(values)), samples=100, seed=7)
    assert stratified_bootstrap_mean_interval(
        {"a": [0.0, 1.0, 10.0], "b": [2.0, 3.0, 100.0]}, samples=100, seed=7
    ) == stratified_bootstrap_mean_interval(
        {"b": [100.0, 3.0, 2.0], "a": [10.0, 1.0, 0.0]}, samples=100, seed=7
    )
