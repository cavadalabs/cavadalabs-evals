from __future__ import annotations

import json
import os
import runpy
import subprocess
import tarfile
from collections.abc import Callable
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from cavada_eval.protocol import ProtocolError, sha256_file
from cavada_eval.results_registry import (
    _attestation_binding_errors,
    _read_archive,
    _tar_bytes,
    build_public_evidence_archive,
    verify_github_attestation,
    verify_public_evidence_archive,
)

ROOT = Path(__file__).parents[1]
TOOLS = runpy.run_path(str(ROOT / "scripts" / "validate_results_registry.py"))
validate_registry = cast(Callable[..., list[str]], TOOLS["validate_registry"])
NOW = datetime(2026, 8, 20, 12, tzinfo=timezone.utc)


def test_registry_v1_is_exactly_empty() -> None:
    registry = json.loads((ROOT / "results" / "registry.json").read_text(encoding="utf-8"))
    assert validate_registry(registry, initial_empty=True) == []


def test_registry_v1_fails_closed_on_any_result() -> None:
    registry: dict[str, Any] = {"registry_version": "1.0.0", "results": [{"rankable": False}]}
    assert "must remain empty" in "\n".join(validate_registry(registry))


def _canonical_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _evidence(tmp_path: Path) -> tuple[Path, dict[str, Any], dict[str, Any], Callable[..., dict[str, Any]], Callable[..., dict[str, Any]]]:
    results = tmp_path / "results"
    source = tmp_path / "source"
    (source / "run").mkdir(parents=True)
    (source / "governance").mkdir()
    behavior = {
        "artifact_type": "behavior-run",
        "valid": True,
        "integrity_valid": True,
        "semantic_valid": True,
        "assurance_valid": True,
        "failures": [],
    }
    manifest = {
        "protocol_version": "1.0.0",
        "assurance": "conformance-fixture",
        "suite": {"name": "synthetic-test-only", "version": "0.0.0"},
        "target": {"expected_reported_model": "synthetic-target", "revision": "test-only"},
    }
    (source / "run" / "bundle.json").write_text('{"fixture":true}\n', encoding="utf-8")
    (source / "run" / "manifest.json").write_text(_canonical_json(manifest), encoding="utf-8")
    (source / "run" / "verification.json").write_text(_canonical_json(behavior), encoding="utf-8")
    (source / "governance" / "engagement.json").write_text('{"fixture":"engagement"}\n', encoding="utf-8")
    (source / "governance" / "release-approval.json").write_text('{"fixture":"release"}\n', encoding="utf-8")
    archive = build_public_evidence_archive(
        source,
        results / "archive" / "sha256",
        references={
            "run_bundle": "run/bundle.json",
            "engagement": "governance/engagement.json",
            "release_approval": "governance/release-approval.json",
            "verification_result": "run/verification.json",
        },
    )
    digest = archive.stem
    record: dict[str, Any] = {
        "record_version": "2.0.0",
        "record_id": "synthetic-conformance-1",
        "record_type": "conformance",
        "archive": {
            "relative_path": f"archive/sha256/{digest}.tar",
            "sha256": digest,
            "format": "cavada-public-evidence-tar",
            "format_version": "1.0.0",
        },
        "artifact_type": "behavior-run",
        "suite": {"name": "synthetic-test-only", "version": "0.0.0"},
        "system": {"identity": "synthetic-target", "revision": "test-only"},
        "protocol_version": "1.0.0",
        "assurance_level": "conformance-fixture",
        "verification_result_sha256": sha256_file(source / "run" / "verification.json"),
        "release_approval_sha256": sha256_file(source / "governance" / "release-approval.json"),
        "published_at": "2026-08-20T10:00:00Z",
        "expires_at": "2026-08-21T10:00:00Z",
        "claim_scope": [],
        "rankable": False,
        "model_claim_allowed": False,
        "benchmark_claim_allowed": False,
        "reproduction_status": "not-reproduced",
        "attestation": None,
    }
    registry = {
        "registry_version": "2.0.0",
        "records": [record],
        "events": [
            {
                "event_version": "2.0.0",
                "event_id": "published-synthetic-1",
                "record_id": record["record_id"],
                "event_type": "published",
                "occurred_at": record["published_at"],
                "previous_event_id": None,
                "related_record_id": None,
                "reason": "Synthetic conformance fixture for registry tests only.",
            }
        ],
    }

    def behavior_verifier(_run: Path, **_options: object) -> dict[str, Any]:
        return behavior

    def release_verifier(_run: Path, _engagement: Path, _approval: Path, **_options: object) -> dict[str, Any]:
        return {
            "assurance_level": "conformance-fixture",
            "permitted_claims": [],
            "model_claim_allowed": False,
            "benchmark_claim_allowed": False,
            "expires_at": record["expires_at"],
        }

    return results, registry, record, behavior_verifier, release_verifier


def test_registry_v2_is_empty_by_default_and_reconstructs_nonrankable_conformance(tmp_path: Path) -> None:
    empty = json.loads((ROOT / "results" / "registry-v2.json").read_text(encoding="utf-8"))
    assert validate_registry(empty, root=ROOT / "results", initial_empty=True, now=NOW) == []

    results, registry, _record, behavior, release = _evidence(tmp_path)
    calls: list[str] = []

    def checked_behavior(*args: object, **kwargs: object) -> dict[str, Any]:
        calls.append("behavior")
        return behavior(*args, **kwargs)

    def checked_release(*args: object, **kwargs: object) -> dict[str, Any]:
        calls.append("release")
        return release(*args, **kwargs)

    assert validate_registry(registry, root=results, now=NOW, behavior_verifier=checked_behavior, release_verifier=checked_release) == []
    assert calls == ["behavior", "release"]


def test_archive_is_deterministic_immutable_and_semantically_reconstructed(tmp_path: Path) -> None:
    results, registry, record, behavior, release = _evidence(tmp_path)
    archive = results / record["archive"]["relative_path"]
    verified = verify_public_evidence_archive(
        archive,
        expected_digest=record["archive"]["sha256"],
        now=NOW,
        behavior_verifier=behavior,
        release_verifier=release,
    )
    assert verified["valid"] is True

    with pytest.raises(ProtocolError, match="immutable"):
        source = tmp_path / "source"
        build_public_evidence_archive(
            source,
            results / "archive" / "sha256",
            references={
                "run_bundle": "run/bundle.json",
                "engagement": "governance/engagement.json",
                "release_approval": "governance/release-approval.json",
                "verification_result": "run/verification.json",
            },
        )

    raw = bytearray(archive.read_bytes())
    raw[512] ^= 1
    archive.write_bytes(raw)
    failures = "\n".join(validate_registry(registry, root=results, now=NOW, behavior_verifier=behavior, release_verifier=release))
    assert any(fragment in failures for fragment in ("digest does not match", "not a readable", "not strict JSON"))


def test_registry_rejects_an_intact_archive_with_invalid_behavior_semantics(tmp_path: Path) -> None:
    results, registry, _record, _behavior, release = _evidence(tmp_path)

    def invalid_behavior(_run: Path, **_options: object) -> dict[str, Any]:
        return {"valid": False, "integrity_valid": True, "semantic_valid": False, "assurance_valid": False, "failures": ["tampered aggregate"]}

    failures = "\n".join(
        validate_registry(registry, root=results, now=NOW, behavior_verifier=invalid_behavior, release_verifier=release)
    )
    assert "archived behavior run is not semantically and assuredly valid" in failures
    assert "archived verification result does not equal canonical reconstruction" in failures


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_archive_rejects_link_members(tmp_path: Path, kind: str) -> None:
    output = tmp_path / f"{kind}.tar"
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("unsafe")
        member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
        member.linkname = "target"
        archive.addfile(member)
    assert "link or non-regular" in "\n".join(verify_public_evidence_archive(output)["failures"])


def test_archive_rejects_traversal_extra_file_filesystem_symlink_and_hardlink(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.tar"
    with tarfile.open(traversal, "w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        archive.addfile(member, __import__("io").BytesIO(b"x"))
    assert "unsafe or non-canonical" in "\n".join(verify_public_evidence_archive(traversal)["failures"])

    results, _registry, record, _behavior, _release = _evidence(tmp_path / "extra")
    original = results / record["archive"]["relative_path"]
    _digest, manifest, files = _read_archive(original)
    files["extra.txt"] = b"undeclared\n"
    extra = tmp_path / "extra.tar"
    extra.write_bytes(_tar_bytes(files))
    assert "closed file set differs" in "\n".join(verify_public_evidence_archive(extra)["failures"])

    symlink = tmp_path / "archive-link.tar"
    symlink.symlink_to(original)
    assert "non-symlink" in "\n".join(verify_public_evidence_archive(symlink)["failures"])

    hardlink = tmp_path / "archive-hardlink.tar"
    os.link(original, hardlink)
    assert "non-hard-linked" in "\n".join(verify_public_evidence_archive(original)["failures"])


def test_registry_v2_is_strict_append_only_and_fail_closed_for_claims(tmp_path: Path) -> None:
    results, registry, record, behavior, release = _evidence(tmp_path)
    previous = deepcopy(registry)
    changed = deepcopy(registry)
    changed["records"][0]["rankable"] = True
    errors = validate_registry(changed, root=results, previous=previous, now=NOW, behavior_verifier=behavior, release_verifier=release)
    assert "registry records are not append-only" in errors
    assert "conformance records cannot be rankable" in "\n".join(errors)

    changed = deepcopy(registry)
    changed["records"][0]["unexpected"] = True
    assert "fields are not exact" in "\n".join(
        validate_registry(changed, root=results, now=NOW, behavior_verifier=behavior, release_verifier=release)
    )

    changed = deepcopy(registry)
    changed["events"] = []
    assert "must begin with one published event" in "\n".join(
        validate_registry(changed, root=results, previous=previous, now=NOW, behavior_verifier=behavior, release_verifier=release)
    )

    changed = deepcopy(registry)
    changed["records"][0]["record_type"] = "official"
    changed["records"][0]["assurance_level"] = "official"
    changed["records"][0]["claim_scope"] = ["claim"]
    assert "registry attestation must be an object" in "\n".join(
        validate_registry(changed, root=results, now=NOW, behavior_verifier=behavior, release_verifier=release)
    )
    assert record["attestation"] is None


def test_registry_lifecycle_contains_one_publication_event(tmp_path: Path) -> None:
    results, registry, _record, behavior, release = _evidence(tmp_path)
    registry["events"].append(
        {
            **registry["events"][0],
            "event_id": "published-synthetic-again",
            "occurred_at": "2026-08-20T11:00:00Z",
            "previous_event_id": "published-synthetic-1",
        }
    )

    failures = validate_registry(
        registry,
        root=results,
        now=NOW,
        behavior_verifier=behavior,
        release_verifier=release,
    )

    assert "registry record synthetic-conformance-1 must contain exactly one published event" in failures


def _attestation(record: dict[str, Any], archive: Path) -> dict[str, Any]:
    return {
        "attestation_version": "1.0.0",
        "provider": "github-artifact-attestations",
        "subject_name": archive.name,
        "subject_sha256": record["archive"]["sha256"],
        "repository": "cavadalabs/cavadalabs-evals",
        "signer_workflow": "cavadalabs/cavadalabs-evals/.github/workflows/release.yml",
        "source_commit": "a" * 40,
        "source_ref": "refs/tags/v0.4.0",
        "protocol_version": "1.0.0",
        "schema_version": "2.0.0",
    }


def test_attestation_binding_and_online_subject_are_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    results, _registry, record, _behavior, _release = _evidence(tmp_path)
    archive = results / record["archive"]["relative_path"]
    attestation = _attestation(record, archive)
    assert _attestation_binding_errors(attestation, record, archive) == []

    def completed(subject: dict[str, Any]) -> subprocess.CompletedProcess[str]:
        output = [{"verificationResult": {"statement": {"subject": [subject]}}}]
        return subprocess.CompletedProcess([], 0, json.dumps(output), "")

    monkeypatch.setattr(
        "cavada_eval.results_registry.subprocess.run",
        lambda *_args, **_kwargs: completed({"name": archive.name, "digest": {"sha256": record["archive"]["sha256"]}}),
    )
    assert verify_github_attestation(archive, attestation) == []

    monkeypatch.setattr(
        "cavada_eval.results_registry.subprocess.run",
        lambda *_args, **_kwargs: completed({"name": "other.tar", "digest": {"sha256": "b" * 64}}),
    )
    assert "exact expected subject" in "\n".join(verify_github_attestation(archive, attestation))

    tampered = {**attestation, "subject_sha256": "b" * 64}
    assert "subject_sha256 does not match" in "\n".join(_attestation_binding_errors(tampered, record, archive))
