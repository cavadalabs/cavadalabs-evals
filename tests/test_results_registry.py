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
    attestable_archive_sha256,
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
        "rankable": False,
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
            "permitted_claims": ["The synthetic fixture traversed the named protocol path."],
            "model_claim_allowed": False,
            "benchmark_claim_allowed": False,
            "approved_at": "2026-08-20T09:00:00Z",
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
    assert calls == ["behavior", "release", "behavior", "release"]


def test_release_attests_only_canonical_official_archives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / f"{'a' * 64}.tar"
    archive.write_bytes(b"archive")
    reconstructed: dict[str, Any] = {
        "valid": True,
        "archive_sha256": "a" * 64,
        "failures": [],
        "behavior_manifest": {"assurance": "conformance-fixture"},
        "release_verification": {"assurance_level": "conformance-fixture"},
    }
    monkeypatch.setattr("cavada_eval.results_registry.verify_public_evidence_archive", lambda *_args, **_kwargs: reconstructed)
    assert attestable_archive_sha256(archive) is None
    wrong_name = tmp_path / "not-content-addressed.tar"
    wrong_name.write_bytes(b"archive")
    with pytest.raises(ProtocolError, match="content-addressed filename"):
        attestable_archive_sha256(wrong_name)

    reconstructed["behavior_manifest"] = {"assurance": "official"}
    reconstructed["release_verification"] = {
        "assurance_level": "approved",
        "model_claim_allowed": True,
        "benchmark_claim_allowed": True,
        "permitted_claims": ["bounded-model-and-benchmark-claim"],
    }
    assert attestable_archive_sha256(archive) == "a" * 64

    reconstructed["valid"] = False
    reconstructed["failures"] = ["semantic mismatch"]
    with pytest.raises(ProtocolError, match="semantic mismatch"):
        attestable_archive_sha256(archive)


def test_active_record_rechecks_current_assurance_but_terminal_history_remains_valid(tmp_path: Path) -> None:
    results, registry, record, behavior, release = _evidence(tmp_path)
    declared = behavior(Path("unused"))
    publication = datetime.fromisoformat(record["published_at"].replace("Z", "+00:00"))

    def expires_after_publication(_run: Path, **options: object) -> dict[str, Any]:
        verification_now = options.get("now")
        if verification_now == publication:
            return declared
        return {**declared, "valid": False, "assurance_valid": False, "failures": ["qualification expired"]}

    active_errors = validate_registry(
        registry,
        root=results,
        now=NOW,
        behavior_verifier=expires_after_publication,
        release_verifier=release,
    )
    assert "current assurance" in "\n".join(active_errors)

    registry["events"].append(
        {
            "event_version": "2.0.0",
            "event_id": "withdrawn-synthetic-1",
            "record_id": record["record_id"],
            "event_type": "withdrawn",
            "occurred_at": "2026-08-20T11:00:00Z",
            "previous_event_id": "published-synthetic-1",
            "related_record_id": None,
            "reason": "Synthetic current assurance expired in this lifecycle test.",
        }
    )
    assert validate_registry(
        registry,
        root=results,
        now=NOW,
        behavior_verifier=expires_after_publication,
        release_verifier=release,
    ) == []


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


def test_archive_publish_race_cannot_overwrite_an_existing_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results, _registry, record, _behavior, _release = _evidence(tmp_path)
    archive = results / record["archive"]["relative_path"]
    source = tmp_path / "source"
    original = archive.read_bytes()
    archive.unlink()
    real_link = os.link

    def concurrent_publish(source_path: Path, output_path: Path, **options: object) -> None:
        output_path.write_bytes(b"concurrent immutable archive")
        real_link(source_path, output_path, **options)

    monkeypatch.setattr("cavada_eval.results_registry.os.link", concurrent_publish)
    with pytest.raises(ProtocolError, match="immutable"):
        build_public_evidence_archive(
            source,
            archive.parent,
            references={
                "run_bundle": "run/bundle.json",
                "engagement": "governance/engagement.json",
                "release_approval": "governance/release-approval.json",
                "verification_result": "run/verification.json",
            },
        )
    assert archive.read_bytes() == b"concurrent immutable archive"
    assert archive.read_bytes() != original


def test_registry_rejects_an_intact_archive_with_invalid_behavior_semantics(tmp_path: Path) -> None:
    results, registry, _record, _behavior, release = _evidence(tmp_path)

    def invalid_behavior(_run: Path, **_options: object) -> dict[str, Any]:
        return {"valid": False, "integrity_valid": True, "semantic_valid": False, "assurance_valid": False, "failures": ["tampered aggregate"]}

    failures = "\n".join(
        validate_registry(registry, root=results, now=NOW, behavior_verifier=invalid_behavior, release_verifier=release)
    )
    assert "archived behavior run is not semantically and assuredly valid" in failures
    assert "archived verification result does not equal canonical reconstruction" in failures


def test_registry_binds_rankability_to_canonical_behavior_verification(tmp_path: Path) -> None:
    results, registry, _record, behavior, release = _evidence(tmp_path)

    def overclaiming_behavior(*args: object, **kwargs: object) -> dict[str, Any]:
        return {**behavior(*args, **kwargs), "rankable": True}

    failures = "\n".join(
        validate_registry(registry, root=results, now=NOW, behavior_verifier=overclaiming_behavior, release_verifier=release)
    )
    assert "rankable does not match canonical behavior verification" in failures


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_archive_rejects_link_members(tmp_path: Path, kind: str) -> None:
    output = tmp_path / f"{kind}.tar"
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("unsafe")
        member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
        member.linkname = "target"
        archive.addfile(member)
    assert "link or non-regular" in "\n".join(verify_public_evidence_archive(output)["failures"])


def test_archive_rejects_file_descendant_path_collision(tmp_path: Path) -> None:
    output = tmp_path / "file-descendant.tar"
    output.write_bytes(_tar_bytes({"evidence-archive.json": b"{}\n", "x": b"file", "x/y": b"child"}))
    assert "file/descendant path collision" in "\n".join(verify_public_evidence_archive(output)["failures"])


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


def test_archive_rejects_false_semantic_reference_metadata(tmp_path: Path) -> None:
    results, _registry, record, _behavior, _release = _evidence(tmp_path)
    original = results / record["archive"]["relative_path"]
    _digest, manifest, files = _read_archive(original)
    replacement = next(item for item in manifest["files"] if item["relative_path"] == "run/manifest.json")
    manifest["run_bundle"] = replacement
    files["evidence-archive.json"] = _canonical_json(manifest).encode()
    forged = tmp_path / "forged-reference.tar"
    forged.write_bytes(_tar_bytes(files))
    failures = "\n".join(verify_public_evidence_archive(forged)["failures"])
    assert "archive run_bundle metadata or canonical basename is invalid" in failures


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


@pytest.mark.parametrize("event_type", ["corrected", "superseded"])
def test_registry_correction_and_supersession_are_append_only(tmp_path: Path, event_type: str) -> None:
    results, registry, record, behavior, release = _evidence(tmp_path)
    previous = deepcopy(registry)
    source = tmp_path / "source"
    approval = source / "governance" / "release-approval.json"
    approval.write_text('{"fixture":"replacement release"}\n', encoding="utf-8")
    replacement_archive = build_public_evidence_archive(
        source,
        results / "archive" / "sha256",
        references={
            "run_bundle": "run/bundle.json",
            "engagement": "governance/engagement.json",
            "release_approval": "governance/release-approval.json",
            "verification_result": "run/verification.json",
        },
    )
    replacement = deepcopy(record)
    replacement.update(
        record_id=f"synthetic-conformance-{event_type}",
        archive={
            **replacement["archive"],
            "relative_path": f"archive/sha256/{replacement_archive.name}",
            "sha256": replacement_archive.stem,
        },
        release_approval_sha256=sha256_file(approval),
        published_at="2026-08-20T10:30:00Z",
    )
    registry["records"].append(replacement)
    registry["events"].extend(
        [
            {
                "event_version": "2.0.0",
                "event_id": f"published-{event_type}-replacement",
                "record_id": replacement["record_id"],
                "event_type": "published",
                "occurred_at": replacement["published_at"],
                "previous_event_id": None,
                "related_record_id": None,
                "reason": f"Synthetic {event_type} replacement for registry tests.",
            },
            {
                "event_version": "2.0.0",
                "event_id": f"{event_type}-synthetic-1",
                "record_id": record["record_id"],
                "event_type": event_type,
                "occurred_at": "2026-08-20T11:00:00Z",
                "previous_event_id": registry["events"][0]["event_id"],
                "related_record_id": replacement["record_id"],
                "reason": f"Synthetic {event_type} lifecycle test.",
            },
        ]
    )

    assert validate_registry(
        registry,
        root=results,
        previous=previous,
        now=NOW,
        behavior_verifier=behavior,
        release_verifier=release,
    ) == []


def test_withdrawal_preserves_the_content_addressed_evidence(tmp_path: Path) -> None:
    results, registry, record, behavior, release = _evidence(tmp_path)
    previous = deepcopy(registry)
    archive = results / record["archive"]["relative_path"]
    archive_digest = sha256_file(archive)
    registry["events"].append(
        {
            "event_version": "2.0.0",
            "event_id": "withdrawn-synthetic-1",
            "record_id": record["record_id"],
            "event_type": "withdrawn",
            "occurred_at": "2026-08-20T11:00:00Z",
            "previous_event_id": registry["events"][0]["event_id"],
            "related_record_id": None,
            "reason": "Synthetic withdrawal that must preserve historical evidence.",
        }
    )

    assert validate_registry(
        registry,
        root=results,
        previous=previous,
        now=NOW,
        behavior_verifier=behavior,
        release_verifier=release,
    ) == []
    assert sha256_file(archive) == archive_digest

    archive.unlink()
    failures = validate_registry(
        registry,
        root=results,
        previous=previous,
        now=NOW,
        behavior_verifier=behavior,
        release_verifier=release,
    )
    assert "public evidence archive is missing" in "\n".join(failures)


def test_registry_rejects_duplicate_public_evidence_record(tmp_path: Path) -> None:
    results, registry, record, behavior, release = _evidence(tmp_path)
    duplicate = deepcopy(record)
    duplicate["record_id"] = "synthetic-conformance-duplicate"
    registry["records"].append(duplicate)
    registry["events"].append(
        {
            **registry["events"][0],
            "event_id": "published-synthetic-duplicate",
            "record_id": duplicate["record_id"],
        }
    )

    failures = "\n".join(
        validate_registry(registry, root=results, now=NOW, behavior_verifier=behavior, release_verifier=release)
    )
    assert "duplicate registry archive digest" in failures
    assert "duplicate registry release approval digest" in failures


def test_registry_rejects_future_publication_and_lifecycle_events(tmp_path: Path) -> None:
    results, registry, _record, behavior, release = _evidence(tmp_path)
    registry["records"][0]["published_at"] = "2026-08-21T11:00:00Z"
    registry["events"][0]["occurred_at"] = "2026-08-21T11:00:00Z"
    failures = validate_registry(
        registry,
        root=results,
        now=NOW,
        behavior_verifier=behavior,
        release_verifier=release,
    )
    assert "registry records[0].published_at is in the future" in failures
    assert "registry events[0].occurred_at is in the future" in failures


def test_expired_record_preserves_historically_valid_evidence(tmp_path: Path) -> None:
    results, registry, record, behavior, release = _evidence(tmp_path)
    registry["events"].append(
        {
            "event_version": "2.0.0",
            "event_id": "expired-synthetic-1",
            "record_id": record["record_id"],
            "event_type": "expired",
            "occurred_at": record["expires_at"],
            "previous_event_id": registry["events"][0]["event_id"],
            "related_record_id": None,
            "reason": "The synthetic approval reached its recorded expiry.",
        }
    )
    observed_times: list[datetime] = []

    def historical_release(*args: object, **kwargs: object) -> dict[str, Any]:
        observed_times.append(cast(datetime, kwargs["now"]))
        return release(*args, **kwargs)

    errors = validate_registry(
        registry,
        root=results,
        now=datetime(2026, 8, 22, 12, tzinfo=timezone.utc),
        behavior_verifier=behavior,
        release_verifier=historical_release,
    )
    assert errors == []
    assert observed_times == [datetime.fromisoformat(record["published_at"].replace("Z", "+00:00"))]


def test_registry_rejects_publication_before_release_approval(tmp_path: Path) -> None:
    results, registry, _record, behavior, release = _evidence(tmp_path)

    def postdated_release(*args: object, **kwargs: object) -> dict[str, Any]:
        return {**release(*args, **kwargs), "approved_at": "2026-08-20T11:00:00Z"}

    failures = validate_registry(
        registry,
        root=results,
        now=NOW,
        behavior_verifier=behavior,
        release_verifier=postdated_release,
    )
    assert "registry record synthetic-conformance-1 was published before its release approval" in failures


def test_archive_uses_the_default_release_verifier_and_rejects_invalid_approval(tmp_path: Path) -> None:
    results, _registry, record, behavior, _release = _evidence(tmp_path)
    archive = results / record["archive"]["relative_path"]

    verified = verify_public_evidence_archive(
        archive,
        expected_digest=record["archive"]["sha256"],
        now=NOW,
        behavior_verifier=behavior,
    )

    assert verified["valid"] is False
    assert "public release verification failed" in "\n".join(verified["failures"])


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


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("attestation_version", "9.0.0", "attestation_version does not match"),
        ("provider", "other-provider", "provider does not match"),
        ("subject_name", "other.tar", "subject_name does not match"),
        ("subject_sha256", "b" * 64, "subject_sha256 does not match"),
        ("repository", "other/repository", "repository does not match"),
        ("signer_workflow", "other/workflow.yml", "signer_workflow must identify"),
        ("source_commit", "not-a-commit", "source_commit must be a full lowercase Git commit"),
        ("source_ref", "refs/heads/main", "source_ref must be an immutable release tag ref"),
        ("protocol_version", "9.0.0", "protocol_version does not match"),
        ("schema_version", "9.0.0", "schema_version does not match"),
    ],
)
def test_attestation_metadata_is_strictly_bound(
    tmp_path: Path,
    field: str,
    value: str,
    expected: str,
) -> None:
    results, _registry, record, _behavior, _release = _evidence(tmp_path)
    archive = results / record["archive"]["relative_path"]
    attestation = _attestation(record, archive)
    attestation[field] = value

    assert expected in "\n".join(_attestation_binding_errors(attestation, record, archive))


def test_historical_source_ref_is_accepted_for_two_phase_registration(tmp_path: Path) -> None:
    results, _registry, record, _behavior, _release = _evidence(tmp_path)
    archive = results / record["archive"]["relative_path"]
    attestation = {**_attestation(record, archive), "source_ref": "refs/tags/v0.4.0", "source_commit": "1" * 40}

    assert _attestation_binding_errors(attestation, record, archive) == []
