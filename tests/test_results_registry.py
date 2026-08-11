from __future__ import annotations

import copy
import json
import runpy
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from cavada_eval.artifacts import write_bundle
from cavada_eval.performance_release import PERFORMANCE_PUBLICATION_VERSION, PERMITTED_CLAIM, export_public_performance
from cavada_eval.protocol import ProtocolError, sha256_bytes, sha256_file
from cavada_eval.public_verify import verify_public_bundle
from cavada_eval.system_evidence import public_system_evidence, system_configuration_id, validate_system_evidence

ROOT = Path(__file__).parents[1]
REGISTRY_TOOLS = runpy.run_path(str(ROOT / "scripts" / "validate_results_registry.py"))
validate_registry = cast(Callable[..., list[str]], REGISTRY_TOOLS["validate_registry"])
current_rankable_result_ids = cast(Callable[..., list[str]], REGISTRY_TOOLS["current_rankable_result_ids"])
exact_performance_release = cast(Callable[..., dict[str, Any] | None], REGISTRY_TOOLS["_exact_performance_release"])
RELEASE_TEST_HELPERS = runpy.run_path(str(ROOT / "tests" / "test_performance_release.py"))
build_performance_run = cast(Callable[..., Path], RELEASE_TEST_HELPERS["_run"])
add_execution_record = cast(Callable[..., None], RELEASE_TEST_HELPERS["_add_execution_record"])
SCHEMA_VALIDATOR = Draft202012Validator(
    json.loads((ROOT / "schemas" / "results-registry.schema.json").read_text(encoding="utf-8")),
    format_checker=FormatChecker(),
)
V2_SCHEMA_VALIDATOR = Draft202012Validator(
    json.loads((ROOT / "schemas" / "results-registry-2.0.0.schema.json").read_text(encoding="utf-8")),
    format_checker=FormatChecker(),
)


def _hash(character: str) -> str:
    return character * 64


def _artifact(character: str) -> dict[str, str]:
    return {"uri": f"https://example.test/{character}.json", "sha256": _hash(character)}


def _compatibility() -> dict[str, Any]:
    def artifact(name: str, character: str) -> dict[str, str]:
        return {"id": name, "version": "1.0.0", "sha256": _hash(character)}

    return {
        "protocol": artifact("protocol", "1"),
        "benchmark": artifact("benchmark", "2"),
        "inputs": artifact("inputs", "3"),
        "measurement": artifact("measurement", "4"),
        "parameters_sha256": _hash("5"),
        "conditions_sha256": _hash("6"),
        "source_commit": "7" * 40,
    }


def _official_system_evidence(manifest: dict[str, Any]) -> dict[str, Any]:
    started = datetime.fromisoformat(manifest["started_at"])
    evidence: dict[str, Any] = {
        "evidence_version": "1.0.0",
        "configuration_id": "",
        "projection": "restricted",
        "collected_at": (started - timedelta(minutes=1)).isoformat(),
        "collection_method": "mixed",
        "server": {
            "host_id": "registry-server",
            "os": {"name": "Linux", "version": "1", "kernel": "1"},
            "cpu": {"model": "test-cpu", "architecture": "x86_64", "sockets": 1, "physical_cores": 1, "logical_cores": 1},
            "memory": {"total_bytes": 1024},
            "numa": {"nodes": 1, "policy": "local"},
            "accelerators": [
                {
                    "index": 0,
                    "vendor": "test-vendor",
                    "model": "test-gpu",
                    "uuid": "device-registry-1",
                    "vram_bytes": 1024,
                    "pci_bus_id": "0000:01:00.0",
                    "power_limit_watts": 100,
                    "graphics_clock_limit_mhz": 1000,
                    "memory_clock_limit_mhz": 1000,
                }
            ],
            "accelerator_topology": "single accelerator",
        },
        "software": {
            "driver": {"name": "test-driver", "version": "1"},
            "compute_runtime": {"name": "test-runtime", "version": "1"},
            "engine": {
                "name": "test-engine",
                "revision": "d" * 40,
                "binary_sha256": "e" * 64,
                "container_image_digest": None,
            },
            "model": {
                "name": "test-model",
                "revision": "a" * 40,
                "artifact_sha256": "c" * 64,
                "dtype": "fp16",
                "quantization": "none",
            },
        },
        "serving": {
            "launch_command_sanitized": "test-server",
            "max_context_tokens": 10,
            "max_batch_size": 1,
            "max_batch_tokens": 8,
            "continuous_batching": True,
            "prefix_cache": False,
            "kv_cache_dtype": "fp16",
            "tensor_parallel": 1,
            "pipeline_parallel": 1,
            "data_parallel": 1,
            "parallel_slots": 1,
        },
        "load_generator": {
            "host_id": "registry-loadgen",
            "os": {"name": "Linux", "version": "1", "kernel": "1"},
            "cpu": {"model": "test-cpu", "architecture": "x86_64", "logical_cores": 1},
            "memory": {"total_bytes": 1024},
            "client": {"name": "cavadalabs-evals", "revision": "a" * 40},
            "colocated_with_server": False,
        },
        "network": {
            "relationship": "tunnel",
            "transport": "tcp",
            "endpoint_host": "127.0.0.1",
            "endpoint_port": 1,
            "route": "registry-loadgen to registry-server",
            "rtt_ms": {
                "method": "TCP connect",
                "samples": 1,
                "median": 0.1,
                "p95": 0.1,
                "measured_at": (started - timedelta(minutes=1)).isoformat(),
            },
        },
        "artifacts": [],
        "unavailable": {"/software/engine/container_image_digest": "engine was not containerized"},
    }
    evidence["configuration_id"] = system_configuration_id(evidence)
    validate_system_evidence(evidence)
    validate_system_evidence(public_system_evidence(evidence))
    return evidence


def _v2_archive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, official: bool) -> Path:
    run = build_performance_run(tmp_path, monkeypatch, open_loop=True)
    if official:
        manifest_path = run / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        evidence = _official_system_evidence(manifest)
        evidence_path = run / "system_evidence_snapshot.json"
        evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        manifest.update(
            {
                "official_requested": True,
                "officially_valid": True,
                "source": {"commit": "a" * 40, "dirty": False, "status_sha256": "b" * 64},
                "system_evidence": {
                    "configuration_id": evidence["configuration_id"],
                    "sha256": sha256_file(evidence_path),
                    "projection": "restricted",
                    "collected_at": evidence["collected_at"],
                },
            }
        )
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        write_bundle(run)
        add_execution_record(run)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        finished = datetime.fromisoformat(manifest["finished_at"])
        governance = tmp_path / "governance"
        governance.mkdir()
        review = governance / "review.txt"
        qualification = governance / "qualification.txt"
        review.write_text("Reviewed exact immutable performance bundle.", encoding="utf-8")
        qualification.write_text("Qualified performance reviewer evidence.", encoding="utf-8")
        approval = {
            "release_version": PERFORMANCE_PUBLICATION_VERSION,
            "release_id": "registry-performance-release-1",
            "status": "approved",
            "run_id": manifest["run_id"],
            "bundle_sha256": sha256_file(run / "bundle.json"),
            "manifest_sha256": sha256_file(manifest_path),
            "configuration_id": evidence["configuration_id"],
            "engagement_id": manifest["engagement"]["engagement_id"],
            "engagement_sha256": manifest["engagement"]["sha256"],
            "execution_owner_id": "executor-1",
            "approver_id": "registry-reviewer-1",
            "independent": True,
            "conflicts": [],
            "conflict_mitigation": "",
            "permitted_claims": [PERMITTED_CLAIM],
            "limitations_acknowledged": True,
            "review_evidence": review.name,
            "review_evidence_sha256": sha256_file(review),
            "qualification_evidence": qualification.name,
            "qualification_evidence_sha256": sha256_file(qualification),
            "approved_at": finished.isoformat(),
            "expires_at": (finished + timedelta(days=1)).isoformat(),
        }
        approval_path = governance / "approval.json"
        approval_path.write_text(json.dumps(approval, sort_keys=True), encoding="utf-8")
        # The reference-input gate has its own tests; keep this registry integration to one real exported request.
        for target in (
            "cavada_eval.performance._require_official_reference_inputs",
            "cavada_eval.performance_release._require_official_reference_inputs",
            "cavada_eval.public_verify._require_official_reference_inputs",
        ):
            monkeypatch.setattr(target, lambda *_args, **_kwargs: None)
        archive = tmp_path / "official-v2.tar.gz"
        export_public_performance(run, archive, approval_path=approval_path, now=finished + timedelta(minutes=1))
        return archive
    archive = tmp_path / "development-v2.tar.gz"
    export_public_performance(run, archive)
    return archive


def _extract(archive: Path, destination: Path) -> dict[str, Any]:
    destination.mkdir()
    with tarfile.open(archive) as package:
        package.extractall(destination, filter="data")
    assert verify_public_bundle(destination)["semantic_valid"] is True
    return json.loads((destination / "public_manifest.json").read_text(encoding="utf-8"))


def _v2_result(archive: Path, extracted: Path) -> dict[str, Any]:
    manifest = json.loads((extracted / "public_manifest.json").read_text(encoding="utf-8"))
    artifact = {
        "uri": "https://example.test/performance-v2.tar.gz",
        "sha256": sha256_file(archive),
        "bundle_sha256": sha256_file(extracted / "bundle.json"),
        "manifest_sha256": sha256_file(extracted / "public_manifest.json"),
    }
    release = manifest.get("release")
    published_at = release["approved_at"] if isinstance(release, dict) else manifest["evaluation_finished_at"]
    expires_at = release["expires_at"] if isinstance(release, dict) else (datetime.fromisoformat(published_at) + timedelta(days=1)).isoformat()
    source = manifest["source"]
    plan = manifest["plan"]
    workload = manifest["workload"]
    runtime = manifest["runtime"]
    official = manifest["official"] is True
    result: dict[str, Any] = {
        "id": "performance-v2-result",
        "kind": "performance",
        "run_id": manifest["run_id"],
        "published_at": published_at,
        "expires_at": expires_at,
        "evaluated_system": f"{runtime['expected_model']} on {runtime['engine']}",
        "assurance": "official" if official else "development",
        "rankable": official,
        "status": manifest["status"],
        "cells": manifest["cells"],
        "source": source,
        "artifact": artifact,
        "compatibility": {
            "protocol": {"id": "llm-serving-performance", "version": manifest["performance_protocol_version"], "sha256": manifest["protocol_sha256"]},
            "benchmark": {"id": plan["name"], "version": plan["revision"], "sha256": plan["sha256"]},
            "inputs": {"id": workload["id"], "version": workload["revision"], "sha256": workload["sha256"]},
            "measurement": {
                "id": "performance-publication",
                "version": manifest["publication_version"],
                "sha256": sha256_file(ROOT / "schemas" / "performance-publication-2.0.0.schema.json"),
            },
            "parameters_sha256": runtime["sha256"],
            "conditions_sha256": manifest["system_evidence"]["sha256"] if manifest["system_evidence"] else sha256_bytes(b"null"),
            "source_commit": source["commit"],
        },
        "claims": release["permitted_claims"] if isinstance(release, dict) else ["Development performance evidence under the declared conditions."],
        "limitations": manifest["limitations"],
    }
    if official:
        result["release_evidence"] = exact_performance_release(
            manifest,
            artifact,
            archive_sha256=artifact["sha256"],
            bundle_sha256=artifact["bundle_sha256"],
            manifest_sha256=artifact["manifest_sha256"],
        )
    return result


def _v2_registry(result: dict[str, Any]) -> dict[str, Any]:
    return {"registry_version": "2.0.0", "results": [result], "reproductions": [], "corrections": []}


def _repack(root: Path, archive: Path) -> None:
    with tarfile.open(archive, "w:gz") as package:
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                package.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)


def _rebind_archive(result: dict[str, Any], archive: Path, root: Path) -> None:
    artifact = result["artifact"]
    artifact.update(
        {
            "sha256": sha256_file(archive),
            "bundle_sha256": sha256_file(root / "bundle.json"),
            "manifest_sha256": sha256_file(root / "public_manifest.json"),
        }
    )
    release = result.get("release_evidence")
    if isinstance(release, dict):
        release["bundle_sha256"] = artifact["bundle_sha256"]
        release["manifest_sha256"] = artifact["manifest_sha256"]
        release["public_release"]["sha256"] = artifact["sha256"]


def _registry() -> dict[str, Any]:
    result_artifact = {
        "uri": "https://example.test/result.tar.gz",
        "sha256": _hash("8"),
        "bundle_sha256": _hash("9"),
        "manifest_sha256": _hash("a"),
    }
    claim = "The named run conforms to the declared protocol within its limitations."
    result = {
        "id": "result-1",
        "kind": "behavior",
        "run_id": "run-1",
        "published_at": "2026-08-05T12:00:00Z",
        "expires_at": "2027-08-05T12:00:00Z",
        "evaluated_system": "Example model revision on the declared runtime",
        "assurance": "official",
        "artifact": result_artifact,
        "compatibility": _compatibility(),
        "claims": [claim],
        "limitations": ["Applies only to the named suite and conditions."],
        "release_evidence": {
            "release_version": "1.0.0",
            "release_id": "release-1",
            "run_id": "run-1",
            "bundle_sha256": result_artifact["bundle_sha256"],
            "manifest_sha256": result_artifact["manifest_sha256"],
            "engagement_id": "engagement-1",
            "engagement_sha256": _hash("b"),
            "approval_sha256": _hash("c"),
            "assurance_level": "approved",
            "permitted_claims": [claim],
            "decision_statuses": {
                "statistical": "passed",
                "security": "passed",
                "privacy_legal": "not-applicable",
                "disclosure": "passed",
                "release": "passed",
            },
            "approved_at": "2026-08-05T11:00:00Z",
            "expires_at": "2027-08-05T12:00:00Z",
            "public_release": {"uri": result_artifact["uri"], "sha256": result_artifact["sha256"]},
        },
    }
    reproduction = {
        "id": "reproduction-1",
        "run_id": "reproduction-run-1",
        "original_result_id": "result-1",
        "original_bundle_sha256": result_artifact["bundle_sha256"],
        "published_at": "2026-08-06T12:00:00Z",
        "expires_at": "2027-08-05T12:00:00Z",
        "artifact": {
            "uri": "https://example.test/reproduction.tar.gz",
            "sha256": _hash("e"),
            "bundle_sha256": _hash("f"),
            "manifest_sha256": _hash("1"),
        },
        "compatibility": _compatibility(),
        "independence": {
            "evaluator_id": "evaluator-1",
            "organization": "Independent laboratory",
            "independent": True,
            "conflicts_disclosed": True,
            "conflicts": [],
            "conflict_mitigation": "",
            "attestation": _artifact("2"),
        },
        "comparison": {
            "outcome": "confirmed",
            "method": "Preregistered exact-cell comparison",
            "evidence": _artifact("3"),
        },
        "limitations": ["Independent replication of only the declared cells."],
    }
    return {"registry_version": "1.0.0", "results": [result], "reproductions": [reproduction], "corrections": []}


def test_empty_public_registry_is_honest_and_schema_valid() -> None:
    registry = json.loads((ROOT / "results" / "registry.json").read_text(encoding="utf-8"))
    V2_SCHEMA_VALIDATOR.validate(registry)
    assert validate_registry(registry, initial_empty=True) == []
    assert "the initial public registry must be empty" in validate_registry(_registry(), initial_empty=True)


def test_frozen_v1_registry_fixture_is_byte_identical() -> None:
    fixture = ROOT / "tests" / "fixtures" / "results-registry-v1.json"
    assert sha256_file(fixture) == "0b102dae3bf27327098e5aa8bf34ea221a96b99f1d6462c5d70469437f4c7319"
    assert sha256_file(ROOT / "schemas" / "results-registry.schema.json") == "9e81bbd7b84b3e7d7e14cb5d8a50d5c49874cd1c01f448593b1f95a16643b58d"
    assert validate_registry(json.loads(fixture.read_text(encoding="utf-8")), initial_empty=True) == []


def test_canonical_registry_uses_the_one_time_empty_v1_to_v2_migration() -> None:
    previous = json.loads((ROOT / "tests" / "fixtures" / "results-registry-v1.json").read_text(encoding="utf-8"))
    current = json.loads((ROOT / "results" / "registry.json").read_text(encoding="utf-8"))

    assert previous["registry_version"] == "1.0.0"
    assert current["registry_version"] == "2.0.0"
    assert validate_registry(current, previous=previous) == []
    assert "registry_version cannot change in place; publish a new registry version" in validate_registry(
        current,
        previous=_registry(),
    )


def test_registry_dispatch_rejects_unknown_version() -> None:
    assert validate_registry({"registry_version": "3.0.0", "results": [], "reproductions": [], "corrections": []}) == ["unsupported registry_version: 3.0.0"]


def test_real_validator_enforces_registry_schema() -> None:
    registry = _registry()
    registry["results"][0]["artifact"]["uri"] = "http://insecure.example/result.tar.gz"
    registry["results"][0]["unexpected"] = True

    errors = validate_registry(registry)

    assert any("schema" in error and "does not match" in error for error in errors)
    assert any("schema" in error and "Additional properties" in error for error in errors)


def test_registry_binds_official_release_and_exact_independent_reproduction() -> None:
    registry = _registry()
    SCHEMA_VALIDATOR.validate(registry)
    assert validate_registry(registry) == []

    registry["results"][0]["release_evidence"]["bundle_sha256"] = _hash("4")
    registry["results"][0]["release_evidence"]["decision_statuses"]["security"] = "not-applicable"
    registry["results"][0]["kind"] = "external-import"
    registry["reproductions"][0]["compatibility"]["parameters_sha256"] = _hash("8")
    errors = validate_registry(registry)
    assert any("does not match its release evidence" in error for error in errors)
    assert any("lacks passed release decisions" in error for error in errors)
    assert any("cannot be official" in error for error in errors)
    assert any("not exactly compatible" in error for error in errors)

    registry = _registry()
    registry["results"][0]["release_evidence"]["public_release"]["sha256"] = _hash("d")
    assert any("exact public artifact" in error for error in validate_registry(registry))


def test_registry_supports_exact_approved_performance_release() -> None:
    registry = _registry()
    result = registry["results"][0]
    artifact = result["artifact"]
    claim = "Bounded performance under the declared runtime and conditions."
    result.update({"kind": "performance", "claims": [claim]})
    result["release_evidence"] = {
        "release_version": "1.0.0",
        "release_id": "performance-release-1",
        "run_id": result["run_id"],
        "source_bundle_sha256": _hash("b"),
        "source_manifest_sha256": _hash("c"),
        "bundle_sha256": artifact["bundle_sha256"],
        "manifest_sha256": artifact["manifest_sha256"],
        "approval_sha256": _hash("d"),
        "approver_id": "independent-performance-reviewer",
        "permitted_claims": [claim],
        "approved_at": "2026-08-05T11:00:00Z",
        "expires_at": "2027-08-05T12:00:00Z",
        "public_release": {"uri": artifact["uri"], "sha256": artifact["sha256"]},
    }

    SCHEMA_VALIDATOR.validate(registry)
    assert validate_registry(registry) == []

    result["release_evidence"]["public_release"]["sha256"] = _hash("e")
    assert any("exact public artifact" in error for error in validate_registry(registry))


def test_v2_registry_accepts_an_actual_verified_development_export_only_as_nonrankable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _v2_archive(tmp_path, monkeypatch, official=False)
    extracted = tmp_path / "development-extracted"
    manifest = _extract(archive, extracted)
    result = _v2_result(archive, extracted)
    registry = _v2_registry(result)

    assert manifest["assurance"] == "development" and manifest["official"] is False
    assert result["assurance"] == "development" and result["rankable"] is False
    assert validate_registry(registry, artifacts={result["id"]: archive}) == []
    assert validate_registry(registry) == ["performance result performance-v2-result requires its local public artifact for offline semantic verification"]

    promoted = copy.deepcopy(registry)
    promoted["results"][0].update({"assurance": "official", "rankable": True})
    assert any("assurance or rankability" in error or "release_evidence" in error for error in validate_registry(promoted, artifacts={result["id"]: archive}))

    reduced = copy.deepcopy(registry)
    reduced["results"][0]["limitations"] = ["A substituted limitation."]
    assert any("limitations differs" in error for error in validate_registry(reduced, artifacts={result["id"]: archive}))


def test_v2_development_registry_claim_and_publication_time_are_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _v2_archive(tmp_path, monkeypatch, official=False)
    extracted = tmp_path / "development-policy-extracted"
    manifest = _extract(archive, extracted)
    result = _v2_result(archive, extracted)

    invented_claim = _v2_registry(copy.deepcopy(result))
    invented_claim["results"][0]["claims"] = ["Fastest serving system ever measured."]
    assert validate_registry(invented_claim, artifacts={result["id"]: archive}) == [
        "development performance result performance-v2-result must use the fixed development claim"
    ]

    premature = _v2_registry(copy.deepcopy(result))
    finished_at = datetime.fromisoformat(manifest["evaluation_finished_at"])
    premature["results"][0]["published_at"] = (finished_at - timedelta(microseconds=1)).isoformat()
    assert validate_registry(premature, artifacts={result["id"]: archive}) == [
        "performance result performance-v2-result cannot be published before its evaluation finished"
    ]


def test_v2_reproductions_fail_closed_without_an_exact_semantic_artifact_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _v2_archive(tmp_path, monkeypatch, official=False)
    extracted = tmp_path / "reproduction-policy-extracted"
    _extract(archive, extracted)
    result = _v2_result(archive, extracted)
    published_at = datetime.fromisoformat(result["published_at"]) + timedelta(minutes=1)
    reproduction = {
        "id": "performance-v2-reproduction",
        "run_id": "independent-run",
        "original_result_id": result["id"],
        "original_bundle_sha256": result["artifact"]["bundle_sha256"],
        "published_at": published_at.isoformat(),
        "expires_at": (published_at + timedelta(days=1)).isoformat(),
        "artifact": {
            "uri": "https://example.test/independent-performance-v2.tar.gz",
            "sha256": _hash("c"),
            "bundle_sha256": _hash("d"),
            "manifest_sha256": _hash("e"),
        },
        "compatibility": copy.deepcopy(result["compatibility"]),
        "independence": {
            "evaluator_id": "independent-evaluator",
            "organization": "Independent laboratory",
            "independent": True,
            "conflicts_disclosed": True,
            "conflicts": [],
            "conflict_mitigation": "",
            "attestation": _artifact("f"),
        },
        "comparison": {
            "outcome": "confirmed",
            "method": "Claimed exact-cell comparison",
            "evidence": _artifact("1"),
        },
        "limitations": ["No semantic reproduction artifact contract exists yet."],
    }
    registry = _v2_registry(result)
    registry["reproductions"].append(reproduction)

    V2_SCHEMA_VALIDATOR.validate(registry)
    assert validate_registry(registry, artifacts={result["id"]: archive}) == [
        "v2 reproductions are unsupported until their exact local artifacts can be semantically verified"
    ]


def test_v2_registry_accepts_an_actual_verified_official_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _v2_archive(tmp_path, monkeypatch, official=True)
    extracted = tmp_path / "official-extracted"
    manifest = _extract(archive, extracted)
    result = _v2_result(archive, extracted)

    assert manifest["publication_version"] == manifest["release"]["release_version"] == "2.0.0"
    assert manifest["status"] == "completed"
    assert manifest["cells"]["invalid_loadgen"] == manifest["cells"]["with_errors"] == 0
    assert result["assurance"] == "official" and result["rankable"] is True
    assert validate_registry(_v2_registry(result), artifacts={result["id"]: archive}) == []
    expired_at = datetime.fromisoformat(result["release_evidence"]["expires_at"])
    assert current_rankable_result_ids(_v2_registry(result), now=expired_at - timedelta(microseconds=1)) == [result["id"]]
    assert validate_registry(_v2_registry(result), artifacts={result["id"]: archive}) == []
    assert current_rankable_result_ids(_v2_registry(result), now=expired_at) == []

    class ExpiredClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            return expired_at + timedelta(days=1)

    with monkeypatch.context() as expired_clock:
        expired_clock.setattr("cavada_eval.public_verify.datetime", ExpiredClock)
        with pytest.raises(ProtocolError, match="release is not currently effective"):
            verify_public_bundle(extracted)
        assert validate_registry(_v2_registry(result), artifacts={result["id"]: archive}) == []

    withdrawn = _v2_registry(result)
    withdrawn_at = datetime.fromisoformat(result["published_at"]) + timedelta(minutes=1)
    withdrawn["corrections"].append(
        {
            "id": "withdraw-performance-v2-result",
            "published_at": withdrawn_at.isoformat(),
            "subject_kind": "result",
            "subject_id": result["id"],
            "subject_bundle_sha256": result["artifact"]["bundle_sha256"],
            "action": "withdraw",
            "reason": "The immutable result remains historical but is no longer current.",
            "notice": _artifact("4"),
            "signature": {"signer_id": "registry-reviewer-1", "method": "sigstore", **_artifact("5")},
        }
    )
    assert validate_registry(withdrawn, artifacts={result["id"]: archive}) == []
    assert current_rankable_result_ids(withdrawn, now=withdrawn_at) == []


def test_v2_registry_rejects_registry_only_identity_and_conditions_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _v2_archive(tmp_path, monkeypatch, official=False)
    extracted = tmp_path / "identity-extracted"
    _extract(archive, extracted)
    result = _v2_result(archive, extracted)
    registry = _v2_registry(result)

    substitutions = {
        "evaluated_system": (
            lambda item: item.update({"evaluated_system": "substituted system"}),
            "performance result performance-v2-result evaluated_system differs from its public manifest",
        ),
        "measurement id": (
            lambda item: item["compatibility"]["measurement"].update({"id": "substituted-measurement"}),
            "performance result performance-v2-result compatibility differs from its public manifest",
        ),
        "measurement sha256": (
            lambda item: item["compatibility"]["measurement"].update({"sha256": "f" * 64}),
            "performance result performance-v2-result compatibility differs from its public manifest",
        ),
        "conditions sha256": (
            lambda item: item["compatibility"].update({"conditions_sha256": "f" * 64}),
            "performance result performance-v2-result compatibility differs from its public manifest",
        ),
    }
    for label, (substitute, expected) in substitutions.items():
        changed = copy.deepcopy(registry)
        substitute(changed["results"][0])
        errors = validate_registry(changed, artifacts={result["id"]: archive})
        assert errors == [expected], label


def test_registry_cli_resolves_the_exact_content_addressed_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _v2_archive(tmp_path, monkeypatch, official=False)
    extracted = tmp_path / "cli-extracted"
    _extract(archive, extracted)
    result = _v2_result(archive, extracted)
    registry_dir = tmp_path / "results"
    artifact_dir = registry_dir / "artifacts"
    artifact_dir.mkdir(parents=True)
    registry_path = registry_dir / "registry.json"
    registry_path.write_text(json.dumps(_v2_registry(result)), encoding="utf-8")
    shutil.copyfile(archive, artifact_dir / f"{result['artifact']['sha256']}.tar.gz")

    completed = subprocess.run(  # noqa: S603 - fixed local interpreter and repository script
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_results_registry.py"),
            str(registry_path),
            "--previous",
            str(ROOT / "tests" / "fixtures" / "results-registry-v1.json"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout == "Results registry is valid\nCurrent rankable results: none\n"


@pytest.mark.parametrize("target", ["status", "schedule", "measurement_denominator", "throughput_denominator", "rate", "release"])
def test_v2_registry_rejects_tamper_and_reseal_across_semantic_and_release_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    archive = _v2_archive(tmp_path, monkeypatch, official=True)
    extracted = tmp_path / "tampered"
    _extract(archive, extracted)
    result = _v2_result(archive, extracted)
    manifest_path = extracted / "public_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if target == "status":
        manifest["status"] = "completed-with-errors"
        result["status"] = manifest["status"]
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    elif target == "schedule":
        observations = [json.loads(line) for line in (extracted / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
        observations[0]["scheduled_monotonic_ns"] += 1_000_000
        (extracted / "observations.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in observations),
            encoding="utf-8",
        )
    elif target in {"measurement_denominator", "throughput_denominator", "rate"}:
        cells = [json.loads(line) for line in (extracted / "cells.jsonl").read_text(encoding="utf-8").splitlines()]
        field = {
            "measurement_denominator": "measurement_window_seconds",
            "throughput_denominator": "throughput_window_seconds",
            "rate": "requests_per_second",
        }[target]
        cells[0][field] = float(cells[0][field]) + 1.0
        (extracted / "cells.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in cells),
            encoding="utf-8",
        )
    else:
        manifest["release"]["approval_sha256"] = "f" * 64
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    write_bundle(extracted)
    tampered_archive = tmp_path / f"{target}.tar.gz"
    _repack(extracted, tampered_archive)
    _rebind_archive(result, tampered_archive, extracted)

    errors = validate_registry(
        _v2_registry(result),
        artifacts={result["id"]: tampered_archive},
    )

    expected = "does not exactly match its public release projection" if target == "release" else "public artifact verification failed"
    assert any(expected in error for error in errors)


def test_v2_registry_rejects_tampered_archive_linkage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _v2_archive(tmp_path, monkeypatch, official=True)
    extracted = tmp_path / "linkage-extracted"
    _extract(archive, extracted)
    result = _v2_result(archive, extracted)
    result["artifact"]["sha256"] = "f" * 64
    result["release_evidence"]["public_release"]["sha256"] = "f" * 64

    assert any("archive bytes" in error for error in validate_registry(_v2_registry(result), artifacts={result["id"]: archive}))


def test_corrections_are_signed_additions_and_prior_records_are_immutable() -> None:
    previous = _registry()
    current = copy.deepcopy(previous)
    replacement = copy.deepcopy(current["results"][0])
    replacement.update(
        {
            "id": "result-2",
            "run_id": "run-2",
            "published_at": "2026-08-07T09:00:00Z",
            "assurance": "compatible",
            "claims": ["Replacement result under the exact declared conditions."],
            "artifact": {
                "uri": "https://example.test/result-2.tar.gz",
                "sha256": _hash("6"),
                "bundle_sha256": _hash("7"),
                "manifest_sha256": _hash("8"),
            },
        }
    )
    replacement.pop("release_evidence")
    current["results"].append(replacement)
    current["corrections"].append(
        {
            "id": "correction-1",
            "published_at": "2026-08-07T10:00:00Z",
            "subject_kind": "result",
            "subject_id": "result-1",
            "subject_bundle_sha256": _hash("9"),
            "action": "supersede",
            "replacement_id": "result-2",
            "reason": "A replacement run corrects the disclosed defect.",
            "notice": _artifact("4"),
            "signature": {"signer_id": "release-reviewer", "method": "sigstore", **_artifact("5")},
        }
    )
    SCHEMA_VALIDATOR.validate(current)
    assert validate_registry(current, previous=previous) == []

    current["results"][0]["limitations"].append("Retrospectively edited.")
    assert any("preserve every previous record" in error for error in validate_registry(current, previous=previous))

    cycle = copy.deepcopy(current)
    cycle["corrections"].append(
        {
            "id": "correction-2",
            "published_at": "2026-08-07T11:00:00Z",
            "subject_kind": "result",
            "subject_id": "result-2",
            "subject_bundle_sha256": _hash("7"),
            "action": "supersede",
            "replacement_id": "result-1",
            "reason": "Invalid circular replacement fixture.",
            "notice": _artifact("6"),
            "signature": {"signer_id": "release-reviewer", "method": "sigstore", **_artifact("7")},
        }
    )
    assert any("supersession cycle" in error for error in validate_registry(cycle))
