from __future__ import annotations

import json
import shutil
from pathlib import Path

from jsonschema import Draft202012Validator

from cavada_eval.artifacts import verify_bundle, write_bundle
from cavada_eval.performance import verify_performance_source_bundle
from cavada_eval.protocol import sha256_file

ROOT = Path(__file__).parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "performance-v1.0-source"
BUNDLE = FIXTURE_ROOT / "bundle"
PROVENANCE_SHA256 = "81c7743a3aad2b6b68920bbdb21cf9dd7bbdc0a29979ca3797e3fa61dd163e9a"
BUNDLE_SHA256 = "e17a15176850513123541116a23a4e7f81917578ebeebab2ce73a2a5587f31c2"
MANIFEST_SCHEMAS = (
    ROOT / "schemas" / "performance-manifest.schema.json",
    ROOT / "schemas" / "performance-manifest-1.1.0.schema.json",
    ROOT / "schemas" / "performance-manifest-2.0.0.schema.json",
)


def _provenance() -> dict[str, object]:
    return json.loads((FIXTURE_ROOT / "provenance.json").read_text(encoding="utf-8"))


def test_historical_v1_source_fixture_has_frozen_integrity_only_assurance() -> None:
    assert sha256_file(FIXTURE_ROOT / "provenance.json") == PROVENANCE_SHA256
    assert sha256_file(BUNDLE / "bundle.json") == BUNDLE_SHA256
    provenance = _provenance()
    source = provenance["source"]
    bundle = provenance["bundle"]
    assert isinstance(source, dict) and isinstance(bundle, dict)
    manifest = json.loads((BUNDLE / "manifest.json").read_text(encoding="utf-8"))

    assert source["commit"] == "9fd83112f0fd62e7dd1832cb50eb1c4a3671cbd7"
    assert manifest["source"] == {
        "commit": "9fd83112f0fd62e7dd1832cb50eb1c4a3671cbd7",
        "dirty": False,
        "status_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    assert manifest["performance_protocol_version"] == manifest["plan_version"] == manifest["report_version"] == "1.0.0"
    assert sha256_file(BUNDLE / "bundle.json") == bundle["sha256"]
    assert sha256_file(BUNDLE / "manifest.json") == bundle["manifest_sha256"]
    assert verify_bundle(BUNDLE) == {"valid": True, "failures": [], "signature": "absent", "files": 18}
    assert verify_performance_source_bundle(BUNDLE) == {
        "valid": True,
        "semantic_valid": False,
        "type": "performance",
        "performance_protocol_version": "1.0.0",
        "assurance": "legacy-hash-only",
        "official": False,
        "rankable": False,
        "authenticity": "unverified",
        "bundle_signature": "absent",
    }

    protocol = provenance["protocol"]
    schemas = provenance["schemas"]
    assert isinstance(protocol, dict) and isinstance(schemas, dict)
    assert sha256_file(ROOT / "PERFORMANCE_PROTOCOL_V1_0.md") == protocol["sha256"]
    assert (ROOT / "PERFORMANCE_PROTOCOL.md").read_bytes() == (ROOT / "PERFORMANCE_PROTOCOL_V1_0.md").read_bytes()
    for name, digest in schemas.items():
        assert sha256_file(ROOT / "schemas" / name) == digest
    schema = json.loads((ROOT / "schemas" / "performance-manifest.schema.json").read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(manifest)) == []
    matching = [
        path.name
        for path in MANIFEST_SCHEMAS
        if not list(Draft202012Validator(json.loads(path.read_text(encoding="utf-8"))).iter_errors(manifest))
    ]
    assert matching == ["performance-manifest.schema.json"]


def test_historical_v1_cells_remain_byte_frozen_without_v2_fields() -> None:
    bundle = _provenance()["bundle"]
    assert isinstance(bundle, dict)
    assert sha256_file(BUNDLE / "cells.jsonl") == bundle["cells_sha256"]
    cells = [json.loads(line) for line in (BUNDLE / "cells.jsonl").read_text(encoding="utf-8").splitlines() if line]
    assert len(cells) == 1
    assert set(cells[0]) == {
        "actual_output_tokens",
        "arrival",
        "block",
        "cell_key",
        "client_queue_ms",
        "concurrency",
        "context_tokens",
        "decode_tokens_per_second",
        "e2e_ms",
        "error_rate",
        "error_types",
        "errors",
        "estimated_cost",
        "goodput_requests",
        "goodput_requests_per_second",
        "input_tokens",
        "input_tokens_per_second",
        "input_tokens_total",
        "measurement_window_seconds",
        "observations",
        "output_tokens",
        "output_tokens_per_second",
        "output_tokens_total",
        "request_rate",
        "requests_per_second",
        "scenario_id",
        "slo_gates",
        "slo_passed",
        "status",
        "successes",
        "tpot_ms",
        "ttft_ms",
        "warnings",
    }
    assert "throughput_window_seconds" not in cells[0]
    assert not any(key.startswith("load_generator") for key in cells[0])
    assert _provenance()["public_bundle"] == {
        "applicable": False,
        "reason": "The pinned source had no performance public exporter, public verifier, performance publication schema, or perf export command.",
    }


def test_historical_v1_claims_cannot_promote_hash_only_evidence(tmp_path: Path) -> None:
    forged = tmp_path / "forged"
    shutil.copytree(BUNDLE, forged)
    manifest_path = forged / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["official"] = True
    manifest["officially_valid"] = True
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    write_bundle(forged)

    result = verify_performance_source_bundle(forged)
    assert result["assurance"] == "legacy-hash-only"
    assert (result["semantic_valid"], result["official"], result["rankable"]) == (False, False, False)
