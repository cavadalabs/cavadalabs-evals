from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from cavada_eval.metrics import _json_schema_errors

ROOT = Path(__file__).parents[1]
SCHEMAS = ROOT / "schemas"
RELEASED_ASSETS_CHECK = ROOT / "scripts" / "check_released_assets.py"
NEW_IDS = {
    "https://schemas.cavadalabs.com/evals/case/2.0.0",
    "https://schemas.cavadalabs.com/evals/suite/2.0.0",
    "https://schemas.cavadalabs.com/evals/manifest/2.0.0",
    "https://schemas.cavadalabs.com/evals/metrics/2.0.0",
    "https://schemas.cavadalabs.com/evals/judge-qualification-blueprint/1.0.0",
    "https://schemas.cavadalabs.com/evals/judge-qualification-blueprint-approval/1.0.0",
    "https://schemas.cavadalabs.com/evals/suite-calibration/2.0.0",
    "https://schemas.cavadalabs.com/evals/suite-calibration-approval/2.0.0",
    "https://schemas.cavadalabs.com/evals/semantic-contamination/2.0.0",
    "https://schemas.cavadalabs.com/evals/judge-qualification/2.0.0",
    "https://schemas.cavadalabs.com/evals/judge-approval/2.0.0",
    "https://schemas.cavadalabs.com/evals/results-registry/1.0.0",
}


def _schemas() -> dict[str, tuple[Path, dict[str, Any]]]:
    loaded: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(SCHEMAS.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(value, dict)
        identifier = value.get("$id")
        assert isinstance(identifier, str), path
        assert identifier not in loaded, f"duplicate $id {identifier}: {loaded[identifier][0]} and {path}"
        loaded[identifier] = path, value
    return loaded


def _object_nodes(value: Any, location: str = "$") -> list[tuple[str, dict[str, Any]]]:
    nodes: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        declared_type = value.get("type")
        if declared_type == "object" or isinstance(declared_type, list) and "object" in declared_type:
            nodes.append((location, value))
        for name, child in value.items():
            nodes.extend(_object_nodes(child, f"{location}/{name}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            nodes.extend(_object_nodes(child, f"{location}/{index}"))
    return nodes


def test_new_schema_ids_are_present_and_globally_unique() -> None:
    assert NEW_IDS <= set(_schemas())


def test_new_object_contracts_are_closed_and_dynamic_maps_are_typed() -> None:
    schemas = _schemas()
    for identifier in NEW_IDS:
        path, schema = schemas[identifier]
        for location, node in _object_nodes(schema):
            assert "additionalProperties" in node, f"{path}:{location} is implicitly open"
            additional = node["additionalProperties"]
            if "properties" in node:
                assert additional is False, f"{path}:{location} is a contractual object but remains open"
            else:
                assert isinstance(additional, dict) and additional, f"{path}:{location} has an untyped dynamic payload"


def test_existing_minimal_validator_rejects_nested_unknown_fields() -> None:
    case_schema = _schemas()["https://schemas.cavadalabs.com/evals/case/2.0.0"][1]
    message_schema = case_schema["$defs"]["message"]
    errors = _json_schema_errors(
        {"role": "user", "content": "hello", "unexpected": "not contracted"},
        message_schema,
        "$.messages[0]",
    )
    assert "$.messages[0].unexpected is not allowed" in errors


def test_released_assets_remain_byte_frozen() -> None:
    result = subprocess.run(  # noqa: S603 -- fixed interpreter and repository-owned script.
        [sys.executable, str(RELEASED_ASSETS_CHECK), "--root", str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_conformance_schema_requires_recorded_target_and_non_claiming_manifest() -> None:
    schemas = _schemas()
    suite = schemas["https://schemas.cavadalabs.com/evals/suite/2.0.0"][1]
    manifest = schemas["https://schemas.cavadalabs.com/evals/manifest/2.0.0"][1]
    registry = schemas["https://schemas.cavadalabs.com/evals/results-registry/1.0.0"][1]
    condition = suite["allOf"][0]
    assert condition["then"]["required"] == ["target"]
    assert condition["then"]["properties"]["target"]["properties"]["kind"] == {"const": "recorded"}
    assert condition["then"]["properties"]["report"]["properties"] == {
        "model_claim_allowed": {"const": False},
        "benchmark_claim_allowed": {"const": False},
    }
    assert {"assurance", "model_claim_allowed", "benchmark_claim_allowed"} <= set(manifest["required"])
    assert manifest["$defs"]["target"]["properties"]["request_model"] == {"$ref": "#/$defs/nullableNonEmpty"}
    assert "official" in manifest["$defs"]["parameters"]["properties"]["mode"]["enum"]
    assert registry["properties"]["results"]["maxItems"] == 0


def test_qualification_schema_declares_the_runtime_minimum_evidence() -> None:
    qualification = _schemas()["https://schemas.cavadalabs.com/evals/judge-qualification/2.0.0"][1]
    result = qualification["$defs"]["judgeResult"]["properties"]
    assert result["checks"]["minItems"] == result["checks"]["maxItems"] == 4
    assert result["checks"]["uniqueItems"] is True
    assert result["modules"]["minProperties"] == 1
