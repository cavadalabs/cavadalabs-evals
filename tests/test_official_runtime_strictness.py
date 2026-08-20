from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cavada_eval.behavior_verify import (
    OFFICIAL_MANIFEST_FIELDS,
    OFFICIAL_METRIC_FIELDS,
    _official_manifest_structure_errors,
)
from cavada_eval.calibration import judge_evidence_errors
from cavada_eval.metrics import METRIC_VERSION
from cavada_eval.profiles import ADAPTER_CONTRACT_VERSION
from cavada_eval.protocol import (
    MANIFEST_SCHEMA_VERSION,
    OFFICIAL_CASE_FIELDS,
    OFFICIAL_SUITE_FIELDS,
    REPORT_VERSION,
    ProtocolError,
    load_suite,
)

ROOT = Path(__file__).parents[1]


def _schema(name: str) -> dict[str, Any]:
    value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_runtime_contract_versions_and_fields_match_v2_schemas() -> None:
    case = _schema("case-2.0.0.schema.json")
    suite = _schema("suite-2.0.0.schema.json")
    manifest = _schema("manifest-2.1.0.schema.json")
    metrics = _schema("metrics-2.0.0.schema.json")

    assert set(case["properties"]) == OFFICIAL_CASE_FIELDS
    assert set(suite["properties"]) == OFFICIAL_SUITE_FIELDS
    assert set(manifest["properties"]) == OFFICIAL_MANIFEST_FIELDS
    assert set(metrics["properties"]) == OFFICIAL_METRIC_FIELDS
    assert manifest["properties"]["schema_version"]["const"] == MANIFEST_SCHEMA_VERSION
    assert manifest["properties"]["metric_version"]["const"] == METRIC_VERSION
    assert manifest["properties"]["report_version"]["const"] == REPORT_VERSION
    assert manifest["properties"]["adapter_contract_version"]["const"] == ADAPTER_CONTRACT_VERSION
    assert case["properties"]["exact_tool_order"] == {
        "type": "array",
        "items": {"type": "string", "minLength": 1},
    }


def test_official_load_rejects_unknown_nested_fields_and_non_strict_request_defaults(tmp_path: Path) -> None:
    root = tmp_path / "suite"
    root.mkdir()
    content = [{"type": "text", "text": "Question", "unexpected": True}]
    case = {
        "id": "one",
        "input": content,
        "messages": [{"role": "user", "content": content, "unexpected": True}],
        "category": "quality",
        "risk_domain": "quality",
        "severity": "low",
        "language": "en",
        "locale": "en-US",
        "split": "holdout",
        "tags": ["strict"],
        "expected_behavior": "answer",
        "expected_behavior_reason": "Answer the question.",
        "source": {"origin": "synthetic", "unexpected": True},
        "review": {"status": "approved", "method": "reviewed", "unexpected": True},
        "unexpected": True,
    }
    (root / "dataset.jsonl").write_text(json.dumps(case) + "\n", encoding="utf-8")
    (root / "rubric.md").write_text("Judge the answer.\n", encoding="utf-8")
    (root / "suite.toml").write_text(
        '''protocol_version = "1.0.0"
name = "strict-v1"
version = "1.0.0"
status = "approved"
description = "Strict fixture"
profile = "text-generation"
dataset = "dataset.jsonl"
rubric = "rubric.md"
data_classification = "synthetic"

[target]
kind = "json"
request_defaults_json = '{"value":1,"value":2}'
capabilities = ["text"]

[statistics]
confidence = 0.95
bootstrap_samples = 1000
seed = 0
unexpected = true

[[gates]]
metric = "pass_rate_ci.lower"
min = 0.8
''',
        encoding="utf-8",
    )

    with pytest.raises(ProtocolError) as caught:
        load_suite(root, official=True)
    message = str(caught.value)
    for expected in (
        "suite.statistics has unknown fields: ['unexpected']",
        "case[1] has unknown fields: ['unexpected']",
        "case[1].input[0] has unknown fields: ['unexpected']",
        "case[1].messages[0] has unknown fields: ['unexpected']",
        "case[1].source has unknown fields: ['unexpected']",
        "case[1].review has unknown fields: ['unexpected']",
        "duplicate JSON key: value",
    ):
        assert expected in message


def test_official_manifest_and_metrics_reject_nested_unknown_fields() -> None:
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "metric_version": METRIC_VERSION,
        "target": {"unexpected": True},
        "judge": {"models": [{"unexpected": True}]},
        "environment": {"hardware": {"unexpected": True}},
        "metrics": {"performance": {"unexpected": True}},
    }
    failures = _official_manifest_structure_errors(manifest)
    assert "official manifest.target has unknown fields: ['unexpected']" in failures
    assert "official manifest.judge.models[0] has unknown fields: ['unexpected']" in failures
    assert "official manifest.environment.hardware has unknown fields: ['unexpected']" in failures
    assert "official metrics.performance has unknown fields: ['unexpected']" in failures


def test_judge_qualification_rejects_unknown_nested_fields() -> None:
    qualification = {
        "bundle_verification": {"valid": True, "unexpected": True},
        "judge_configuration": {"models": [{"unexpected": True}]},
        "judges": {},
    }
    errors = judge_evidence_errors(
        qualification,
        {},
        qualification_sha256="0" * 64,
        expected_judge={},
        rubric_sha256="0" * 64,
    )
    assert "judge qualification.bundle_verification has unknown fields: ['unexpected']" in errors
    assert "judge qualification.judge_configuration.models[0] has unknown fields: ['unexpected']" in errors
