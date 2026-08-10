from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from cavada_eval.artifacts import verify_bundle
from cavada_eval.external import LM_EVAL_ADAPTER, VLLM_BENCH_ADAPTER, import_external_results
from cavada_eval.protocol import ProtocolError, sha256_file


def _write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _source(name: str) -> dict[str, str]:
    return {
        "name": name,
        "version": "1.2.3",
        "commit": "e" * 40,
        "license": "Apache-2.0",
        "dataset_sha256": "a" * 64,
        "evaluator_sha256": "b" * 64,
        "invocation": f"{name} --offline",
    }


def _identity(*, runtime: str = "hf") -> dict[str, str]:
    return {
        "model_id": "org/model",
        "model_revision": "revision-1",
        "model_sha": "d" * 64,
        "runtime_name": runtime,
        "runtime_version": "9.8.7",
        "runtime_revision": "runtime-revision-1",
    }


def _lm_artifact() -> dict[str, Any]:
    return {
        "results": {"hellaswag": {"alias": "HellaSwag", "acc,none": 0.75, "acc_stderr,none": 0.03}},
        "configs": {"hellaswag": {"task": "hellaswag", "dataset_path": "Rowan/hellaswag"}},
        "versions": {"hellaswag": 1.0},
        "n-shot": {"hellaswag": 0},
        "higher_is_better": {"hellaswag": {"acc,none": True}},
        "n-samples": {"hellaswag": {"original": 100, "effective": 100}},
        "task_hashes": {"hellaswag": "f" * 64},
        "config": {"model": "hf"},
        "git_hash": "e" * 12,
        "lm_eval_version": "1.2.3",
        "model_source": "hf",
        "model_name": "org/model",
        "future_upstream_field": {"preserved": True},
    }


def _lm_descriptor(artifact: Path) -> dict[str, Any]:
    return {
        "adapter_version": LM_EVAL_ADAPTER,
        "artifact": artifact.name,
        "artifact_sha256": sha256_file(artifact),
        "source": _source("lm-evaluation-harness"),
        "identity": _identity(),
        "suite": {"id": "lm-eval-core", "version": "1.0.0", "sha256": "c" * 64},
        "evaluation_repository_commit": "e" * 40,
        "outcomes": {"hellaswag": {"status": "pass", "reason": "frozen gate acc >= 0.70"}},
    }


def _vllm_artifact() -> dict[str, Any]:
    return {
        "date": "2026-08-07T00:00:00Z",
        "endpoint_type": "openai-chat",
        "backend": "openai-chat",
        "model_id": "org/model",
        "num_prompts": 2,
        "request_rate": "inf",
        "max_concurrency": 2,
        "duration": 2.0,
        "completed": 2,
        "failed": 0,
        "total_input_tokens": 20,
        "total_output_tokens": 10,
        "request_throughput": 1.0,
        "output_throughput": 5.0,
        "mean_ttft_ms": 10.0,
        "future_upstream_field": {"preserved": True},
    }


def _vllm_descriptor(artifact: Path) -> dict[str, Any]:
    return {
        "adapter_version": VLLM_BENCH_ADAPTER,
        "artifact": artifact.name,
        "artifact_sha256": sha256_file(artifact),
        "source": _source("vllm"),
        "identity": _identity(runtime="vllm"),
        "suite": {"id": "serving-grid", "version": "1.0.0", "sha256": "c" * 64},
        "cell_id": "ctx128-out64-c2",
        "cell_sha256": "d" * 64,
        "endpoint_backend": "openai-chat",
        "outcome": {"status": "pass", "reason": "frozen cell SLOs passed"},
    }


def _result(output: Path) -> dict[str, Any]:
    return json.loads((output / "imported_results.json").read_text(encoding="utf-8"))[0]


def test_lm_eval_adapter_pins_identity_and_preserves_raw_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "lm-eval-results.json"
    _write(artifact, _lm_artifact())
    descriptor = tmp_path / "lm-eval-import.json"
    _write(descriptor, _lm_descriptor(artifact))

    output = tmp_path / "import"
    manifest = import_external_results(descriptor, output)

    assert manifest["adapter"] == LM_EVAL_ADAPTER
    assert manifest["official"] is False
    assert manifest["status_counts"]["pass"] == 1
    assert _result(output)["task"]["id"] == "hellaswag"
    assert _result(output)["task"]["sha256"] == "f" * 64
    assert (output / "upstream_artifact.json").read_bytes() == artifact.read_bytes()
    assert verify_bundle(output)["valid"] is True


def test_lm_eval_adapter_never_invents_an_unmapped_outcome(tmp_path: Path) -> None:
    artifact = tmp_path / "lm-eval-results.json"
    _write(artifact, _lm_artifact())
    value = _lm_descriptor(artifact)
    value["outcomes"] = {}
    descriptor = tmp_path / "lm-eval-import.json"
    _write(descriptor, value)

    output = tmp_path / "import"
    import_external_results(descriptor, output)

    assert _result(output)["status"] == "invalid"
    assert "no explicit outcome" in _result(output)["status_evidence"]["reason"]


def test_lm_eval_adapter_fails_closed_on_identity_or_artifact_mismatch(tmp_path: Path) -> None:
    artifact = tmp_path / "lm-eval-results.json"
    _write(artifact, _lm_artifact())
    value = _lm_descriptor(artifact)
    value["identity"]["model_id"] = "other/model"
    descriptor = tmp_path / "lm-eval-import.json"
    _write(descriptor, value)

    output = tmp_path / "import"
    with pytest.raises(ProtocolError, match="model/runtime identity"):
        import_external_results(descriptor, output)
    assert not output.exists()

    value = _lm_descriptor(artifact)
    value["source"]["version"] = "9.9.9"
    _write(descriptor, value)
    with pytest.raises(ProtocolError, match="version differs"):
        import_external_results(descriptor, output)
    assert not output.exists()

    value = _lm_descriptor(artifact)
    value["identity"]["model_sha"] = "mutable-name"
    _write(descriptor, value)
    with pytest.raises(ProtocolError, match="model_sha must be a lowercase SHA-256"):
        import_external_results(descriptor, output)
    assert not output.exists()

    value = _lm_descriptor(artifact)
    value["artifact_sha256"] = "0" * 64
    _write(descriptor, value)
    with pytest.raises(ProtocolError, match="artifact hash"):
        import_external_results(descriptor, output)
    assert not output.exists()


def test_vllm_adapter_imports_one_explicitly_identified_cell(tmp_path: Path) -> None:
    artifact = tmp_path / "vllm-result.json"
    _write(artifact, _vllm_artifact())
    descriptor = tmp_path / "vllm-import.json"
    _write(descriptor, _vllm_descriptor(artifact))

    output = tmp_path / "import"
    manifest = import_external_results(descriptor, output)

    assert manifest["adapter"] == VLLM_BENCH_ADAPTER
    assert manifest["upstream_artifact"]["sha256"] == sha256_file(artifact)
    assert _result(output)["case_id"] == "ctx128-out64-c2"
    assert _result(output)["status"] == "pass"
    assert verify_bundle(output)["valid"] is True


@pytest.mark.parametrize(
    ("changes", "expected_status"),
    [
        ({"completed": 1, "failed": 1, "errors": ["", "connection reset"]}, "error"),
        ({"completed": 1, "failed": 1}, "invalid"),
        ({"completed": 1, "failed": 0}, "invalid"),
    ],
)
def test_vllm_adapter_maps_failure_and_missing_evidence_fail_closed(tmp_path: Path, changes: dict[str, Any], expected_status: str) -> None:
    upstream = _vllm_artifact()
    upstream.update(changes)
    artifact = tmp_path / "vllm-result.json"
    _write(artifact, upstream)
    descriptor = tmp_path / "vllm-import.json"
    _write(descriptor, _vllm_descriptor(artifact))

    output = tmp_path / "import"
    import_external_results(descriptor, output)

    assert _result(output)["status"] == expected_status


def test_vllm_adapter_rejects_skipped_claim_for_completed_work(tmp_path: Path) -> None:
    artifact = tmp_path / "vllm-result.json"
    _write(artifact, _vllm_artifact())
    value = _vllm_descriptor(artifact)
    value["outcome"] = {"status": "skipped", "reason": "operator marked skipped"}
    descriptor = tmp_path / "vllm-import.json"
    _write(descriptor, value)

    output = tmp_path / "import"
    with pytest.raises(ProtocolError, match="cannot be mapped to skipped"):
        import_external_results(descriptor, output)
    assert not output.exists()


def test_external_import_rejects_unimplemented_generic_adapter_before_output(tmp_path: Path) -> None:
    descriptor = tmp_path / "generic.json"
    _write(descriptor, {"adapter_version": "1.0.0", "source": _source("generic"), "suite": {}, "results": []})
    output = tmp_path / "import"

    with pytest.raises(ProtocolError, match="unsupported external adapter"):
        import_external_results(descriptor, output)
    assert not output.exists()


def test_external_descriptor_schema_matches_both_built_in_adapters(tmp_path: Path) -> None:
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "external-import.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    lm_artifact = tmp_path / "lm.json"
    vllm_artifact = tmp_path / "vllm.json"
    _write(lm_artifact, _lm_artifact())
    _write(vllm_artifact, _vllm_artifact())

    validator.validate(_lm_descriptor(lm_artifact))
    validator.validate(_vllm_descriptor(vllm_artifact))
