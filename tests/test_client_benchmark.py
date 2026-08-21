from __future__ import annotations

import json
import time
import tomllib
from pathlib import Path
from typing import Any

import pytest

from cavada_eval import client_benchmark
from cavada_eval.client_benchmark import load_client_benchmark, plan_client_benchmark, run_client_benchmark
from cavada_eval.performance import load_performance_plan, performance_plan_summary
from cavada_eval.protocol import ProtocolError


def _benchmark_files(root: Path, *, source: str = 'dataset = "dataset.jsonl"', max_requests: int = 20) -> Path:
    (root / "dataset.jsonl").write_text(
        json.dumps({"id": "ctx-8", "context_tokens": 8, "prompt": "Count to two."}) + "\n",
        encoding="utf-8",
    )
    config = root / "benchmark.toml"
    config.write_text(
        f'''benchmark_version = "1.0.0"
name = "client-test"
{source}
concurrency = [1, 2]
warmup_requests = 1
duration_seconds = 0.05
repetitions = 1
timeout = 2
max_requests = {max_requests}
output_tokens = 2
data_classification = "synthetic"

[target]
endpoint = "http://127.0.0.1:8000/v1"
model = "test-model"
model_revision = "model-revision-1"
api_key_env = "CLIENT_BENCHMARK_TOKEN"
''',
        encoding="utf-8",
    )
    return config


def test_load_plan_and_run_delegate_without_serializing_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _benchmark_files(tmp_path)
    loaded = load_client_benchmark(config)
    planned = plan_client_benchmark(loaded, tmp_path / "planned")

    assert planned.plan.config["profile"] == "client-benchmark-v1"
    assert planned.plan.config["scenarios"][0]["duration_seconds"] == 0.05
    assert planned.runtime.config.get("pricing") is None
    assert planned.runtime.config["hardware_observed"] is False
    assert planned.runtime.config["gpu_count"] == 0
    assert planned.runtime.config["tensor_parallel"] == 0
    assert planned.runtime.config["engine_revision"] == "not-observed"
    assert planned.runtime.config["model_artifact_revision"] == "not-observed"
    assert "gpu_count = 1" not in planned.runtime.path.read_text(encoding="utf-8")
    assert performance_plan_summary(planned.plan, planned.runtime)["planned_requests_is_upper_bound"] is True

    api_key_value = "opaque-client-test-value"
    monkeypatch.setenv("CLIENT_BENCHMARK_TOKEN", api_key_value)
    result = tmp_path / "delegated-result"

    def fake_run(plan: Any, runtime: Any, **kwargs: Any) -> Path:
        assert plan.config["profile"] == "client-benchmark-v1"
        assert runtime.config["api_key_env"] == "CLIENT_BENCHMARK_TOKEN"
        assert kwargs["repo_root"] == tmp_path
        assert api_key_value not in plan.path.read_text(encoding="utf-8")
        assert api_key_value not in runtime.path.read_text(encoding="utf-8")
        return result

    monkeypatch.setattr(client_benchmark, "run_performance_campaign", fake_run)
    assert run_client_benchmark(loaded, repo_root=tmp_path) == result


def test_missing_api_key_fails_before_transport(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _benchmark_files(tmp_path)
    monkeypatch.delenv("CLIENT_BENCHMARK_TOKEN", raising=False)
    calls = 0

    def forbidden_transport(*_args: Any, **_kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        nonlocal calls
        calls += 1
        raise AssertionError("transport must not run without the configured credential")

    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", forbidden_transport)
    with pytest.raises(ProtocolError, match="CLIENT_BENCHMARK_TOKEN.*not set.*no network request"):
        run_client_benchmark(config, repo_root=tmp_path)
    assert calls == 0


def test_trusted_factory_is_materialized_before_core_validation(tmp_path: Path) -> None:
    config = _benchmark_files(tmp_path, source='factory = "trusted_dataset:make"')
    (tmp_path / "trusted_dataset.py").write_text(
        "def make():\n    return [{'id': 'factory-8', 'context_tokens': 8, 'prompt': 'Factory prompt.'}]\n",
        encoding="utf-8",
    )
    with pytest.raises(ProtocolError, match="explicit trust_factory=True"):
        load_client_benchmark(config)
    loaded = load_client_benchmark(config, trust_factory=True)
    assert b"Factory prompt." in loaded.workload_bytes
    planned = plan_client_benchmark(loaded, tmp_path / "factory-plan")
    assert planned.plan.workload[0]["id"] == "factory-8"


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ('dataset = "../dataset.jsonl"', "canonical relative path"),
        ('dataset = "dataset.jsonl"\nfactory = "trusted_dataset:make"', "exactly one"),
        ('factory = "not-a-module:make"', "module:callable"),
    ],
)
def test_client_source_contract_fails_closed(tmp_path: Path, source: str, message: str) -> None:
    config = _benchmark_files(tmp_path, source=source)
    with pytest.raises(ProtocolError, match=message):
        load_client_benchmark(config)


def test_dataset_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    config = _benchmark_files(tmp_path)
    (tmp_path / "dataset.jsonl").write_text('{"id":"one","id":"two","context_tokens":8,"prompt":"x"}\n', encoding="utf-8")
    with pytest.raises(ProtocolError, match="strict UTF-8 JSONL"):
        load_client_benchmark(config)


def test_official_profile_still_rejects_closed_loop_duration(tmp_path: Path) -> None:
    planned = plan_client_benchmark(load_client_benchmark(_benchmark_files(tmp_path)), tmp_path / "planned")
    source = planned.plan.path.read_text(encoding="utf-8").replace('profile = "client-benchmark-v1"', 'profile = "llm-serving-v1"')
    official_path = planned.directory / "official-plan.toml"
    official_path.write_text(source.replace("duration_seconds = 0.05\n", ""), encoding="utf-8")
    official_plan = load_performance_plan(official_path)
    with pytest.raises(ProtocolError, match="plan and runtime profiles are incompatible"):
        performance_plan_summary(official_plan, planned.runtime)
    planned.plan.path.write_text(source, encoding="utf-8")
    with pytest.raises(ProtocolError, match="closed-loop scenario .* cannot define duration_seconds"):
        load_performance_plan(planned.plan.path)


def test_duration_closed_loop_uses_existing_transport_and_request_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _benchmark_files(tmp_path, max_requests=8)
    api_key_value = "opaque-transport-test-value"
    observed_keys: list[str] = []
    monkeypatch.setenv("CLIENT_BENCHMARK_TOKEN", api_key_value)

    def fake_post(_url: str, _payload: dict[str, Any], api_key: str, _timeout: float, *, request_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        observed_keys.append(api_key)
        time.sleep(0.005)
        return (
            {
                "model": "test-model",
                "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                "stream_events": [],
            },
            {
                "ttft_ms": 1.0,
                "total_ms": 2.0,
                "headers_ms": 0.5,
                "inter_chunk_ms": [],
                "request_bytes": 100,
                "response_bytes": 100,
                "request_id": request_id,
            },
        )

    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", fake_post)
    run_dir = run_client_benchmark(config, repo_root=Path.cwd(), output_root=tmp_path / "runs")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    observations = [json.loads(line) for line in (run_dir / "observations.jsonl").read_text(encoding="utf-8").splitlines()]

    assert sum(row["status"] == "success" for row in observations) == 6
    assert len({row["cell_key"] for row in observations}) == 2
    assert all(row.get("error_type") != "request-budget" for row in observations)
    assert manifest["requests"] == 8
    assert manifest["planned_requests_is_upper_bound"] is True
    assert manifest["estimated_cost"] is None
    assert any("hardware was not observed" in limitation for limitation in summary["limitations"])
    report = (run_dir / "report.html").read_text(encoding="utf-8")
    assert "not official performance evidence" in report
    assert "used for official performance evidence" not in report
    assert observed_keys and set(observed_keys) == {api_key_value}
    assert tomllib.loads((run_dir / "plan_snapshot.toml").read_text(encoding="utf-8"))["profile"] == "client-benchmark-v1"
    assert all(api_key_value.encode() not in path.read_bytes() for path in run_dir.rglob("*") if path.is_file())


def test_duration_stops_closed_loop_without_reaching_request_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _benchmark_files(tmp_path, max_requests=100)
    source = config.read_text(encoding="utf-8").replace("concurrency = [1, 2]", "concurrency = [1]")
    config.write_text(source, encoding="utf-8")
    monkeypatch.setenv("CLIENT_BENCHMARK_TOKEN", "opaque-duration-test-value")

    def fake_post(_url: str, _payload: dict[str, Any], _api_key: str, _timeout: float, *, request_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        time.sleep(0.005)
        return (
            {"model": "test-model", "usage": {"prompt_tokens": 8, "completion_tokens": 2}, "stream_events": []},
            {"ttft_ms": 1.0, "total_ms": 2.0, "request_id": request_id},
        )

    monkeypatch.setattr("cavada_eval.performance._post_openai_stream", fake_post)
    run_dir = run_client_benchmark(config, repo_root=Path.cwd(), output_root=tmp_path / "runs")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    observations = [json.loads(line) for line in (run_dir / "observations.jsonl").read_text(encoding="utf-8").splitlines()]

    assert 2 <= len(observations) < 100
    assert manifest["requests"] == len(observations) + 1
    assert all(row.get("error_type") != "request-budget" for row in observations)


def test_explicit_pricing_is_preserved_without_a_builtin_catalog(tmp_path: Path) -> None:
    config = _benchmark_files(tmp_path)
    config.write_text(
        config.read_text(encoding="utf-8")
        + '''
[target.pricing]
currency = "EUR"
source = "client-contract"
effective_at = "2026-08-01T00:00:00Z"
input_per_million = 0.1
output_per_million = 0.4
''',
        encoding="utf-8",
    )
    planned = plan_client_benchmark(load_client_benchmark(config), tmp_path / "priced")
    assert planned.runtime.config["pricing"] == {
        "currency": "EUR",
        "source": "client-contract",
        "effective_at": "2026-08-01T00:00:00Z",
        "input_per_million": 0.1,
        "output_per_million": 0.4,
    }
