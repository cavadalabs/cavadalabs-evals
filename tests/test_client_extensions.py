from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from collections.abc import Awaitable, Mapping
from pathlib import Path
from typing import cast

from cavada_eval.evaluators import (
    CallableEvaluator,
    EvalCase,
    EvaluationResult,
    contains,
    exact_match,
    json_fields,
    json_valid,
    normalized_match,
    regex_match,
    retrieval_metrics,
    serve_evaluators,
    token_f1_score,
)
from cavada_eval.targets import (
    CallableTarget,
    JSONValue,
    OpenAICompatibleTarget,
    RecordedTarget,
    TargetInvocationError,
    TargetResponse,
    serve_target,
)


def _post(endpoint: str, value: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    request = urllib.request.Request(endpoint, data=json.dumps(value).encode(), headers={"Content-Type": "application/json"}, method="POST")  # noqa: S310
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        parsed = json.loads(response.read())
    assert isinstance(parsed, dict)
    return cast(dict[str, JSONValue], parsed)


def test_callable_targets_normalize_sync_async_and_hide_errors() -> None:
    sync_target = CallableTarget(
        "sync",
        lambda case: {
            "output": f"hello {case['id']}",
            "usage": {"input_tokens": 2, "output_tokens": 2},
            "latency": {"total_ms": 12.0},
            "citations": [{"id": "source-1"}],
            "retrieval": ["source-1"],
            "tool_calls": [{"name": "lookup"}],
            "trace": [{"step": "answer"}],
            "metadata": {"tenant": "test"},
        },
        "sync-model",
        "revision-1",
        ("text", "retrieval"),
    )
    direct = sync_target({"id": "one"})
    assert not isinstance(direct, Awaitable)
    assert direct["answer"] == "hello one" and direct["model"] == "sync-model"
    assert direct["retrieval"] == ["source-1"] and direct["raw"]["output"] == "hello one"  # type: ignore[index]
    assert direct["latency"] == {"total_ms": 12.0}
    assert direct["metadata"] == {"tenant": "test"}

    async def async_call(case: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
        await asyncio.sleep(0)
        return {"answer": f"async {case['id']}", "model": "reported-async", "raw": {"provider_id": "r-1"}}

    async_target = CallableTarget("async", async_call, "requested-async", "revision-2")
    with serve_target(async_target) as endpoint:
        served = _post(endpoint, {"client_case": {"id": "two", "input": "question"}})
    assert served["answer"] == "async two" and served["model"] == "reported-async"
    assert served["raw"] == {"provider_id": "r-1"}

    def secret_failure(_case: Mapping[str, JSONValue]) -> str:
        raise RuntimeError("provider-secret-value")

    with serve_target(CallableTarget("broken", secret_failure, "model")) as endpoint:
        try:
            _post(endpoint, {"client_case": {"id": "bad", "input": "question"}})
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode()
        else:
            raise AssertionError("failed target unexpectedly returned success")
    assert status == 500 and "invocation failed" in body and "provider-secret-value" not in body


def test_openai_configuration_is_inert_and_recorded_targets_preserve_raw_evidence(tmp_path: Path) -> None:
    target = OpenAICompatibleTarget("http://127.0.0.1:8000/v1", "requested-model", "openai")
    try:
        target({"input": "question"})
    except TargetInvocationError as exc:
        assert "canonical evaluator transport" in str(exc)
    else:
        raise AssertionError("OpenAI target bypassed the canonical evaluator transport")

    recorded = tmp_path / "responses.jsonl"
    recorded.write_text(json.dumps({"case_id": "case-1", "response": {"output": "recorded", "usage": {"total_tokens": 1}}}) + "\n", encoding="utf-8")
    recorded_response = RecordedTarget("recorded", recorded, "recorded-model", "sha256:test")({"id": "case-1"})
    assert recorded_response["answer"] == "recorded" and recorded_response["usage"] == {"total_tokens": 1}


def test_builtin_evaluators_use_expected_fields_and_expose_config_identity() -> None:
    response: TargetResponse = {"answer": "  Hello WORLD ", "model": "target"}
    case = EvalCase(
        "case-1",
        "prompt",
        {
            "answer": "hello world",
            "pattern": r"Hello\s+WORLD",
            "json": {"answer.value": 3},
            "docs": ["doc-a", "doc-b"],
        },
    )
    assert exact_match(expected_field="answer")(case, response).passed is False  # type: ignore[union-attr]
    normalized = normalized_match(expected_field="answer")
    assert normalized(case, response).passed is True  # type: ignore[union-attr]
    assert normalized.required_capabilities == ("text",) and len(normalized.config_id) == 64
    assert normalized.config == {"type": "normalized-match", "expected_field": "answer"}
    assert token_f1_score("answer", 1.0)(case, response).passed is True  # type: ignore[union-attr]
    assert contains(required=["Hello"], forbidden=["secret"])(case, response).passed is True  # type: ignore[union-attr]
    assert regex_match(expected_field="pattern")(case, response).passed is True  # type: ignore[union-attr]
    assert json_valid()(case, {"answer": '{"value":3}', "model": "target"}).passed is True  # type: ignore[union-attr]
    assert json_fields(required={"value": 3})(case, {"answer": '{"value":3}', "model": "target"}).passed is True  # type: ignore[union-attr]
    retrieval = retrieval_metrics("docs", threshold=1.0, precision_threshold=2 / 3)
    retrieval_result = retrieval(case, {"answer": "grounded", "model": "target", "retrieval": ["doc-a", {"id": "doc-b"}, "noise"]})
    assert retrieval_result.passed is True  # type: ignore[union-attr]
    assert retrieval.required_capabilities == ("retrieval",)
    assert [
        evaluator.config["type"]
        for evaluator in (
            exact_match(),
            normalized_match(),
            contains(required="x"),
            regex_match("x"),
            json_valid(),
            json_fields(required=["x"]),
            token_f1_score(),
            retrieval_metrics(required=["x"]),
        )
    ] == ["exact-match", "normalized-match", "contains", "regex", "json-valid", "json-fields", "token-f1", "retrieval"]


def test_loopback_evaluators_support_async_and_emit_invalid_without_leaks() -> None:
    async def async_evaluator(_case: EvalCase, _response: TargetResponse) -> EvaluationResult:
        await asyncio.sleep(0)
        return EvaluationResult(True, 1.0, {"async": 1.0}, "async passed", evidence={"source": "test"})

    evaluators = [exact_match(expected_field="answer"), CallableEvaluator("async", async_evaluator, config={"version": "1"})]
    request: dict[str, JSONValue] = {
        "client_case": {"id": "case", "input": "prompt", "expected": {"answer": "expected"}},
        "client_response": {"output": "expected", "model": "target", "usage": {"total_tokens": 2}},
    }
    with serve_evaluators(evaluators, "local-evaluator") as endpoint:
        raw = _post(endpoint, request)
    content = raw["choices"][0]["message"]["content"]  # type: ignore[index]
    judgment = json.loads(cast(str, content))
    assert raw["model"] == "local-evaluator" and judgment["verdict"] == "pass" and judgment["score"] == 5
    assert set(judgment["criteria"]) == {"exact_match", "async"}

    def broken(_case: EvalCase, _response: TargetResponse) -> EvaluationResult:
        raise RuntimeError("evaluator-secret-value")

    with serve_evaluators([CallableEvaluator("broken", broken)], "local-evaluator") as endpoint:
        invalid_raw = _post(endpoint, request)
    invalid_content = invalid_raw["choices"][0]["message"]["content"]  # type: ignore[index]
    invalid = json.loads(cast(str, invalid_content))
    assert invalid_raw["cavada_client_evaluator_status"] == "execution-error"
    assert invalid["verdict"] == "invalid" and invalid["criteria"]["broken"]["execution_error"] is True
    assert "evaluator-secret-value" not in cast(str, invalid_content)


def test_direct_callable_target_error_is_generic() -> None:
    def broken(_case: Mapping[str, JSONValue]) -> str:
        raise RuntimeError("do-not-leak")

    try:
        CallableTarget("broken", broken, "model")({"id": "case"})
    except TargetInvocationError as exc:
        assert str(exc) == "target invocation failed" and "do-not-leak" not in str(exc)
    else:
        raise AssertionError("broken callable did not fail")
