from __future__ import annotations

import hashlib
import inspect
import json
import math
import re
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Protocol, TypeAlias, cast, runtime_checkable

from .metrics import normalize_text, retrieval_scores, token_f1
from .protocol import _strict_json_loads
from .targets import JSONValue, TargetResponse, _json_clone, _normalize_target_response, _serve_json


@dataclass(frozen=True)
class EvalCase:
    id: str
    input: JSONValue
    expected: JSONValue = None
    metadata: Mapping[str, JSONValue] = field(default_factory=dict)
    extras: Mapping[str, JSONValue] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResult:
    passed: bool
    score: float
    metrics: Mapping[str, float] = field(default_factory=dict)
    reason: str = ""
    error: str | None = None
    invalid: bool = False
    evidence: Mapping[str, JSONValue] = field(default_factory=dict)


@runtime_checkable
class Evaluator(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def required_capabilities(self) -> tuple[str, ...]: ...

    @property
    def config(self) -> Mapping[str, JSONValue]: ...

    @property
    def config_id(self) -> str: ...

    def __call__(self, case: EvalCase, response: TargetResponse) -> EvaluationResult | Awaitable[EvaluationResult]: ...


EvaluationCallable: TypeAlias = Callable[[EvalCase, TargetResponse], EvaluationResult | Awaitable[EvaluationResult]]
_MISSING = object()


@dataclass(frozen=True)
class CallableEvaluator:
    name: str
    callable: EvaluationCallable
    required_capabilities: tuple[str, ...] = ("text",)
    config: Mapping[str, JSONValue] = field(default_factory=dict)

    @property
    def config_id(self) -> str:
        value = {"name": self.name, "required_capabilities": self.required_capabilities, "config": self.config}
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def __call__(self, case: EvalCase, response: TargetResponse) -> EvaluationResult | Awaitable[EvaluationResult]:
        return self.callable(case, response)


def _evaluator(name: str, config: Mapping[str, JSONValue], evaluate: EvaluationCallable, *capabilities: str) -> Evaluator:
    return CallableEvaluator(name, evaluate, capabilities or ("text",), config)


def _mapping(value: object) -> Mapping[str, JSONValue]:
    cloned = _json_clone(value)
    if not isinstance(cloned, dict):
        raise ValueError("expected a JSON object")
    return cloned


def _field(value: object, path: str) -> object:
    current = value
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _expected(case: EvalCase, expected_field: str | None) -> object:
    if expected_field is None:
        return case.expected
    for source in (case.expected, case.extras, case.metadata):
        value = _field(source, expected_field)
        if value is not _MISSING:
            return value
    return _MISSING


def _invalid(reason: str = "evaluator input is invalid") -> EvaluationResult:
    return EvaluationResult(False, 0.0, reason=reason, invalid=True)


def _strings(value: object) -> list[str] | None:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and all(isinstance(item, str) for item in value):
        return list(cast(Sequence[str], value))
    return None


def _text_expected(case: EvalCase, expected_field: str | None) -> str | None:
    value = _expected(case, expected_field)
    return value if isinstance(value, str) else None


def exact_match(expected_field: str | None = None, *, name: str = "exact_match") -> Evaluator:
    def evaluate(case: EvalCase, response: TargetResponse) -> EvaluationResult:
        expected = _text_expected(case, expected_field)
        if expected is None:
            return _invalid("expected text is unavailable")
        passed = response["answer"] == expected
        return EvaluationResult(passed, float(passed), {name: float(passed)}, "exact text matched" if passed else "exact text differed")

    return _evaluator(name, {"type": "exact-match", "expected_field": expected_field}, evaluate)


def normalized_match(expected_field: str | None = None, *, name: str = "normalized_match") -> Evaluator:
    def evaluate(case: EvalCase, response: TargetResponse) -> EvaluationResult:
        expected = _text_expected(case, expected_field)
        if expected is None:
            return _invalid("expected text is unavailable")
        passed = normalize_text(response["answer"]) == normalize_text(expected)
        return EvaluationResult(passed, float(passed), {name: float(passed)}, "normalized text matched" if passed else "normalized text differed")

    return _evaluator(name, {"type": "normalized-match", "expected_field": expected_field}, evaluate)


def contains(
    required: str | Sequence[str] | None = None,
    forbidden: str | Sequence[str] | None = None,
    *,
    expected_field: str | None = None,
    case_sensitive: bool = True,
    name: str = "contains",
) -> Evaluator:
    configured_required, configured_forbidden = _strings(required), _strings(forbidden)
    if configured_required is None or configured_forbidden is None:
        raise ValueError("required and forbidden must be strings or string sequences")

    def evaluate(case: EvalCase, response: TargetResponse) -> EvaluationResult:
        expected = _expected(case, expected_field)
        expected_config = expected if isinstance(expected, Mapping) else {}
        required_values = configured_required or _strings(expected_config.get("required", expected))
        forbidden_values = configured_forbidden or _strings(expected_config.get("forbidden"))
        if required_values is None or forbidden_values is None or not (required_values or forbidden_values):
            return _invalid("contains configuration is unavailable")
        actual = response["answer"] if case_sensitive else response["answer"].casefold()
        required_checked = [item if case_sensitive else item.casefold() for item in required_values]
        forbidden_checked = [item if case_sensitive else item.casefold() for item in forbidden_values]
        checks = [item in actual for item in required_checked] + [item not in actual for item in forbidden_checked]
        score = sum(checks) / len(checks)
        evidence = _mapping({"required": required_values, "forbidden": forbidden_values})
        return EvaluationResult(all(checks), score, {name: score}, "containment requirements evaluated", evidence=evidence)

    return _evaluator(
        name,
        _mapping(
            {
                "type": "contains",
                "required": configured_required,
                "forbidden": configured_forbidden,
                "expected_field": expected_field,
                "case_sensitive": case_sensitive,
            }
        ),
        evaluate,
    )


def regex_match(pattern: str | None = None, *, expected_field: str | None = None, flags: int = 0, name: str = "regex_match") -> Evaluator:
    if pattern is not None:
        re.compile(pattern, flags)

    def evaluate(case: EvalCase, response: TargetResponse) -> EvaluationResult:
        resolved = pattern or _text_expected(case, expected_field)
        if resolved is None:
            expected = _expected(case, expected_field)
            resolved = expected.get("pattern") if isinstance(expected, Mapping) else None
        if not isinstance(resolved, str):
            return _invalid("regex pattern is unavailable")
        try:
            passed = re.search(resolved, response["answer"], flags) is not None
        except re.error:
            return _invalid("regex pattern is invalid")
        return EvaluationResult(passed, float(passed), {name: float(passed)}, "regex evaluated", evidence={"pattern": resolved})

    return _evaluator(name, {"type": "regex", "pattern": pattern, "expected_field": expected_field, "flags": flags}, evaluate)


def json_valid(*, name: str = "json_valid") -> Evaluator:
    def evaluate(_case: EvalCase, response: TargetResponse) -> EvaluationResult:
        try:
            _strict_json_loads(response["answer"])
        except (ValueError, json.JSONDecodeError):
            return EvaluationResult(False, 0.0, {name: 0.0}, "answer is not valid JSON")
        return EvaluationResult(True, 1.0, {name: 1.0}, "answer is valid JSON")

    return _evaluator(name, {"type": "json-valid"}, evaluate)


def json_fields(
    required: Mapping[str, JSONValue] | Sequence[str] | None = None,
    forbidden: Sequence[str] | None = None,
    *,
    expected_field: str | None = None,
    name: str = "json_fields",
) -> Evaluator:
    if isinstance(required, (str, bytes)) or isinstance(forbidden, (str, bytes)):
        raise ValueError("JSON field lists must be sequences, not strings")

    def evaluate(case: EvalCase, response: TargetResponse) -> EvaluationResult:
        try:
            actual = _strict_json_loads(response["answer"])
        except (ValueError, json.JSONDecodeError):
            return EvaluationResult(False, 0.0, {name: 0.0}, "answer is not valid JSON")
        if not isinstance(actual, dict):
            return EvaluationResult(False, 0.0, {name: 0.0}, "answer JSON is not an object")
        expected = _expected(case, expected_field)
        expected_config = expected if isinstance(expected, Mapping) else {}
        resolved_required: Mapping[str, object] | Sequence[str]
        if required is not None:
            resolved_required = required
        elif isinstance(expected_config.get("required"), (Mapping, Sequence)):
            resolved_required = cast(Mapping[str, object] | Sequence[str], expected_config["required"])
        else:
            resolved_required = expected_config
        resolved_forbidden = list(forbidden or cast(Sequence[str], expected_config.get("forbidden", [])))
        if isinstance(resolved_required, Mapping):
            checks = [_field(actual, path) == value for path, value in resolved_required.items()]
            required_names = list(resolved_required)
        else:
            required_names = list(resolved_required)
            if not all(isinstance(item, str) for item in required_names):
                return _invalid("required JSON fields are invalid")
            checks = [_field(actual, path) is not _MISSING for path in required_names]
        checks.extend(_field(actual, path) is _MISSING for path in resolved_forbidden)
        if not checks:
            return _invalid("JSON field configuration is unavailable")
        score = sum(checks) / len(checks)
        evidence = _mapping({"required": required_names, "forbidden": resolved_forbidden})
        return EvaluationResult(all(checks), score, {name: score}, "JSON fields evaluated", evidence=evidence)

    return _evaluator(
        name,
        {"type": "json-fields", "required": _json_clone(required), "forbidden": _json_clone(forbidden), "expected_field": expected_field},
        evaluate,
    )


def token_f1_score(expected_field: str | None = None, threshold: float = 1.0, *, name: str = "token_f1") -> Evaluator:
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be from 0 to 1")

    def evaluate(case: EvalCase, response: TargetResponse) -> EvaluationResult:
        expected = _text_expected(case, expected_field)
        if expected is None:
            return _invalid("expected text is unavailable")
        score = token_f1(expected, response["answer"])
        return EvaluationResult(score >= threshold, score, {name: score}, "token F1 evaluated", evidence={"threshold": threshold})

    return _evaluator(name, {"type": "token-f1", "expected_field": expected_field, "threshold": threshold}, evaluate)


def _retrieval_ids(value: object) -> list[str] | None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return None
    result: list[str] = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, Mapping):
            identifier = next((item.get(key) for key in ("id", "document_id", "source_id", "chunk_id") if isinstance(item.get(key), str)), None)
            if not isinstance(identifier, str):
                return None
            result.append(identifier)
        else:
            return None
    return result


def retrieval_metrics(
    expected_field: str | None = None,
    *,
    required: Sequence[str] | None = None,
    forbidden: Sequence[str] | None = None,
    k: int | None = None,
    threshold: float = 1.0,
    precision_threshold: float = 0.0,
    name: str = "retrieval",
) -> Evaluator:
    if not 0 <= threshold <= 1 or not 0 <= precision_threshold <= 1 or (k is not None and k < 1):
        raise ValueError("retrieval thresholds must be from 0 to 1 and k must be positive")

    def evaluate(case: EvalCase, response: TargetResponse) -> EvaluationResult:
        expected = _expected(case, expected_field)
        expected_config = expected if isinstance(expected, Mapping) else {}
        required_ids = list(required) if required is not None else _retrieval_ids(expected_config.get("required", expected))
        forbidden_ids = list(forbidden or cast(Sequence[str], expected_config.get("forbidden", [])))
        actual_ids = _retrieval_ids(response.get("retrieval"))
        if required_ids is None or actual_ids is None:
            return _invalid("retrieval evidence is unavailable")
        scores = retrieval_scores(required_ids, actual_ids, k or max(len(actual_ids), len(required_ids), 1))
        forbidden_ok = not (set(forbidden_ids) & set(actual_ids))
        passed = scores["recall_at_k"] >= threshold and scores["precision_at_k"] >= precision_threshold and forbidden_ok
        evidence = _mapping({"required": required_ids, "forbidden": forbidden_ids})
        return EvaluationResult(passed, scores["recall_at_k"], scores, "retrieval evidence evaluated", evidence=evidence)

    return _evaluator(
        name,
        {
            "type": "retrieval",
            "expected_field": expected_field,
            "required": _json_clone(required),
            "forbidden": _json_clone(forbidden),
            "k": k,
            "threshold": threshold,
            "precision_threshold": precision_threshold,
        },
        evaluate,
        "retrieval",
    )


def _case(value: object) -> EvalCase:
    if not isinstance(value, Mapping) or not isinstance(value.get("id"), str) or "input" not in value:
        raise ValueError("invalid client case")
    metadata = value.get("metadata", {})
    extras = value.get("extras", {})
    if not isinstance(metadata, Mapping) or not isinstance(extras, Mapping):
        raise ValueError("invalid client case metadata")
    unknown = {str(key): cast(JSONValue, item) for key, item in value.items() if key not in {"id", "input", "expected", "metadata", "extras"}}
    return EvalCase(
        cast(str, value["id"]),
        cast(JSONValue, value["input"]),
        cast(JSONValue, value.get("expected")),
        cast(Mapping[str, JSONValue], metadata),
        {**cast(Mapping[str, JSONValue], extras), **unknown},
    )


def _valid_result(value: object) -> bool:
    return (
        isinstance(value, EvaluationResult)
        and isinstance(value.passed, bool)
        and isinstance(value.score, (int, float))
        and not isinstance(value.score, bool)
        and math.isfinite(value.score)
        and 0 <= value.score <= 1
        and all(isinstance(metric, str) and isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) for metric, score in value.metrics.items())
    )


async def _judgment(
    evaluators: Sequence[Evaluator], case: EvalCase, response: TargetResponse
) -> tuple[dict[str, JSONValue], bool]:
    criteria: dict[str, JSONValue] = {}
    results: list[EvaluationResult] = []
    invalid = False
    execution_error = False
    for evaluator in evaluators:
        try:
            value = evaluator(case, response)
            result = await value if inspect.isawaitable(value) else value
        except Exception:
            execution_error = True
            criteria[evaluator.name] = {
                "passed": False,
                "score": 0.0,
                "invalid": False,
                "execution_error": True,
                "error": "evaluator execution failed",
            }
            continue
        try:
            valid_result = _valid_result(result)
            if valid_result:
                _json_clone(result.evidence)
        except Exception:
            valid_result = False
        if not valid_result:
            invalid = True
            criteria[evaluator.name] = {"passed": False, "score": 0.0, "invalid": True, "error": "evaluator returned invalid result"}
            continue
        if result.error is not None:
            execution_error = True
            criteria[evaluator.name] = {
                "passed": False,
                "score": result.score,
                "invalid": False,
                "execution_error": True,
                "error": "evaluator execution failed",
            }
            continue
        result_invalid = result.invalid
        invalid = invalid or result_invalid
        criteria[evaluator.name] = {
            "passed": result.passed,
            "score": result.score,
            "metrics": dict(result.metrics),
            "reason": "evaluator output invalid" if result_invalid else result.reason,
            "invalid": result_invalid,
            "evidence": dict(result.evidence),
        }
        results.append(result)
    score = sum(result.score for result in results) / len(evaluators)
    verdict = "invalid" if invalid or execution_error else "pass" if all(result.passed for result in results) else "fail"
    reason = (
        "evaluator execution failed"
        if execution_error
        else "evaluator output invalid"
        if invalid
        else "all evaluators passed"
        if verdict == "pass"
        else "one or more evaluators failed"
    )
    return {"verdict": verdict, "score": min(5, int(score * 5 + 0.5)), "reason": reason, "criteria": criteria}, execution_error


@contextmanager
def serve_evaluators(evaluators: Sequence[Evaluator], model: str) -> Iterator[str]:
    configured = tuple(evaluators)
    names = [evaluator.name for evaluator in configured]
    if not configured or any(not name for name in names) or len(names) != len(set(names)) or not model:
        raise ValueError("evaluators require unique names and a model identity")

    async def invoke(request: dict[str, JSONValue]) -> JSONValue:
        parsed: object = request if "client_case" in request and "client_response" in request else None
        if parsed is None:
            messages = request.get("messages")
            user_content: JSONValue = None
            if isinstance(messages, list):
                for message in reversed(messages):
                    if isinstance(message, dict) and message.get("role") == "user":
                        user_content = message.get("content")
                        break
            if isinstance(user_content, list):
                user_content = next(
                    (
                        part.get("text")
                        for part in user_content
                        if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)
                    ),
                    None,
                )
            parsed = _strict_json_loads(user_content) if isinstance(user_content, str) else None
        if not isinstance(parsed, dict) or "client_case" not in parsed or "client_response" not in parsed:
            raise ValueError("missing client evidence")
        case = _case(parsed["client_case"])
        raw_response = parsed["client_response"]
        if not isinstance(raw_response, Mapping):
            raise ValueError("invalid client response")
        response = _normalize_target_response(cast(Mapping[str, JSONValue], raw_response), "client-target")
        judgment, execution_error = await _judgment(configured, case, response)
        content = json.dumps(judgment, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        result: dict[str, JSONValue] = {"model": model, "choices": [{"message": {"role": "assistant", "content": content}}]}
        if execution_error:
            result["cavada_client_evaluator_status"] = "execution-error"
        return result

    with _serve_json(invoke) as endpoint:
        yield endpoint
