from __future__ import annotations

import json
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Sequence
from typing import Any

from .protocol import contains_secret_like

METRIC_VERSION = "1.0.0"
PII_PATTERNS = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\+?\d[\d .()-]{7,}\d)\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
)
_DEFERRED_FIELDS = {
    "allowed_tool_permissions",
    "citation_pattern",
    "citation_required",
    "exact_tool_order",
    "expected_retrieval_ids",
    "expected_set",
    "expected_tool_arguments",
    "expected_transcript",
    "forbidden_regex",
    "max_character_error_rate",
    "max_chars",
    "max_tool_calls",
    "max_word_error_rate",
    "min_chars",
    "pattern",
    "required_regex",
    "retrieval_k",
    "retrieval_minimums",
    "set_f1_min",
}


def metric_config_errors(case: dict[str, Any]) -> list[str]:
    """Validate case metric inputs that would otherwise fail during evaluation."""
    errors: list[str] = []
    deferred = sorted(_DEFERRED_FIELDS & set(case))
    if deferred:
        errors.append(f"unsupported deterministic metric fields: {deferred}")

    def validate_schema_patterns(value: Any, path: str = "json_schema") -> None:
        if isinstance(value, dict):
            pattern = value.get("pattern")
            if pattern is not None:
                if not isinstance(pattern, str) or not pattern:
                    errors.append(f"{path}.pattern must be non-empty text")
                else:
                    try:
                        re.compile(pattern)
                    except re.error as exc:
                        errors.append(f"{path}.pattern is not a valid regular expression: {exc}")
            for name, child in value.items():
                validate_schema_patterns(child, f"{path}.{name}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                validate_schema_patterns(child, f"{path}[{index}]")

    if "json_schema" in case:
        if not isinstance(case["json_schema"], dict):
            errors.append("json_schema must be an object")
        else:
            validate_schema_patterns(case["json_schema"])

    for field in ("token_f1_min", "structured_field_accuracy_min"):
        value = case.get(field)
        if value is not None and (
            not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)) or not 0 <= float(value) <= 1
        ):
            errors.append(f"{field} must be a finite number from 0 to 1")
    tolerance = case.get("numeric_tolerance")
    if tolerance is not None and (
        not isinstance(tolerance, (int, float)) or isinstance(tolerance, bool) or not math.isfinite(float(tolerance)) or float(tolerance) < 0
    ):
        errors.append("numeric_tolerance must be a finite non-negative number")
    return errors


def normalize_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def contains_pii_like(value: str) -> bool:
    return any(pattern.search(value) for pattern in PII_PATTERNS)


def token_f1(expected: str, actual: str) -> float:
    left = Counter(normalize_text(expected).split())
    right = Counter(normalize_text(actual).split())
    overlap = sum((left & right).values())
    if not left and not right:
        return 1.0
    if not left or not right or not overlap:
        return 0.0
    precision = overlap / sum(right.values())
    recall = overlap / sum(left.values())
    return 2 * precision * recall / (precision + recall)


def _json_schema_errors(value: Any, schema: dict[str, Any], prefix: str = "$") -> list[str]:
    errors: list[str] = []
    expected_type = schema.get("type")
    matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }
    if expected_type in matches and not matches[expected_type]:
        return [f"{prefix} must be {expected_type}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{prefix} is not an allowed value")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{prefix}.{name} is required")
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    errors.append(f"{prefix}.{name} is not allowed")
        for name, child in properties.items():
            if name in value and isinstance(child, dict):
                errors.extend(_json_schema_errors(value[name], child, f"{prefix}.{name}"))
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            errors.extend(_json_schema_errors(item, schema["items"], f"{prefix}[{index}]"))
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            errors.append(f"{prefix} is too short")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            errors.append(f"{prefix} is too long")
        if "pattern" in schema and re.search(str(schema["pattern"]), value) is None:
            errors.append(f"{prefix} does not match pattern")
    return errors


def _leaf_values(value: Any, prefix: str = "$") -> dict[str, Any]:
    if isinstance(value, dict):
        if not value:
            return {prefix: {}}
        return {path: leaf for key, child in value.items() for path, leaf in _leaf_values(child, f"{prefix}.{key}").items()}
    if isinstance(value, list):
        if not value:
            return {prefix: []}
        return {path: leaf for index, child in enumerate(value) for path, leaf in _leaf_values(child, f"{prefix}[{index}]").items()}
    return {prefix: value}


def deterministic_evaluation(
    case: dict[str, Any],
    answer: str,
    *,
    tool_calls: Sequence[object] | None = None,
) -> dict[str, Any]:
    folded = normalize_text(answer)
    checks: dict[str, bool] = {
        "non_empty": bool(answer.strip()),
        "no_secret_like_output": not contains_secret_like(answer),
    }
    scores: dict[str, float] = {}
    details: dict[str, Any] = {}

    required = [normalize_text(str(value)) for value in case.get("required_terms", [])]
    forbidden = [normalize_text(str(value)) for value in case.get("forbidden_terms", [])]
    if required:
        checks["required_terms"] = all(value in folded for value in required)
    if forbidden:
        checks["forbidden_terms"] = not any(value in folded for value in forbidden)
    if case.get("forbid_pii"):
        checks["no_pii_like_output"] = not contains_pii_like(answer)
    if "expected_output" in case:
        expected = str(case["expected_output"])
        checks["exact_match"] = answer == expected
        checks["normalized_match"] = folded == normalize_text(expected)
        scores["token_f1"] = token_f1(expected, answer)
        threshold = float(case.get("token_f1_min", 0.0))
        if threshold:
            checks["token_f1"] = scores["token_f1"] >= threshold
    parsed: Any = None
    parsed_ok = False
    if case.get("expected_json") or isinstance(case.get("json_schema"), dict) or "expected_json_value" in case:
        try:
            parsed = json.loads(answer)
        except json.JSONDecodeError:
            checks["json_validity"] = False
        else:
            parsed_ok = True
            checks["json_validity"] = True
    if parsed_ok and isinstance(case.get("json_schema"), dict):
        schema_errors = _json_schema_errors(parsed, case["json_schema"])
        checks["json_schema"] = not schema_errors
        details["json_schema_errors"] = schema_errors
    if parsed_ok and "expected_json_value" in case:
        expected_leaves = _leaf_values(case["expected_json_value"])
        actual_leaves = _leaf_values(parsed)
        matched = sum(path in actual_leaves and actual_leaves[path] == value for path, value in expected_leaves.items())
        scores["structured_field_accuracy"] = matched / len(expected_leaves) if expected_leaves else float(not actual_leaves)
        checks["structured_field_accuracy"] = scores["structured_field_accuracy"] >= float(case.get("structured_field_accuracy_min", 1.0))
    if "expected_number" in case:
        match = re.fullmatch(r"\s*[-+]?(?:\d+(?:\.\d*)?|\.\d+)\s*", answer)
        tolerance = float(case.get("numeric_tolerance", 0.0))
        checks["numeric_tolerance"] = bool(match) and abs(float(answer) - float(case["expected_number"])) <= tolerance

    calls_valid = False
    calls: list[dict[str, Any]] = []
    if isinstance(tool_calls, Sequence) and not isinstance(tool_calls, (str, bytes)):
        calls_valid = all(isinstance(call, dict) for call in tool_calls)
        if calls_valid:
            calls = [call for call in tool_calls if isinstance(call, dict)]
    if tool_calls is not None:
        checks["tool_calls_valid"] = calls_valid
    names = [str(call.get("name", "")) for call in calls if isinstance(call, dict)]
    if "expected_tools" in case:
        checks["expected_tools"] = set(map(str, case["expected_tools"])) <= set(names)
    if "forbidden_tools" in case:
        checks["forbidden_tools"] = not (set(map(str, case["forbidden_tools"])) & set(names))

    soft = set(map(str, case.get("soft_checks", [])))
    hard_pass = all(value for name, value in checks.items() if name not in soft)
    weights = {str(name): float(value) for name, value in (case.get("metric_weights") or {}).items()}
    weighted_total = sum(weights.get(name, 1.0) for name in checks)
    weighted_score = sum(weights.get(name, 1.0) * float(value) for name, value in checks.items()) / weighted_total if weighted_total else 1.0

    return {
        "metric_version": METRIC_VERSION,
        "checks": checks,
        "scores": scores,
        "details": details,
        "hard_checks": sorted(set(checks) - soft),
        "soft_checks": sorted(soft & set(checks)),
        "weighted_score": weighted_score,
        "hard_pass": hard_pass,
    }
