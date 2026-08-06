from __future__ import annotations

import json
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any

from .protocol import contains_secret_like

METRIC_VERSION = "1.0.0"
PII_PATTERNS = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\+?\d[\d .()-]{7,}\d)\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
)


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


def set_scores(expected: Iterable[str], actual: Iterable[str]) -> dict[str, float]:
    left = {normalize_text(str(item)) for item in expected}
    right = {normalize_text(str(item)) for item in actual}
    overlap = len(left & right)
    precision = overlap / len(right) if right else float(not left)
    recall = overlap / len(left) if left else float(not right)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def error_rate(expected: Sequence[str], actual: Sequence[str]) -> float:
    previous = list(range(len(actual) + 1))
    for left_index, left in enumerate(expected, 1):
        current = [left_index]
        for right_index, right in enumerate(actual, 1):
            current.append(min(current[-1] + 1, previous[right_index] + 1, previous[right_index - 1] + (left != right)))
        previous = current
    return previous[-1] / len(expected) if expected else float(bool(actual))


def retrieval_scores(expected_ids: Iterable[str], retrieved_ids: Sequence[str], k: int) -> dict[str, float]:
    expected = list(dict.fromkeys(str(item) for item in expected_ids))
    retrieved = list(dict.fromkeys(str(item) for item in retrieved_ids))[:k]
    relevant = set(expected)
    hits = [identifier in relevant for identifier in retrieved]
    hit_count = sum(hits)
    reciprocal_rank = next((1 / (index + 1) for index, hit in enumerate(hits) if hit), 0.0)
    dcg = sum((1 if hit else 0) / math.log2(index + 2) for index, hit in enumerate(hits))
    ideal = sum(1 / math.log2(index + 2) for index in range(min(len(relevant), k)))
    return {
        "hit_rate": float(hit_count > 0),
        "recall_at_k": hit_count / len(relevant) if relevant else float(not retrieved),
        "precision_at_k": hit_count / len(retrieved) if retrieved else float(not relevant),
        "mrr": reciprocal_rank,
        "ndcg_at_k": dcg / ideal if ideal else float(not retrieved),
    }


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
        return {path: leaf for key, child in value.items() for path, leaf in _leaf_values(child, f"{prefix}.{key}").items()}
    if isinstance(value, list):
        return {path: leaf for index, child in enumerate(value) for path, leaf in _leaf_values(child, f"{prefix}[{index}]").items()}
    return {prefix: value}


def deterministic_evaluation(
    case: dict[str, Any],
    answer: str,
    *,
    target_raw: dict[str, Any] | None = None,
    retrieved_ids: Sequence[str] | None = None,
    tool_calls: Sequence[dict[str, Any]] | None = None,
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
    if "required_regex" in case:
        checks["required_regex"] = all(re.search(str(pattern), answer) is not None for pattern in case["required_regex"])
    if "forbidden_regex" in case:
        checks["forbidden_regex"] = all(re.search(str(pattern), answer) is None for pattern in case["forbidden_regex"])
    if "min_chars" in case:
        checks["min_chars"] = len(answer) >= int(case["min_chars"])
    if "max_chars" in case:
        checks["max_chars"] = len(answer) <= int(case["max_chars"])

    parsed: Any = None
    if case.get("expected_json") or isinstance(case.get("json_schema"), dict):
        try:
            parsed = json.loads(answer)
        except json.JSONDecodeError:
            checks["json_validity"] = False
        else:
            checks["json_validity"] = True
    if parsed is not None and isinstance(case.get("json_schema"), dict):
        schema_errors = _json_schema_errors(parsed, case["json_schema"])
        checks["json_schema"] = not schema_errors
        details["json_schema_errors"] = schema_errors
    if parsed is not None and "expected_json_value" in case:
        expected_leaves = _leaf_values(case["expected_json_value"])
        actual_leaves = _leaf_values(parsed)
        matched = sum(path in actual_leaves and actual_leaves[path] == value for path, value in expected_leaves.items())
        scores["structured_field_accuracy"] = matched / len(expected_leaves) if expected_leaves else float(not actual_leaves)
        checks["structured_field_accuracy"] = scores["structured_field_accuracy"] >= float(case.get("structured_field_accuracy_min", 1.0))
    if "expected_set" in case:
        try:
            actual_set = json.loads(answer)
        except json.JSONDecodeError:
            actual_set = None
        if not isinstance(actual_set, list):
            checks["set_output"] = False
        else:
            set_result = set_scores(case["expected_set"], actual_set)
            scores.update({f"set_{name}": value for name, value in set_result.items()})
            checks["set_output"] = set_result["f1"] >= float(case.get("set_f1_min", 1.0))
    if "expected_number" in case:
        match = re.fullmatch(r"\s*[-+]?(?:\d+(?:\.\d*)?|\.\d+)\s*", answer)
        tolerance = float(case.get("numeric_tolerance", 0.0))
        checks["numeric_tolerance"] = bool(match) and abs(float(answer) - float(case["expected_number"])) <= tolerance
    if "expected_transcript" in case:
        expected_transcript = normalize_text(str(case["expected_transcript"]))
        scores["word_error_rate"] = error_rate(expected_transcript.split(), folded.split())
        scores["character_error_rate"] = error_rate(list(expected_transcript), list(folded))
        if "max_word_error_rate" in case:
            checks["word_error_rate"] = scores["word_error_rate"] <= float(case["max_word_error_rate"])
        if "max_character_error_rate" in case:
            checks["character_error_rate"] = scores["character_error_rate"] <= float(case["max_character_error_rate"])

    if case.get("expected_retrieval_ids") is not None:
        resolved = list(retrieved_ids or [])
        k = int(case.get("retrieval_k", len(resolved) or 1))
        retrieval = retrieval_scores(case["expected_retrieval_ids"], resolved, k)
        scores.update(retrieval)
        for metric, threshold in (case.get("retrieval_minimums") or {}).items():
            checks[f"retrieval_{metric}"] = metric in retrieval and retrieval[metric] >= float(threshold)

    calls = list(tool_calls or [])
    names = [str(call.get("name", "")) for call in calls if isinstance(call, dict)]
    if "expected_tools" in case:
        checks["expected_tools"] = set(map(str, case["expected_tools"])) <= set(names)
    if "forbidden_tools" in case:
        checks["forbidden_tools"] = not (set(map(str, case["forbidden_tools"])) & set(names))
    if case.get("exact_tool_order") is not None:
        checks["exact_tool_order"] = names == list(map(str, case["exact_tool_order"]))
    if "max_tool_calls" in case:
        checks["max_tool_calls"] = len(calls) <= int(case["max_tool_calls"])
    if isinstance(case.get("expected_tool_arguments"), dict):
        arguments = {str(call.get("name")): call.get("arguments") for call in calls if isinstance(call, dict)}
        checks["expected_tool_arguments"] = all(arguments.get(str(name)) == expected for name, expected in case["expected_tool_arguments"].items())
    if isinstance(case.get("allowed_tool_permissions"), list):
        allowed = set(map(str, case["allowed_tool_permissions"]))
        checks["tool_permissions"] = all(str(call.get("permission", "")) in allowed for call in calls if call.get("permission") is not None)
    if case.get("citation_required"):
        checks["citation_presence"] = re.search(r"https?://|\[[0-9]+\]|\([A-Za-z][^)]*,?\s*\d{4}\)", answer) is not None
    if "citation_pattern" in case:
        checks["citation_format"] = re.search(str(case["citation_pattern"]), answer) is not None

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
