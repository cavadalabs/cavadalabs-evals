from __future__ import annotations

import importlib
import math
import os
from typing import Any

from .assets import content_text
from .protocol import ProtocolError

SECURE_ENVIRONMENT = {
    "DEEPEVAL_TELEMETRY_OPT_OUT": "true",
    "DEEPEVAL_DISABLE_DOTENV": "1",
    "DEEPEVAL_DISABLE_LEGACY_KEYFILE": "1",
    "DEEPEVAL_UPDATE_WARNING_OPT_IN": "false",
    "ERROR_REPORTING": "false",
}
LLM_METRICS = {
    "answer_relevancy": "AnswerRelevancyMetric",
    "faithfulness": "FaithfulnessMetric",
    "contextual_precision": "ContextualPrecisionMetric",
    "contextual_recall": "ContextualRecallMetric",
    "contextual_relevancy": "ContextualRelevancyMetric",
    "hallucination": "HallucinationMetric",
    "bias": "BiasMetric",
    "toxicity": "ToxicityMetric",
    "pii_leakage": "PIILeakageMetric",
    "misuse": "MisuseMetric",
}


def secure_import() -> tuple[Any, Any, str]:
    for name, value in SECURE_ENVIRONMENT.items():
        current = os.getenv(name)
        if current is not None and current.casefold() != value:
            raise ProtocolError(f"unsafe DeepEval environment setting: {name}={current!r}")
        os.environ[name] = value
    try:
        deepeval = importlib.import_module("deepeval")
        metrics = importlib.import_module("deepeval.metrics")
        test_case = importlib.import_module("deepeval.test_case")
    except ImportError as exc:
        raise ProtocolError("DeepEval is not installed; install the published `deepeval` extra or run `uv sync --extra deepeval`") from exc
    version = str(getattr(deepeval, "__version__", "unknown"))
    if not version.startswith("3."):
        raise ProtocolError(f"unsupported DeepEval version: {version}")
    return metrics, test_case, version


def evaluate_metrics(
    configurations: list[dict[str, Any]],
    case: dict[str, Any],
    answer: str,
    *,
    official: bool,
) -> list[dict[str, Any]]:
    metrics_module, test_case_module, version = secure_import()
    test_case = test_case_module.LLMTestCase(
        input=content_text(case.get("input")),
        actual_output=answer,
        expected_output=case.get("expected_output"),
        context=case.get("context"),
        retrieval_context=case.get("retrieval_context"),
        name=str(case.get("id")),
        tags=list(map(str, case.get("tags", []))),
    )
    results: list[dict[str, Any]] = []
    for configuration in configurations:
        name = str(configuration.get("name", ""))
        threshold = float(configuration.get("threshold", 0.5))
        if name == "exact_match":
            metric = metrics_module.ExactMatchMetric(threshold=threshold)
        elif name == "pattern_match":
            pattern = configuration.get("pattern") or case.get("pattern")
            if not isinstance(pattern, str):
                raise ProtocolError("DeepEval pattern_match requires a pattern")
            metric = metrics_module.PatternMatchMetric(pattern=pattern, ignore_case=bool(configuration.get("ignore_case", False)), threshold=threshold)
        elif name in LLM_METRICS:
            if official:
                raise ProtocolError("official DeepEval LLM metrics require a CavadaLabs identity-verifying judge adapter")
            metric_type = getattr(metrics_module, LLM_METRICS[name])
            metric = metric_type(threshold=threshold, model=configuration.get("model"), async_mode=False)
        else:
            raise ProtocolError(f"unsupported DeepEval metric: {name}")
        try:
            score = float(metric.measure(test_case, _show_indicator=False, _log_metric_to_confident=False))
        except Exception as exc:
            raise ProtocolError(f"DeepEval metric {name} failed: {exc}") from exc
        if not math.isfinite(score):
            raise ProtocolError(f"DeepEval metric {name} returned a non-finite score")
        results.append(
            {
                "engine": "deepeval",
                "engine_version": version,
                "name": name,
                "threshold": threshold,
                "score": score,
                "success": bool(metric.is_successful()),
                "reason": getattr(metric, "reason", None),
                "evaluation_model": getattr(metric, "evaluation_model", None),
                "evaluation_cost": getattr(metric, "evaluation_cost", None),
                "hard_fail": bool(configuration.get("hard_fail", False)),
            }
        )
    return results
