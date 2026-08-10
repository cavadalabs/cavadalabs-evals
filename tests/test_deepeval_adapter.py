from __future__ import annotations

from types import SimpleNamespace

import pytest

from cavada_eval import deepeval_adapter
from cavada_eval.protocol import ProtocolError


def test_deepeval_rejects_non_finite_scores(monkeypatch: pytest.MonkeyPatch) -> None:
    metric = SimpleNamespace(
        measure=lambda *_args, **_kwargs: float("nan"),
        is_successful=lambda: True,
    )
    metrics = SimpleNamespace(ExactMatchMetric=lambda **_kwargs: metric)
    test_cases = SimpleNamespace(LLMTestCase=lambda **_kwargs: object())
    monkeypatch.setattr(deepeval_adapter, "secure_import", lambda: (metrics, test_cases, "3.9.9"))

    with pytest.raises(ProtocolError, match="non-finite score"):
        deepeval_adapter.evaluate_metrics(
            [{"name": "exact_match"}],
            {"id": "case-1", "input": "input"},
            "answer",
            official=False,
        )
