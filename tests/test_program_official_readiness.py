from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from cavada_eval.program import _official_suite_validation


def test_declared_official_capability_is_not_treated_as_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 20, tzinfo=timezone.utc)
    suite = object()
    monkeypatch.setattr("cavada_eval.program.load_suite", lambda _path: suite)

    def reject_declared_suite(candidate: object, *, official: bool, now: datetime | None) -> list[str]:
        assert candidate is suite and official is True
        assert now == datetime(2026, 8, 20, tzinfo=timezone.utc)
        return ["approval expired"]

    monkeypatch.setattr("cavada_eval.program.validate_suite", reject_declared_suite)
    registry: dict[str, Any] = {
        "suites": [
            {"id": "synthetic-v1", "path": "suite", "official_capable": True},
            {"id": "candidate-v1", "path": "candidate", "official_capable": False},
        ]
    }

    result = _official_suite_validation(registry, repo_root=tmp_path, now=now)

    assert result == {
        "declared_official_capable": 1,
        "verified_official_capable": 0,
        "official_validation_failures": [
            {"suite_id": "synthetic-v1", "failures": ["approval expired"]},
        ],
    }
