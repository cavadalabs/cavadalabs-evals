from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from cavada_eval.program import _official_suite_validation, validate_reviewer_fixtures
from cavada_eval.protocol import ProtocolError, Suite


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


def test_missing_official_suite_path_cannot_establish_program_readiness(tmp_path: Path) -> None:
    result = _official_suite_validation(
        {"suites": [{"id": "missing-v1", "path": None, "official_capable": True}]},
        repo_root=tmp_path,
        now=datetime(2026, 8, 20, tzinfo=timezone.utc),
    )

    assert result["verified_official_capable"] == 0
    assert result["official_validation_failures"] == [
        {"suite_id": "missing-v1", "failures": ["official-capable suite path is missing"]}
    ]


@pytest.mark.parametrize(
    "failure",
    [
        "suite is not approved",
        "judge qualification blueprint approval is not currently effective",
        "judge qualification blueprint approval has been revoked",
    ],
)
def test_unapproved_expired_or_revoked_suite_cannot_establish_program_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    suite = object()
    monkeypatch.setattr("cavada_eval.program.load_suite", lambda _path: suite)
    monkeypatch.setattr("cavada_eval.program.validate_suite", lambda *_args, **_kwargs: [failure])

    result = _official_suite_validation(
        {"suites": [{"id": "blocked-v1", "path": "suite", "official_capable": True}]},
        repo_root=tmp_path,
        now=datetime(2026, 8, 20, tzinfo=timezone.utc),
    )

    assert result["verified_official_capable"] == 0
    assert result["official_validation_failures"] == [{"suite_id": "blocked-v1", "failures": [failure]}]


def test_nonexistent_official_suite_cannot_establish_program_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_path: Path) -> object:
        raise ProtocolError("suite does not exist")

    monkeypatch.setattr("cavada_eval.program.load_suite", missing)
    result = _official_suite_validation(
        {"suites": [{"id": "absent-v1", "path": "absent", "official_capable": True}]},
        repo_root=tmp_path,
        now=datetime(2026, 8, 20, tzinfo=timezone.utc),
    )

    assert result["verified_official_capable"] == 0
    assert result["official_validation_failures"] == [
        {"suite_id": "absent-v1", "failures": ["suite does not exist"]}
    ]


def test_conformance_fixture_cannot_establish_official_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite = Suite(
        root=tmp_path,
        config={"report": {"assurance": "conformance-fixture"}},
        cases=(),
        rubric="",
        dataset_path=tmp_path / "dataset.jsonl",
        rubric_path=tmp_path / "rubric.md",
    )
    monkeypatch.setattr("cavada_eval.program.load_suite", lambda _path: suite)
    monkeypatch.setattr("cavada_eval.program.validate_suite", lambda *_args, **_kwargs: [])

    result = _official_suite_validation(
        {"suites": [{"id": "synthetic-v1", "path": "suite", "official_capable": True}]},
        repo_root=tmp_path,
        now=datetime(2026, 8, 20, tzinfo=timezone.utc),
    )

    assert result["verified_official_capable"] == 0
    assert result["official_validation_failures"] == [
        {
            "suite_id": "synthetic-v1",
            "failures": ["conformance fixtures cannot establish official program readiness"],
        }
    ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            '{"id":"fixture","id":"duplicate","module":"privacy","language":"en",'
            '"prompt":"p","response":"r","gold_label":"pass","severity":"high",'
            '"rationale":"because","status":"approved"}',
            "duplicate JSON key: id",
        ),
        (
            '{"id":"fixture","module":"privacy","language":"en","prompt":"p",'
            '"response":"r","gold_label":"pass","severity":"high","rationale":1e999,'
            '"status":"approved"}',
            "non-finite JSON number",
        ),
    ],
)
def test_reviewer_fixtures_use_strict_json(tmp_path: Path, raw: str, expected: str) -> None:
    path = tmp_path / "reviewer.jsonl"
    path.write_text(raw + "\n", encoding="utf-8")
    suite = Suite(
        root=tmp_path,
        config={"gates": [{"category": "privacy"}]},
        cases=({"language": "en"},),
        rubric="",
        dataset_path=tmp_path / "dataset.jsonl",
        rubric_path=tmp_path / "rubric.md",
    )

    assert expected in "\n".join(validate_reviewer_fixtures(path, suite))
