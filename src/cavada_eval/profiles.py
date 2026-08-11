from __future__ import annotations

import hashlib
from typing import Any

ADAPTER_CONTRACT_VERSION = "1.0.0"
BENCHMARK_PRESET_VERSION = "1.1.0"

BENCHMARK_PRESETS: dict[str, dict[str, Any]] = {
    "smoke": {
        "max_cases": 25,
        "repetitions": 1,
        "judge_repetitions": 1,
        "mode": "smoke",
    },
    "quick": {
        "max_cases": 100,
        "repetitions": 1,
        "judge_repetitions": 1,
        "mode": "regression",
    },
    "standard": {
        "max_cases": 1000,
        "repetitions": 2,
        "judge_repetitions": 2,
        "mode": "candidate",
    },
    "reference": {
        "max_cases": 0,
        "repetitions": 3,
        "judge_repetitions": 3,
        "mode": "candidate",
        "performance_plan": "performance/plans/llm-serving-v2.toml",
    },
}


def canonical_preset(name: str | None) -> str:
    if name and name not in BENCHMARK_PRESETS:
        raise ValueError(f"unsupported benchmark preset: {name}")
    return name or ""


def benchmark_preset(name: str) -> dict[str, Any]:
    return {"name": name, "version": BENCHMARK_PRESET_VERSION, **BENCHMARK_PRESETS[name]}


def stratified_cases(cases: tuple[dict[str, Any], ...], limit: int) -> tuple[dict[str, Any], ...]:
    """Select a stable, scenario-group-safe round-robin sample across declared strata."""
    if limit <= 0 or limit >= len(cases):
        return cases
    groups: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        groups.setdefault(str(case.get("scenario_group_id") or case["id"]), []).append(case)
    buckets: dict[str, dict[tuple[str, ...], list[list[dict[str, Any]]]]] = {}
    for group in groups.values():
        representative = next((case for case in group if case.get("scenario_role") == "primary"), group[0])
        category = str(representative.get("category", "missing"))
        stratum = tuple(str(representative.get(field, "missing")) for field in ("risk_domain", "severity", "language", "split"))
        buckets.setdefault(category, {}).setdefault(stratum, []).append(group)
    schedules: dict[str, list[list[dict[str, Any]]]] = {}
    for category, strata in buckets.items():
        for groups_in_stratum in strata.values():
            groups_in_stratum.sort(key=lambda value: hashlib.sha256(str(value[0].get("scenario_group_id") or value[0]["id"]).encode()).hexdigest())
        schedule: list[list[dict[str, Any]]] = []
        while any(strata.values()):
            for stratum in sorted(strata, key=lambda value: hashlib.sha256("\0".join(value).encode()).hexdigest()):
                if strata[stratum]:
                    schedule.append(strata[stratum].pop(0))
        schedules[category] = schedule
    selected: list[dict[str, Any]] = []
    while any(schedules.values()):
        added = False
        for category in sorted(schedules):
            schedule = schedules[category]
            if not schedule:
                continue
            remaining = limit - len(selected)
            fitting = next((index for index, group in enumerate(schedule) if len(group) <= remaining), None)
            if fitting is not None:
                selected.extend(schedule.pop(fitting))
                added = True
        if not added:
            break
    return tuple(selected)

TASK_PROFILES: dict[str, set[str]] = {
    "text-generation": {"text"},
    "classification": {"text"},
    "structured-extraction": {"text"},
    "translation": {"text"},
    "summarization": {"text"},
    "conversation": {"text", "conversation"},
    "safety": {"text"},
    "privacy": {"text"},
    "fairness": {"text"},
}
