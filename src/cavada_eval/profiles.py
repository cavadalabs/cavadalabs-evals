from __future__ import annotations

import hashlib
from typing import Any

# `built_in=False` blocks official use until a pinned, identity-verifying
# adapter and calibration evidence are attached.
ADAPTER_CONTRACT_VERSION = "1.0.0"
BENCHMARK_PRESET_VERSION = "1.1.0"

BENCHMARK_PRESETS: dict[str, dict[str, Any]] = {
    "smoke": {
        "max_cases": 25,
        "repetitions": 1,
        "judge_repetitions": 1,
        "mode": "smoke",
        "performance_plan": "performance/plans/llm-serving-smoke-v1.toml",
        "official_eligible": False,
    },
    "quick": {
        "max_cases": 100,
        "repetitions": 1,
        "judge_repetitions": 1,
        "mode": "regression",
        "performance_plan": "performance/plans/llm-serving-quick-v1.toml",
        "official_eligible": False,
    },
    "standard": {
        "max_cases": 1000,
        "repetitions": 2,
        "judge_repetitions": 2,
        "mode": "candidate",
        "performance_plan": "performance/plans/llm-serving-standard-v1.toml",
        "official_eligible": False,
    },
    "reference": {
        "max_cases": 0,
        "repetitions": 3,
        "judge_repetitions": 3,
        "mode": "candidate",
        "performance_plan": "performance/plans/llm-serving-v2.toml",
        "official_eligible": True,
    },
}


def canonical_preset(name: str | None) -> str:
    value = "reference" if name == "full" else (name or "")
    if value and value not in BENCHMARK_PRESETS:
        raise ValueError(f"unsupported benchmark preset: {name}")
    return value


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

TASK_PROFILES: dict[str, dict[str, Any]] = {
    "text-generation": {"inputs": ["text"], "output": "text", "built_in": True},
    "classification": {"inputs": ["text"], "output": "text", "built_in": True},
    "structured-extraction": {"inputs": ["text"], "output": "json", "built_in": True},
    "translation": {"inputs": ["text"], "output": "text", "built_in": True},
    "summarization": {"inputs": ["text"], "output": "text", "built_in": True},
    "rag-retriever": {"inputs": ["text", "retrieval"], "output": "retrieval", "built_in": True},
    "rag-generator": {"inputs": ["text", "retrieval"], "output": "text", "built_in": True},
    "rag-end-to-end": {"inputs": ["text", "retrieval"], "output": "text", "built_in": True},
    "conversation": {"inputs": ["text", "conversation"], "output": "text", "built_in": True},
    "agent": {"inputs": ["text", "tools"], "output": "text", "built_in": False},
    "mcp": {"inputs": ["text", "tools", "mcp"], "output": "text", "built_in": False},
    "image-to-text": {"inputs": ["image"], "output": "text", "built_in": True},
    "text-image-to-text": {"inputs": ["text", "image"], "output": "text", "built_in": True},
    "audio-to-text": {"inputs": ["audio"], "output": "text", "built_in": True},
    "audio-text-to-text": {"inputs": ["text", "audio"], "output": "text", "built_in": True},
    "document-to-text": {"inputs": ["document"], "output": "text", "built_in": False},
    "text-to-image": {"inputs": ["text"], "output": "image", "built_in": False},
    "image-editing": {"inputs": ["text", "image"], "output": "image", "built_in": False},
    "image-retrieval": {"inputs": ["image", "retrieval"], "output": "retrieval", "built_in": False},
    "text-to-audio": {"inputs": ["text"], "output": "audio", "built_in": False},
    "audio-to-audio": {"inputs": ["audio"], "output": "audio", "built_in": False},
    "video-to-text": {"inputs": ["video"], "output": "text", "built_in": False},
    "text-to-video": {"inputs": ["text"], "output": "video", "built_in": False},
    "video-editing": {"inputs": ["text", "video"], "output": "video", "built_in": False},
    "audio-video-to-text": {"inputs": ["audio", "video"], "output": "text", "built_in": False},
    "sandboxed-code": {"inputs": ["text", "code"], "output": "code", "built_in": False},
    "embedding": {"inputs": ["text"], "output": "embedding", "built_in": False},
    "reranking": {"inputs": ["text", "retrieval"], "output": "ranking", "built_in": False},
    "clustering": {"inputs": ["embedding"], "output": "clusters", "built_in": False},
    "semantic-search": {"inputs": ["text", "retrieval"], "output": "ranking", "built_in": False},
    "safety": {"inputs": ["text"], "output": "text", "built_in": True},
    "privacy": {"inputs": ["text"], "output": "text", "built_in": True},
    "fairness": {"inputs": ["text"], "output": "text", "built_in": True},
    "performance": {"inputs": ["text"], "output": "text", "built_in": True},
}


def profile_summary() -> list[dict[str, Any]]:
    return [{"name": name, **value} for name, value in sorted(TASK_PROFILES.items())]


def preset_summary() -> list[dict[str, Any]]:
    return [benchmark_preset(name) for name in BENCHMARK_PRESETS]
