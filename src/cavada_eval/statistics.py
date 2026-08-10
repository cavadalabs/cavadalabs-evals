from __future__ import annotations

import math
import random
from collections.abc import Iterable, Mapping, Sequence
from statistics import mean, median, pstdev
from typing import Any


def _finite_values(values: Iterable[float]) -> list[float]:
    try:
        samples = [float(value) for value in values]
    except (TypeError, ValueError) as exc:
        raise ValueError("statistical inputs must be finite numbers") from exc
    if any(not math.isfinite(value) for value in samples):
        raise ValueError("statistical inputs must be finite numbers")
    return samples


def _resampling_parameters(confidence: float, samples: int, seed: int) -> None:
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(float(confidence))
        or not 0 < float(confidence) < 1
        or not isinstance(samples, int)
        or isinstance(samples, bool)
        or samples < 100
        or not isinstance(seed, int)
        or isinstance(seed, bool)
    ):
        raise ValueError("confidence must be finite and between 0 and 1, samples at least 100, and seed an integer")


def percentile(values: Sequence[float], probability: float) -> float:
    if not isinstance(probability, (int, float)) or isinstance(probability, bool) or not math.isfinite(float(probability)) or not 0 <= float(probability) <= 1:
        raise ValueError("probability must be a finite number from 0 to 1")
    ordered = sorted(_finite_values(values))
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def distribution(values: Iterable[float]) -> dict[str, float | int]:
    samples = _finite_values(values)
    if not samples:
        return {"count": 0, "min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0, "stdev": 0.0, "p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0}
    return {
        "count": len(samples),
        "min": min(samples),
        "max": max(samples),
        "mean": mean(samples),
        "median": median(samples),
        "stdev": pstdev(samples),
        "p50": percentile(samples, 0.50),
        "p90": percentile(samples, 0.90),
        "p95": percentile(samples, 0.95),
        "p99": percentile(samples, 0.99),
    }


def bootstrap_mean_interval(
    values: Sequence[float],
    *,
    confidence: float = 0.95,
    samples: int = 10_000,
    seed: int = 0,
) -> dict[str, float | int]:
    _resampling_parameters(confidence, samples, seed)
    source = _finite_values(values)
    if not source:
        return {"lower": 0.0, "upper": 0.0, "confidence": confidence, "samples": samples, "seed": seed}
    rng = random.Random(seed)  # noqa: S311 -- deterministic statistical resampling, not cryptography.
    estimates = [mean(rng.choices(source, k=len(source))) for _ in range(samples)]
    tail = (1 - confidence) / 2
    return {
        "lower": percentile(estimates, tail),
        "upper": percentile(estimates, 1 - tail),
        "confidence": confidence,
        "samples": samples,
        "seed": seed,
    }


def stratified_bootstrap_mean_interval(
    strata: Mapping[str, Sequence[float]],
    *,
    confidence: float = 0.95,
    samples: int = 10_000,
    seed: int = 0,
) -> dict[str, float | int]:
    _resampling_parameters(confidence, samples, seed)
    groups = {name: finite for name, values in strata.items() if (finite := _finite_values(values))}
    if not groups:
        return bootstrap_mean_interval([], confidence=confidence, samples=samples, seed=seed)
    rng = random.Random(seed)  # noqa: S311 -- deterministic statistical resampling, not cryptography.
    total = sum(len(values) for values in groups.values())
    estimates = [sum(sum(rng.choices(values, k=len(values))) for values in groups.values()) / total for _ in range(samples)]
    tail = (1 - confidence) / 2
    return {
        "lower": percentile(estimates, tail),
        "upper": percentile(estimates, 1 - tail),
        "confidence": confidence,
        "samples": samples,
        "seed": seed,
        "strata": len(groups),
    }


def mcnemar_exact(baseline: Sequence[bool], candidate: Sequence[bool]) -> dict[str, float | int]:
    if len(baseline) != len(candidate) or not baseline or not all(isinstance(value, bool) for value in (*baseline, *candidate)):
        raise ValueError("paired non-empty boolean samples of equal length are required")
    baseline_only = sum(left and not right for left, right in zip(baseline, candidate, strict=True))
    candidate_only = sum(right and not left for left, right in zip(baseline, candidate, strict=True))
    discordant = baseline_only + candidate_only
    if discordant == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, index) for index in range(min(baseline_only, candidate_only) + 1)) / (2**discordant)
        p_value = min(1.0, 2 * tail)
    return {"baseline_only": baseline_only, "candidate_only": candidate_only, "discordant": discordant, "p_value": p_value}


def paired_binary_comparison(
    baseline: dict[str, bool],
    candidate: dict[str, bool],
    *,
    confidence: float = 0.95,
    samples: int = 10_000,
    seed: int = 0,
) -> dict[str, Any]:
    if not all(isinstance(value, bool) for value in (*baseline.values(), *candidate.values())):
        raise ValueError("paired comparison inputs must be booleans")
    shared = sorted(set(baseline) & set(candidate))
    if not shared:
        raise ValueError("runs have no shared case IDs")
    left = [bool(baseline[item]) for item in shared]
    right = [bool(candidate[item]) for item in shared]
    deltas = [float(candidate_value) - float(baseline_value) for baseline_value, candidate_value in zip(left, right, strict=True)]
    return {
        "cases": len(shared),
        "baseline_pass_rate": mean(left),
        "candidate_pass_rate": mean(right),
        "absolute_delta": mean(deltas),
        "relative_delta": (mean(right) - mean(left)) / mean(left) if mean(left) else None,
        "delta_ci": bootstrap_mean_interval(deltas, confidence=confidence, samples=samples, seed=seed),
        "mcnemar": mcnemar_exact(left, right),
        "wins": sum(delta > 0 for delta in deltas),
        "ties": sum(delta == 0 for delta in deltas),
        "losses": sum(delta < 0 for delta in deltas),
    }


def holm_adjust(p_values: Sequence[float]) -> list[float]:
    values = _finite_values(p_values)
    if any(not 0 <= value <= 1 for value in values):
        raise ValueError("p-values must be finite numbers from 0 to 1")
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    adjusted = [0.0] * len(indexed)
    running = 0.0
    for rank, (original_index, value) in enumerate(indexed):
        running = max(running, min(1.0, (len(indexed) - rank) * value))
        adjusted[original_index] = running
    return adjusted
