from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import tempfile
import tomllib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PROTOCOL_VERSION = "1.0.0"
BEHAVIORS = {"answer", "refuse", "abstain", "redirect", "safe_complete"}
RISK_DOMAINS = {"quality", "security", "privacy", "safety", "reliability"}
SEVERITIES = {"low", "medium", "high", "critical"}
REVIEW_STATUSES = {"approved", "needs_review", "rejected"}
SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
)


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Suite:
    root: Path
    config: dict[str, Any]
    cases: tuple[dict[str, Any], ...]
    rubric: str
    dataset_path: Path
    rubric_path: Path

    @property
    def name(self) -> str:
        return str(self.config["name"])

    @property
    def version(self) -> str:
        return str(self.config["version"])

    @property
    def status(self) -> str:
        return str(self.config["status"])


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def contains_secret_like(value: Any) -> bool:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
    os.chmod(path, 0o600)


def _inside(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ProtocolError(f"Suite path escapes its directory: {relative}") from exc
    return path


def _read_jsonl(path: Path) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ProtocolError(f"Invalid JSONL line {line_number}: {exc.msg}") from exc
            if not isinstance(row, dict):
                raise ProtocolError(f"Invalid JSONL line {line_number}: expected object")
            rows.append(row)
    return tuple(rows)


def load_suite(path: str | Path, *, official: bool = False) -> Suite:
    root = Path(path).resolve()
    config_path = root / "suite.toml"
    if not config_path.is_file():
        raise ProtocolError(f"Missing suite.toml in {root}")
    with config_path.open("rb") as handle:
        config = tomllib.load(handle)
    dataset_path = _inside(root, str(config.get("dataset", "dataset.jsonl")))
    rubric_path = _inside(root, str(config.get("rubric", "rubric.md")))
    if not dataset_path.is_file() or not rubric_path.is_file():
        raise ProtocolError("Dataset and rubric must exist inside the suite")
    suite = Suite(root, config, _read_jsonl(dataset_path), rubric_path.read_text(), dataset_path, rubric_path)
    errors = validate_suite(suite, official=official)
    if errors:
        raise ProtocolError("\n".join(errors))
    return suite


def validate_suite(suite: Suite, *, official: bool = False) -> list[str]:
    errors: list[str] = []
    config = suite.config
    for field in ("name", "version", "status", "data_classification"):
        if not isinstance(config.get(field), str) or not str(config[field]).strip():
            errors.append(f"suite.{field} is required")
    if config.get("protocol_version") != PROTOCOL_VERSION:
        errors.append(f"protocol_version must be {PROTOCOL_VERSION}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(config.get("version", ""))):
        errors.append("suite.version must be semantic x.y.z")
    if config.get("status") not in {"candidate", "approved", "retired"}:
        errors.append("suite.status must be candidate, approved, or retired")
    if not suite.cases:
        errors.append("dataset is empty")
    if contains_secret_like(config) or contains_secret_like(suite.rubric):
        errors.append("suite configuration or rubric contains secret-like material")
    pinned_dataset = config.get("dataset_sha256")
    pinned_rubric = config.get("rubric_sha256")
    if pinned_dataset and pinned_dataset != sha256_file(suite.dataset_path):
        errors.append("dataset_sha256 does not match dataset")
    if pinned_rubric and pinned_rubric != sha256_file(suite.rubric_path):
        errors.append("rubric_sha256 does not match rubric")

    seen_ids: set[str] = set()
    seen_inputs: set[str] = set()
    for index, case in enumerate(suite.cases, 1):
        prefix = f"case[{index}]"
        case_id = case.get("id")
        prompt = case.get("input")
        if not isinstance(case_id, str) or not case_id.strip():
            errors.append(f"{prefix}.id is required")
        elif case_id in seen_ids:
            errors.append(f"duplicate case id: {case_id}")
        else:
            seen_ids.add(case_id)
        if not isinstance(prompt, str) or not prompt.strip():
            errors.append(f"{prefix}.input is required")
        elif prompt in seen_inputs:
            errors.append(f"duplicate case input: {case_id}")
        else:
            seen_inputs.add(prompt)
        if case.get("expected_behavior") not in BEHAVIORS:
            errors.append(f"{prefix}.expected_behavior is invalid")
        if case.get("risk_domain") not in RISK_DOMAINS:
            errors.append(f"{prefix}.risk_domain is invalid")
        if case.get("severity") not in SEVERITIES:
            errors.append(f"{prefix}.severity is invalid")
        if not isinstance(case.get("category"), str) or not case["category"].strip():
            errors.append(f"{prefix}.category is required")
        if not isinstance(case.get("expected_behavior_reason"), str) or not case["expected_behavior_reason"].strip():
            errors.append(f"{prefix}.expected_behavior_reason is required")
        review = case.get("review")
        if not isinstance(review, dict) or review.get("status") not in REVIEW_STATUSES:
            errors.append(f"{prefix}.review.status is invalid")
        text = json.dumps(case, ensure_ascii=False)
        if contains_secret_like(text):
            errors.append(f"{prefix} contains secret-like material")

    if official:
        if suite.status != "approved":
            errors.append("official runs require suite.status=approved")
        unresolved = [case.get("id") for case in suite.cases if (case.get("review") or {}).get("status") != "approved"]
        if unresolved:
            errors.append(f"official runs require all cases approved; unresolved={len(unresolved)}")
        if not suite.config.get("gates"):
            errors.append("official runs require at least one gate")
        if not pinned_dataset or not pinned_rubric:
            errors.append("official runs require pinned dataset_sha256 and rubric_sha256")
        missing_provenance = [
            case.get("id")
            for case in suite.cases
            if not isinstance(case.get("source"), dict)
            or not isinstance((case.get("review") or {}).get("method"), str)
            or not case["review"]["method"].strip()
        ]
        if missing_provenance:
            errors.append(f"official runs require source and review method; missing={len(missing_provenance)}")
    return errors


def audit_suite(suite: Suite) -> dict[str, Any]:
    categories: dict[str, int] = {}
    behaviors: dict[str, int] = {}
    reviews: dict[str, int] = {}
    for case in suite.cases:
        categories[case["category"]] = categories.get(case["category"], 0) + 1
        behaviors[case["expected_behavior"]] = behaviors.get(case["expected_behavior"], 0) + 1
        status = case["review"]["status"]
        reviews[status] = reviews.get(status, 0) + 1
    return {
        "protocol_version": PROTOCOL_VERSION,
        "suite": f"{suite.name}@{suite.version}",
        "status": suite.status,
        "cases": len(suite.cases),
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
        "suite_config_sha256": sha256_file(suite.root / "suite.toml"),
        "categories": dict(sorted(categories.items())),
        "expected_behaviors": dict(sorted(behaviors.items())),
        "reviews": dict(sorted(reviews.items())),
    }


def wilson_interval(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    if confidence != 0.95:
        raise ProtocolError("Only the audited 95% Wilson interval is currently supported")
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def deterministic_checks(case: dict[str, Any], answer: str) -> dict[str, bool]:
    folded = answer.casefold()
    checks = {
        "non_empty": bool(answer.strip()),
        "no_secret_like_output": not contains_secret_like(answer),
    }
    required = [str(value).casefold() for value in case.get("required_terms", [])]
    forbidden = [str(value).casefold() for value in case.get("forbidden_terms", [])]
    if required:
        checks["required_terms"] = all(value in folded for value in required)
    if forbidden:
        checks["forbidden_terms"] = not any(value in folded for value in forbidden)
    if case.get("expected_json"):
        try:
            json.loads(answer)
        except json.JSONDecodeError:
            checks["json_validity"] = False
        else:
            checks["json_validity"] = True
    return checks


def git_evidence(root: Path) -> dict[str, Any]:
    def command(*args: str) -> str:
        result = subprocess.run(
            ["git", *args], cwd=root, text=True, capture_output=True, check=False, timeout=10
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    commit = command("rev-parse", "HEAD")
    status = command("status", "--porcelain", "--untracked-files=normal")
    return {"commit": commit, "dirty": bool(status), "status_sha256": sha256_bytes(status.encode())}


def environment_evidence(root: Path) -> dict[str, Any]:
    lock = root / "uv.lock"
    hardware: dict[str, Any] = {"machine": platform.machine(), "processor": platform.processor()}
    try:
        gpu = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,uuid", "--format=csv,noheader"],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
        if gpu.returncode == 0:
            hardware["gpus"] = [line.strip() for line in gpu.stdout.splitlines() if line.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "hardware": hardware,
        "uv_lock_sha256": sha256_file(lock) if lock.is_file() else "",
    }


def new_run_dir(root: Path, suite: Suite, model_label: str) -> tuple[str, Path]:
    now = datetime.now(timezone.utc)
    run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    safe_model = re.sub(r"[^A-Za-z0-9_.-]+", "-", model_label).strip("-") or "model"
    path = root / "runs" / suite.name / f"{run_id}_{safe_model}"
    path.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(path, 0o700)
    return run_id, path


def summarize(rows: Iterable[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    observations = list(rows)
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in observations:
        groups.setdefault(str(row.get("case_id")), []).append(row)
    items: list[dict[str, Any]] = []
    for case_id, group in groups.items():
        observed = {str(row.get("status")) for row in group}
        if "error" in observed:
            status = "error"
        elif "invalid" in observed:
            status = "invalid"
        elif "fail" in observed:
            status = "fail"
        elif observed == {"skipped"}:
            status = "skipped"
        elif observed == {"pass"}:
            status = "pass"
        else:
            status = "invalid"
        items.append(
            {
                "case_id": case_id,
                "category": group[0].get("category"),
                "status": status,
                "observations": len(group),
            }
        )
    statuses = {name: sum(row.get("status") == name for row in items) for name in ("pass", "fail", "invalid", "error", "skipped")}
    judged = statuses["pass"] + statuses["fail"]
    lower, upper = wilson_interval(statuses["pass"], judged)
    metrics = {
        "total": len(items),
        "observations": len(observations),
        **statuses,
        "pass_rate": statuses["pass"] / judged if judged else 0.0,
        "pass_rate_ci95": {"lower": lower, "upper": upper},
        "officially_valid": statuses["invalid"] == statuses["error"] == statuses["skipped"] == 0,
    }
    categories: list[dict[str, Any]] = []
    for category in sorted({str(row.get("category")) for row in items}):
        group = [row for row in items if row.get("category") == category]
        passed = sum(row.get("status") == "pass" for row in group)
        failed = sum(row.get("status") == "fail" for row in group)
        valid = passed + failed
        low, high = wilson_interval(passed, valid)
        categories.append(
            {
                "category": category,
                "total": len(group),
                "pass": passed,
                "fail": failed,
                "invalid": sum(row.get("status") == "invalid" for row in group),
                "error": sum(row.get("status") == "error" for row in group),
                "pass_rate": passed / valid if valid else 0.0,
                "ci95_lower": low,
                "ci95_upper": high,
            }
        )
    return metrics, categories


def apply_gates(suite: Suite, metrics: dict[str, Any], categories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    by_category = {row["category"]: row for row in categories}
    for gate in suite.config.get("gates", []):
        category = gate.get("category")
        source = by_category.get(category, {}) if category else metrics
        metric = str(gate.get("metric", "pass_rate_ci95.lower"))
        value: Any = source
        for part in metric.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        minimum = float(gate.get("min", 0))
        if not isinstance(value, (int, float)) or float(value) < minimum:
            failures.append({"category": category or "overall", "metric": metric, "minimum": minimum, "actual": value})
    return failures


def write_category_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = ["category", "total", "pass", "fail", "invalid", "error", "pass_rate", "ci95_lower", "ci95_upper"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(path, 0o600)
