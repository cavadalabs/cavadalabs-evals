from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from .profiles import profile_summary
from .protocol import PROTOCOL_VERSION, ProtocolError, Suite, load_suite, wilson_gate_power

PROGRAM_STATUSES = {"planned", "draft", "candidate", "calibrated", "approved", "deprecated", "retired"}
ASSURANCE_LEVELS = ("development", "candidate", "calibrated", "approved", "independently-reproduced")
EXECUTION_SUPPORT = {"built-in", "adapter-required"}
MODALITIES = {"text", "image", "audio", "video", "retrieval", "tools", "mcp", "code", "embedding"}
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*-v[1-9][0-9]*$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
STATUS_ASSURANCE = {
    "planned": {"development"},
    "draft": {"development"},
    "candidate": {"candidate"},
    "calibrated": {"calibrated"},
    "approved": {"approved", "independently-reproduced"},
    "deprecated": set(ASSURANCE_LEVELS),
    "retired": set(ASSURANCE_LEVELS),
}


def validate_case_blueprint(path: Path, suite: Suite) -> list[str]:
    try:
        with path.open("rb") as handle:
            blueprint = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [f"cannot load case blueprint: {exc}"]
    errors: list[str] = []
    total = blueprint.get("target_unique_scenarios")
    languages = blueprint.get("languages")
    each = blueprint.get("language_target_each")
    splits = blueprint.get("splits")
    modules = blueprint.get("modules")
    if not isinstance(total, int) or isinstance(total, bool) or total < 1:
        errors.append("target_unique_scenarios must be a positive integer")
    if not isinstance(languages, list) or not languages or not all(isinstance(item, str) and item for item in languages):
        errors.append("languages must be a non-empty string array")
    if not isinstance(each, int) or isinstance(each, bool) or each < 1:
        errors.append("language_target_each must be a positive integer")
    elif isinstance(total, int) and isinstance(languages, list) and each * len(languages) != total:
        errors.append("language allocation does not equal target_unique_scenarios")
    if not isinstance(splits, dict) or set(splits) != {"public", "practice", "calibration", "holdout"}:
        errors.append("splits must define exactly public, practice, calibration, and holdout")
    elif not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in splits.values()):
        errors.append("split counts must be non-negative integers")
    elif isinstance(total, int) and sum(splits.values()) != total:
        errors.append("split counts do not equal target_unique_scenarios")
    if not isinstance(modules, list) or not modules:
        errors.append("modules must contain at least one entry")
        return errors

    gate_map = {
        gate.get("category"): gate.get("min")
        for gate in suite.config.get("gates", [])
        if isinstance(gate, dict)
    }
    seen: set[str] = set()
    module_total = 0
    holdout_total = 0
    for index, module in enumerate(modules, 1):
        prefix = f"module[{index}]"
        if not isinstance(module, dict):
            errors.append(f"{prefix} must be a table")
            continue
        module_id = module.get("id")
        target = module.get("target")
        holdout = module.get("minimum_holdout")
        gate = module.get("draft_gate")
        design_rate = module.get("design_pass_rate")
        minimum_power = module.get("minimum_power")
        if not isinstance(module_id, str) or not module_id:
            errors.append(f"{prefix}.id must be non-empty")
        elif module_id in seen:
            errors.append(f"duplicate module id: {module_id}")
        else:
            seen.add(module_id)
        if not isinstance(target, int) or isinstance(target, bool) or target < 1:
            errors.append(f"{prefix}.target must be a positive integer")
        else:
            module_total += target
        if not isinstance(holdout, int) or isinstance(holdout, bool) or holdout < 1:
            errors.append(f"{prefix}.minimum_holdout must be a positive integer")
        else:
            holdout_total += holdout
            if isinstance(target, int) and holdout > target:
                errors.append(f"{prefix}.minimum_holdout exceeds target")
        if module.get("primary_metric") != "pass_rate_ci.lower":
            errors.append(f"{prefix}.primary_metric must be pass_rate_ci.lower")
        if not isinstance(gate, (int, float)) or isinstance(gate, bool) or not 0 < float(gate) <= 1:
            errors.append(f"{prefix}.draft_gate must be in (0, 1]")
        else:
            configured_gate = gate_map.get(module_id)
            if not isinstance(configured_gate, (int, float)) or isinstance(configured_gate, bool) or float(configured_gate) != float(gate):
                errors.append(f"{prefix}.draft_gate must match the suite gate")
        if (
            not isinstance(design_rate, (int, float))
            or isinstance(design_rate, bool)
            or not isinstance(gate, (int, float))
            or not float(gate) < float(design_rate) <= 1
        ):
            errors.append(f"{prefix}.design_pass_rate must be greater than draft_gate and at most 1")
        if not isinstance(minimum_power, (int, float)) or isinstance(minimum_power, bool) or not 0 < float(minimum_power) < 1:
            errors.append(f"{prefix}.minimum_power must be in (0, 1)")
        if (
            isinstance(holdout, int)
            and not isinstance(holdout, bool)
            and isinstance(gate, (int, float))
            and not isinstance(gate, bool)
            and isinstance(design_rate, (int, float))
            and not isinstance(design_rate, bool)
            and isinstance(minimum_power, (int, float))
            and not isinstance(minimum_power, bool)
            and 0 < float(gate) < float(design_rate) <= 1
            and wilson_gate_power(holdout, float(gate), float(design_rate)) < float(minimum_power)
        ):
            errors.append(f"{prefix}.minimum_holdout does not achieve minimum_power")
    if isinstance(total, int) and module_total != total:
        errors.append("module targets do not equal target_unique_scenarios")
    if isinstance(splits, dict) and isinstance(splits.get("holdout"), int) and holdout_total > splits["holdout"]:
        errors.append("minimum module holdouts exceed the holdout split")
    if seen != set(gate_map):
        errors.append("blueprint modules and suite gate categories must match")
    return errors


def load_program_registry(path: Path, *, repo_root: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            registry = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot load program registry: {exc}") from exc
    errors = validate_program_registry(registry, repo_root=repo_root)
    if errors:
        raise ProtocolError("invalid program registry:\n" + "\n".join(errors))
    suites = registry["suites"]
    return {
        **registry,
        "summary": {
            "suite_count": len(suites),
            "by_status": {status: sum(item["status"] == status for item in suites) for status in sorted(PROGRAM_STATUSES)},
            "by_assurance": {level: sum(item["assurance"] == level for item in suites) for level in ASSURANCE_LEVELS},
            "built_in": sum(item["execution_support"] == "built-in" for item in suites),
            "adapter_required": sum(item["execution_support"] == "adapter-required" for item in suites),
            "official_capable": sum(bool(item["official_capable"]) for item in suites),
        },
    }


def validate_program_registry(registry: dict[str, Any], *, repo_root: Path) -> list[str]:
    errors: list[str] = []
    required = {
        "program_version",
        "registry_version",
        "protocol_version",
        "compatibility_policy",
        "result_expiry_days",
        "assurance_levels",
        "suites",
    }
    unknown = set(registry) - required
    missing = required - set(registry)
    if missing:
        errors.append(f"missing program fields: {sorted(missing)}")
    if unknown:
        errors.append(f"unknown program fields: {sorted(unknown)}")
    for field in ("program_version", "registry_version"):
        if not isinstance(registry.get(field), str) or not VERSION_PATTERN.fullmatch(str(registry[field])):
            errors.append(f"{field} must be semantic version X.Y.Z")
    if registry.get("protocol_version") != PROTOCOL_VERSION:
        errors.append(f"protocol_version must be {PROTOCOL_VERSION}")
    if registry.get("compatibility_policy") != "same-major-explicit-cross-version-mapping":
        errors.append("compatibility_policy must fail closed across incompatible major versions")
    expiry = registry.get("result_expiry_days")
    if not isinstance(expiry, int) or isinstance(expiry, bool) or expiry < 1:
        errors.append("result_expiry_days must be a positive integer")
    if registry.get("assurance_levels") != list(ASSURANCE_LEVELS):
        errors.append(f"assurance_levels must be ordered as {list(ASSURANCE_LEVELS)}")
    suites = registry.get("suites")
    if not isinstance(suites, list) or not suites:
        errors.append("suites must contain at least one entry")
        return errors

    known_profiles = {item["name"]: bool(item["built_in"]) for item in profile_summary()}
    seen: set[str] = set()
    for index, item in enumerate(suites, 1):
        prefix = f"suite[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be a table")
            continue
        item_required = {
            "id",
            "family",
            "version",
            "status",
            "assurance",
            "modalities",
            "languages",
            "profiles",
            "execution_support",
            "official_capable",
            "claims",
            "exclusions",
            "external_prerequisites",
        }
        missing_item = item_required - set(item)
        unknown_item = set(item) - item_required - {"path"}
        if missing_item:
            errors.append(f"{prefix} missing fields: {sorted(missing_item)}")
            continue
        if unknown_item:
            errors.append(f"{prefix} unknown fields: {sorted(unknown_item)}")
        suite_id = item.get("id")
        if not isinstance(suite_id, str) or not ID_PATTERN.fullmatch(suite_id):
            errors.append(f"{prefix}.id must match {ID_PATTERN.pattern}")
        elif suite_id in seen:
            errors.append(f"duplicate suite id: {suite_id}")
        else:
            seen.add(suite_id)
        if not isinstance(item.get("family"), str) or not item["family"].strip():
            errors.append(f"{prefix}.family must be non-empty")
        if not isinstance(item.get("version"), str) or not VERSION_PATTERN.fullmatch(item["version"]):
            errors.append(f"{prefix}.version must be semantic version X.Y.Z")
        status = item.get("status")
        assurance = item.get("assurance")
        if status not in PROGRAM_STATUSES:
            errors.append(f"{prefix}.status is invalid")
        elif assurance not in STATUS_ASSURANCE[status]:
            errors.append(f"{prefix}.assurance {assurance!r} is inconsistent with status {status!r}")
        if item.get("execution_support") not in EXECUTION_SUPPORT:
            errors.append(f"{prefix}.execution_support is invalid")
        if not isinstance(item.get("official_capable"), bool):
            errors.append(f"{prefix}.official_capable must be boolean")
        elif item["official_capable"] and status != "approved":
            errors.append(f"{prefix} cannot be official-capable before approval")
        for field in ("modalities", "languages", "profiles", "claims", "exclusions", "external_prerequisites"):
            value = item.get(field)
            if not isinstance(value, list) or not value or not all(isinstance(part, str) and part.strip() for part in value):
                errors.append(f"{prefix}.{field} must be a non-empty string array")
        modalities = item.get("modalities")
        if isinstance(modalities, list) and not set(modalities) <= MODALITIES:
            errors.append(f"{prefix}.modalities contains unsupported values: {sorted(set(modalities) - MODALITIES)}")
        profiles = item.get("profiles")
        if isinstance(profiles, list):
            missing_profiles = sorted(set(profiles) - set(known_profiles))
            if missing_profiles:
                errors.append(f"{prefix}.profiles contains unknown values: {missing_profiles}")
            if item.get("execution_support") == "built-in" and any(not known_profiles.get(profile, False) for profile in profiles):
                errors.append(f"{prefix} claims built-in support for an adapter-required profile")

        suite_path = item.get("path")
        if status == "planned":
            if suite_path is not None:
                errors.append(f"{prefix}.path must be omitted while planned")
            continue
        if not isinstance(suite_path, str) or not suite_path:
            errors.append(f"{prefix}.path is required after planning")
            continue
        relative = Path(suite_path)
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"{prefix}.path must be a repository-relative safe path")
            continue
        absolute = (repo_root / relative).resolve()
        try:
            absolute.relative_to(repo_root.resolve())
        except ValueError:
            errors.append(f"{prefix}.path escapes the repository")
            continue
        if not absolute.is_dir():
            errors.append(f"{prefix}.path does not exist: {suite_path}")
            continue
        try:
            suite = load_suite(absolute)
        except ProtocolError as exc:
            errors.append(f"{prefix}.path is invalid: {exc}")
            continue
        if (suite.name, suite.version, suite.status) != (suite_id, item.get("version"), status):
            errors.append(
                f"{prefix} registry identity/status does not match suite: "
                f"{suite.name}@{suite.version} ({suite.status})"
            )
        blueprint_path = absolute / "case_blueprint.toml"
        if blueprint_path.is_file():
            errors.extend(f"{prefix}.case_blueprint: {error}" for error in validate_case_blueprint(blueprint_path, suite))
    return errors
