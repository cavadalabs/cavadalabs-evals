from __future__ import annotations

import difflib
import json
import re
import tomllib
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any, TypeGuard

from .assets import content_text
from .profiles import TASK_PROFILES
from .protocol import PROTOCOL_VERSION, ProtocolError, Suite, load_suite, wilson_gate_power

ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*-v[1-9][0-9]*$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def _positive_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _probability(value: object, *, include_one: bool = False) -> TypeGuard[int | float]:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    return 0 < float(value) and (float(value) <= 1 if include_one else float(value) < 1)


def _allocation_errors(value: object, dimensions: set[str], total: object, total_name: str) -> list[str]:
    if not isinstance(value, dict) or set(value) != dimensions:
        return [f"allocations must define exactly {sorted(dimensions)}"]
    errors: list[str] = []
    for dimension, entries in value.items():
        valid = (
            isinstance(entries, list)
            and bool(entries)
            and all(
                isinstance(item, dict) and set(item) == {"id", "target"} and isinstance(item["id"], str) and item["id"] and _positive_int(item["target"])
                for item in entries
            )
        )
        if not valid:
            errors.append(f"allocation {dimension} must contain id/target entries")
        elif len({item["id"] for item in entries}) != len(entries):
            errors.append(f"allocation {dimension} contains duplicate ids")
        elif isinstance(total, int) and sum(item["target"] for item in entries) != total:
            errors.append(f"allocation {dimension} does not equal {total_name}")
    return errors


def validate_cross_suite_duplicates(suites: list[Suite]) -> list[str]:
    rows: list[tuple[str, str, str, Counter[str], set[str], float, float]] = []
    for suite in suites:
        threshold = float((suite.config.get("governance") or {}).get("near_duplicate_threshold", 0.92))
        semantic_threshold = float((suite.config.get("governance") or {}).get("semantic_duplicate_threshold", 0.95))
        for case in suite.cases:
            normalized = " ".join(unicodedata.normalize("NFKC", content_text(case.get("input"))).casefold().split())
            tokens = set(re.findall(r"\w+", normalized))
            rows.append((suite.name, str(case.get("id")), normalized, Counter(normalized), tokens, threshold, semantic_threshold))
    if len(rows) > 5_000:
        return ["cross-suite duplicate validation is limited to 5,000 cases; use a reviewed indexed detector"]
    errors: list[str] = []
    for index, (left_suite, left_id, left, left_chars, left_tokens, left_threshold, left_semantic) in enumerate(rows):
        for right_suite, right_id, right, right_chars, right_tokens, right_threshold, right_semantic in rows[index + 1 :]:
            if left_suite == right_suite:
                continue
            if left == right:
                errors.append(f"cross-suite duplicate inputs: {left_suite}/{left_id}, {right_suite}/{right_id}")
                continue
            if left_tokens and right_tokens:
                containment = len(left_tokens & right_tokens) / min(len(left_tokens), len(right_tokens))
                if containment >= min(left_semantic, right_semantic):
                    errors.append(
                        f"cross-suite token-containment duplicate inputs: {left_suite}/{left_id}, {right_suite}/{right_id} (containment={containment:.3f})"
                    )
                    continue
            threshold = min(left_threshold, right_threshold)
            length_total = len(left) + len(right)
            if 2 * min(len(left), len(right)) / length_total < threshold:
                continue
            smaller, larger = (left_chars, right_chars) if len(left_chars) <= len(right_chars) else (right_chars, left_chars)
            if 2 * sum(min(count, larger[character]) for character, count in smaller.items()) / length_total < threshold:
                continue
            matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
            ratio = matcher.ratio()
            if ratio >= threshold:
                errors.append(f"cross-suite near-duplicate inputs: {left_suite}/{left_id}, {right_suite}/{right_id} (similarity={ratio:.3f})")
    return errors


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
    allocations = blueprint.get("allocations")
    modules = blueprint.get("modules")
    required_case_fields = blueprint.get("required_case_fields")
    if not _positive_int(total):
        errors.append("target_unique_scenarios must be a positive integer")
    if not isinstance(languages, list) or not languages or not all(isinstance(item, str) and item for item in languages):
        errors.append("languages must be a non-empty string array")
    if not _positive_int(each):
        errors.append("language_target_each must be a positive integer")
    elif isinstance(total, int) and isinstance(languages, list) and each * len(languages) != total:
        errors.append("language allocation does not equal target_unique_scenarios")
    if not isinstance(splits, dict) or set(splits) != {"public", "practice", "calibration", "holdout"}:
        errors.append("splits must define exactly public, practice, calibration, and holdout")
    elif not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in splits.values()):
        errors.append("split counts must be non-negative integers")
    elif isinstance(total, int) and sum(splits.values()) != total:
        errors.append("split counts do not equal target_unique_scenarios")
    required_dimensions = {"locale", "difficulty", "severity", "operating_condition", "expected_behavior"}
    errors.extend(_allocation_errors(allocations, required_dimensions, total, "target_unique_scenarios"))
    if not isinstance(modules, list) or not modules:
        errors.append("modules must contain at least one entry")
        return errors
    if (
        not isinstance(required_case_fields, list)
        or not required_case_fields
        or not all(isinstance(field, str) and field for field in required_case_fields)
        or len(set(required_case_fields)) != len(required_case_fields)
    ):
        errors.append("required_case_fields must be a unique non-empty string array")
        required_case_fields = []

    gate_map = {gate.get("category"): gate.get("min") for gate in suite.config.get("gates", []) if isinstance(gate, dict)}
    seen: set[str] = set()
    module_total = 0
    holdout_total = 0
    module_subcategories: dict[str, set[str]] = {}
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
        subcategories = module.get("subcategories")
        if not isinstance(module_id, str) or not module_id:
            errors.append(f"{prefix}.id must be non-empty")
        elif module_id in seen:
            errors.append(f"duplicate module id: {module_id}")
        else:
            seen.add(module_id)
        if not _positive_int(target):
            errors.append(f"{prefix}.target must be a positive integer")
        else:
            module_total += target
        if not _positive_int(holdout):
            errors.append(f"{prefix}.minimum_holdout must be a positive integer")
        else:
            holdout_total += holdout
            if isinstance(target, int) and holdout > target:
                errors.append(f"{prefix}.minimum_holdout exceeds target")
        if module.get("primary_metric") != "pass_rate_ci.lower":
            errors.append(f"{prefix}.primary_metric must be pass_rate_ci.lower")
        if not _probability(gate, include_one=True):
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
        if not _probability(minimum_power):
            errors.append(f"{prefix}.minimum_power must be in (0, 1)")
        if (
            _positive_int(holdout)
            and _probability(gate)
            and _probability(design_rate, include_one=True)
            and _probability(minimum_power)
            and float(gate) < float(design_rate)
            and wilson_gate_power(holdout, float(gate), float(design_rate)) < float(minimum_power)
        ):
            errors.append(f"{prefix}.minimum_holdout does not achieve minimum_power")
        subcategory_errors = _allocation_errors({"subcategories": subcategories}, {"subcategories"}, target, "target")
        errors.extend(f"{prefix}.subcategories {error.removeprefix('allocation subcategories ')}" for error in subcategory_errors)
        if not subcategory_errors and isinstance(module_id, str) and isinstance(subcategories, list):
            module_subcategories[module_id] = {str(value["id"]) for value in subcategories}
    if isinstance(total, int) and module_total != total:
        errors.append("module targets do not equal target_unique_scenarios")
    if isinstance(splits, dict) and isinstance(splits.get("holdout"), int) and holdout_total > splits["holdout"]:
        errors.append("minimum module holdouts exceed the holdout split")
    if seen != set(gate_map):
        errors.append("blueprint modules and suite gate categories must match")
    allowed_allocations: dict[str, set[str]] = {}
    if isinstance(allocations, dict):
        for dimension, values in allocations.items():
            if isinstance(values, list):
                allowed_allocations[dimension] = {str(value["id"]) for value in values if isinstance(value, dict) and "id" in value}
    current_counts: dict[str, Counter[str]] = {
        "language": Counter(),
        "split": Counter(),
        "module": Counter(),
        **{dimension: Counter() for dimension in allowed_allocations},
    }
    scenario_aware = any(case.get("scenario_role") is not None for case in suite.cases)
    group_contracts: dict[str, tuple[str, str, str]] = {}
    for index, case in enumerate(suite.cases, 1):
        prefix = f"case[{index}]"
        missing = sorted(set(required_case_fields) - set(case))
        if missing:
            errors.append(f"{prefix} missing blueprint fields: {missing}")
        module = case.get("module")
        if module != case.get("category") or module not in module_subcategories:
            errors.append(f"{prefix}.module must equal a declared category")
        elif case.get("subcategory") not in module_subcategories[str(module)]:
            errors.append(f"{prefix}.subcategory is not declared for module {module}")
        language = case.get("language")
        if isinstance(languages, list) and language not in languages:
            errors.append(f"{prefix}.language is outside the blueprint")
        split = case.get("split")
        if isinstance(splits, dict) and split not in splits:
            errors.append(f"{prefix}.split is outside the blueprint")
        for dimension, allowed in allowed_allocations.items():
            if case.get(dimension) not in allowed:
                errors.append(f"{prefix}.{dimension} is outside the blueprint")
            elif not scenario_aware or case.get("scenario_role") == "primary":
                current_counts[dimension][str(case[dimension])] += 1
        if not scenario_aware or case.get("scenario_role") == "primary":
            for dimension, value in (("language", language), ("split", split), ("module", module)):
                current_counts[dimension][str(value)] += 1
        group = case.get("scenario_group_id")
        contract = str(split), str(module), str(language)
        if not isinstance(group, str) or not group:
            errors.append(f"{prefix}.scenario_group_id must be non-empty")
        elif group in group_contracts and group_contracts[group] != contract:
            errors.append(f"scenario group {group!r} crosses split, module, or language boundaries")
        else:
            group_contracts[group] = contract
    allocation_ceilings = (
        {
            dimension: {str(value["id"]): int(value["target"]) for value in values}
            for dimension, values in allocations.items()
            if isinstance(values, list)
            and all(isinstance(value, dict) and isinstance(value.get("id"), str) and isinstance(value.get("target"), int) for value in values)
        }
        if isinstance(allocations, dict)
        else {}
    )
    ceilings = {
        "language": {str(value): int(each) for value in languages} if isinstance(languages, list) and isinstance(each, int) else {},
        "split": {str(key): int(value) for key, value in splits.items()} if isinstance(splits, dict) else {},
        "module": {
            str(module["id"]): int(module["target"])
            for module in modules
            if isinstance(module, dict) and isinstance(module.get("id"), str) and isinstance(module.get("target"), int)
        },
        **allocation_ceilings,
    }
    for dimension, counts in current_counts.items():
        for value, count in counts.items():
            if value in ceilings.get(dimension, {}) and count > ceilings[dimension][value]:
                errors.append(f"current {dimension}={value!r} count {count} exceeds blueprint target {ceilings[dimension][value]}")
    return errors


def validate_reviewer_fixtures(path: Path, suite: Suite) -> list[str]:
    errors: list[str] = []
    fields = {"id", "module", "language", "prompt", "response", "gold_label", "severity", "rationale", "status"}
    labels = {"pass", "fail", "invalid", "borderline"}
    modules = {gate.get("category") for gate in suite.config.get("gates", []) if isinstance(gate, dict)}
    languages = {str(case.get("language")) for case in suite.cases if case.get("language")}
    seen_ids: set[str] = set()
    seen_modules: set[str] = set()
    seen_languages: set[str] = set()
    seen_labels: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [f"cannot read reviewer fixtures: {exc}"]
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        prefix = f"fixture[{line_number}]"
        try:
            fixture = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"{prefix} is invalid JSON: {exc.msg}")
            continue
        if not isinstance(fixture, dict) or set(fixture) != fields:
            errors.append(f"{prefix} fields must be exactly {sorted(fields)}")
            continue
        fixture_id = fixture.get("id")
        if not isinstance(fixture_id, str) or not fixture_id:
            errors.append(f"{prefix}.id must be non-empty")
        elif fixture_id in seen_ids:
            errors.append(f"duplicate reviewer fixture id: {fixture_id}")
        else:
            seen_ids.add(fixture_id)
        module = fixture.get("module")
        language = fixture.get("language")
        label = fixture.get("gold_label")
        if module not in modules:
            errors.append(f"{prefix}.module is not a suite gate category")
        else:
            seen_modules.add(str(module))
        if language not in languages:
            errors.append(f"{prefix}.language is not represented by authoring fixtures")
        else:
            seen_languages.add(str(language))
        if label not in labels:
            errors.append(f"{prefix}.gold_label is invalid")
        else:
            seen_labels.add(str(label))
        if fixture.get("severity") not in {"low", "medium", "high", "critical"}:
            errors.append(f"{prefix}.severity is invalid")
        if fixture.get("status") != "draft-author-gold":
            errors.append(f"{prefix}.status must remain draft-author-gold until independent approval")
        for field in ("prompt", "response", "rationale"):
            if not isinstance(fixture.get(field), str) or not fixture[field].strip():
                errors.append(f"{prefix}.{field} must be non-empty")
    if seen_modules != modules:
        errors.append("reviewer fixtures must cover every suite gate category")
    if seen_languages != languages:
        errors.append("reviewer fixtures must cover every suite language")
    if seen_labels != labels:
        errors.append("reviewer fixtures must cover pass, fail, invalid, and borderline")
    return errors


def validate_judge_qualification_blueprint(path: Path, suite: Suite, *, raw: bytes | None = None) -> list[str]:
    try:
        blueprint = tomllib.loads((raw if raw is not None else path.read_bytes()).decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return [f"cannot load judge qualification blueprint: {exc}"]
    errors: list[str] = []
    target = blueprint.get("target_unique_responses")
    allocations = blueprint.get("allocations")
    modules = blueprint.get("modules")
    required_probes = blueprint.get("required_probe_types")
    if not isinstance(blueprint.get("version"), str) or not VERSION_PATTERN.fullmatch(blueprint["version"]):
        errors.append("judge qualification blueprint version must be semantic X.Y.Z")
    if blueprint.get("status") != "preregistration-draft":
        errors.append("status must remain preregistration-draft until independent approval")
    if not _positive_int(target):
        errors.append("target_unique_responses must be a positive integer")
    if not isinstance(blueprint.get("minimum_model_families"), int) or blueprint["minimum_model_families"] < 4:
        errors.append("minimum_model_families must be at least four")
    if not _positive_int(blueprint.get("minimum_judge_repetitions")):
        errors.append("minimum_judge_repetitions must be a positive integer")
    maximum_invalid = blueprint.get("maximum_invalid_cases")
    if not isinstance(maximum_invalid, int) or isinstance(maximum_invalid, bool) or maximum_invalid < 0:
        errors.append("maximum_invalid_cases must be a non-negative integer")
    if not _probability(blueprint.get("minimum_repeat_stability"), include_one=True):
        errors.append("minimum_repeat_stability must be in (0, 1]")
    required_dimensions = {"language", "severity", "response_length", "response_style", "probe_type"}
    errors.extend(_allocation_errors(allocations, required_dimensions, target, "target_unique_responses"))
    probe_values = allocations.get("probe_type", []) if isinstance(allocations, dict) else []
    probe_ids = {str(value["id"]) for value in probe_values if isinstance(value, dict) and "id" in value}
    if not isinstance(required_probes, list) or set(required_probes) != probe_ids:
        errors.append("required_probe_types must exactly match the probe_type allocation")
    suite_modules = {gate.get("category") for gate in suite.config.get("gates", []) if isinstance(gate, dict)}
    seen: set[str] = set()
    module_total = 0
    if not isinstance(modules, list) or not modules:
        errors.append("modules must contain qualification targets")
        return errors
    expected_fields = {
        "id",
        "target",
        "pass_target",
        "fail_target",
        "failure_sensitivity_gate",
        "pass_specificity_gate",
        "design_rate",
        "minimum_power",
    }
    for index, module in enumerate(modules, 1):
        prefix = f"module[{index}]"
        if not isinstance(module, dict) or set(module) != expected_fields:
            errors.append(f"{prefix} fields must be exactly {sorted(expected_fields)}")
            continue
        module_id = module["id"]
        if module_id not in suite_modules or module_id in seen:
            errors.append(f"{prefix}.id must be a unique suite gate category")
        seen.add(str(module_id))
        count = module["target"]
        pass_target = module["pass_target"]
        fail_target = module["fail_target"]
        if not all(_positive_int(value) for value in (count, pass_target, fail_target)):
            errors.append(f"{prefix} targets must be positive integers")
            continue
        module_total += count
        if pass_target + fail_target != count:
            errors.append(f"{prefix} pass/fail targets do not equal target")
        gate_values = (module["failure_sensitivity_gate"], module["pass_specificity_gate"])
        design_rate = module["design_rate"]
        minimum_power = module["minimum_power"]
        if not all(_probability(value) for value in (*gate_values, minimum_power)):
            errors.append(f"{prefix} gates and minimum_power must be in (0, 1)")
            continue
        if not isinstance(design_rate, (int, float)) or isinstance(design_rate, bool) or not max(map(float, gate_values)) < float(design_rate) <= 1:
            errors.append(f"{prefix}.design_rate must exceed both gates and be at most 1")
            continue
        for label, sample_size, gate in (("pass", pass_target, gate_values[1]), ("fail", fail_target, gate_values[0])):
            if wilson_gate_power(sample_size, float(gate), float(design_rate)) < float(minimum_power):
                errors.append(f"{prefix}.{label}_target does not achieve minimum_power")
    if seen != suite_modules:
        errors.append("judge qualification modules must match suite gate categories")
    if isinstance(target, int) and module_total != target:
        errors.append("module targets do not equal target_unique_responses")
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
    return registry


def validate_program_registry(registry: dict[str, Any], *, repo_root: Path) -> list[str]:
    errors: list[str] = []
    required = {"registry_version", "protocol_version", "suites"}
    if set(registry) != required:
        errors.append(f"program fields must be exactly {sorted(required)}")
    if not isinstance(registry.get("registry_version"), str) or not VERSION_PATTERN.fullmatch(str(registry.get("registry_version"))):
        errors.append("registry_version must be semantic version X.Y.Z")
    if registry.get("protocol_version") != PROTOCOL_VERSION:
        errors.append(f"protocol_version must be {PROTOCOL_VERSION}")
    suites = registry.get("suites")
    if not isinstance(suites, list) or not suites:
        errors.append("suites must contain at least one entry")
        return errors

    known_profiles = set(TASK_PROFILES)
    seen: set[str] = set()
    loaded_suites: list[Suite] = []
    for index, item in enumerate(suites, 1):
        prefix = f"suite[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be a table")
            continue
        fields = {
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
            "path",
        }
        if set(item) != fields:
            errors.append(f"{prefix} fields must be exactly {sorted(fields)}")
            continue
        suite_id = item.get("id")
        if not isinstance(suite_id, str) or not ID_PATTERN.fullmatch(suite_id):
            errors.append(f"{prefix}.id must match {ID_PATTERN.pattern}")
        elif suite_id in seen:
            errors.append(f"duplicate suite id: {suite_id}")
        else:
            seen.add(suite_id)
        if not isinstance(item.get("version"), str) or not VERSION_PATTERN.fullmatch(item["version"]):
            errors.append(f"{prefix}.version must be semantic version X.Y.Z")
        profiles = item.get("profiles")
        if isinstance(profiles, list) and profiles:
            missing_profiles = sorted(set(profiles) - known_profiles)
            if missing_profiles:
                errors.append(f"{prefix}.profiles contains unknown values: {missing_profiles}")
        else:
            errors.append(f"{prefix}.profiles must be a non-empty array")

        suite_path = item.get("path")
        if not isinstance(suite_path, str) or not suite_path:
            errors.append(f"{prefix}.path must be non-empty")
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
        try:
            suite = load_suite(absolute)
        except ProtocolError as exc:
            errors.append(f"{prefix}.path is invalid: {exc}")
            continue
        loaded_suites.append(suite)
        if (suite.name, suite.version, suite.status) != (suite_id, item.get("version"), item.get("status")):
            errors.append(f"{prefix} registry identity/status does not match suite: {suite.name}@{suite.version} ({suite.status})")
        for label, relative_path, validator in (
            ("case_blueprint", Path("case_blueprint.toml"), validate_case_blueprint),
            ("reviewer_qualification", Path("review/reviewer_qualification.jsonl"), validate_reviewer_fixtures),
            ("judge_qualification", Path("judge/qualification_blueprint.toml"), validate_judge_qualification_blueprint),
        ):
            artifact = absolute / relative_path
            if artifact.is_file():
                errors.extend(f"{prefix}.{label}: {error}" for error in validator(artifact, suite))
    errors.extend(validate_cross_suite_duplicates(loaded_suites))
    return errors
