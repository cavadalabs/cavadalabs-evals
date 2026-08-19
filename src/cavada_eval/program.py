from __future__ import annotations

import difflib
import json
import re
import tomllib
import unicodedata
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .assets import content_text
from .profiles import profile_summary
from .protocol import (
    PROTOCOL_VERSION,
    ProtocolError,
    Suite,
    _strict_json_loads,
    load_suite,
    sha256_file,
    wilson_gate_power,
)

PROGRAM_STATUSES = {"planned", "draft", "candidate", "calibrated", "approved", "deprecated", "retired"}
ASSURANCE_LEVELS = ("development", "candidate", "calibrated", "approved", "independently-reproduced")
EXECUTION_SUPPORT = {"built-in", "adapter-required"}
MODALITIES = {"text", "image", "audio", "video", "retrieval", "tools", "mcp", "code", "embedding"}
SOURCE_KINDS = {"law", "standard", "guidance", "threat-intelligence", "framework", "benchmark", "tool", "service"}
SOURCE_APPROVALS = {"reference-approved", "adapter-candidate", "legal-review-required", "service-authorization-required", "blocked"}
SOURCE_USES = {"reference-only", "optional-adapter", "discovery-only", "blocked"}
REDISTRIBUTION = {"reference-only", "allowed-with-notice", "prohibited", "review-required"}
DATA_TRANSFERS = {"none", "local-only", "third-party-service", "review-required"}
CROSSWALK_STATUSES = {"implemented-partial", "reference-only", "planned", "license-required", "legal-review-required"}
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
                        f"cross-suite token-containment duplicate inputs: {left_suite}/{left_id}, "
                        f"{right_suite}/{right_id} (containment={containment:.3f})"
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
                errors.append(
                    f"cross-suite near-duplicate inputs: {left_suite}/{left_id}, "
                    f"{right_suite}/{right_id} (similarity={ratio:.3f})"
                )
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
    required_dimensions = {"locale", "difficulty", "severity", "operating_condition", "expected_behavior"}
    if not isinstance(allocations, dict) or set(allocations) != required_dimensions:
        errors.append(f"allocations must define exactly {sorted(required_dimensions)}")
    else:
        for dimension, values in allocations.items():
            if (
                not isinstance(values, list)
                or not values
                or not all(
                    isinstance(value, dict)
                    and set(value) == {"id", "target"}
                    and isinstance(value["id"], str)
                    and value["id"]
                    and isinstance(value["target"], int)
                    and not isinstance(value["target"], bool)
                    and value["target"] > 0
                    for value in values
                )
            ):
                errors.append(f"allocation {dimension} must contain id/target entries")
            elif len({value["id"] for value in values}) != len(values):
                errors.append(f"allocation {dimension} contains duplicate ids")
            elif isinstance(total, int) and sum(value["target"] for value in values) != total:
                errors.append(f"allocation {dimension} does not equal target_unique_scenarios")
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

    gate_map = {
        gate.get("category"): gate.get("min")
        for gate in suite.config.get("gates", [])
        if isinstance(gate, dict)
    }
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
        if (
            not isinstance(subcategories, list)
            or not subcategories
            or not all(
                isinstance(value, dict)
                and set(value) == {"id", "target"}
                and isinstance(value["id"], str)
                and value["id"]
                and isinstance(value["target"], int)
                and not isinstance(value["target"], bool)
                and value["target"] > 0
                for value in subcategories
            )
        ):
            errors.append(f"{prefix}.subcategories must contain id/target entries")
        elif len({value["id"] for value in subcategories}) != len(subcategories):
            errors.append(f"{prefix}.subcategories contains duplicate ids")
        elif isinstance(target, int) and sum(value["target"] for value in subcategories) != target:
            errors.append(f"{prefix}.subcategories do not equal target")
        elif isinstance(module_id, str):
            module_subcategories[module_id] = {str(value["id"]) for value in subcategories}
    if isinstance(total, int) and module_total != total:
        errors.append("module targets do not equal target_unique_scenarios")
    if isinstance(splits, dict) and isinstance(splits.get("holdout"), int) and holdout_total > splits["holdout"]:
        errors.append("minimum module holdouts exceed the holdout split")
    if seen != set(gate_map):
        errors.append("blueprint modules and suite gate categories must match")
    allowed_allocations = {
        dimension: {str(value["id"]) for value in values}
        for dimension, values in allocations.items()
        if isinstance(values, list) and all(isinstance(value, dict) and "id" in value for value in values)
    } if isinstance(allocations, dict) else {}
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
    allocation_ceilings = {
        dimension: {str(value["id"]): int(value["target"]) for value in values}
        for dimension, values in allocations.items()
        if isinstance(values, list)
        and all(isinstance(value, dict) and isinstance(value.get("id"), str) and isinstance(value.get("target"), int) for value in values)
    } if isinstance(allocations, dict) else {}
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


def validate_judge_qualification_blueprint(
    path: Path,
    suite: Suite,
    *,
    raw: bytes | None = None,
) -> list[str]:
    try:
        captured = path.read_bytes() if raw is None else raw
        blueprint = tomllib.loads(captured.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return [f"cannot load judge qualification blueprint: {exc}"]
    errors: list[str] = []
    expected_fields = {
        "version",
        "status",
        "target_unique_responses",
        "minimum_model_families",
        "minimum_target_repetitions",
        "minimum_judge_repetitions",
        "maximum_invalid_cases",
        "minimum_repeat_stability",
        "required_probe_types",
        "allocations",
        "modules",
    }
    if set(blueprint) != expected_fields:
        errors.append(f"judge qualification blueprint fields must be exactly {sorted(expected_fields)}")
    target = blueprint.get("target_unique_responses")
    allocations = blueprint.get("allocations")
    modules = blueprint.get("modules")
    required_probes = blueprint.get("required_probe_types")
    if not isinstance(blueprint.get("version"), str) or not VERSION_PATTERN.fullmatch(blueprint["version"]):
        errors.append("judge qualification blueprint version must be semantic X.Y.Z")
    if blueprint.get("status") != "preregistered":
        errors.append("status must remain preregistered; approval is separate evidence")
    if not isinstance(target, int) or isinstance(target, bool) or target < 1:
        errors.append("target_unique_responses must be a positive integer")
    if not isinstance(blueprint.get("minimum_model_families"), int) or blueprint["minimum_model_families"] < 4:
        errors.append("minimum_model_families must be at least four")
    for field in ("minimum_target_repetitions", "minimum_judge_repetitions"):
        value = blueprint.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            errors.append(f"{field} must be a positive integer")
    maximum_invalid = blueprint.get("maximum_invalid_cases")
    if not isinstance(maximum_invalid, int) or isinstance(maximum_invalid, bool) or maximum_invalid < 0:
        errors.append("maximum_invalid_cases must be a non-negative integer")
    repeat_stability = blueprint.get("minimum_repeat_stability")
    if (
        not isinstance(repeat_stability, (int, float))
        or isinstance(repeat_stability, bool)
        or not 0 < float(repeat_stability) <= 1
    ):
        errors.append("minimum_repeat_stability must be in (0, 1]")
    required_dimensions = {"language", "severity", "response_length", "response_style", "probe_type"}
    if not isinstance(allocations, dict) or set(allocations) != required_dimensions:
        errors.append(f"allocations must define exactly {sorted(required_dimensions)}")
    else:
        for dimension, values in allocations.items():
            if (
                not isinstance(values, list)
                or not values
                or not all(
                    isinstance(value, dict)
                    and set(value) == {"id", "target"}
                    and isinstance(value["id"], str)
                    and value["id"]
                    and isinstance(value["target"], int)
                    and not isinstance(value["target"], bool)
                    and value["target"] > 0
                    for value in values
                )
            ):
                errors.append(f"allocation {dimension} must contain id/target entries")
            elif len({value["id"] for value in values}) != len(values):
                errors.append(f"allocation {dimension} contains duplicate ids")
            elif isinstance(target, int) and sum(value["target"] for value in values) != target:
                errors.append(f"allocation {dimension} does not equal target_unique_responses")
    probe_values = allocations.get("probe_type", []) if isinstance(allocations, dict) else []
    probe_ids = {str(value["id"]) for value in probe_values if isinstance(value, dict) and "id" in value}
    if not isinstance(required_probes, list) or set(required_probes) != probe_ids:
        errors.append("required_probe_types must exactly match the probe_type allocation")
    suite_modules = {
        str(gate["category"])
        for gate in suite.config.get("gates", [])
        if isinstance(gate, dict) and isinstance(gate.get("category"), str) and gate["category"]
    }
    seen: set[str] = set()
    module_total = 0
    if not isinstance(modules, list) or not modules:
        errors.append("modules must contain qualification targets")
        return errors
    expected_fields = {
        "id", "target", "pass_target", "fail_target", "failure_sensitivity_gate",
        "pass_specificity_gate", "design_rate", "minimum_power",
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
        if not all(isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in (count, pass_target, fail_target)):
            errors.append(f"{prefix} targets must be positive integers")
            continue
        module_total += count
        if pass_target + fail_target != count:
            errors.append(f"{prefix} pass/fail targets do not equal target")
        gate_values = (module["failure_sensitivity_gate"], module["pass_specificity_gate"])
        design_rate = module["design_rate"]
        minimum_power = module["minimum_power"]
        if not all(isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < float(value) < 1 for value in (*gate_values, minimum_power)):
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


def validate_judge_qualification_blueprint_approval(
    path: Path,
    suite: Suite,
    blueprint_sha256: str,
    *,
    raw: bytes | None = None,
    now: datetime | None = None,
    require_effective: bool = True,
) -> list[str]:
    try:
        captured = path.read_bytes() if raw is None else raw
        approval = _strict_json_loads(captured)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"cannot load judge qualification blueprint approval: {exc}"]
    if not isinstance(approval, dict):
        return ["judge qualification blueprint approval must be a JSON object"]

    expected_fields = {
        "approval_version",
        "approval_id",
        "scope",
        "status",
        "independent",
        "blueprint_sha256",
        "suite",
        "approver_id",
        "approver_qualification_evidence",
        "approver_qualification_evidence_sha256",
        "conflicts",
        "conflicts_resolved",
        "decision_rationale",
        "approved_at",
        "expires_at",
        "revoked_at",
        "revocation_reason",
    }
    errors: list[str] = []
    if set(approval) != expected_fields:
        errors.append(f"judge qualification blueprint approval fields must be exactly {sorted(expected_fields)}")
    expected_suite = {
        "name": suite.name,
        "version": suite.version,
        "dataset_sha256": sha256_file(suite.dataset_path),
        "rubric_sha256": sha256_file(suite.rubric_path),
    }
    required_text = (
        "approval_id",
        "approver_id",
        "approver_qualification_evidence",
        "conflicts",
        "decision_rationale",
        "approved_at",
        "expires_at",
    )
    if (
        approval.get("approval_version") != "1.0.0"
        or approval.get("scope") != "judge-qualification-blueprint"
        or approval.get("status") != "passed"
        or approval.get("independent") is not True
        or approval.get("conflicts_resolved") is not True
        or approval.get("blueprint_sha256") != blueprint_sha256
        or approval.get("suite") != expected_suite
        or not all(isinstance(approval.get(field), str) and approval[field].strip() for field in required_text)
    ):
        errors.append("judge qualification blueprint approval is incomplete, unlinked, or did not pass")
    evidence_hash = approval.get("approver_qualification_evidence_sha256")
    if not isinstance(evidence_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", evidence_hash):
        errors.append("judge qualification blueprint approver evidence SHA-256 is invalid")
    else:
        relative = approval.get("approver_qualification_evidence")
        if isinstance(relative, str):
            evidence_path = (suite.root / relative).resolve()
            try:
                evidence_path.relative_to(suite.root.resolve())
            except ValueError:
                errors.append("judge qualification blueprint approver evidence escapes the suite")
            else:
                if (suite.root / relative).is_symlink() or not evidence_path.is_file():
                    errors.append("judge qualification blueprint approver evidence must be a regular suite-local file")
                elif sha256_file(evidence_path) != evidence_hash:
                    errors.append("judge qualification blueprint approver evidence hash mismatch")

    revoked_at = approval.get("revoked_at")
    revocation_reason = approval.get("revocation_reason")
    if revoked_at is not None or revocation_reason != "":
        errors.append("judge qualification blueprint approval has been revoked")
    try:
        approved_at = datetime.fromisoformat(str(approval.get("approved_at", "")).replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(str(approval.get("expires_at", "")).replace("Z", "+00:00"))
        if approved_at.tzinfo is None or expires_at.tzinfo is None:
            raise ValueError
    except ValueError:
        errors.append("judge qualification blueprint approval timestamps are invalid")
    else:
        current = now or datetime.now(timezone.utc)
        if expires_at <= approved_at or (require_effective and (approved_at > current or expires_at <= current)):
            errors.append("judge qualification blueprint approval is not currently effective")
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
    source_register = load_source_register(repo_root / registry["source_register"])
    crosswalk = load_evidence_crosswalk(
        repo_root / registry["evidence_crosswalk"],
        {str(source["id"]) for source in source_register["sources"]},
    )
    return {
        **registry,
        "summary": {
            "suite_count": len(suites),
            "by_status": {status: sum(item["status"] == status for item in suites) for status in sorted(PROGRAM_STATUSES)},
            "by_assurance": {level: sum(item["assurance"] == level for item in suites) for level in ASSURANCE_LEVELS},
            "built_in": sum(item["execution_support"] == "built-in" for item in suites),
            "adapter_required": sum(item["execution_support"] == "adapter-required" for item in suites),
            "official_capable": sum(bool(item["official_capable"]) for item in suites),
            "sources": source_register["summary"],
            "crosswalk": crosswalk["summary"],
        },
    }


def load_source_register(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            register = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot load source register: {exc}") from exc
    errors = validate_source_register(register)
    if errors:
        raise ProtocolError("invalid source register:\n" + "\n".join(errors))
    sources = register["sources"]
    return {
        **register,
        "summary": {
            "count": len(sources),
            "by_approval": {
                status: sum(item["approval"] == status for item in sources)
                for status in sorted(SOURCE_APPROVALS)
            },
            "by_official_use": {
                use: sum(item["official_use"] == use for item in sources)
                for use in sorted(SOURCE_USES)
            },
        },
    }


def validate_source_register(register: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {"register_version", "reviewed_at", "review_due", "sources"}
    if set(register) != required:
        errors.append(f"source register fields must be exactly {sorted(required)}")
    if not isinstance(register.get("register_version"), str) or not VERSION_PATTERN.fullmatch(str(register.get("register_version"))):
        errors.append("source register version must be semantic X.Y.Z")
    dates: dict[str, date] = {}
    for field in ("reviewed_at", "review_due"):
        try:
            dates[field] = date.fromisoformat(str(register.get(field)))
        except ValueError:
            errors.append(f"source register {field} must be YYYY-MM-DD")
    if dates.get("review_due") and dates.get("reviewed_at") and dates["review_due"] <= dates["reviewed_at"]:
        errors.append("source register review_due must be after reviewed_at")
    sources = register.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("source register must contain sources")
        return errors
    source_fields = {
        "id", "kind", "name", "publisher", "version", "revision", "primary_url", "license",
        "license_url", "redistribution", "commercial_use", "data_transfer", "approval",
        "official_use", "conditions",
    }
    seen: set[str] = set()
    for index, source in enumerate(sources, 1):
        prefix = f"source[{index}]"
        if not isinstance(source, dict) or set(source) != source_fields:
            errors.append(f"{prefix} fields must be exactly {sorted(source_fields)}")
            continue
        source_id = source.get("id")
        if not isinstance(source_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", source_id):
            errors.append(f"{prefix}.id must be kebab-case")
        elif source_id in seen:
            errors.append(f"duplicate source id: {source_id}")
        else:
            seen.add(source_id)
        for field in ("name", "publisher", "version", "revision", "license", "commercial_use"):
            if not isinstance(source.get(field), str) or not source[field].strip():
                errors.append(f"{prefix}.{field} must be non-empty")
        for field in ("primary_url", "license_url"):
            if not isinstance(source.get(field), str) or not source[field].startswith("https://"):
                errors.append(f"{prefix}.{field} must be an HTTPS URL")
        for field, allowed in (
            ("kind", SOURCE_KINDS),
            ("approval", SOURCE_APPROVALS),
            ("official_use", SOURCE_USES),
            ("redistribution", REDISTRIBUTION),
            ("data_transfer", DATA_TRANSFERS),
        ):
            if source.get(field) not in allowed:
                errors.append(f"{prefix}.{field} is invalid")
        if not isinstance(source.get("conditions"), list) or not source["conditions"] or not all(
            isinstance(value, str) and value.strip() for value in source["conditions"]
        ):
            errors.append(f"{prefix}.conditions must be a non-empty string array")
        if source.get("official_use") == "optional-adapter" and source.get("approval") != "adapter-candidate":
            errors.append(f"{prefix} optional adapters must have adapter-candidate approval")
    return errors


def load_evidence_crosswalk(path: Path, source_ids: set[str]) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            crosswalk = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"cannot load evidence crosswalk: {exc}") from exc
    errors: list[str] = []
    required = {"crosswalk_version", "reviewed_at", "review_due", "claim_policy", "mappings"}
    if set(crosswalk) != required:
        errors.append(f"evidence crosswalk fields must be exactly {sorted(required)}")
    if not isinstance(crosswalk.get("crosswalk_version"), str) or not VERSION_PATTERN.fullmatch(str(crosswalk.get("crosswalk_version"))):
        errors.append("evidence crosswalk version must be semantic X.Y.Z")
    try:
        reviewed_at = date.fromisoformat(str(crosswalk.get("reviewed_at")))
        review_due = date.fromisoformat(str(crosswalk.get("review_due")))
        if review_due <= reviewed_at:
            errors.append("evidence crosswalk review_due must be after reviewed_at")
    except ValueError:
        errors.append("evidence crosswalk dates must be YYYY-MM-DD")
    if not isinstance(crosswalk.get("claim_policy"), str) or not crosswalk["claim_policy"].strip():
        errors.append("evidence crosswalk claim_policy is required")
    mappings = crosswalk.get("mappings")
    fields = {"id", "source_id", "source_version", "status", "scope", "repository_evidence", "external_evidence", "limitations"}
    seen: set[str] = set()
    if not isinstance(mappings, list) or not mappings:
        errors.append("evidence crosswalk must contain mappings")
        mappings = []
    for index, mapping in enumerate(mappings, 1):
        prefix = f"mapping[{index}]"
        if not isinstance(mapping, dict) or set(mapping) != fields:
            errors.append(f"{prefix} fields must be exactly {sorted(fields)}")
            continue
        mapping_id = mapping.get("id")
        if not isinstance(mapping_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", mapping_id):
            errors.append(f"{prefix}.id must be kebab-case")
        elif mapping_id in seen:
            errors.append(f"duplicate evidence mapping id: {mapping_id}")
        else:
            seen.add(mapping_id)
        if mapping.get("source_id") not in source_ids:
            errors.append(f"{prefix}.source_id is absent from the source register")
        if mapping.get("status") not in CROSSWALK_STATUSES:
            errors.append(f"{prefix}.status is invalid")
        for field in ("source_version", "scope"):
            if not isinstance(mapping.get(field), str) or not mapping[field].strip():
                errors.append(f"{prefix}.{field} must be non-empty")
        for field in ("repository_evidence", "external_evidence", "limitations"):
            values = mapping.get(field)
            if not isinstance(values, list) or not values or not all(isinstance(value, str) and value.strip() for value in values):
                errors.append(f"{prefix}.{field} must be a non-empty string array")
    if errors:
        raise ProtocolError("invalid evidence crosswalk:\n" + "\n".join(errors))
    return {
        **crosswalk,
        "summary": {
            "count": len(mappings),
            "by_status": {status: sum(mapping["status"] == status for mapping in mappings) for status in sorted(CROSSWALK_STATUSES)},
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
        "source_register",
        "evidence_crosswalk",
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
    if registry.get("source_register") != "program/source-register.toml":
        errors.append("source_register must be program/source-register.toml")
    if registry.get("evidence_crosswalk") != "standards/evidence_crosswalk.toml":
        errors.append("evidence_crosswalk must be standards/evidence_crosswalk.toml")
    suites = registry.get("suites")
    if not isinstance(suites, list) or not suites:
        errors.append("suites must contain at least one entry")
        return errors

    known_profiles = {item["name"]: bool(item["built_in"]) for item in profile_summary()}
    seen: set[str] = set()
    loaded_suites: list[Suite] = []
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
        loaded_suites.append(suite)
        if (suite.name, suite.version, suite.status) != (suite_id, item.get("version"), status):
            errors.append(
                f"{prefix} registry identity/status does not match suite: "
                f"{suite.name}@{suite.version} ({suite.status})"
            )
        blueprint_path = absolute / "case_blueprint.toml"
        if blueprint_path.is_file():
            errors.extend(f"{prefix}.case_blueprint: {error}" for error in validate_case_blueprint(blueprint_path, suite))
        reviewer_path = absolute / "review" / "reviewer_qualification.jsonl"
        if reviewer_path.is_file():
            errors.extend(f"{prefix}.reviewer_qualification: {error}" for error in validate_reviewer_fixtures(reviewer_path, suite))
        judge_blueprint_path = absolute / "judge" / "qualification_blueprint.toml"
        if judge_blueprint_path.is_file():
            errors.extend(
                f"{prefix}.judge_qualification: {error}"
                for error in validate_judge_qualification_blueprint(judge_blueprint_path, suite)
            )
    errors.extend(validate_cross_suite_duplicates(loaded_suites))
    return errors
