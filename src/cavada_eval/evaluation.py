from __future__ import annotations

import csv
import html
import importlib
import inspect
import itertools
import json
import math
import os
import random
import re
import string
import sys
import tomllib
import unicodedata
import urllib.parse
from contextlib import ExitStack
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence, cast

from .artifacts import verify_bundle, write_bundle
from .behavior_verify import verify_behavior_run
from .evaluators import (
    CallableEvaluator,
    EvalCase,
    Evaluator,
    contains,
    exact_match,
    json_fields,
    json_valid,
    normalized_match,
    regex_match,
    retrieval_metrics,
    serve_evaluators,
    token_f1_score,
)
from .protocol import ProtocolError, _strict_json_loads, atomic_json, atomic_text, contains_secret_like, load_suite, sha256_bytes, wilson_interval
from .runner import _read_json_object, _read_jsonl, run
from .statistics import paired_binary_comparison
from .targets import CallableTarget, OpenAICompatibleTarget, RecordedTarget, Target, serve_target

EXPERIMENT_VERSION = "1.0.0"
MAX_CLIENT_DATASET_BYTES = 64 * 1024 * 1024
MAX_CLIENT_CASES = 100_000
_FACTORY_REFERENCE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_.]*")
_CALLABLE_IDENTITIES: dict[int, tuple[Callable[..., Any], str]] = {}


@dataclass(frozen=True)
class PromptVariant:
    name: str
    template: str | None = None
    system: str | None = None
    messages: tuple[dict[str, str], ...] = ()
    renderer: Callable[[EvalCase], Any] | None = None
    renderer_reference: str = ""

    def __post_init__(self) -> None:
        modes = sum(value is not None and value != () for value in (self.template, self.messages, self.renderer))
        if not self.name or modes != 1:
            raise ValueError("PromptVariant requires a name and exactly one renderer mode")

    @property
    def identity(self) -> str:
        value = {
            "name": self.name,
            "template": self.template,
            "system": self.system,
            "messages": self.messages,
            "renderer": self.renderer_reference or (_callable_identity(self.renderer) if self.renderer else ""),
        }
        return _digest(value)

    def render(self, case: EvalCase) -> tuple[Any, list[dict[str, str]] | None]:
        if self.renderer is not None:
            try:
                rendered = self.renderer(case)
            except Exception as exc:
                raise ProtocolError(f'Prompt renderer "{self.name}" failed ({type(exc).__name__})') from exc
            if inspect.isawaitable(rendered):
                raise ProtocolError(f'Prompt renderer "{self.name}" must be synchronous')
            if isinstance(rendered, str):
                messages = ([{"role": "system", "content": self.system}, {"role": "user", "content": rendered}] if self.system else None)
                return rendered, messages
            if isinstance(rendered, list):
                return _chat_result(self.name, rendered)
            return _json_text(rendered, f'Prompt renderer "{self.name}" returned non-JSON data'), None
        values = _case_fields(case)
        if self.messages:
            rendered_messages = [
                {"role": message["role"], "content": _format(message["content"], values, self.name)}
                for message in self.messages
            ]
            if self.system:
                rendered_messages.insert(0, {"role": "system", "content": self.system})
            return _chat_result(self.name, rendered_messages)
        text = _format(str(self.template), values, self.name)
        messages = ([{"role": "system", "content": self.system}, {"role": "user", "content": text}] if self.system else None)
        return text, messages


@dataclass(frozen=True)
class ExperimentPlan:
    name: str
    profile: str
    seed: int
    dataset: Any
    prompts: tuple[PromptVariant, ...]
    targets: tuple[Target, ...]
    evaluators: tuple[Evaluator, ...]
    run: dict[str, Any]
    output_directory: Path
    data_classification: str
    description: str = ""
    source_bytes: bytes = b""
    project_root: Path = field(default_factory=Path.cwd)
    dataset_options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PreparedCell:
    cell_id: str
    prompt: PromptVariant
    target: Target
    repetition: int
    cases: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class PreparedExperiment:
    plan: ExperimentPlan
    cases: tuple[EvalCase, ...]
    dataset_snapshot: bytes
    dataset_sha256: str
    cells: tuple[PreparedCell, ...]
    summary: dict[str, Any]


@dataclass(frozen=True)
class ExperimentResult:
    path: Path
    summary: dict[str, Any]
    verification: dict[str, Any]


def _digest(value: Any) -> str:
    return sha256_bytes(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def _json_text(value: Any, error: str) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ProtocolError(error) from exc


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ProtocolError(f"{label} contains unknown fields: {unknown}")


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(f"{label} must be non-empty text")
    return value


def _positive_int(value: Any, label: str, *, zero: bool = False, maximum: int = 1_000_000) -> int:
    minimum = 0 if zero else 1
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ProtocolError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(value: Any, label: str, *, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ProtocolError(f"{label} must be true or false")
    return value


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9_.-]+", "-", value.casefold()).strip("-.")
    if not slug:
        raise ProtocolError("experiment name must contain a letter or digit")
    return slug[:80]


def _safe_file(root: Path, relative: str, label: str) -> Path:
    path = Path(relative)
    candidate = root / path
    if relative != unicodedata.normalize("NFC", relative) or "\\" in relative or path.is_absolute() or ".." in path.parts or candidate.is_symlink():
        raise ProtocolError(f"{label} must be a regular project-relative file")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ProtocolError(f"{label} does not exist: {relative}")
    return resolved


def _load_factory(reference: str, root: Path, label: str) -> Callable[..., Any]:
    if _FACTORY_REFERENCE.fullmatch(reference) is None:
        raise ProtocolError(f"{label} must use module:callable syntax")
    module_name, attribute = reference.split(":", 1)
    inserted = str(root.resolve())
    sys.path.insert(0, inserted)
    try:
        local_module = root.joinpath(*module_name.split(".")).with_suffix(".py")
        if local_module.is_file() and not local_module.is_symlink() and "." not in module_name:
            unique_name = f"_cavada_client_{sha256_bytes(str(local_module.resolve()).encode())}"
            spec = importlib.util.spec_from_file_location(unique_name, local_module)
            if spec is None or spec.loader is None:
                raise ImportError("cannot create a local module specification")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:
            importlib.invalidate_caches()
            module = importlib.import_module(module_name)
            if local_module.is_file() and Path(str(module.__file__)).resolve() != local_module.resolve():
                raise ImportError("module resolved outside the client project")
        value: Any = module
        for part in attribute.split("."):
            value = getattr(value, part)
    except (ImportError, AttributeError) as exc:
        raise ProtocolError(f"Cannot load trusted local {label} {reference!r}: {exc}") from exc
    except Exception as exc:
        raise ProtocolError(f"Trusted local {label} {reference!r} failed while loading ({type(exc).__name__})") from exc
    finally:
        if sys.path and sys.path[0] == inserted:
            sys.path.pop(0)
    if not callable(value):
        raise ProtocolError(f"{label} {reference!r} is not callable")
    return cast(Callable[..., Any], value)


def _callable_identity(value: Callable[..., Any] | None) -> str:
    if value is None:
        return ""
    cached = _CALLABLE_IDENTITIES.get(id(value))
    if cached is not None and cached[0] is value:
        return cached[1]
    subject = value.__func__ if inspect.ismethod(value) else value
    reference = f"{subject.__module__}:{getattr(subject, '__qualname__', subject.__class__.__qualname__)}"
    try:
        source = inspect.getsource(subject).encode()
    except (OSError, TypeError):
        source = reference.encode()
    state: dict[str, Any] = {
        "reference": reference,
        "source_sha256": sha256_bytes(source),
        "defaults": getattr(subject, "__defaults__", None),
        "kwdefaults": getattr(subject, "__kwdefaults__", None),
    }
    closure = getattr(subject, "__closure__", None)
    if closure:
        try:
            state["closure"] = [cell.cell_contents for cell in closure]
        except ValueError as exc:
            raise ProtocolError(f"callable {reference} contains an empty closure cell") from exc
    owner = value.__self__ if inspect.ismethod(value) and not inspect.isclass(value.__self__) else value if not inspect.isroutine(value) else None
    if owner is not None and hasattr(owner, "__dict__"):
        state["instance"] = vars(owner)
    try:
        identity = f"{reference}@sha256:{_digest(state)}"
    except (TypeError, ValueError) as exc:
        raise ProtocolError(
            f"callable {reference} captures non-JSON state; use CallableTarget or CallableEvaluator with an explicit immutable revision/config"
        ) from exc
    if len(_CALLABLE_IDENTITIES) >= 1024:
        _CALLABLE_IDENTITIES.clear()  # ponytail: bounded process cache; persist identities in the plan for cross-process resume.
    _CALLABLE_IDENTITIES[id(value)] = (value, identity)
    return identity


def _case_fields(case: EvalCase) -> dict[str, Any]:
    fields: dict[str, Any] = {"id": case.id}
    for value in (case.input, case.expected, case.metadata, case.extras):
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key in fields and fields[key] != item:
                    raise ProtocolError(f"Prompt field {key!r} is ambiguous in case {case.id}")
                fields[str(key)] = item
    fields.setdefault("input", case.input)
    fields.setdefault("expected", case.expected)
    fields.setdefault("metadata", case.metadata)
    return fields


def _format(template: str, values: dict[str, Any], prompt_name: str) -> str:
    try:
        for _literal, field_name, format_spec, conversion in string.Formatter().parse(template):
            if field_name is not None and (not field_name.isidentifier() or format_spec or conversion):
                raise ProtocolError(f'Prompt "{prompt_name}" may reference only plain field names')
        return template.format_map(values)
    except KeyError as exc:
        available = ", ".join(sorted(values))
        raise ProtocolError(
            f'Prompt "{prompt_name}" references unknown field: {exc.args[0]}\nAvailable fields: {available}'
        ) from exc
    except (IndexError, ValueError, AttributeError) as exc:
        raise ProtocolError(f'Prompt "{prompt_name}" has an invalid template: {exc}') from exc


def _chat_result(name: str, value: Any) -> tuple[str, list[dict[str, str]]]:
    if not isinstance(value, list) or not value:
        raise ProtocolError(f'Prompt "{name}" returned an empty chat')
    messages: list[dict[str, str]] = []
    for index, message in enumerate(value):
        if (
            not isinstance(message, Mapping)
            or message.get("role") not in {"system", "user", "assistant"}
            or not isinstance(message.get("content"), str)
            or not message["content"].strip()
        ):
            raise ProtocolError(f'Prompt "{name}" message {index} must contain role and text content')
        messages.append({"role": str(message["role"]), "content": str(message["content"])})
    users = [message["content"] for message in messages if message["role"] == "user"]
    if not users or messages[-1]["role"] != "user":
        raise ProtocolError(f'Prompt "{name}" must end with a user message')
    return users[-1], messages


def _record_case(record: Mapping[str, Any], id_field: str) -> EvalCase:
    identifier = record.get(id_field)
    if identifier is None:
        identifier = "case-" + _digest(record)[:16]
    if not isinstance(identifier, str) or not identifier.strip():
        raise ProtocolError(f"Dataset field {id_field!r} must be non-empty text")
    explicit_input = record.get("input")
    explicit_expected = record.get("expected")
    metadata = record.get("metadata", {})
    extras = record.get("extras", {})
    if metadata is not None and not isinstance(metadata, Mapping):
        raise ProtocolError(f"Dataset case {identifier} metadata must be an object")
    if extras is not None and not isinstance(extras, Mapping):
        raise ProtocolError(f"Dataset case {identifier} extras must be an object")
    return EvalCase(
        id=identifier,
        input=explicit_input if "input" in record else dict(record),
        expected=explicit_expected if "expected" in record else dict(record),
        metadata=dict(metadata or {}),
        extras=dict(extras or {}),
    )


def materialize_dataset(
    source: Any,
    *,
    root: Path | None = None,
    id_field: str = "id",
    split: str = "",
    split_field: str = "split",
    sample: int = 0,
    limit: int = 0,
    seed: int = 0,
) -> tuple[EvalCase, ...]:
    project_root = (root or Path.cwd()).resolve()
    resolved_source = source
    if isinstance(source, str) and _FACTORY_REFERENCE.fullmatch(source):
        try:
            resolved_source = _load_factory(source, project_root, "dataset factory")()
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError(f"Trusted dataset factory {source!r} failed ({type(exc).__name__})") from exc
    elif callable(source):
        try:
            resolved_source = source()
        except Exception as exc:
            raise ProtocolError(f"Trusted dataset factory failed ({type(exc).__name__})") from exc
    elif isinstance(source, (str, Path)):
        path = Path(source)
        path = _safe_file(project_root, str(path), "dataset path") if not path.is_absolute() else path.resolve()
        if path.is_symlink() or not path.is_file():
            raise ProtocolError("dataset path must be a regular file")
        if path.suffix.casefold() == ".jsonl":
            rows: list[Any] = []
            raw_dataset = path.read_bytes()
            if len(raw_dataset) > MAX_CLIENT_DATASET_BYTES:
                raise ProtocolError(f"dataset exceeds {MAX_CLIENT_DATASET_BYTES} bytes")
            for number, raw in enumerate(raw_dataset.splitlines(), 1):
                if not raw.strip():
                    continue
                try:
                    rows.append(_strict_json_loads(raw))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise ProtocolError(f"Invalid JSONL dataset line {number}: {exc}") from exc
            resolved_source = rows
        elif path.suffix.casefold() == ".csv":
            if path.stat().st_size > MAX_CLIENT_DATASET_BYTES:
                raise ProtocolError(f"dataset exceeds {MAX_CLIENT_DATASET_BYTES} bytes")
            try:
                with path.open(encoding="utf-8", newline="") as handle:
                    resolved_source = list(csv.DictReader(handle))
            except UnicodeDecodeError as exc:
                raise ProtocolError("CSV dataset must be UTF-8") from exc
        else:
            raise ProtocolError("dataset path must end in .jsonl or .csv")
    try:
        records = list(itertools.islice(iter(cast(Iterable[Any], resolved_source)), MAX_CLIENT_CASES + 1))
    except ProtocolError:
        raise
    except TypeError as exc:
        raise ProtocolError("dataset source must be an iterable of objects") from exc
    except Exception as exc:
        raise ProtocolError(f"dataset source failed during materialization ({type(exc).__name__})") from exc
    if len(records) > MAX_CLIENT_CASES:
        raise ProtocolError(f"dataset exceeds {MAX_CLIENT_CASES} cases")
    cases: list[EvalCase] = []
    for index, record in enumerate(records, 1):
        if isinstance(record, EvalCase):
            case = record
        elif isinstance(record, Mapping):
            case = _record_case(record, id_field)
        else:
            raise ProtocolError(f"Dataset item {index} must be an object or EvalCase")
        _json_text(asdict(case), f"Dataset case {case.id} is not finite JSON-like data")
        cases.append(case)
    seen: set[str] = set()
    for case in cases:
        if case.id in seen:
            raise ProtocolError(f"Dataset factory returned duplicate case ID: {case.id}")
        seen.add(case.id)
    if split:
        cases = [case for case in cases if str(_case_fields(case).get(split_field, "")) == split]
    if sample:
        if sample > len(cases):
            raise ProtocolError(f"dataset sample={sample} exceeds the {len(cases)} selected cases")
        selected = sorted(random.Random(seed).sample(range(len(cases)), sample))  # noqa: S311 -- deterministic dataset selection.
        cases = [cases[index] for index in selected]
    if limit:
        cases = cases[:limit]
    if not cases:
        raise ProtocolError("dataset selection is empty")
    return tuple(cases)


def _strings(value: Any, label: str, *, default: Sequence[str] = ()) -> tuple[str, ...]:
    if value is None:
        return tuple(default)
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ProtocolError(f"{label} must be an array of non-empty strings")
    return tuple(value)


def _number(value: Any, label: str, *, minimum: float = 0.0) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)) or value < minimum:
        raise ProtocolError(f"{label} must be a number of at least {minimum:g}")
    return float(value)


def _load_prompt(value: Any, root: Path, index: int) -> PromptVariant:
    label = f"prompts[{index}]"
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a table")
    _reject_unknown(value, {"name", "template", "static", "system", "messages", "factory"}, label)
    name = _nonempty(value.get("name"), f"{label}.name")
    modes = [field for field in ("template", "static", "messages", "factory") if value.get(field) is not None]
    if len(modes) != 1:
        raise ProtocolError(f"{label} must define exactly one of template, static, messages, or factory")
    system = value.get("system")
    if system is not None and (not isinstance(system, str) or not system.strip()):
        raise ProtocolError(f"{label}.system must be non-empty text")
    if "messages" in modes:
        raw_messages = value["messages"]
        if not isinstance(raw_messages, list) or not raw_messages:
            raise ProtocolError(f"{label}.messages must be a non-empty array of role/content tables")
        messages: list[dict[str, str]] = []
        for message_index, message in enumerate(raw_messages):
            if not isinstance(message, dict):
                raise ProtocolError(f"{label}.messages[{message_index}] must be a table")
            _reject_unknown(message, {"role", "content"}, f"{label}.messages[{message_index}]")
            messages.append(
                {
                    "role": _nonempty(message.get("role"), f"{label}.messages[{message_index}].role"),
                    "content": _nonempty(message.get("content"), f"{label}.messages[{message_index}].content"),
                }
            )
        return PromptVariant(name=name, system=system, messages=tuple(messages))
    if "factory" in modes:
        reference = _nonempty(value["factory"], f"{label}.factory")
        return PromptVariant(
            name=name,
            system=system,
            renderer=_load_factory(reference, root, "prompt renderer"),
            renderer_reference=reference,
        )
    field_name = modes[0]
    text = _nonempty(value[field_name], f"{label}.{field_name}")
    return PromptVariant(name=name, system=system, template=text)


def _target_identity(target: Target) -> dict[str, Any]:
    revision = target.revision or (_callable_identity(target.callable) if isinstance(target, CallableTarget) else "")
    result: dict[str, Any] = {
        "name": target.name,
        "model": target.model,
        "revision": revision,
        "capabilities": list(target.capabilities),
    }
    if isinstance(target, OpenAICompatibleTarget):
        result.update(
            {
                "type": "openai-compatible",
                "base_url": target.base_url,
                "api_key_env": target.api_key_env,
                "stream": target.stream,
                "pricing": dict(target.pricing) if target.pricing else None,
            }
        )
    elif isinstance(target, RecordedTarget):
        try:
            raw = target.path.read_bytes()
        except OSError as exc:
            raise ProtocolError(f'Recorded target "{target.name}" cannot read {target.path}') from exc
        result.update({"type": "recorded", "source_name": target.path.name, "source_sha256": sha256_bytes(raw)})
    elif isinstance(target, CallableTarget):
        result.update({"type": "callable", "callable": _callable_identity(target.callable)})
    else:
        result.update({"type": "callable", "callable": _callable_identity(target)})
    return result


def _load_target(value: Any, root: Path, index: int) -> Target:
    label = f"targets[{index}]"
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a table")
    _reject_unknown(
        value,
        {"name", "type", "base_url", "model", "api_key_env", "revision", "capabilities", "stream", "pricing", "factory", "path"},
        label,
    )
    name = _nonempty(value.get("name"), f"{label}.name")
    model = _nonempty(value.get("model", name), f"{label}.model")
    revision = value.get("revision", "")
    if not isinstance(revision, str):
        raise ProtocolError(f"{label}.revision must be text")
    capabilities = _strings(value.get("capabilities"), f"{label}.capabilities", default=("text",))
    if value.get("factory") is not None:
        reference = _nonempty(value["factory"], f"{label}.factory")
        return CallableTarget(name=name, callable=_load_factory(reference, root, "target callable"), model=model, revision=revision, capabilities=capabilities)
    kind = value.get("type")
    if kind == "recorded":
        path = _safe_file(root, _nonempty(value.get("path"), f"{label}.path"), f"{label}.path")
        return RecordedTarget(name=name, path=path, model=model, revision=revision, capabilities=capabilities)
    if kind != "openai-compatible":
        raise ProtocolError(f"{label}.type must be openai-compatible or recorded, or define factory")
    base_url = _nonempty(value.get("base_url"), f"{label}.base_url").rstrip("/")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ProtocolError(f"{label}.base_url must be an HTTP(S) URL without credentials, query, or fragment")
    pricing = value.get("pricing")
    if pricing is not None:
        if not isinstance(pricing, dict):
            raise ProtocolError(f"{label}.pricing must be a table")
        _reject_unknown(pricing, {"currency", "source", "effective_at", "input_per_million", "output_per_million"}, f"{label}.pricing")
        required_pricing = {"currency", "source", "effective_at", "input_per_million", "output_per_million"}
        if not required_pricing <= set(pricing):
            raise ProtocolError(f"{label}.pricing is missing: {sorted(required_pricing - set(pricing))}")
        if any(not isinstance(pricing[field], str) or not pricing[field].strip() for field in ("currency", "source", "effective_at")):
            raise ProtocolError(f"{label}.pricing text fields must be non-empty")
        for field in ("input_per_million", "output_per_million"):
            _number(pricing[field], f"{label}.pricing.{field}")
    api_key_env = value.get("api_key_env", "")
    if not isinstance(api_key_env, str) or (api_key_env and not api_key_env.isidentifier()):
        raise ProtocolError(f"{label}.api_key_env must be an environment-variable name")
    return OpenAICompatibleTarget(
        name=name,
        base_url=base_url,
        model=model,
        api_key_env=api_key_env,
        revision=revision,
        capabilities=capabilities,
        stream=_boolean(value.get("stream"), f"{label}.stream"),
        pricing=cast(Mapping[str, Any], pricing) if pricing else None,
    )


def _load_evaluator(value: Any, root: Path, index: int) -> Evaluator:
    label = f"evaluators[{index}]"
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a table")
    _reject_unknown(
        value,
        {
            "type",
            "name",
            "factory",
            "expected_field",
            "required",
            "forbidden",
            "case_sensitive",
            "pattern",
            "flags",
            "threshold",
            "precision_threshold",
            "k",
            "required_capabilities",
        },
        label,
    )
    kind = value.get("type")
    name = str(value.get("name") or kind or "custom")
    expected_field = value.get("expected_field")
    if expected_field is not None and (not isinstance(expected_field, str) or not expected_field.strip()):
        raise ProtocolError(f"{label}.expected_field must be non-empty text")
    if value.get("factory") is not None:
        reference = _nonempty(value["factory"], f"{label}.factory")
        capabilities = _strings(value.get("required_capabilities"), f"{label}.required_capabilities", default=("text",))
        factory = _load_factory(reference, root, "evaluator callable")
        return CallableEvaluator(
            name=name,
            callable=factory,
            required_capabilities=capabilities,
            config={"factory": reference, "identity": _callable_identity(factory), "type": "callable"},
        )
    required = value.get("required")
    forbidden = value.get("forbidden")
    if kind == "exact-match":
        return exact_match(expected_field, name=name)
    if kind == "normalized-match":
        return normalized_match(expected_field, name=name)
    if kind in {"contains", "forbidden-terms"}:
        return contains(
            required=cast(str | Sequence[str] | None, required),
            forbidden=cast(str | Sequence[str] | None, forbidden),
            expected_field=expected_field,
            case_sensitive=_boolean(value.get("case_sensitive"), f"{label}.case_sensitive", default=True),
            name=name,
        )
    if kind == "regex":
        return regex_match(
            value.get("pattern"),
            expected_field=expected_field,
            flags=_positive_int(value.get("flags", 0), f"{label}.flags", zero=True),
            name=name,
        )
    if kind == "json-valid":
        return json_valid(name=name)
    if kind == "json-fields":
        return json_fields(
            required=cast(Mapping[str, Any] | Sequence[str] | None, required),
            forbidden=cast(Sequence[str] | None, forbidden),
            expected_field=expected_field,
            name=name,
        )
    if kind == "token-f1":
        return token_f1_score(
            expected_field,
            threshold=_number(value.get("threshold", 1.0), f"{label}.threshold"),
            name=name,
        )
    if kind == "retrieval":
        return retrieval_metrics(
            expected_field,
            required=cast(Sequence[str] | None, required),
            forbidden=cast(Sequence[str] | None, forbidden),
            k=_positive_int(value["k"], f"{label}.k") if value.get("k") is not None else None,
            threshold=_number(value.get("threshold", 1.0), f"{label}.threshold"),
            precision_threshold=_number(value.get("precision_threshold", 0.0), f"{label}.precision_threshold"),
            name=name,
        )
    raise ProtocolError(f"{label}.type is unsupported: {kind!r}")


def load_experiment_plan(path: str | Path) -> ExperimentPlan:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ProtocolError("experiment plan must not be a symlink")
    source_path = candidate.resolve()
    try:
        source = source_path.read_bytes()
        config = tomllib.loads(source.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolError(f"Cannot load experiment plan: {exc}") from exc
    _json_text(config, "experiment plan contains non-finite or non-JSON-like values")
    if contains_secret_like(config):
        raise ProtocolError("experiment plan appears to contain a secret; use api_key_env instead")
    if not isinstance(config, dict):
        raise ProtocolError("experiment plan must be a TOML table")
    _reject_unknown(config, {"version", "name", "description", "profile", "seed", "dataset", "prompts", "targets", "evaluators", "run", "output"}, "plan")
    if str(config.get("version")) != "1":
        raise ProtocolError('experiment plan requires version = "1"')
    name = _nonempty(config.get("name"), "plan.name")
    description = config.get("description", "")
    if not isinstance(description, str):
        raise ProtocolError("plan.description must be text")
    profile = str(config.get("profile", "client"))
    if profile not in {"quick", "client", "official"}:
        raise ProtocolError("plan.profile must be quick, client, or official")
    if profile == "official":
        raise ProtocolError("the simple facade does not create official evidence; use a validated canonical suite with cavada-eval run --official")
    seed = config.get("seed", 0)
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ProtocolError("plan.seed must be an integer")
    root = source_path.parent
    dataset = config.get("dataset")
    if not isinstance(dataset, dict):
        raise ProtocolError("plan.dataset must be a table")
    _reject_unknown(dataset, {"type", "path", "factory", "id_field", "classification", "split", "split_field", "sample", "limit"}, "dataset")
    dataset_type = dataset.get("type")
    if dataset.get("factory") is not None:
        if dataset_type not in {None, "factory"}:
            raise ProtocolError("dataset.type must be factory when dataset.factory is used")
        dataset_source: Any = _nonempty(dataset["factory"], "dataset.factory")
    else:
        if dataset_type not in {"jsonl", "csv"}:
            raise ProtocolError("dataset.type must be jsonl or csv, or define dataset.factory")
        dataset_source = _safe_file(root, _nonempty(dataset.get("path"), "dataset.path"), "dataset.path")
        if dataset_source.suffix.casefold() != f".{dataset_type}":
            raise ProtocolError(f"dataset.path must end in .{dataset_type}")
    classification = str(dataset.get("classification", ""))
    if classification not in {"public", "synthetic", "internal", "confidential", "restricted"}:
        raise ProtocolError("dataset.classification must be public, synthetic, internal, confidential, or restricted")
    for field_name, default in (("id_field", "id"), ("split", ""), ("split_field", "split")):
        if not isinstance(dataset.get(field_name, default), str):
            raise ProtocolError(f"dataset.{field_name} must be text")
    raw_prompts = config.get("prompts")
    raw_targets = config.get("targets")
    raw_evaluators = config.get("evaluators")
    if not isinstance(raw_prompts, list) or not raw_prompts:
        raise ProtocolError("plan requires at least one [[prompts]] table")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ProtocolError("plan requires at least one [[targets]] table")
    if not isinstance(raw_evaluators, list) or not raw_evaluators:
        raise ProtocolError("plan requires at least one [[evaluators]] table")
    prompts = tuple(_load_prompt(item, root, index) for index, item in enumerate(raw_prompts))
    targets = tuple(_load_target(item, root, index) for index, item in enumerate(raw_targets))
    try:
        evaluators = tuple(_load_evaluator(item, root, index) for index, item in enumerate(raw_evaluators))
    except (TypeError, ValueError, re.error) as exc:
        raise ProtocolError(f"invalid evaluator configuration: {exc}") from exc
    for label, names in (("prompt", [item.name for item in prompts]), ("target", [item.name for item in targets]), ("evaluator", [item.name for item in evaluators])):
        if len(names) != len(set(names)):
            raise ProtocolError(f"duplicate {label} name: {next(name for name in names if names.count(name) > 1)}")
    run_config = config.get("run", {})
    if not isinstance(run_config, dict):
        raise ProtocolError("plan.run must be a table")
    _reject_unknown(
        run_config,
        {
            "concurrency",
            "timeout_seconds",
            "retries",
            "repetitions",
            "max_cases",
            "max_requests",
            "max_cost",
            "max_tokens",
            "max_elapsed_seconds",
            "rate_limit",
            "fail_fast",
            "resume",
            "external_authorization",
        },
        "run",
    )
    normalized_run = {
        "concurrency": _positive_int(run_config.get("concurrency", 4), "run.concurrency", maximum=64),
        "timeout_seconds": _number(run_config.get("timeout_seconds", 60), "run.timeout_seconds", minimum=0.001),
        "retries": _positive_int(run_config.get("retries", 2), "run.retries", zero=True, maximum=10),
        "repetitions": _positive_int(run_config.get("repetitions", 1), "run.repetitions", maximum=1000),
        "max_cases": _positive_int(run_config.get("max_cases", 0), "run.max_cases", zero=True),
        "max_requests": _positive_int(run_config.get("max_requests", 10_000), "run.max_requests"),
        "max_cost": _number(run_config.get("max_cost", 0), "run.max_cost"),
        "max_tokens": _positive_int(run_config.get("max_tokens", 0), "run.max_tokens", zero=True),
        "max_elapsed_seconds": _number(run_config.get("max_elapsed_seconds", 0), "run.max_elapsed_seconds"),
        "rate_limit": _number(run_config.get("rate_limit", 0), "run.rate_limit"),
        "fail_fast": _boolean(run_config.get("fail_fast"), "run.fail_fast"),
        "resume": _boolean(run_config.get("resume"), "run.resume"),
        "external_authorization": run_config.get("external_authorization", ""),
    }
    if not isinstance(normalized_run["external_authorization"], str):
        raise ProtocolError("run.external_authorization must be a project-relative path")
    output = config.get("output", {})
    if not isinstance(output, dict):
        raise ProtocolError("plan.output must be a table")
    _reject_unknown(output, {"directory", "formats"}, "output")
    formats = _strings(output.get("formats"), "output.formats", default=("json", "html"))
    if set(formats) != {"json", "html"}:
        raise ProtocolError("output.formats must contain json and html")
    directory_value = output.get("directory", "runs")
    if not isinstance(directory_value, str) or not directory_value:
        raise ProtocolError("output.directory must be non-empty text")
    directory = Path(directory_value)
    if directory.is_absolute() or not directory.parts or ".." in directory.parts or "\\" in directory_value:
        raise ProtocolError("output.directory must be a project-relative path")
    output_directory = (root / directory).resolve()
    return ExperimentPlan(
        name=name,
        profile=profile,
        seed=seed,
        dataset=dataset_source,
        prompts=prompts,
        targets=targets,
        evaluators=evaluators,
        run=normalized_run,
        output_directory=output_directory,
        data_classification=classification,
        description=description,
        source_bytes=source,
        project_root=root,
        dataset_options={key: value for key, value in dataset.items() if key not in {"path", "factory", "classification"}},
    )


def _evaluator_identity(evaluator: Evaluator) -> dict[str, Any]:
    result = {
        "name": evaluator.name,
        "required_capabilities": list(evaluator.required_capabilities),
        "config": dict(evaluator.config),
        "config_id": evaluator.config_id,
    }
    if isinstance(evaluator, CallableEvaluator):
        result["callable"] = _callable_identity(evaluator.callable)
    return result


def _plan_snapshot(plan: ExperimentPlan) -> dict[str, Any]:
    dataset: dict[str, Any] = {"classification": plan.data_classification, **plan.dataset_options}
    if isinstance(plan.dataset, Path):
        dataset.update({"source_name": plan.dataset.name, "source_sha256": sha256_bytes(plan.dataset.read_bytes())})
    elif isinstance(plan.dataset, str):
        dataset.update({"factory": plan.dataset})
    elif callable(plan.dataset):
        dataset.update({"factory": _callable_identity(plan.dataset)})
    else:
        dataset.update({"source": "python-iterable"})
    return {
        "experiment_version": EXPERIMENT_VERSION,
        "name": plan.name,
        "description": plan.description,
        "profile": plan.profile,
        "seed": plan.seed,
        "dataset": dataset,
        "prompts": [
            {
                "name": prompt.name,
                "template": prompt.template,
                "system": prompt.system,
                "messages": list(prompt.messages),
                "renderer": prompt.renderer_reference or (_callable_identity(prompt.renderer) if prompt.renderer else ""),
                "identity": prompt.identity,
            }
            for prompt in plan.prompts
        ],
        "targets": [_target_identity(target) for target in plan.targets],
        "evaluators": [_evaluator_identity(evaluator) for evaluator in plan.evaluators],
        "run": dict(plan.run),
        "output": {"directory": str(plan.output_directory), "formats": ["json", "html"]},
    }


def _rendered_case(case: EvalCase, prompt: PromptVariant, evaluators: Sequence[Evaluator]) -> dict[str, Any]:
    rendered, messages = prompt.render(case)
    input_text = rendered if isinstance(rendered, str) else _json_text(rendered, f"Prompt {prompt.name!r} returned invalid structured input")
    metadata = dict(case.metadata)
    risk_domain = metadata.get("risk_domain") if metadata.get("risk_domain") in {"quality", "security", "privacy", "safety", "reliability", "performance", "fairness"} else "quality"
    severity = metadata.get("severity") if metadata.get("severity") in {"low", "medium", "high", "critical"} else "low"
    split = metadata.get("split") if metadata.get("split") in {"public", "practice", "calibration", "holdout"} else "practice"
    client_case = asdict(case)
    result: dict[str, Any] = {
        "id": case.id,
        "input": input_text,
        "category": str(metadata.get("category") or "client-eval"),
        "risk_domain": risk_domain,
        "severity": severity,
        "language": str(metadata.get("language") or "und"),
        "locale": str(metadata.get("locale") or "und"),
        "split": split,
        "expected_behavior": "answer",
        "expected_behavior_reason": "Apply only the evaluators frozen in the client experiment plan.",
        "mandatory_criteria": [evaluator.name for evaluator in evaluators],
        "source": {
            "origin": "client-experiment-plan",
            "metadata": {
                "client_case": client_case,
                "client_target_case": {
                    "id": case.id,
                    "input": input_text,
                    "metadata": dict(case.metadata),
                    "extras": dict(case.extras),
                    "prompt": input_text,
                    "messages": messages,
                },
                "prompt_name": prompt.name,
                "prompt_identity": prompt.identity,
            },
        },
        "review": {"status": "approved", "method": "automatic-client-plan-validation"},
    }
    if messages is not None:
        result["messages"] = messages
    return result


def prepare_experiment(plan: ExperimentPlan) -> PreparedExperiment:
    for label, names in (
        ("prompt", [item.name for item in plan.prompts]),
        ("target", [item.name for item in plan.targets]),
        ("evaluator", [item.name for item in plan.evaluators]),
    ):
        if not names:
            raise ProtocolError(f"experiment requires at least one {label}")
        if not all(isinstance(name, str) and name for name in names):
            raise ProtocolError(f"{label} names must be non-empty text")
        if len(names) != len(set(names)):
            raise ProtocolError(f"duplicate {label} name")
    options = plan.dataset_options
    cases = materialize_dataset(
        plan.dataset,
        root=plan.project_root,
        id_field=str(options.get("id_field", "id")),
        split=str(options.get("split", "")),
        split_field=str(options.get("split_field", "split")),
        sample=_positive_int(options.get("sample", 0), "dataset.sample", zero=True),
        limit=_positive_int(options.get("limit", 0), "dataset.limit", zero=True),
        seed=plan.seed,
    )
    max_cases = int(plan.run["max_cases"])
    if max_cases:
        cases = cases[:max_cases]
    if not cases:
        raise ProtocolError("run.max_cases produced an empty dataset")
    dataset_snapshot = b"".join(
        json.dumps(asdict(case), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        for case in cases
    )
    dataset_sha256 = sha256_bytes(dataset_snapshot)
    capability_errors: list[str] = []
    for target in plan.targets:
        if not all(isinstance(value, str) and value for value in (target.name, target.model)) or not isinstance(target.revision, str):
            capability_errors.append("Targets require non-empty name and model identities plus a text revision")
        capabilities = tuple(target.capabilities)
        if not capabilities or not all(isinstance(value, str) and value for value in capabilities):
            capability_errors.append(f'Target "{target.name}" capabilities must be non-empty strings')
        elif len(capabilities) != len(set(capabilities)):
            capability_errors.append(f'Target "{target.name}" declares duplicate capabilities')
        for evaluator in plan.evaluators:
            if not isinstance(evaluator.name, str) or not evaluator.name:
                capability_errors.append("Evaluators require non-empty names")
                continue
            try:
                _json_text(_evaluator_identity(evaluator), f'Evaluator "{evaluator.name}" has invalid configuration')
            except (AttributeError, TypeError, ValueError) as exc:
                raise ProtocolError(f'Evaluator "{evaluator.name}" does not implement the public evaluator contract') from exc
            required_capabilities = tuple(evaluator.required_capabilities)
            if not required_capabilities or not all(isinstance(value, str) and value for value in required_capabilities):
                capability_errors.append(f'Evaluator "{evaluator.name}" capabilities must be non-empty strings')
                continue
            missing = sorted(set(required_capabilities) - set(capabilities))
            if missing:
                capability_errors.append(
                    f'Evaluator {evaluator.name} requires response.{missing[0]}, but target "{target.name}" does not declare {missing[0]} capability.'
                )
    if capability_errors:
        raise ProtocolError("\n".join(capability_errors))
    target_requests = len(cases) * len(plan.prompts) * len(plan.targets) * int(plan.run["repetitions"])
    maximum_target_attempts = (
        len(cases)
        * len(plan.prompts)
        * int(plan.run["repetitions"])
        * sum(0 if isinstance(target, RecordedTarget) else int(plan.run["retries"]) + 1 for target in plan.targets)
    )
    if maximum_target_attempts > int(plan.run["max_requests"]):
        raise ProtocolError(
            f"The experiment expands to {target_requests:,} requests ({maximum_target_attempts:,} maximum target attempts) "
            f"and exceeds max_requests={plan.run['max_requests']:,}.\n"
            "Reduce the matrix or raise the explicit limit after reviewing cavada-eval plan output."
        )
    if plan.run["max_cost"] and any(not isinstance(target, OpenAICompatibleTarget) or target.pricing is None for target in plan.targets):
        raise ProtocolError("run.max_cost requires an explicit pricing source for every target; no cost was estimated")
    if plan.run["max_cost"]:
        currencies = {str(target.pricing["currency"]) for target in plan.targets if isinstance(target, OpenAICompatibleTarget) and target.pricing}
        if len(currencies) != 1:
            raise ProtocolError("run.max_cost requires every target pricing source to use the same currency")
    cells: list[PreparedCell] = []
    for prompt in plan.prompts:
        rendered_cases = tuple(_rendered_case(case, prompt, plan.evaluators) for case in cases)
        rendered_raw = b"".join(
            json.dumps(case, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            for case in rendered_cases
        )
        rendered_sha256 = sha256_bytes(rendered_raw)
        for target in plan.targets:
            for repetition in range(1, int(plan.run["repetitions"]) + 1):
                identity = {
                    "experiment": plan.name,
                    "profile": plan.profile,
                    "dataset_sha256": dataset_sha256,
                    "rendered_dataset_sha256": rendered_sha256,
                    "prompt": prompt.identity,
                    "target": _target_identity(target),
                    "evaluators": [_evaluator_identity(evaluator) for evaluator in plan.evaluators],
                    "run": plan.run,
                    "repetition": repetition,
                }
                cells.append(PreparedCell(_digest(identity)[:24], prompt, target, repetition, rendered_cases))
    missing_credentials = [
        target.api_key_env
        for target in plan.targets
        if isinstance(target, OpenAICompatibleTarget) and target.api_key_env and target.api_key_env not in os.environ
    ]
    rows = [
        {
            "cell_id": cell.cell_id,
            "dataset_sha256": dataset_sha256,
            "prompt": cell.prompt.name,
            "target": cell.target.name,
            "target_model": cell.target.model,
            "repetition": cell.repetition,
            "evaluators": [evaluator.name for evaluator in plan.evaluators],
            "cases": len(cases),
            "target_requests": len(cases),
            "maximum_target_attempts": 0 if isinstance(cell.target, RecordedTarget) else len(cases) * (int(plan.run["retries"]) + 1),
        }
        for cell in cells
    ]
    summary = {
        "experiment_version": EXPERIMENT_VERSION,
        "name": plan.name,
        "profile": plan.profile,
        "dataset": {"cases": len(cases), "sha256": dataset_sha256, "classification": plan.data_classification},
        "prompt_variants": [prompt.name for prompt in plan.prompts],
        "targets": [target.name for target in plan.targets],
        "evaluators": [evaluator.name for evaluator in plan.evaluators],
        "cells": rows,
        "cell_count": len(rows),
        "target_requests": target_requests,
        "logical_observations": target_requests,
        "maximum_target_attempts": maximum_target_attempts,
        "evaluator_applications": target_requests * len(plan.evaluators),
        "concurrency": plan.run["concurrency"],
        "max_cost": plan.run["max_cost"] or None,
        "output_directory": str(plan.output_directory),
        "network_used": False,
        "warnings": (
            [f"Environment variable {name} is not set. The secret was not read and no network call was attempted." for name in sorted(set(missing_credentials))]
            + (["quick results are development evidence and are not suitable for strong claims"] if plan.profile == "quick" else [])
        ),
    }
    return PreparedExperiment(plan, cases, dataset_snapshot, dataset_sha256, tuple(cells), summary)


def _toml(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    raise ProtocolError(f"cannot encode TOML value: {value!r}")


def _write_once(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(raw)
    except FileExistsError as exc:
        if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
            raise ProtocolError(f"refusing to overwrite experiment artifact: {path}") from exc
    os.chmod(path, 0o600)


def _recorded_responses(target: RecordedTarget, cases: Sequence[EvalCase]) -> bytes:
    rows = []
    for case in cases:
        try:
            response = target({"case_id": case.id})
        except Exception as exc:
            raise ProtocolError(f'Recorded target "{target.name}" has no valid response for case {case.id}') from exc
        if inspect.isawaitable(response):  # pragma: no cover - RecordedTarget is synchronous by contract.
            raise ProtocolError("recorded target unexpectedly returned an awaitable")
        rows.append({"case_id": case.id, "response": response})
    return b"".join(
        json.dumps(row, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode() + b"\n" for row in rows
    )


def _suite_bytes(prepared: PreparedExperiment, cell: PreparedCell) -> tuple[bytes, bytes, bytes, bytes | None]:
    dataset = b"".join(
        json.dumps(case, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode() + b"\n" for case in cell.cases
    )
    evaluator_snapshot = [_evaluator_identity(evaluator) for evaluator in prepared.plan.evaluators]
    rubric = (
        "# Cavada client evaluator bridge 1.0.0\n\n"
        "Apply only the evaluator configuration frozen below. Missing required evidence is invalid. "
        "This candidate evaluation does not authorize official, compliance, certification, or ranking claims.\n\n"
        f"```json\n{json.dumps(evaluator_snapshot, ensure_ascii=False, indent=2, sort_keys=True)}\n```\n"
    ).encode()
    target = cell.target
    capabilities = sorted(set(target.capabilities))
    target_lines: list[str]
    recorded: bytes | None = None
    if isinstance(target, RecordedTarget):
        recorded = _recorded_responses(target, prepared.cases)
        target_lines = [
            'kind = "recorded"',
            'responses = "recorded_responses.jsonl"',
            f"responses_sha256 = {_toml(sha256_bytes(recorded))}",
            'response_field = "answer"',
            'reported_model_field = "model"',
        ]
    elif isinstance(target, OpenAICompatibleTarget):
        target_lines = ['kind = "openai"', f"stream = {_toml(target.stream)}", f"retries = {prepared.plan.run['retries']}"]
    else:
        target_lines = [
            'kind = "json"',
            'request_field = "message"',
            'request_defaults_json = "{}"',
            'response_field = "answer"',
            'reported_model_field = "model"',
            f"retries = {prepared.plan.run['retries']}",
        ]
    target_lines.extend(
        [
            'retrieved_ids_field = "retrieval"',
            'sources_field = "citations"',
            'tools_field = "tool_calls"',
            f"capabilities = {_toml(capabilities)}",
        ]
    )
    suite_lines = [
        'protocol_version = "1.0.0"',
        f"name = {_toml('client-' + _safe_slug(prepared.plan.name)[:32] + '-' + cell.cell_id)}",
        'version = "1.0.0"',
        'status = "candidate"',
        f"description = {_toml('Generated client evaluation cell for ' + prepared.plan.name + '.')}",
        'profile = "text-generation"',
        'dataset = "dataset.jsonl"',
        'rubric = "rubric.md"',
        f"data_classification = {_toml(prepared.plan.data_classification)}",
        f"dataset_sha256 = {_toml(sha256_bytes(dataset))}",
        f"rubric_sha256 = {_toml(sha256_bytes(rubric))}",
        "temperature = 0",
        "max_tokens = 1024",
        "",
        "[governance]",
        f"retention = {_toml('Client-controlled; see experiment plan ' + prepared.plan.name)}",
        "",
        "[statistics]",
        "confidence = 0.95",
        "bootstrap_samples = 1000",
        f"seed = {prepared.plan.seed}",
        "",
        "[target]",
        *target_lines,
    ]
    if isinstance(target, OpenAICompatibleTarget) and target.pricing:
        pricing = dict(target.pricing)
        required = {"currency", "source", "effective_at", "input_per_million", "output_per_million"}
        if not required <= set(pricing):
            raise ProtocolError(f'Target "{target.name}" pricing is missing: {sorted(required - set(pricing))}')
        suite_lines.extend(
            [
                "",
                "[pricing]",
                *[f"{field} = {_toml(pricing[field])}" for field in ("currency", "source", "effective_at", "input_per_million", "output_per_million")],
                "judge_input_per_million = 0.0",
                "judge_output_per_million = 0.0",
            ]
        )
    return ("\n".join(suite_lines) + "\n").encode(), dataset, rubric, recorded


def _write_cell_suite(prepared: PreparedExperiment, cell: PreparedCell, root: Path) -> Path:
    suite_root = root / "cells" / cell.cell_id / "suite"
    suite, dataset, rubric, recorded = _suite_bytes(prepared, cell)
    _write_once(suite_root / "suite.toml", suite)
    _write_once(suite_root / "dataset.jsonl", dataset)
    _write_once(suite_root / "rubric.md", rubric)
    if recorded is not None:
        _write_once(suite_root / "recorded_responses.jsonl", recorded)
    load_suite(suite_root)
    return suite_root


def _runtime_root() -> Path:
    source_root = Path(__file__).resolve().parents[2]
    if (source_root / "PROTOCOL.md").is_file() and (source_root / "src" / "cavada_eval").is_dir():
        return source_root
    package_root = Path(__file__).resolve().parent
    if (package_root / "PROTOCOL.md").is_file():
        return package_root
    raise ProtocolError("installed package is missing the canonical PROTOCOL.md asset")


def _new_experiment_root(prepared: PreparedExperiment) -> Path:
    parent = prepared.plan.output_directory
    parent.mkdir(parents=True, exist_ok=True)
    identifier = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(5).hex()
    root = parent / _safe_slug(prepared.plan.name) / identifier
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    return root


def resolve_experiment_path(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.name == "latest" and candidate.is_file():
        raw = candidate.read_text(encoding="utf-8").strip()
        resolved = (candidate.parent / raw).resolve()
        if not resolved.is_relative_to(candidate.parent.resolve()):
            raise ProtocolError("runs/latest contains an unsafe path")
        candidate = resolved
    resolved = candidate.resolve()
    if not resolved.is_dir() or not (resolved / "experiment.json").is_file():
        raise ProtocolError(f"experiment run does not exist: {path}")
    return resolved


def _latest_experiment(plan: ExperimentPlan) -> Path:
    latest = plan.output_directory / "latest"
    if not latest.is_file():
        raise ProtocolError("no prior experiment is available to resume")
    return resolve_experiment_path(latest)


def _safe_relative(root: Path, value: str, label: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts or "\\" in value:
        raise ProtocolError(f"{label} is not a safe relative path")
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ProtocolError(f"{label} escapes the experiment")
    return resolved


def _loopback_http_endpoint(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urllib.parse.urlsplit(value)
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )


def _load_object(path: Path, label: str) -> dict[str, Any]:
    return _read_json_object(path, f"{label} is not valid strict JSON")[0]


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return _read_jsonl(path)


def _partial_run(cell_root: Path) -> Path | None:
    candidates = sorted(
        manifest.parent
        for manifest in cell_root.glob("runs/*/*/manifest.json")
        if not (manifest.parent / "bundle.json").exists()
    )
    if len(candidates) > 1:
        raise ProtocolError(f"cell contains multiple partial runs: {cell_root.name}")
    return candidates[0] if candidates else None


def _authorization_path(plan: ExperimentPlan) -> str:
    reference = str(plan.run.get("external_authorization", ""))
    return str(_safe_file(plan.project_root, reference, "run.external_authorization")) if reference else ""


def _run_cell(
    prepared: PreparedExperiment,
    cell: PreparedCell,
    experiment_root: Path,
    resume_dir: Path | None,
    *,
    remaining_cost: float,
    remaining_tokens: int,
    remaining_seconds: float,
    progress: bool,
) -> Path:
    target = cell.target
    target_revision = target.revision or (_callable_identity(target.callable) if isinstance(target, CallableTarget) else "")
    if isinstance(target, OpenAICompatibleTarget):
        parsed = urllib.parse.urlsplit(target.base_url)
        if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ProtocolError(f'Target "{target.name}" must use HTTPS or a loopback endpoint')
        if target.api_key_env and target.api_key_env not in os.environ:
            raise ProtocolError(
                f"Environment variable {target.api_key_env} is not set.\nThe secret was not read and no network call was attempted."
            )
    suite = load_suite(experiment_root / "cells" / cell.cell_id / "suite")
    judge_model = "cavada-client-evaluator-v1"
    judge_revision = _digest([_evaluator_identity(evaluator) for evaluator in prepared.plan.evaluators])
    cell_root = experiment_root / "cells" / cell.cell_id
    with ExitStack() as stack:
        if isinstance(target, OpenAICompatibleTarget):
            endpoint = target.base_url
            request_model: str | None = target.model
            target_key_env = target.api_key_env or "CAVADA_CLIENT_UNUSED_TARGET_KEY"
        elif isinstance(target, RecordedTarget):
            endpoint = "recorded://local"
            request_model = None
            target_key_env = "CAVADA_CLIENT_UNUSED_TARGET_KEY"
        else:
            endpoint = stack.enter_context(serve_target(target))
            request_model = None
            target_key_env = "CAVADA_CLIENT_UNUSED_TARGET_KEY"
        judge_endpoint = stack.enter_context(serve_evaluators(prepared.plan.evaluators, judge_model))
        return run(
            suite,
            repo_root=_runtime_root(),
            output_root=cell_root,
            endpoint=endpoint,
            model_label=target.name,
            expected_model=target.model,
            model_revision=target_revision,
            request_model=request_model,
            judge_endpoint=judge_endpoint,
            judge_model=judge_model,
            expected_judge_model=judge_model,
            judge_revision=judge_revision,
            target_key_env=target_key_env,
            judge_key_env="CAVADA_CLIENT_UNUSED_EVALUATOR_KEY",
            repetitions=1,
            judge_repetitions=1,
            max_cases=0,
            timeout=float(prepared.plan.run["timeout_seconds"]),
            official=False,
            allow_external_judge=False,
            mode="smoke" if prepared.plan.profile == "quick" else "candidate",
            max_target_calls=len(prepared.cases),
            max_judge_calls=len(prepared.cases),
            max_total_tokens=remaining_tokens,
            max_elapsed_seconds=remaining_seconds,
            max_estimated_cost=remaining_cost,
            external_authorization=_authorization_path(prepared.plan),
            resume_dir=resume_dir,
            concurrency=int(prepared.plan.run["concurrency"]),
            requests_per_second=float(prepared.plan.run["rate_limit"]),
            progress=progress,
        )


def _case_outcomes(run_dir: Path) -> dict[str, bool]:
    statuses: dict[str, set[str]] = {}
    for row in _jsonl(run_dir / "case_results.jsonl"):
        statuses.setdefault(str(row.get("case_id")), set()).add(str(row.get("status")))
    return {
        case_id: values == {"pass"}
        for case_id, values in statuses.items()
        if values <= {"pass", "fail"}
    }


def _cell_budget_usage(run_dir: Path) -> tuple[float, int, float]:
    manifest = _load_object(run_dir / "manifest.json", "cell manifest")
    metrics = manifest.get("metrics")
    if not isinstance(metrics, dict):
        raise ProtocolError("cell manifest has no metrics for experiment budget accounting")
    cost = metrics.get("cost")
    budgets = metrics.get("budgets")
    performance = metrics.get("performance")
    estimated_cost = cost.get("estimated_total", 0.0) if isinstance(cost, dict) else 0.0
    total_tokens = budgets.get("total_tokens", 0) if isinstance(budgets, dict) else 0
    elapsed_seconds = performance.get("elapsed_seconds", 0.0) if isinstance(performance, dict) else 0.0
    if (
        not isinstance(estimated_cost, (int, float))
        or isinstance(estimated_cost, bool)
        or not math.isfinite(float(estimated_cost))
        or not isinstance(total_tokens, (int, float))
        or isinstance(total_tokens, bool)
        or not math.isfinite(float(total_tokens))
        or not isinstance(elapsed_seconds, (int, float))
        or isinstance(elapsed_seconds, bool)
        or not math.isfinite(float(elapsed_seconds))
    ):
        raise ProtocolError("cell manifest contains invalid budget evidence")
    return float(estimated_cost), int(total_tokens), float(elapsed_seconds)


def _remaining_budget(limit: float, used: float, label: str) -> float:
    if not limit:
        return 0.0
    remaining = limit - used
    if remaining <= 1e-12:
        raise ProtocolError(f"experiment budget exhausted before the next target call: {label}")
    return remaining


def _aggregate(rows: Sequence[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    result = []
    for value in sorted({str(row[field]) for row in rows}):
        selected = [row for row in rows if row[field] == value]
        passed = sum(int(row.get("pass", 0)) for row in selected)
        failed = sum(int(row.get("fail", 0)) for row in selected)
        judged = passed + failed
        lower, upper = wilson_interval(passed, judged)
        result.append(
            {
                field: value,
                "cells": len(selected),
                "pass": passed,
                "fail": failed,
                "error": sum(int(row.get("error", 0)) for row in selected),
                "invalid": sum(int(row.get("invalid", 0)) for row in selected),
                "skipped": sum(int(row.get("skipped", 0)) for row in selected),
                "pass_rate": passed / judged if judged else 0.0,
                "pass_rate_ci": {"lower": lower, "upper": upper, "confidence": 0.95},
            }
        )
    return result


def _results_summary(root: Path, state: Mapping[str, Any]) -> dict[str, Any]:
    raw_cells = state.get("cells")
    if not isinstance(raw_cells, list):
        raise ProtocolError("experiment state has invalid cells")
    plan = _load_object(root / "plan.normalized.json", "normalized plan snapshot")
    prompts = plan.get("prompts")
    targets = plan.get("targets")
    evaluators = plan.get("evaluators")
    if not isinstance(prompts, list) or not isinstance(targets, list) or not isinstance(evaluators, list):
        raise ProtocolError("normalized plan matrix is invalid")
    repetitions = (plan.get("run") or {}).get("repetitions", 0) if isinstance(plan.get("run"), dict) else 0
    expected_matrix = [
        (prompt.get("name"), target.get("name"), repetition)
        for prompt in prompts
        if isinstance(prompt, dict)
        for target in targets
        if isinstance(target, dict)
        for repetition in range(1, int(repetitions) + 1)
    ]
    actual_matrix = [(item.get("prompt"), item.get("target"), item.get("repetition")) for item in raw_cells if isinstance(item, dict)]
    if actual_matrix != expected_matrix:
        raise ProtocolError("experiment cell matrix differs from the normalized plan")
    source_cases = _jsonl(root / "dataset.snapshot.jsonl")
    evaluator_revision = _digest(evaluators)
    rows: list[dict[str, Any]] = []
    outcomes: dict[str, dict[str, bool]] = {}
    failure_breakdown: dict[str, int] = {}
    informative: list[dict[str, Any]] = []
    for item in raw_cells:
        if not isinstance(item, dict) or not isinstance(item.get("cell_id"), str):
            raise ProtocolError("experiment state contains an invalid cell")
        row: dict[str, Any] = {
            "cell_id": item["cell_id"],
            "prompt": item.get("prompt"),
            "target": item.get("target"),
            "model": item.get("model"),
            "repetition": item.get("repetition"),
            "status": item.get("status"),
            "run": item.get("run"),
            "pass": 0,
            "fail": 0,
            "error": 0,
            "invalid": 0,
            "skipped": 0,
            "pass_rate": 0.0,
            "pass_rate_ci": {"lower": 0.0, "upper": 0.0, "confidence": 0.95},
            "p50_latency_ms": None,
            "usage": None,
            "cost": None,
            "verification": None,
        }
        if item.get("status") == "skipped":
            row["skipped"] = len(source_cases)
        run_reference = item.get("run")
        if item.get("status") == "complete" and isinstance(run_reference, str):
            run_dir = _safe_relative(root, run_reference, f"cell {item['cell_id']} run")
            if not run_dir.is_relative_to((root / "cells" / str(item["cell_id"])).resolve()):
                raise ProtocolError(f"cell {item['cell_id']} points outside its immutable cell directory")
            verification = verify_behavior_run(run_dir)
            if verification.get("valid") is not True:
                raise ProtocolError(f"cell {item['cell_id']} failed canonical behavior verification")
            manifest = _load_object(run_dir / "manifest.json", "cell manifest")
            target_evidence = manifest.get("target")
            judge_evidence = manifest.get("judge")
            if (
                not isinstance(target_evidence, dict)
                or target_evidence.get("label") != item.get("target")
                or target_evidence.get("expected_reported_model") != item.get("model")
                or not isinstance(judge_evidence, dict)
                or judge_evidence.get("revision") != evaluator_revision
            ):
                raise ProtocolError(f"cell {item['cell_id']} identity differs from its canonical behavior run")
            prompt_config = next((prompt for prompt in prompts if isinstance(prompt, dict) and prompt.get("name") == item.get("prompt")), None)
            target_config = next((target for target in targets if isinstance(target, dict) and target.get("name") == item.get("target")), None)
            if not isinstance(prompt_config, dict) or not isinstance(target_config, dict):
                raise ProtocolError(f"cell {item['cell_id']} is absent from the normalized plan")
            try:
                suite_config = tomllib.loads((run_dir / "suite_snapshot.toml").read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                raise ProtocolError(f"cell {item['cell_id']} suite snapshot is invalid") from exc
            suite_target = suite_config.get("target")
            plan_run = plan.get("run")
            target_type = target_config.get("type")
            expected_kind = (
                {"openai-compatible": "openai", "recorded": "recorded", "callable": "json"}.get(target_type)
                if isinstance(target_type, str)
                else None
            )
            observed_capabilities = target_evidence.get("capabilities")
            expected_capabilities = target_config.get("capabilities")
            expected_pricing = target_config.get("pricing")
            suite_pricing = suite_config.get("pricing")
            target_endpoint = target_evidence.get("endpoint")
            judge_endpoint = judge_evidence.get("endpoint") if isinstance(judge_evidence, dict) else None
            pricing_fields = ("currency", "source", "effective_at", "input_per_million", "output_per_million")
            pricing_matches = (
                suite_pricing is None
                if expected_pricing is None
                else isinstance(expected_pricing, dict)
                and isinstance(suite_pricing, dict)
                and {field: suite_pricing.get(field) for field in pricing_fields} == expected_pricing
            )
            if (
                expected_kind is None
                or not isinstance(suite_target, dict)
                or not isinstance(plan_run, dict)
                or target_evidence.get("kind") != expected_kind
                or suite_target.get("kind") != expected_kind
                or (expected_kind == "json" and not _loopback_http_endpoint(target_endpoint))
                or (expected_kind == "recorded" and target_endpoint != "recorded://local")
                or (expected_kind != "openai" and target_evidence.get("request_model") is not None)
                or target_evidence.get("revision") != target_config.get("revision")
                or not isinstance(observed_capabilities, list)
                or not all(isinstance(value, str) for value in observed_capabilities)
                or not isinstance(expected_capabilities, list)
                or not all(isinstance(value, str) for value in expected_capabilities)
                or sorted(observed_capabilities) != sorted(expected_capabilities)
                or (expected_kind != "recorded" and suite_target.get("retries", 2) != plan_run.get("retries"))
                or (
                    expected_kind == "openai"
                    and (
                        target_evidence.get("endpoint") != target_config.get("base_url")
                        or target_evidence.get("request_model") != target_config.get("model")
                        or suite_target.get("stream") is not target_config.get("stream")
                        or not pricing_matches
                    )
                )
                or not _loopback_http_endpoint(judge_endpoint)
                or judge_evidence.get("requested_model") != "cavada-client-evaluator-v1"
                or judge_evidence.get("expected_reported_model") != "cavada-client-evaluator-v1"
            ):
                raise ProtocolError(f"cell {item['cell_id']} target configuration differs from the normalized plan")
            if expected_kind == "recorded":
                source_sha256 = target_config.get("source_sha256")
                source_copy = root / "sources" / "targets" / f"{source_sha256}.jsonl"
                if (
                    not isinstance(source_sha256, str)
                    or re.fullmatch(r"[a-f0-9]{64}", source_sha256) is None
                    or source_copy.is_symlink()
                    or not source_copy.is_file()
                    or sha256_bytes(source_copy.read_bytes()) != source_sha256
                ):
                    raise ProtocolError(f"cell {item['cell_id']} recorded target source differs from the normalized plan")
            expected_cell_id = _digest(
                {
                    "experiment": plan.get("name"),
                    "profile": plan.get("profile"),
                    "dataset_sha256": (state.get("dataset") or {}).get("sha256") if isinstance(state.get("dataset"), dict) else None,
                    "rendered_dataset_sha256": sha256_bytes((run_dir / "dataset_snapshot.jsonl").read_bytes()),
                    "prompt": prompt_config.get("identity"),
                    "target": target_config,
                    "evaluators": evaluators,
                    "run": plan_run,
                    "repetition": item.get("repetition"),
                }
            )[:24]
            if item["cell_id"] != expected_cell_id:
                raise ProtocolError(f"cell {item['cell_id']} identity differs from the normalized plan")
            rendered_cases = _jsonl(run_dir / "dataset_snapshot.jsonl")
            client_cases: list[Any] = []
            for case in rendered_cases:
                source = case.get("source")
                metadata = source.get("metadata") if isinstance(source, dict) else None
                if (
                    not isinstance(metadata, dict)
                    or metadata.get("prompt_name") != item.get("prompt")
                    or metadata.get("prompt_identity") != prompt_config.get("identity")
                    or not isinstance(metadata.get("client_case"), dict)
                ):
                    raise ProtocolError(f"cell {item['cell_id']} prompt evidence differs from the normalized plan")
                client_cases.append(metadata["client_case"])
            if client_cases != source_cases:
                raise ProtocolError(f"cell {item['cell_id']} dataset differs from the experiment snapshot")
            metrics = manifest.get("metrics")
            if not isinstance(metrics, dict):
                raise ProtocolError(f"cell {item['cell_id']} manifest has no metrics")
            for status in ("pass", "fail", "error", "invalid", "skipped"):
                row[status] = int(metrics.get(status, 0))
            row["pass_rate"] = float(metrics.get("pass_rate", 0.0))
            row["pass_rate_ci"] = metrics.get("pass_rate_ci")
            performance = metrics.get("performance")
            latency = performance.get("target_latency_ms") if isinstance(performance, dict) else None
            if isinstance(latency, dict) and int(latency.get("count", 0)):
                row["p50_latency_ms"] = latency.get("p50")
            cost = metrics.get("cost")
            input_usage = performance.get("input_tokens") if isinstance(performance, dict) else None
            output_usage = performance.get("output_tokens") if isinstance(performance, dict) else None
            if isinstance(cost, dict) and any(isinstance(value, dict) and int(value.get("count", 0)) for value in (input_usage, output_usage)):
                row["cost"] = {key: cost.get(key) for key in ("currency", "source", "estimated_total")}
            case_results = _jsonl(run_dir / "case_results.jsonl")
            observed_usage = [result for result in case_results if isinstance(result.get("input_tokens"), (int, float)) or isinstance(result.get("output_tokens"), (int, float))]
            if observed_usage:
                row["usage"] = {
                    "observations": len(observed_usage),
                    "input_tokens": sum(float(result.get("input_tokens", 0)) for result in observed_usage),
                    "output_tokens": sum(float(result.get("output_tokens", 0)) for result in observed_usage),
                }
            row["verification"] = {
                key: verification.get(key)
                for key in ("valid", "integrity_valid", "semantic_valid", "assurance_valid", "assurance_level", "rankable")
            }
            outcomes[str(item["cell_id"])] = _case_outcomes(run_dir)
            for failure in _jsonl(run_dir / "failures.jsonl"):
                category = str(failure.get("category") or failure.get("reason") or "uncategorized")
                failure_breakdown[category] = failure_breakdown.get(category, 0) + 1
                informative.append(
                    {
                        "cell_id": item["cell_id"],
                        "case_id": failure.get("case_id"),
                        "status": failure.get("status"),
                        "category": category,
                        "reason": failure.get("reason"),
                    }
                )
        rows.append(row)
    comparisons = []
    complete = [row for row in rows if row["cell_id"] in outcomes]
    for left_index, left in enumerate(complete):
        for right in complete[left_index + 1 :]:
            try:
                comparison = paired_binary_comparison(
                    outcomes[str(left["cell_id"])],
                    outcomes[str(right["cell_id"])],
                    samples=1000,
                    seed=int(state.get("seed", 0)),
                )
            except ValueError:
                continue
            comparisons.append({"baseline": left["cell_id"], "candidate": right["cell_id"], **comparison})
    return {
        "experiment_version": EXPERIMENT_VERSION,
        "experiment_id": state.get("experiment_id"),
        "name": state.get("name"),
        "description": plan.get("description", ""),
        "profile": state.get("profile"),
        "status": state.get("status"),
        "created_at": state.get("created_at"),
        "finished_at": state.get("finished_at"),
        "dataset": state.get("dataset"),
        "evaluators": state.get("evaluators"),
        "configuration": {"prompts": prompts, "targets": targets, "evaluators": evaluators},
        "cells": rows,
        "by_target": _aggregate(rows, "target"),
        "by_prompt": _aggregate(rows, "prompt"),
        "comparisons": comparisons,
        "failure_breakdown": [{"category": key, "count": failure_breakdown[key]} for key in sorted(failure_breakdown)],
        "informative_cases": informative[:20],
        "limitations": [
            "Client evidence is candidate assurance, not an official or certification claim.",
            "Callable factories execute as trusted local code and are not sandboxed.",
            "Costs are absent unless pricing and provider usage are both observed.",
            "Per-target and per-prompt pooled rates are descriptive; per-cell intervals are the primary uncertainty estimate.",
            "No composite AI score is produced.",
        ],
        "rankable": False,
        "claim_scope": [],
    }


def _format_percent(value: Any) -> str:
    return f"{100 * float(value):.1f}%" if isinstance(value, (int, float)) else "n/a"


def _report_html(summary: Mapping[str, Any]) -> bytes:
    def escaped(value: Any) -> str:
        return html.escape(str(value), quote=True)

    cell_rows = []
    for row in cast(Sequence[Mapping[str, Any]], summary.get("cells", [])):
        interval: Mapping[str, Any] = row["pass_rate_ci"] if isinstance(row.get("pass_rate_ci"), Mapping) else {}
        latency = row.get("p50_latency_ms")
        cost = row.get("cost")
        usage = row.get("usage")
        cost_text = "n/a"
        if isinstance(cost, Mapping) and isinstance(cost.get("estimated_total"), (int, float)):
            cost_text = f"{cost['estimated_total']:.4f} {cost.get('currency', '')}".strip()
        usage_text = (
            f"{float(usage.get('input_tokens', 0)):g} in / {float(usage.get('output_tokens', 0)):g} out"
            if isinstance(usage, Mapping)
            else "n/a"
        )
        valid = (row.get("verification") or {}).get("valid") if isinstance(row.get("verification"), Mapping) else False
        cell_rows.append(
            "<tr>"
            f"<td><code>{escaped(row.get('cell_id'))}</code></td><td>{escaped(row.get('target'))}</td><td>{escaped(row.get('prompt'))}</td>"
            f"<td>{_format_percent(row.get('pass_rate'))}</td>"
            f"<td>[{_format_percent(interval.get('lower'))}, {_format_percent(interval.get('upper'))}]</td>"
            f"<td>{escaped(row.get('fail'))}</td><td>{escaped(row.get('error'))}</td><td>{escaped(row.get('invalid'))}</td><td>{escaped(row.get('skipped'))}</td>"
            f"<td>{escaped(f'{float(latency):.1f} ms' if isinstance(latency, (int, float)) else 'n/a')}</td><td>{escaped(usage_text)}</td><td>{escaped(cost_text)}</td>"
            f"<td><span class={'ok' if valid else 'bad'}>{'verified' if valid else 'invalid'}</span></td></tr>"
        )
    comparison_rows = []
    for item in cast(Sequence[Mapping[str, Any]], summary.get("comparisons", [])):
        interval = cast(Mapping[str, Any], item["delta_ci"]) if isinstance(item.get("delta_ci"), Mapping) else {}
        comparison_rows.append(
            "<tr>"
            f"<td><code>{escaped(item.get('baseline'))}</code></td><td><code>{escaped(item.get('candidate'))}</code></td>"
            f"<td>{escaped(item.get('cases'))}</td><td>{float(item.get('absolute_delta', 0)):+.3f}</td>"
            f"<td>[{float(interval.get('lower', 0)):+.3f}, {float(interval.get('upper', 0)):+.3f}]</td>"
            f"<td>{escaped(item.get('wins'))}/{escaped(item.get('ties'))}/{escaped(item.get('losses'))}</td></tr>"
        )
    failure_rows = "".join(
        f"<tr><td>{escaped(item.get('category'))}</td><td>{escaped(item.get('count'))}</td></tr>"
        for item in cast(Sequence[Mapping[str, Any]], summary.get("failure_breakdown", []))
    )
    case_rows = "".join(
        "<tr>"
        f"<td><code>{escaped(item.get('cell_id'))}</code></td><td>{escaped(item.get('case_id'))}</td><td>{escaped(item.get('status'))}</td>"
        f"<td>{escaped(item.get('category'))}</td><td>{escaped(item.get('reason'))}</td></tr>"
        for item in cast(Sequence[Mapping[str, Any]], summary.get("informative_cases", []))
    )
    limitations = "".join(f"<li>{escaped(item)}</li>" for item in cast(Sequence[Any], summary.get("limitations", [])))
    dataset: Mapping[str, Any] = cast(Mapping[str, Any], summary["dataset"]) if isinstance(summary.get("dataset"), Mapping) else {}
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escaped(summary.get('name'))} — Cavada client evaluation</title>
<style>
:root{{--ink:#18212b;--muted:#637083;--line:#d8dee8;--paper:#fff;--accent:#2357d9;--ok:#147a45;--bad:#b42318}}
*{{box-sizing:border-box}} body{{margin:0;background:#f4f6f9;color:var(--ink);font:15px/1.45 system-ui,sans-serif}}
main{{max-width:1180px;margin:32px auto;padding:32px;background:var(--paper);box-shadow:0 8px 30px #24324a18}}
h1{{margin:0 0 6px;font-size:30px}} h2{{margin-top:34px}} .lede,.muted{{color:var(--muted)}}
.facts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:24px 0}}
.fact{{padding:14px;border:1px solid var(--line);border-radius:8px}} .fact strong{{display:block;font-size:20px}}
.scroll{{overflow:auto}} table{{width:100%;border-collapse:collapse;font-size:13px}} th,td{{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}} th{{background:#f7f9fc}}
code{{font-size:12px}} .ok{{color:var(--ok);font-weight:650}} .bad{{color:var(--bad);font-weight:650}} footer{{margin-top:36px;color:var(--muted)}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;padding:14px;background:#f7f9fc;border:1px solid var(--line);border-radius:8px}}
</style></head><body><main>
<h1>{escaped(summary.get('name'))}</h1><p class="lede">Client evaluation report · {escaped(summary.get('finished_at') or summary.get('created_at'))}</p>
<p>{escaped(summary.get('description'))}</p>
<div class="facts"><div class="fact"><span>Profile</span><strong>{escaped(summary.get('profile'))}</strong></div>
<div class="fact"><span>Dataset cases</span><strong>{escaped(dataset.get('cases'))}</strong></div>
<div class="fact"><span>Cells</span><strong>{len(cast(Sequence[Any], summary.get('cells', [])))}</strong></div>
<div class="fact"><span>Run status</span><strong>{escaped(summary.get('status'))}</strong></div></div>
<p><strong>Experiment ID:</strong> <code>{escaped(summary.get('experiment_id'))}</code><br>
<strong>Dataset SHA-256:</strong> <code>{escaped(dataset.get('sha256'))}</code><br>
<strong>Evaluators:</strong> {escaped(', '.join(map(str, cast(Sequence[Any], summary.get('evaluators', [])))))}</p>
<details><summary><strong>Frozen prompt, target, and evaluator configuration</strong></summary><pre>{escaped(json.dumps(summary.get('configuration'), ensure_ascii=False, indent=2, sort_keys=True))}</pre></details>
<h2>Configuration results</h2><div class="scroll"><table><thead><tr><th>Cell</th><th>Target</th><th>Prompt</th><th>Pass rate</th><th>95% CI</th><th>Failed</th><th>Errors</th><th>Invalid</th><th>Skipped</th><th>p50 latency</th><th>Usage</th><th>Cost</th><th>Evidence</th></tr></thead>
<tbody>{''.join(cell_rows)}</tbody></table></div>
<h2>Paired comparisons</h2><p class="muted">Only shared cases with pass/fail outcomes are paired; errors, invalid and skipped cases remain visible above.</p>
<div class="scroll"><table><thead><tr><th>Baseline</th><th>Candidate</th><th>Cases</th><th>Delta</th><th>95% CI</th><th>Wins/ties/losses</th></tr></thead><tbody>{''.join(comparison_rows)}</tbody></table></div>
<h2>Failure categories</h2><table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>{failure_rows}</tbody></table>
<h2>Informative non-pass cases</h2><div class="scroll"><table><thead><tr><th>Cell</th><th>Case</th><th>Status</th><th>Category</th><th>Reason</th></tr></thead><tbody>{case_rows}</tbody></table></div>
<h2>Limits</h2><ul>{limitations}</ul>
<footer>Generated from immutable behavior bundles. Integrity, semantic and assurance states are retained separately; no composite score is produced.</footer>
</main></body></html>
"""
    return document.encode("utf-8")


def verify_experiment(path: str | Path, *, write_result: bool = False) -> dict[str, Any]:
    root = resolve_experiment_path(path)
    integrity_failures: list[str] = []
    semantic_failures: list[str] = []
    assurance_failures: list[str] = []
    try:
        integrity = verify_bundle(root)
    except ProtocolError as exc:
        integrity = {"valid": False, "failures": [str(exc)]}
    integrity_failures.extend(map(str, integrity.get("failures", [])))
    try:
        state = _load_object(root / "experiment.json", "experiment state")
        _reject_unknown(
            state,
            {"artifact_type", "experiment_version", "experiment_id", "name", "profile", "seed", "status", "created_at", "finished_at", "plan_sha256", "dataset", "evaluators", "cells"},
            "experiment",
        )
        if state.get("artifact_type") != "client-experiment" or state.get("experiment_version") != EXPERIMENT_VERSION:
            semantic_failures.append("unsupported client experiment identity")
        if state.get("profile") not in {"quick", "client"}:
            assurance_failures.append("client experiment profile must be quick or client")
        plan_snapshot = _load_object(root / "plan.normalized.json", "normalized plan snapshot")
        if state.get("plan_sha256") != _digest(plan_snapshot):
            semantic_failures.append("normalized plan snapshot differs from experiment binding")
        if any(state.get(field) != plan_snapshot.get(field) for field in ("name", "profile", "seed")):
            semantic_failures.append("experiment identity differs from the normalized plan")
        expected_evaluators = plan_snapshot.get("evaluators")
        expected_evaluator_names = (
            [item.get("name") for item in expected_evaluators if isinstance(item, dict)]
            if isinstance(expected_evaluators, list)
            else None
        )
        if state.get("evaluators") != expected_evaluator_names:
            semantic_failures.append("experiment evaluators differ from the normalized plan")
        dataset = state.get("dataset")
        dataset_rows = _jsonl(root / "dataset.snapshot.jsonl")
        plan_dataset = plan_snapshot.get("dataset")
        if (
            not isinstance(dataset, dict)
            or set(dataset) != {"sha256", "cases", "classification"}
            or dataset.get("sha256") != sha256_bytes((root / "dataset.snapshot.jsonl").read_bytes())
            or dataset.get("cases") != len(dataset_rows)
            or not isinstance(plan_dataset, dict)
            or dataset.get("classification") != plan_dataset.get("classification")
        ):
            semantic_failures.append("dataset snapshot differs from experiment binding")
        summary = _results_summary(root, state)
        expected_summary = (json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
        if (root / "summary.json").read_bytes() != expected_summary:
            semantic_failures.append("summary.json does not reconstruct from canonical cell artifacts")
        if (root / "report.html").read_bytes() != _report_html(summary):
            semantic_failures.append("report.html does not reconstruct from canonical cell artifacts")
        for row in cast(Sequence[Mapping[str, Any]], summary.get("cells", [])):
            verification = row.get("verification")
            if row.get("status") == "complete" and (not isinstance(verification, Mapping) or verification.get("valid") is not True):
                semantic_failures.append(f"cell {row.get('cell_id')} failed canonical behavior verification")
            if isinstance(verification, Mapping) and verification.get("rankable") is not False:
                assurance_failures.append(f"cell {row.get('cell_id')} unexpectedly claims rankability")
        if summary.get("rankable") is not False or summary.get("claim_scope") != []:
            assurance_failures.append("client experiment cannot be rankable or carry official claims")
    except (OSError, UnicodeDecodeError, ValueError, TypeError, KeyError, ProtocolError) as exc:
        semantic_failures.append(str(exc))
        state = {}
    result = {
        "verification_version": "1.0.0",
        "artifact_type": "client-experiment",
        "valid": not integrity_failures and not semantic_failures and not assurance_failures,
        "integrity_valid": not integrity_failures,
        "semantic_valid": not semantic_failures,
        "assurance_valid": not assurance_failures,
        "integrity_failures": integrity_failures,
        "semantic_failures": semantic_failures,
        "assurance_failures": assurance_failures,
        "failures": [*integrity_failures, *semantic_failures, *assurance_failures],
        "assurance_level": state.get("profile", "unsupported"),
        "complete": state.get("status") == "complete",
        "claim_scope": [],
        "rankable": False,
    }
    if write_result:
        atomic_json(root / "verification.json", result)
    return result


def _client_preflight(prepared: PreparedExperiment) -> None:
    external_hosts: set[str] = set()
    for target in prepared.plan.targets:
        if not isinstance(target, OpenAICompatibleTarget):
            continue
        parsed = urllib.parse.urlsplit(target.base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ProtocolError(f'Target "{target.name}" base_url must not contain credentials, query, or fragment')
        if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ProtocolError(f'Target "{target.name}" must use HTTPS or a loopback endpoint')
        if not isinstance(target.api_key_env, str) or (target.api_key_env and not target.api_key_env.isidentifier()):
            raise ProtocolError(f'Target "{target.name}" api_key_env must be text')
        if target.api_key_env and target.api_key_env not in os.environ:
            raise ProtocolError(
                f"Environment variable {target.api_key_env} is not set.\nThe secret was not read and no network call was attempted."
            )
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            external_hosts.add(str(parsed.hostname))
    authorization_path = _authorization_path(prepared.plan)
    if prepared.plan.data_classification not in {"public", "synthetic"} and external_hosts and not authorization_path:
        raise ProtocolError(f"non-public dataset requires an external authorization covering: {sorted(external_hosts)}")
    if authorization_path:
        record = _load_object(Path(authorization_path), "external authorization")
        destinations = record.get("destinations")
        if not isinstance(destinations, list) or not all(isinstance(item, dict) and isinstance(item.get("host"), str) for item in destinations):
            raise ProtocolError("external authorization requires destinations with host, region, and purpose")
        authorized = {str(item["host"]) for item in destinations}
        if not external_hosts <= authorized:
            raise ProtocolError(f"external authorization omits hosts: {sorted(external_hosts - authorized)}")
        try:
            effective = datetime.fromisoformat(str(record["effective_at"]).replace("Z", "+00:00"))
            expires = datetime.fromisoformat(str(record["expires_at"]).replace("Z", "+00:00"))
        except (KeyError, ValueError) as exc:
            raise ProtocolError("external authorization timestamps are invalid") from exc
        now = datetime.now(timezone.utc)
        if effective.tzinfo is None or expires.tzinfo is None or not effective <= now < expires:
            raise ProtocolError("external authorization is not currently effective")


def run_experiment(plan: ExperimentPlan, *, resume: bool | None = None, progress: bool = False) -> ExperimentResult:
    prepared = prepare_experiment(plan)
    should_resume = bool(plan.run.get("resume")) if resume is None else resume
    normalized = _plan_snapshot(plan)
    normalized_sha256 = _digest(normalized)
    if should_resume:
        root = _latest_experiment(plan)
        if (root / "bundle.json").is_file():
            verification = verify_experiment(root)
            if not verification["valid"]:
                raise ProtocolError("the latest finalized experiment is invalid and cannot be resumed")
            return ExperimentResult(root, _load_object(root / "summary.json", "experiment summary"), verification)
        state = _load_object(root / "experiment.json", "experiment state")
        if state.get("plan_sha256") != normalized_sha256:
            raise ProtocolError("resume plan differs from the interrupted experiment")
        if (state.get("dataset") or {}).get("sha256") != prepared.dataset_sha256:
            raise ProtocolError("resume dataset differs from the interrupted experiment")
        expected_cells = [cell.cell_id for cell in prepared.cells]
        actual_cells = [item.get("cell_id") for item in state.get("cells", []) if isinstance(item, dict)]
        if actual_cells != expected_cells:
            raise ProtocolError("resume matrix differs from the interrupted experiment")
        _results_summary(root, state)
        state["status"] = "running"
        state["finished_at"] = None
    else:
        root = _new_experiment_root(prepared)
        created_at = datetime.now(timezone.utc).isoformat()
        state = {
            "artifact_type": "client-experiment",
            "experiment_version": EXPERIMENT_VERSION,
            "experiment_id": root.name,
            "name": plan.name,
            "profile": plan.profile,
            "seed": plan.seed,
            "status": "running",
            "created_at": created_at,
            "finished_at": None,
            "plan_sha256": normalized_sha256,
            "dataset": {"sha256": prepared.dataset_sha256, "cases": len(prepared.cases), "classification": plan.data_classification},
            "evaluators": [evaluator.name for evaluator in plan.evaluators],
            "cells": [
                {
                    "cell_id": cell.cell_id,
                    "prompt": cell.prompt.name,
                    "target": cell.target.name,
                    "model": cell.target.model,
                    "repetition": cell.repetition,
                    "status": "pending",
                    "run": None,
                }
                for cell in prepared.cells
            ],
        }
        atomic_json(root / "plan.normalized.json", normalized)
        if plan.source_bytes:
            _write_once(root / "plan.snapshot.toml", plan.source_bytes)
        else:
            atomic_json(root / "plan.snapshot.json", normalized)
        _write_once(root / "dataset.snapshot.jsonl", prepared.dataset_snapshot)
        for target in plan.targets:
            if isinstance(target, RecordedTarget):
                _write_once(root / "sources" / "targets" / f"{sha256_bytes(target.path.read_bytes())}.jsonl", target.path.read_bytes())
        relative = root.relative_to(plan.output_directory).as_posix()
        atomic_text(plan.output_directory / "latest", relative + "\n")
    atomic_json(root / "experiment.json", state)
    _client_preflight(prepared)
    for cell in prepared.cells:
        _write_cell_suite(prepared, cell, root)
    by_id = {str(item["cell_id"]): item for item in state["cells"] if isinstance(item, dict)}
    used_cost = 0.0
    used_tokens = 0
    used_seconds = 0.0
    try:
        for cell in prepared.cells:
            item = by_id[cell.cell_id]
            if item.get("status") == "complete" and isinstance(item.get("run"), str):
                completed_run = _safe_relative(root, str(item["run"]), "completed cell run")
                existing = verify_behavior_run(completed_run)
                if existing["valid"]:
                    cost, tokens, seconds = _cell_budget_usage(completed_run)
                    used_cost += cost
                    used_tokens += tokens
                    used_seconds += seconds
                    continue
                raise ProtocolError(f"completed cell {cell.cell_id} no longer verifies")
            remaining_cost = _remaining_budget(float(prepared.plan.run["max_cost"]), used_cost, "estimated cost")
            remaining_tokens = int(_remaining_budget(float(prepared.plan.run["max_tokens"]), used_tokens, "total tokens"))
            remaining_seconds = _remaining_budget(float(prepared.plan.run["max_elapsed_seconds"]), used_seconds, "elapsed time")
            cell_root = root / "cells" / cell.cell_id
            partial = _partial_run(cell_root)
            run_dir = _run_cell(
                prepared,
                cell,
                root,
                partial,
                remaining_cost=remaining_cost,
                remaining_tokens=remaining_tokens,
                remaining_seconds=remaining_seconds,
                progress=progress,
            )
            item.update({"status": "complete", "run": run_dir.relative_to(root).as_posix()})
            atomic_json(root / "experiment.json", state)
            cost, tokens, seconds = _cell_budget_usage(run_dir)
            used_cost += cost
            used_tokens += tokens
            used_seconds += seconds
            for used, limit, label in (
                (used_cost, float(prepared.plan.run["max_cost"]), "estimated cost"),
                (float(used_tokens), float(prepared.plan.run["max_tokens"]), "total tokens"),
                (used_seconds, float(prepared.plan.run["max_elapsed_seconds"]), "elapsed time"),
            ):
                if limit and used > limit + 1e-12:
                    raise ProtocolError(f"experiment budget exhausted: {label}")
            manifest = _load_object(run_dir / "manifest.json", "cell manifest")
            metrics: dict[str, Any] = manifest["metrics"] if isinstance(manifest.get("metrics"), dict) else {}
            if prepared.plan.run["fail_fast"] and any(int(metrics.get(name, 0)) for name in ("fail", "error", "invalid")):
                for pending in state["cells"]:
                    if isinstance(pending, dict) and pending.get("status") == "pending":
                        pending["status"] = "skipped"
                state["status"] = "stopped"
                break
    except KeyboardInterrupt:
        state["status"] = "interrupted"
        for cell in prepared.cells:
            item = by_id[cell.cell_id]
            if item.get("status") == "pending":
                partial = _partial_run(root / "cells" / cell.cell_id)
                if partial is not None:
                    item.update({"status": "partial", "run": partial.relative_to(root).as_posix()})
                    break
        atomic_json(root / "experiment.json", state)
        raise
    if state.get("status") == "running":
        state["status"] = "complete"
    state["finished_at"] = datetime.now(timezone.utc).isoformat()
    atomic_json(root / "experiment.json", state)
    summary = _results_summary(root, state)
    atomic_json(root / "summary.json", summary)
    atomic_text(root / "report.html", _report_html(summary).decode("utf-8"))
    write_bundle(root)
    verification = verify_experiment(root, write_result=True)
    if not verification["valid"]:
        raise ProtocolError("generated client experiment failed verification: " + "; ".join(verification["failures"]))
    return ExperimentResult(root, summary, verification)


def evaluate(
    *,
    target: Target | Callable[[Mapping[str, Any]], Any],
    dataset: str | Path | Iterable[Mapping[str, Any] | EvalCase] | Callable[[], Iterable[Mapping[str, Any] | EvalCase]],
    prompt: str | Sequence[Mapping[str, str]] | Callable[[EvalCase], Any] | PromptVariant,
    evaluators: Sequence[Evaluator | Callable[[EvalCase, Any], Any]],
    name: str = "client-evaluation",
    description: str = "",
    profile: str = "client",
    seed: int = 0,
    data_classification: str = "internal",
    output_directory: str | Path = "runs",
    repetitions: int = 1,
    concurrency: int = 4,
    timeout_seconds: float = 60,
    retries: int | None = None,
    max_cases: int = 0,
    max_requests: int = 10_000,
    max_cost: float = 0,
    max_tokens: int = 0,
    rate_limit: float = 0,
    external_authorization: str = "",
    resume: bool = False,
) -> ExperimentResult:
    if profile not in {"quick", "client"}:
        raise ProtocolError("evaluate profile must be quick or client; official runs use a validated canonical suite")
    if data_classification not in {"public", "synthetic", "internal", "confidential", "restricted"}:
        raise ProtocolError("evaluate data_classification is unsupported")
    if not isinstance(description, str):
        raise ProtocolError("evaluate description must be text")
    if isinstance(target, Target):
        normalized_target = target
    elif callable(target):
        target_name = getattr(target, "__name__", "callable-target")
        normalized_target = CallableTarget(target_name, target, model=target_name, revision=_callable_identity(target))
    else:
        raise ProtocolError("target must implement the Target protocol or be callable")
    retry_count = 2 if retries is None else retries
    if isinstance(prompt, PromptVariant):
        normalized_prompt = prompt
    elif isinstance(prompt, str):
        normalized_prompt = PromptVariant("default", template=prompt)
    elif callable(prompt):
        normalized_prompt = PromptVariant("default", renderer=prompt, renderer_reference=_callable_identity(prompt))
    elif isinstance(prompt, Sequence) and all(isinstance(item, Mapping) for item in prompt):
        messages = tuple(
            {"role": str(item.get("role", "")), "content": str(item.get("content", ""))}
            for item in cast(Sequence[Mapping[str, str]], prompt)
        )
        normalized_prompt = PromptVariant("default", messages=messages)
    else:
        raise ProtocolError("prompt must be text, chat messages, a callable, or PromptVariant")
    normalized_evaluators: list[Evaluator] = []
    for evaluator in evaluators:
        if isinstance(evaluator, Evaluator):
            normalized_evaluators.append(evaluator)
        elif callable(evaluator):
            evaluator_name = getattr(evaluator, "__name__", "callable-evaluator")
            normalized_evaluators.append(
                CallableEvaluator(
                    evaluator_name,
                    evaluator,
                    config={"factory": _callable_identity(evaluator), "type": "callable"},
                )
            )
        else:
            raise ProtocolError("evaluators must implement Evaluator or be callable")
    if not normalized_evaluators:
        raise ProtocolError("at least one evaluator is required")
    project_root = Path.cwd().resolve()
    plan = ExperimentPlan(
        name=name,
        profile=profile,
        seed=seed,
        dataset=dataset,
        prompts=(normalized_prompt,),
        targets=(normalized_target,),
        evaluators=tuple(normalized_evaluators),
        run={
            "concurrency": _positive_int(concurrency, "concurrency", maximum=64),
            "timeout_seconds": _number(timeout_seconds, "timeout_seconds", minimum=0.001),
            "retries": _positive_int(retry_count, "retries", zero=True, maximum=10),
            "repetitions": _positive_int(repetitions, "repetitions", maximum=1000),
            "max_cases": _positive_int(max_cases, "max_cases", zero=True),
            "max_requests": _positive_int(max_requests, "max_requests"),
            "max_cost": _number(max_cost, "max_cost"),
            "max_tokens": _positive_int(max_tokens, "max_tokens", zero=True),
            "max_elapsed_seconds": 0.0,
            "rate_limit": _number(rate_limit, "rate_limit"),
            "fail_fast": False,
            "resume": resume,
            "external_authorization": external_authorization,
        },
        output_directory=(project_root / output_directory).resolve() if not Path(output_directory).is_absolute() else Path(output_directory).resolve(),
        data_classification=data_classification,
        description=description,
        project_root=project_root,
    )
    return run_experiment(plan, resume=resume)


def init_client_project(destination: str | Path) -> Path:
    root = Path(destination).resolve()
    try:
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise ProtocolError(f"refusing to overwrite project: {root}") from exc
    config = b'''version = "1"
name = "customer-support-eval"
description = "Offline customer-support prompt evaluation."
profile = "client"
seed = 42

[dataset]
type = "jsonl"
path = "data/example.jsonl"
classification = "synthetic"

[[prompts]]
name = "baseline"
template = "{question}"

[[targets]]
name = "offline-example"
factory = "custom:local_target"
model = "recorded-example-v1"
revision = "example-1"

[[evaluators]]
type = "exact-match"
expected_field = "answer"

[run]
concurrency = 2
timeout_seconds = 30
repetitions = 1
max_requests = 100

[output]
directory = "runs"
formats = ["json", "html"]
'''
    data = (
        '{"id":"ticket-001","question":"What is the support code?","answer":"SUPPORT-001"}\n'
        '{"id":"ticket-002","question":"What is the billing code?","answer":"BILLING-002"}\n'
    ).encode()
    custom = b'''def local_target(request):
    answers = {
        "What is the support code?": "SUPPORT-001",
        "What is the billing code?": "BILLING-002",
    }
    return {"output": answers.get(request["input"], "unknown"), "usage": {"prompt_tokens": 5, "completion_tokens": 1}}


def support_dataset():
    yield {"id": "ticket-001", "question": "What is the support code?", "answer": "SUPPORT-001"}
'''
    readme = b'''# Cavada client evaluation example

This project is fully offline. Run:

```sh
cavada-eval plan eval.toml
cavada-eval run eval.toml
cavada-eval report runs/latest
cavada-eval verify runs/latest
```

Factories in `custom.py` are trusted local code and are not sandboxed.
Results use client/candidate assurance; they are not official certification claims.
'''
    _write_once(root / "eval.toml", config)
    _write_once(root / "data" / "example.jsonl", data)
    _write_once(root / "custom.py", custom)
    _write_once(root / "README.md", readme)
    _write_once(root / ".gitignore", b"runs/\n__pycache__/\n")
    return root
