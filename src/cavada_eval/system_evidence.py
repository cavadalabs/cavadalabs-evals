from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from .protocol import ProtocolError, contains_secret_like

SYSTEM_EVIDENCE_VERSION = "1.0.0"
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_PLACEHOLDERS = ("replace-with", "todo", "unknown")

_ROOT_KEYS = {
    "evidence_version",
    "configuration_id",
    "projection",
    "collected_at",
    "collection_method",
    "server",
    "software",
    "serving",
    "load_generator",
    "network",
    "artifacts",
    "unavailable",
}
_SERVER_KEYS = {"host_id", "os", "cpu", "memory", "numa", "accelerators", "accelerator_topology"}
_OS_KEYS = {"name", "version", "kernel"}
_CPU_KEYS = {"model", "architecture", "sockets", "physical_cores", "logical_cores"}
_MEMORY_KEYS = {"total_bytes"}
_NUMA_KEYS = {"nodes", "policy"}
_ACCELERATOR_KEYS = {
    "index",
    "vendor",
    "model",
    "uuid",
    "vram_bytes",
    "pci_bus_id",
    "power_limit_watts",
    "graphics_clock_limit_mhz",
    "memory_clock_limit_mhz",
}
_SOFTWARE_KEYS = {"driver", "compute_runtime", "engine", "model"}
_NAME_VERSION_KEYS = {"name", "version"}
_ENGINE_KEYS = {"name", "revision", "binary_sha256", "container_image_digest"}
_MODEL_KEYS = {"name", "revision", "artifact_sha256", "dtype", "quantization"}
_SERVING_KEYS = {
    "launch_command_sanitized",
    "max_context_tokens",
    "max_batch_size",
    "max_batch_tokens",
    "continuous_batching",
    "prefix_cache",
    "kv_cache_dtype",
    "tensor_parallel",
    "pipeline_parallel",
    "data_parallel",
    "parallel_slots",
}
_LOAD_GENERATOR_KEYS = {"host_id", "os", "cpu", "memory", "client", "colocated_with_server"}
_LOAD_CPU_KEYS = {"model", "architecture", "logical_cores"}
_CLIENT_KEYS = {"name", "revision"}
_NETWORK_KEYS = {"relationship", "transport", "endpoint_host", "endpoint_port", "route", "rtt_ms"}
_RTT_KEYS = {"method", "samples", "median", "p95", "measured_at"}
_ARTIFACT_KEYS = {"kind", "name", "sha256"}


def _object(value: Any, path: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"system evidence {path} must be an object")
    missing = sorted(keys - set(value))
    unknown = sorted(set(value) - keys)
    if missing:
        raise ProtocolError(f"system evidence {path} is missing fields: {missing}")
    if unknown:
        raise ProtocolError(f"system evidence {path} has unknown fields: {unknown}")
    return value


def _text(value: Any, path: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(f"system evidence {path} must be a non-empty string")
    if any(marker in value.casefold() for marker in _PLACEHOLDERS):
        raise ProtocolError(f"system evidence {path} contains a placeholder")


def _positive_int(value: Any, path: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ProtocolError(f"system evidence {path} must be a positive integer")


def _positive_number(value: Any, path: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise ProtocolError(f"system evidence {path} must be a positive finite number")


def _boolean(value: Any, path: str) -> None:
    if not isinstance(value, bool):
        raise ProtocolError(f"system evidence {path} must be a boolean")


def _timestamp(value: Any, path: str) -> None:
    _text(value, path)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(f"system evidence {path} must be an ISO-8601 datetime") from exc
    if parsed.tzinfo is None:
        raise ProtocolError(f"system evidence {path} must include a timezone")


def _pointer(path: tuple[str | int, ...]) -> str:
    return "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in path)


def _null_paths(value: Any, path: tuple[str | int, ...] = ()) -> set[str]:
    if value is None:
        return {_pointer(path)}
    paths: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            paths.update(_null_paths(child, (*path, key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.update(_null_paths(child, (*path, index)))
    return paths


def _resolve_pointer(value: Any, pointer: str) -> Any:
    if not pointer.startswith("/"):
        raise KeyError(pointer)
    current = value
    for raw in pointer[1:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise KeyError(pointer)
    return current


def _configuration_material(evidence: dict[str, Any]) -> dict[str, Any]:
    material = copy.deepcopy(evidence)
    for key in ("configuration_id", "projection", "collected_at", "collection_method", "artifacts", "unavailable"):
        material.pop(key, None)
    server = material.get("server")
    if isinstance(server, dict):
        server.pop("host_id", None)
        accelerators = server.get("accelerators")
        if isinstance(accelerators, list):
            for accelerator in accelerators:
                if isinstance(accelerator, dict):
                    accelerator.pop("uuid", None)
                    accelerator.pop("pci_bus_id", None)
            if all(isinstance(accelerator, dict) and isinstance(accelerator.get("index"), int) for accelerator in accelerators):
                accelerators.sort(key=lambda accelerator: accelerator["index"])
    load_generator = material.get("load_generator")
    if isinstance(load_generator, dict):
        load_generator.pop("host_id", None)
    network = material.get("network")
    if isinstance(network, dict):
        for key in ("endpoint_host", "endpoint_port", "route", "rtt_ms"):
            network.pop(key, None)
    return material


def system_configuration_id(evidence: dict[str, Any]) -> str:
    """Return the stable ID for the material system configuration, not a run."""
    canonical = json.dumps(_configuration_material(evidence), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"cfg-sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


def validate_system_evidence(evidence: Any) -> None:
    root = _object(evidence, "root", _ROOT_KEYS)
    if root["evidence_version"] != SYSTEM_EVIDENCE_VERSION:
        raise ProtocolError(f"system evidence evidence_version must be {SYSTEM_EVIDENCE_VERSION}")
    if root["projection"] not in {"restricted", "public"}:
        raise ProtocolError("system evidence projection must be restricted or public")
    if root["collection_method"] not in {"manual", "automated", "mixed"}:
        raise ProtocolError("system evidence collection_method must be manual, automated, or mixed")
    _timestamp(root["collected_at"], "collected_at")

    server = _object(root["server"], "server", _SERVER_KEYS)
    _text(server["host_id"], "server.host_id", nullable=True)
    os_value = _object(server["os"], "server.os", _OS_KEYS)
    for key in _OS_KEYS:
        _text(os_value[key], f"server.os.{key}", nullable=True)
    cpu = _object(server["cpu"], "server.cpu", _CPU_KEYS)
    for key in ("model", "architecture"):
        _text(cpu[key], f"server.cpu.{key}", nullable=True)
    for key in ("sockets", "physical_cores", "logical_cores"):
        _positive_int(cpu[key], f"server.cpu.{key}", nullable=True)
    if cpu["physical_cores"] is not None and cpu["logical_cores"] is not None and cpu["physical_cores"] > cpu["logical_cores"]:
        raise ProtocolError("system evidence server physical_cores cannot exceed logical_cores")
    memory = _object(server["memory"], "server.memory", _MEMORY_KEYS)
    _positive_int(memory["total_bytes"], "server.memory.total_bytes", nullable=True)
    numa = _object(server["numa"], "server.numa", _NUMA_KEYS)
    _positive_int(numa["nodes"], "server.numa.nodes", nullable=True)
    _text(numa["policy"], "server.numa.policy", nullable=True)
    _text(server["accelerator_topology"], "server.accelerator_topology", nullable=True)
    accelerators = server["accelerators"]
    if accelerators is not None and (not isinstance(accelerators, list) or not accelerators):
        raise ProtocolError("system evidence server.accelerators must be null or a non-empty array")
    seen_indices: set[int] = set()
    seen_uuids: set[str] = set()
    seen_pci_bus_ids: set[str] = set()
    for index, raw in enumerate(accelerators or []):
        accelerator = _object(raw, f"server.accelerators[{index}]", _ACCELERATOR_KEYS)
        if not isinstance(accelerator["index"], int) or isinstance(accelerator["index"], bool) or accelerator["index"] < 0:
            raise ProtocolError(f"system evidence server.accelerators[{index}].index must be a non-negative integer")
        if accelerator["index"] in seen_indices:
            raise ProtocolError("system evidence accelerator indices must be unique")
        seen_indices.add(accelerator["index"])
        for key in ("vendor", "model", "uuid", "pci_bus_id"):
            _text(accelerator[key], f"server.accelerators[{index}].{key}", nullable=key in {"uuid", "pci_bus_id"})
        if accelerator["uuid"] is not None:
            if accelerator["uuid"] in seen_uuids:
                raise ProtocolError("system evidence accelerator UUIDs must be unique")
            seen_uuids.add(accelerator["uuid"])
        if accelerator["pci_bus_id"] is not None:
            if accelerator["pci_bus_id"] in seen_pci_bus_ids:
                raise ProtocolError("system evidence accelerator PCI bus IDs must be unique")
            seen_pci_bus_ids.add(accelerator["pci_bus_id"])
        _positive_int(accelerator["vram_bytes"], f"server.accelerators[{index}].vram_bytes", nullable=True)
        for key in ("power_limit_watts", "graphics_clock_limit_mhz", "memory_clock_limit_mhz"):
            _positive_number(accelerator[key], f"server.accelerators[{index}].{key}", nullable=True)

    software = _object(root["software"], "software", _SOFTWARE_KEYS)
    for group in ("driver", "compute_runtime"):
        item = _object(software[group], f"software.{group}", _NAME_VERSION_KEYS)
        for key in _NAME_VERSION_KEYS:
            _text(item[key], f"software.{group}.{key}", nullable=True)
    engine = _object(software["engine"], "software.engine", _ENGINE_KEYS)
    _text(engine["name"], "software.engine.name")
    _text(engine["revision"], "software.engine.revision")
    if engine["binary_sha256"] is not None and (not isinstance(engine["binary_sha256"], str) or not _SHA256.fullmatch(engine["binary_sha256"])):
        raise ProtocolError("system evidence software.engine.binary_sha256 must be lowercase SHA-256 or null")
    if engine["container_image_digest"] is not None and (
        not isinstance(engine["container_image_digest"], str) or not _DIGEST.fullmatch(engine["container_image_digest"])
    ):
        raise ProtocolError("system evidence software.engine.container_image_digest must be sha256:<lowercase SHA-256> or null")
    if engine["binary_sha256"] is None and engine["container_image_digest"] is None:
        raise ProtocolError("system evidence requires an engine binary hash or container image digest")
    model = _object(software["model"], "software.model", _MODEL_KEYS)
    for key in ("name", "revision", "dtype", "quantization"):
        _text(model[key], f"software.model.{key}")
    if not isinstance(model["artifact_sha256"], str) or not _SHA256.fullmatch(model["artifact_sha256"]):
        raise ProtocolError("system evidence software.model.artifact_sha256 must be lowercase SHA-256")

    serving = _object(root["serving"], "serving", _SERVING_KEYS)
    for key in ("launch_command_sanitized", "kv_cache_dtype"):
        _text(serving[key], f"serving.{key}")
    for key in ("max_context_tokens", "max_batch_size", "tensor_parallel", "pipeline_parallel", "data_parallel", "parallel_slots"):
        _positive_int(serving[key], f"serving.{key}")
    _positive_int(serving["max_batch_tokens"], "serving.max_batch_tokens", nullable=True)
    for key in ("continuous_batching", "prefix_cache"):
        _boolean(serving[key], f"serving.{key}")
    required_accelerators = serving["tensor_parallel"] * serving["pipeline_parallel"] * serving["data_parallel"]
    if isinstance(accelerators, list) and required_accelerators > len(accelerators):
        raise ProtocolError("system evidence configured parallelism cannot exceed accelerator count")

    load_generator = _object(root["load_generator"], "load_generator", _LOAD_GENERATOR_KEYS)
    _text(load_generator["host_id"], "load_generator.host_id", nullable=True)
    load_os = _object(load_generator["os"], "load_generator.os", _OS_KEYS)
    for key in _OS_KEYS:
        _text(load_os[key], f"load_generator.os.{key}", nullable=True)
    load_cpu = _object(load_generator["cpu"], "load_generator.cpu", _LOAD_CPU_KEYS)
    for key in ("model", "architecture"):
        _text(load_cpu[key], f"load_generator.cpu.{key}", nullable=True)
    _positive_int(load_cpu["logical_cores"], "load_generator.cpu.logical_cores", nullable=True)
    load_memory = _object(load_generator["memory"], "load_generator.memory", _MEMORY_KEYS)
    _positive_int(load_memory["total_bytes"], "load_generator.memory.total_bytes", nullable=True)
    client = _object(load_generator["client"], "load_generator.client", _CLIENT_KEYS)
    for key in _CLIENT_KEYS:
        _text(client[key], f"load_generator.client.{key}")
    _boolean(load_generator["colocated_with_server"], "load_generator.colocated_with_server")

    network = _object(root["network"], "network", _NETWORK_KEYS)
    if network["relationship"] not in {"same-host", "direct-lan", "routed-lan", "wan", "tunnel"}:
        raise ProtocolError("system evidence network.relationship is invalid")
    if network["transport"] not in {"tcp", "tls", "unix-socket"}:
        raise ProtocolError("system evidence network.transport is invalid")
    colocated = load_generator["colocated_with_server"]
    if (network["relationship"] == "same-host") != colocated:
        raise ProtocolError("system evidence same-host relationship must match load-generator colocation")
    for key in ("endpoint_host", "route"):
        _text(network[key], f"network.{key}", nullable=True)
    if network["endpoint_port"] is not None and (
        not isinstance(network["endpoint_port"], int)
        or isinstance(network["endpoint_port"], bool)
        or not 1 <= network["endpoint_port"] <= 65535
    ):
        raise ProtocolError("system evidence network.endpoint_port must be from 1 to 65535 or null")
    rtt = network["rtt_ms"]
    if rtt is not None:
        rtt = _object(rtt, "network.rtt_ms", _RTT_KEYS)
        _text(rtt["method"], "network.rtt_ms.method")
        _positive_int(rtt["samples"], "network.rtt_ms.samples")
        _timestamp(rtt["measured_at"], "network.rtt_ms.measured_at")
        for key in ("median", "p95"):
            value = rtt[key]
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
                raise ProtocolError(f"system evidence network.rtt_ms.{key} must be a non-negative finite number")
        if rtt["p95"] < rtt["median"]:
            raise ProtocolError("system evidence network.rtt_ms.p95 cannot be below median")

    artifacts = root["artifacts"]
    if not isinstance(artifacts, list):
        raise ProtocolError("system evidence artifacts must be an array")
    artifact_names: set[str] = set()
    for index, raw in enumerate(artifacts):
        artifact = _object(raw, f"artifacts[{index}]", _ARTIFACT_KEYS)
        for key in ("kind", "name"):
            _text(artifact[key], f"artifacts[{index}].{key}")
        if not isinstance(artifact["sha256"], str) or not _SHA256.fullmatch(artifact["sha256"]):
            raise ProtocolError(f"system evidence artifacts[{index}].sha256 must be lowercase SHA-256")
        if artifact["name"] in artifact_names:
            raise ProtocolError("system evidence artifact names must be unique")
        artifact_names.add(artifact["name"])

    unavailable = root["unavailable"]
    if not isinstance(unavailable, dict) or any(not isinstance(path, str) or not isinstance(reason, str) or not reason.strip() for path, reason in unavailable.items()):
        raise ProtocolError("system evidence unavailable must map JSON pointers to non-empty reasons")
    nulls = _null_paths({key: value for key, value in root.items() if key != "unavailable"})
    if nulls != set(unavailable):
        missing = sorted(nulls - set(unavailable))
        stale = sorted(set(unavailable) - nulls)
        raise ProtocolError(f"system evidence unavailable does not match null fields; missing={missing}, stale={stale}")
    for path in unavailable:
        try:
            if _resolve_pointer(root, path) is not None:
                raise ProtocolError(f"system evidence unavailable path is not null: {path}")
        except (KeyError, IndexError, ValueError) as exc:
            raise ProtocolError(f"system evidence unavailable path is invalid: {path}") from exc

    if contains_secret_like({key: value for key, value in root.items() if key != "configuration_id"}):
        raise ProtocolError("system evidence contains secret-like material")
    if root["projection"] == "public":
        private = [server["host_id"], load_generator["host_id"], network["endpoint_host"], network["endpoint_port"], network["route"]]
        private.extend(value for accelerator in accelerators or [] for value in (accelerator["uuid"], accelerator["pci_bus_id"]))
        if any(value is not None for value in private):
            raise ProtocolError("public system evidence must redact host, device, endpoint, and route identifiers")
        if re.search(r"(?:/Users/|/home/|[A-Za-z]:\\\\Users\\\\)", json.dumps(root, ensure_ascii=False)):
            raise ProtocolError("public system evidence contains a user-home path")
    expected_id = system_configuration_id(root)
    if root["configuration_id"] != expected_id:
        raise ProtocolError(f"system evidence configuration_id mismatch; expected {expected_id}")


def load_system_evidence(path: str | Path) -> dict[str, Any]:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ProtocolError("system evidence must not be a symlink")
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"cannot load system evidence: {exc}") from exc
    validate_system_evidence(value)
    return cast(dict[str, Any], value)


def public_system_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Return a valid public projection without host or device identifiers."""
    validate_system_evidence(evidence)
    public = copy.deepcopy(evidence)
    public["projection"] = "public"
    sensitive = [
        "/server/host_id",
        "/load_generator/host_id",
        "/network/endpoint_host",
        "/network/endpoint_port",
        "/network/route",
    ]
    accelerators = public["server"]["accelerators"]
    if isinstance(accelerators, list):
        for index in range(len(accelerators)):
            sensitive.extend((f"/server/accelerators/{index}/uuid", f"/server/accelerators/{index}/pci_bus_id"))
    sensitive_values = [str(_resolve_pointer(public, path)) for path in sensitive if isinstance(_resolve_pointer(public, path), str)]
    for path in sensitive:
        if _resolve_pointer(public, path) is not None:
            parent_pointer, field = path.rsplit("/", 1)
            parent = _resolve_pointer(public, parent_pointer)
            if isinstance(parent, dict):
                parent[field] = None
            public["unavailable"][path] = "redacted from public projection"
    serialized = json.dumps(public, ensure_ascii=False)
    if any(len(value) >= 6 and value in serialized for value in sensitive_values):
        raise ProtocolError("system evidence public projection repeats a private identifier in a non-redacted field")
    if re.search(r"(?:/Users/|/home/|[A-Za-z]:\\\\Users\\\\)", serialized):
        raise ProtocolError("system evidence public projection contains a user-home path; sanitize launch and artifact evidence")
    validate_system_evidence(public)
    return public
