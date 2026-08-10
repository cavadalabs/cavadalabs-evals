from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

from cavada_eval.protocol import ProtocolError
from cavada_eval.system_evidence import (
    load_system_evidence,
    public_system_evidence,
    system_configuration_id,
    validate_system_evidence,
)


def _evidence() -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "evidence_version": "1.0.0",
        "configuration_id": "",
        "projection": "restricted",
        "collected_at": "2026-08-07T12:00:00+02:00",
        "collection_method": "mixed",
        "server": {
            "host_id": "inference-01",
            "os": {"name": "Ubuntu", "version": "24.04", "kernel": "6.8.0-64-generic"},
            "cpu": {"model": "AMD EPYC 9354", "architecture": "x86_64", "sockets": 1, "physical_cores": 32, "logical_cores": 64},
            "memory": {"total_bytes": 274877906944},
            "numa": {"nodes": 1, "policy": "local"},
            "accelerators": [
                {
                    "index": 0,
                    "vendor": "AMD",
                    "model": "Radeon RX 7900 XTX",
                    "uuid": "GPU-deadbeef-0001",
                    "vram_bytes": 25769803776,
                    "pci_bus_id": "0000:03:00.0",
                    "power_limit_watts": 355,
                    "graphics_clock_limit_mhz": 2500,
                    "memory_clock_limit_mhz": None,
                },
                {
                    "index": 1,
                    "vendor": "AMD",
                    "model": "Radeon RX 7900 XTX",
                    "uuid": "GPU-deadbeef-0002",
                    "vram_bytes": 25769803776,
                    "pci_bus_id": "0000:0d:00.0",
                    "power_limit_watts": 355,
                    "graphics_clock_limit_mhz": 2500,
                    "memory_clock_limit_mhz": 1249,
                },
            ],
            "accelerator_topology": "two PCIe 4.0 x16 devices; no peer-to-peer link",
        },
        "software": {
            "driver": {"name": "amdgpu", "version": "6.8.5"},
            "compute_runtime": {"name": "ROCm", "version": "7.0.0"},
            "engine": {
                "name": "llama.cpp",
                "revision": "0123456789abcdef0123456789abcdef01234567",
                "binary_sha256": "a" * 64,
                "container_image_digest": "sha256:" + "b" * 64,
            },
            "model": {
                "name": "Qwen3-32B",
                "revision": "main@0123456789abcdef",
                "artifact_sha256": "c" * 64,
                "dtype": "GGUF",
                "quantization": "Q4_K_M",
            },
        },
        "serving": {
            "launch_command_sanitized": "llama-server --model model.gguf --parallel 2 --ctx-size 32768",
            "max_context_tokens": 32768,
            "max_batch_size": 2048,
            "max_batch_tokens": 2048,
            "continuous_batching": True,
            "prefix_cache": False,
            "kv_cache_dtype": "f16",
            "tensor_parallel": 2,
            "pipeline_parallel": 1,
            "data_parallel": 1,
            "parallel_slots": 2,
        },
        "load_generator": {
            "host_id": "loadgen-01",
            "os": {"name": "macOS", "version": "15.6", "kernel": "Darwin 24.6.0"},
            "cpu": {"model": "Apple M4", "architecture": "arm64", "logical_cores": 10},
            "memory": {"total_bytes": 17179869184},
            "client": {"name": "cavadalabs-evals", "revision": "fedcba9876543210fedcba9876543210fedcba98"},
            "colocated_with_server": False,
        },
        "network": {
            "relationship": "tunnel",
            "transport": "tcp",
            "endpoint_host": "127.0.0.1",
            "endpoint_port": 8080,
            "route": "loadgen-01 -> SSH tunnel -> inference-01",
            "rtt_ms": {
                "method": "TCP connect",
                "samples": 100,
                "median": 1.2,
                "p95": 2.4,
                "measured_at": "2026-08-07T11:55:00+02:00",
            },
        },
        "artifacts": [{"kind": "engine-log", "name": "startup.log", "sha256": "d" * 64}],
        "unavailable": {"/server/accelerators/0/memory_clock_limit_mhz": "device API did not expose the configured limit"},
    }
    evidence["configuration_id"] = system_configuration_id(evidence)
    return evidence


def test_valid_system_evidence_loads_with_hash_pins_and_explicit_absence(tmp_path: Path) -> None:
    evidence = _evidence()
    validate_system_evidence(evidence)
    path = tmp_path / "system-evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    assert load_system_evidence(path) == evidence


def test_duplicate_accelerator_pci_bus_ids_are_rejected() -> None:
    evidence = _evidence()
    evidence["server"]["accelerators"][1]["pci_bus_id"] = evidence["server"]["accelerators"][0]["pci_bus_id"]
    evidence["configuration_id"] = system_configuration_id(evidence)
    with pytest.raises(ProtocolError, match="PCI bus IDs must be unique"):
        validate_system_evidence(evidence)


def test_invalid_system_evidence_rejects_fake_zero_unexplained_null_and_id_drift() -> None:
    zero = _evidence()
    zero["server"]["memory"]["total_bytes"] = 0
    with pytest.raises(ProtocolError, match="positive integer"):
        validate_system_evidence(zero)

    unexplained = _evidence()
    unexplained["network"]["rtt_ms"] = None
    with pytest.raises(ProtocolError, match="unavailable does not match null fields"):
        validate_system_evidence(unexplained)

    unpinned = _evidence()
    unpinned["software"]["model"]["artifact_sha256"] = "latest"
    with pytest.raises(ProtocolError, match="artifact_sha256 must be lowercase SHA-256"):
        validate_system_evidence(unpinned)

    changed = _evidence()
    changed["serving"]["parallel_slots"] = 4
    with pytest.raises(ProtocolError, match="configuration_id mismatch"):
        validate_system_evidence(changed)

    impossible_parallelism = _evidence()
    impossible_parallelism["serving"]["data_parallel"] = 2
    impossible_parallelism["configuration_id"] = system_configuration_id(impossible_parallelism)
    with pytest.raises(ProtocolError, match="parallelism cannot exceed accelerator count"):
        validate_system_evidence(impossible_parallelism)

    inconsistent_topology = _evidence()
    inconsistent_topology["network"]["relationship"] = "same-host"
    inconsistent_topology["configuration_id"] = system_configuration_id(inconsistent_topology)
    with pytest.raises(ProtocolError, match="must match load-generator colocation"):
        validate_system_evidence(inconsistent_topology)

    leaky_public = _evidence()
    leaky_public["projection"] = "public"
    with pytest.raises(ProtocolError, match="must redact"):
        validate_system_evidence(leaky_public)


def test_public_projection_redacts_identifiers_and_remains_valid() -> None:
    restricted = _evidence()
    public = public_system_evidence(restricted)
    assert public["projection"] == "public"
    assert public["configuration_id"] == restricted["configuration_id"]
    assert public["server"]["host_id"] is None
    assert public["server"]["accelerators"][0]["uuid"] is None
    assert public["server"]["accelerators"][0]["pci_bus_id"] is None
    assert public["load_generator"]["host_id"] is None
    assert public["network"]["endpoint_host"] is None
    assert public["network"]["endpoint_port"] is None
    assert public["network"]["route"] is None
    assert all(public["unavailable"][path] == "redacted from public projection" for path in (
        "/server/host_id",
        "/server/accelerators/0/uuid",
        "/server/accelerators/0/pci_bus_id",
        "/load_generator/host_id",
        "/network/endpoint_host",
        "/network/endpoint_port",
        "/network/route",
    ))
    validate_system_evidence(public)
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "performance-system-evidence.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(public)

    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate({**restricted, "projection": "public"})

    leaky = _evidence()
    leaky["server"]["accelerator_topology"] += "; GPU-deadbeef-0001"
    leaky["configuration_id"] = system_configuration_id(leaky)
    with pytest.raises(ProtocolError, match="repeats a private identifier"):
        public_system_evidence(leaky)

    private_path = _evidence()
    private_path["serving"]["launch_command_sanitized"] = "server --model /Users/alice/private/model.gguf"
    private_path["configuration_id"] = system_configuration_id(private_path)
    with pytest.raises(ProtocolError, match="user-home path"):
        public_system_evidence(private_path)


def test_configuration_id_is_stable_across_provenance_and_private_identifiers() -> None:
    original = _evidence()
    equivalent = copy.deepcopy(original)
    equivalent["collected_at"] = "2026-08-08T12:00:00+02:00"
    equivalent["collection_method"] = "manual"
    equivalent["artifacts"] = []
    equivalent["server"]["host_id"] = "replacement-hostname"
    equivalent["server"]["accelerators"][0]["uuid"] = "replacement-device-uuid"
    equivalent["server"]["accelerators"].reverse()
    equivalent["load_generator"]["host_id"] = "replacement-loadgen"
    equivalent["network"]["endpoint_host"] = "10.0.0.9"
    equivalent["network"]["rtt_ms"]["median"] = 1.4
    assert system_configuration_id(equivalent) == original["configuration_id"]

    material_change = copy.deepcopy(original)
    material_change["software"]["driver"]["version"] = "6.9.0"
    assert system_configuration_id(material_change) != original["configuration_id"]
