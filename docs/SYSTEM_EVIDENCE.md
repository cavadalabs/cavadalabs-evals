# Performance system evidence

`performance-system-evidence` v1 records the complete system that produced an
LLM serving result. It is separate from the immutable performance plan,
workload, runtime connection descriptor, and report. The contract does not
collect hardware and never starts an inference engine.

The authoritative machine-readable shape is
`schemas/performance-system-evidence.schema.json`. Runtime validation uses only
the Python standard library through `cavada_eval.system_evidence`.

## Required evidence

The JSON document records:

- server OS, release, kernel, CPU, RAM, NUMA policy, accelerators, device UUIDs,
  VRAM, PCI location, topology, configured power limit, and clock limits;
- driver, compute runtime, engine revision and binary/container digest, plus
  model identity, revision, artifact SHA-256, dtype, and quantization;
- exact credential-free launch command, context capacity, cache and batching
  policy, tensor/pipeline/data parallelism, and parallel request slots;
- load-generator OS, CPU, RAM, client revision, and colocation status;
- network relationship, transport, endpoint, route, and an optional measured
  RTT distribution with method, sample count, timestamp, median, and p95;
- hashes of retained supporting artifacts such as startup logs or topology
  captures.

All sizes are bytes. Power is watts, clocks are MHz, and RTT is milliseconds.
Numeric facts that are unknown must be `null`, never `0`. Every `null` must have
one matching JSON Pointer and a non-empty reason in `unavailable`; stale reasons
are rejected. Required engine and model artifact hashes cannot be replaced by
an unavailable marker: the engine needs a binary SHA-256 or pinned container
digest, and the model artifact always needs a SHA-256.

## Configuration identity

`configuration_id` has the form `cfg-sha256:<digest>` and identifies material
configuration, not a campaign execution. A `run_id` remains unique and
immutable for each run; repeated runs of an unchanged system reuse the same
configuration ID.

The canonical digest includes server hardware/software and serving settings,
load-generator specification, and network class. It deliberately excludes:

- collection time and method;
- artifact inventory and absence explanations;
- server/load-generator host IDs, accelerator UUIDs and PCI addresses;
- endpoint host/port, route text, and sampled RTT;
- restricted versus public projection.

Those fields remain retained evidence but are either provenance, observations,
or identifiers rather than configuration dimensions. A material change such as
a driver revision, accelerator model, engine hash, model hash, launch command,
cache policy, or parallelism changes the ID.

```python
from cavada_eval.system_evidence import (
    public_system_evidence,
    system_configuration_id,
    validate_system_evidence,
)

evidence["configuration_id"] = system_configuration_id(evidence)
validate_system_evidence(evidence)
public = public_system_evidence(evidence)
```

`load_system_evidence(path)` rejects symlinks, malformed JSON, unknown or
missing fields, placeholders, secret-like material, invalid timestamps,
unexplained nulls, fake zero capacities, invalid hashes, duplicate device
identities, impossible parallelism, and a stale configuration ID.

## Restricted and public projections

The restricted document retains host IDs, device UUIDs, PCI addresses, endpoint
and route. `public_system_evidence()` returns a deep copy, sets `projection` to
`public`, replaces those identifiers with explicit redacted nulls, validates the
result, and preserves the configuration ID. It does not mutate the source.

The launch command is already a public-safe field. Producers must remove
credentials, private paths, tokens, query values, and unnecessary personal data
before validation. Public projection is a final identifier redaction step, not
a substitute for preparing credential-free evidence.

## Runner integration

The performance runner:

1. loads and validates the evidence before endpoint contact;
2. copies the exact JSON into the new immutable run directory;
3. records its file SHA-256 and `configuration_id` in the run manifest;
4. requires a complete restricted document collected within 24 hours for an
   official run;
5. includes only `public_system_evidence()` in a public export;
6. compares results by exact plan/workload cells and discloses differing
   configuration IDs rather than treating a runtime label as hardware proof.

Pass the document explicitly during validation and execution:

```bash
uv run cavada-eval perf validate --preset reference \
  --runtime /secure/path/runtime.toml \
  --system-evidence /secure/path/system-evidence.json
uv run cavada-eval perf run /secure/path/runtime.toml --preset reference \
  --system-evidence /secure/path/system-evidence.json
```

Do not mutate a released workload or performance plan to add system evidence.
The evidence is a separate versioned input, so existing v1 measurement hashes
remain unchanged.
