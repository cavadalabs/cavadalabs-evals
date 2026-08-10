# Performance package

This directory contains versioned, non-secret inputs for the dedicated LLM
serving engine. `plans/` defines preregistered cells and gates; `workloads/`
contains hash-pinned public or synthetic prompts. Machine/runtime descriptors
belong outside the repository and start from `runtime.example.toml`.
Current reference runs use
[Performance Protocol v2](../PERFORMANCE_PROTOCOL_V2.md). The unanchored
historical-development [v1.1 protocol](../PERFORMANCE_PROTOCOL_V1_1.md), commit-anchored
[v1.0 protocol](../PERFORMANCE_PROTOCOL_V1_0.md), and their inputs remain
immutable for bundles that record those versions.
The exact anchor and schema matrix is recorded in
[version provenance](VERSION_PROVENANCE.md).

## Reference synthetic workload card

- ID/revision: `llm-serving-synthetic-v2@2.0.0`
- Owner/origin: CavadaLabs, generated in-house on 2026-08-07
- License: repository Apache License 2.0
- Classification: synthetic; no intended personal data
- Purpose: prompt-length scaling, long-context serving, latency, throughput,
  capacity, and tokenizer-difference observation
- Contents: two neutral prompt variants at each declared 128, 512, 2k, 8k,
  32k, 64k, 128k, and 256k input-token target
- Cache policy: `diverse`; a deterministic, fixed-width key derived from the
  frozen seed, cell, block, phase, row, and request index is prepended to the
  first message. Equal plans therefore send equal request sequences across
  runtimes without accidentally benchmarking a shared full-prompt prefix.
- Known limitation: declared token targets are approximate across tokenizers;
  each row reserves 64 approximate tokens for message framing, instructions,
  and the cache key, and provider-reported usage remains authoritative. The
  reference plan is therefore `iso-prompt`, not strict `iso-token`
- Prohibited use: response-quality, safety, factuality, privacy, fairness, legal
  compliance, or exact equal-token claims

The commit-anchored v1 workload remains immutable for historical smoke, quick,
standard, and reference runs. Changing any row requires a new workload
revision, a new hash in a newly versioned plan, and updated documentation.
Never edit commit-anchored inputs in place.

## Built-in execution presets

| Preset | Plan | Intended use |
| --- | --- | --- |
| `smoke` | `llm-serving-smoke-v1.toml` | Historical-development v1.1 endpoint check |
| `quick` | `llm-serving-quick-v1.toml` | Historical-development v1.1 98-request regression |
| `standard` | `llm-serving-standard-v1.toml` | Historical-development v1.1 825-request campaign |
| `reference` (`full`) | `llm-serving-v2.toml` | Current v2 reference; the only official-capable preset, with every other gate still required |

Run a preset without manually selecting its plan:

```bash
uv run cavada-eval perf validate --preset quick --runtime /secure/runtime.toml
uv run cavada-eval perf run /secure/runtime.toml --preset quick
uv run cavada-eval perf validate --preset reference --runtime /secure/runtime.toml \
  --system-evidence /secure/system-evidence.json
```

Validation is offline and does not contact the endpoint. The quick run is
non-official; continue with `reference` only when preparing official-capable
work and follow the remaining evidence steps in
[the operator guide](../docs/PERFORMANCE.md). Preset plans are immutable inputs,
not runtime overrides. Performance request counts are determined by cells,
warm-up, load, duration, and repetitions; they are intentionally distinct from
quality-suite case counts.

The inference engine remains externally managed. These client-side measurements
do not establish response quality, hardware utilization, or energy use.
