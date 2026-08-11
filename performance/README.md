# Performance package

This directory contains versioned, non-secret inputs for the dedicated LLM
serving engine. `plans/` defines preregistered cells and gates; `workloads/`
contains hash-pinned public or synthetic prompts. Machine/runtime descriptors
belong outside the repository and start from `runtime.example.toml`.
Current reference runs use
[Performance Protocol v2](../PERFORMANCE_PROTOCOL_V2.md). The commit-anchored
[v1.0 protocol](../PERFORMANCE_PROTOCOL_V1_0.md) and released v1 inputs remain
byte-frozen for hash-only verification; current producer, export,
public-verification, and comparison paths accept v2 only.
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

The commit-anchored v1 inputs remain byte-frozen solely for hash-only
verification of recorded bundles. Never edit them in place.

## Built-in performance preset

| Preset | Plan | Intended use |
| --- | --- | --- |
| `reference` | `llm-serving-v2.toml` | Current v2 reference; official-capable only when every other gate also passes |

Run a preset without manually selecting its plan:

```bash
uv run cavada-eval perf validate --preset reference --runtime /secure/runtime.toml \
  --system-evidence /secure/system-evidence.json
uv run cavada-eval perf run /secure/runtime.toml --preset reference
```

Validation is offline and does not contact the endpoint. Follow the remaining
evidence steps in
[the operator guide](../docs/PERFORMANCE.md). Preset plans are immutable inputs,
not runtime overrides. Performance request counts are determined by cells,
warm-up, load, duration, and repetitions; they are intentionally distinct from
quality-suite case counts.

The inference engine remains externally managed. These client-side measurements
do not establish response quality, hardware utilization, or energy use.
