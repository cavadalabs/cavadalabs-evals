# Running LLM serving benchmarks

The performance engine calls an already running OpenAI-compatible streaming
endpoint. Keep llama.cpp, vLLM, SGLang, TensorRT-LLM, TGI, or another server
outside the repository; this avoids privileged process control and keeps the
same measurement path across engines.

## 1. Describe the runtime

Copy `performance/runtime.example.toml` to a machine-specific file that is not
committed. Fill every immutable revision and the exact hardware topology. The
endpoint must return its exact `expected_model` and streaming usage containing
`prompt_tokens` and `completion_tokens`.

`max_context_tokens` is total input plus output capacity. To run the full
reference plan with 256k input and 8k output, set it to at least `270336` and
ensure the server was launched with that capacity. Cells that do not fit are
recorded as skipped.

The sanitized launch command is evidence only and is never executed. Codex may
start a server when explicitly asked, but it must use the engine's documented
command, keep credentials out of arguments and artifacts, confirm readiness,
record the exact command/revisions, and stop only the process it started.

## 2. Validate without network access

```bash
uv run cavada-eval perf validate performance/plans/llm-serving-v1.toml \
  --runtime /secure/path/runtime.toml

# Equivalent built-in plan selection:
uv run cavada-eval perf validate --preset reference \
  --runtime /secure/path/runtime.toml
```

The reference workload is `iso-prompt`: every runtime receives identical text,
while observed input token counts expose tokenizer differences. For a strict
`iso-token` comparison, create a versioned tokenizer-calibrated workload and
set a justified tolerance. Never relabel approximate prompts as iso-token.

## 3. Run

Use the short functional profile first:

```bash
uv run cavada-eval perf run performance/plans/llm-serving-smoke-v1.toml \
  /secure/path/runtime.toml
```

Use `quick` for a repeatable development regression and `standard` for a broad
candidate campaign:

```bash
uv run cavada-eval perf run /secure/path/runtime.toml --preset quick
uv run cavada-eval perf run /secure/path/runtime.toml --preset standard
```

Then run the full reference campaign (`full` is accepted as a CLI alias):

```bash
uv run cavada-eval perf run /secure/path/runtime.toml --preset reference
```

The plan combines:

- single-user sweeps over 128 through 262,144 input tokens and 128 through
  8,192 requested output tokens;
- closed-loop concurrency from 1 through 64;
- focused 128k/256k long-context concurrency;
- open-loop offered rates from 1 through 20 requests/second;
- separate warm-ups, three randomized measurement blocks, cooldowns, bounded
  execution, and bootstrap tail-latency intervals.

The reference plan is intentionally expensive. Do not mutate it or present a
smoke, quick, or standard campaign as the reference protocol. Any new plan is a
new versioned measurement input with its own hash and claim scope.

Exit code `0` means execution completed and every evaluated cell passed its
aggregate SLO gates. Exit code `1` preserves a completed report but signals an
SLO or execution failure; execution status and SLO evidence remain separate in
the manifest.

## 4. Compare exact compatible runs

```bash
uv run cavada-eval perf compare \
  runs/performance/llm-serving-v1/RUN_A \
  runs/performance/llm-serving-v1/RUN_B \
  --output runs/performance/comparisons/COMPARISON_ID
```

Comparison rejects modified plans/workloads, invalid bundles, duplicate runtime
IDs, and campaigns with no shared completed cells. Use distinct runtime IDs for
every model, engine, GPU topology, or material configuration.

The comparison report places models on rows and exact context/output/load cells
on columns for each primary metric. Its complete grid keeps performance columns
before long runtime and GPU identity fields; the same exact values remain
available in `comparison.csv` and `comparison.json`.

## Artifacts

Each immutable run contains plan/runtime/workload snapshots, `requests.jsonl`,
raw `responses.jsonl`, `observations.jsonl`, `warmups.jsonl`, `cells.jsonl`,
`events.jsonl`, `cells.csv`, `summary.json`, HTML/PDF reports, accessible SVG
figures, manifest, checksums, bundle, optional signature, and verification.

## Reliable operating conditions

- Use a dedicated load generator that is not the inference host when testing
  large throughput, synchronize clocks for external telemetry, and record the
  physical/network topology.
- Pin engine/model revisions and server arguments; disable unrelated workloads,
  autoscaling, and power-policy changes unless they are part of the test.
- Preload the model, check health, check available disk/VRAM, and retain engine
  logs separately with a hash/reference if they contain no secrets.
- Run comparable systems in interleaved or randomized order under the same
  conditions. Repeat on another day for claims sensitive to thermal or shared
  infrastructure effects.
- Do not infer GPU utilization or energy from client timing. Add an approved,
  synchronized hardware collector when those measurements become required.

See `PERFORMANCE_PROTOCOL.md` for normative rules. Quality, safety, privacy, and
compliance evaluations remain separate benchmark suites.
