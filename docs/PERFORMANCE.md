# Running LLM serving benchmarks

The performance engine calls an already running OpenAI-compatible streaming
endpoint. Keep llama.cpp, vLLM, SGLang, TensorRT-LLM, TGI, or another server
outside the repository; this avoids privileged process control and keeps the
same measurement path across engines.

The current reference plan and workload are revision 2 inputs under Performance
Protocol v2.0. They are new immutable artifacts, not edits to the commit-anchored
v1.0 plans, workload, or protocol retained for historical hash verification.

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
uv run cavada-eval perf validate --preset reference \
  --runtime /secure/path/runtime.toml \
  --system-evidence /secure/path/system-evidence.json
```

Use this command to validate locally without contacting the endpoint. The
`reference` preset follows
[Performance Protocol v2](../PERFORMANCE_PROTOCOL_V2.md) and is the only
official-capable preset; every other official gate still applies. The
system-evidence file is optional for development runs and mandatory for an
official reference run. Its restricted form, freshness, runtime identity,
hardware topology, endpoint transport, and configuration ID are checked before
network access; see [system evidence](SYSTEM_EVIDENCE.md).

An official run also requires a local, restricted execution-responsibility
record supplied with `--execution-record`. Create it before execution and bind
it to the exact bytes of every input:

```json
{
  "record_version": "1.0.0",
  "engagement_id": "stable-local-engagement-id",
  "execution_owner_id": "stable-accountable-executor-id",
  "scope": "Execute the exact hash-bound LLM serving performance campaign.",
  "protocol_sha256": "64 lowercase hex characters",
  "plan_sha256": "64 lowercase hex characters",
  "workload_sha256": "64 lowercase hex characters",
  "runtime_sha256": "64 lowercase hex characters",
  "system_evidence_sha256": "64 lowercase hex characters",
  "recorded_at": "timezone-aware ISO-8601 time before execution"
}
```

This record assigns responsibility and scope; it does not invent or imply
organizational authorization. The runner validates it before creating the run,
stores a private byte-exact snapshot, and records only its IDs, timestamp, and
SHA-256 in the manifest.

Official execution also requires `--engagement` with a separate, currently
effective operator-supplied record:

```json
{
  "engagement_version": "1.0.0",
  "engagement_id": "same ID as the execution record",
  "status": "approved",
  "scope": "Run and release only this exact performance campaign.",
  "execution_owner_id": "same owner as the execution record",
  "protocol_sha256": "exact protocol SHA-256",
  "plan_sha256": "exact plan SHA-256",
  "workload_sha256": "exact workload SHA-256",
  "runtime_sha256": "exact runtime SHA-256",
  "system_evidence_sha256": "exact restricted evidence SHA-256",
  "configuration_id": "exact cfg-sha256 identifier",
  "approved_at": "timezone-aware ISO-8601 time before the execution record",
  "expires_at": "timezone-aware ISO-8601 time after the campaign and release"
}
```

This is a bounded local governance assertion, not authentication, legal
certification, or proof of organizational authority. The runner reads each
governance file once before creating output or contacting the endpoint, stores
the exact private bytes, and projects their hashes and bounded identifiers into
the manifest. Here `status: approved` means the operator activated this exact
execution scope; independent release authority is asserted only by the
separate post-run approval.

The reference workload is `iso-prompt`: every runtime receives the same
deterministic sequence of text while observed input token counts expose
tokenizer differences. Its `diverse` cache policy prepends a stable per-request
key, so comparable runs remain identical without sharing the complete prompt
prefix. For a strict `iso-token` comparison, create a versioned
tokenizer-calibrated workload and set a justified tolerance. Never relabel
approximate prompts as iso-token.

## 3. Run

After offline validation, run the current v2 reference campaign. Development
runs omit `--official` and its governance inputs; official-capable work uses:

```bash
uv run cavada-eval perf run /secure/path/runtime.toml --preset reference \
  --system-evidence /secure/path/system-evidence.json \
  --execution-record /secure/path/performance-execution-record.json \
  --engagement /secure/path/performance-engagement.json \
  --official
```

The plan combines:

- single-user sweeps over 128 through 262,144 input tokens and 128 through
  8,192 requested output tokens;
- closed-loop concurrency from 1 through 64;
- focused 128k/256k long-context concurrency;
- open-loop offered rates from 1 through 20 requests/second;
- separate warm-ups, three randomized measurement blocks, cooldowns, bounded
  execution, and bootstrap tail-latency intervals;
- deterministic seeded Poisson open-loop arrivals and at least 100 successful
  observations before an E2E p99 gate can pass in every reference cell.

### Open-loop load-generator validity

Each measured request retains its planned monotonic arrival, actual transport
dispatch, first content, and completion timestamps. `dispatch_lag_ms` is
dispatch minus planned arrival; scheduled TTFT/E2E are first content/completion
minus planned arrival. The existing TTFT/E2E from dispatch remain separate
endpoint-and-transport measurements, and `client_queue_ms` remains the legacy
scheduler/worker queue diagnostic.

For a preregistered measurement window, offered rate is scheduled requests per
second, achieved dispatch rate counts requests dispatched within that window,
and completion rate counts terminal outcomes completed within it. Rate fidelity
is achieved dispatch rate divided by offered rate. The versioned plan supplies
the minimum fidelity and maximum dispatch-lag thresholds; there are no implicit
defaults for the current protocol.

The arrival/measurement denominator is the preregistered duration `T`; a
dispatch or completion exactly at its end is included. Requests scheduled in
`T` may finish during drain and still satisfy goodput. Successful requests and
provider-reported input/output token totals use the separately published
`throughput_window_seconds`, measured from batch start through the final
terminal outcome. Closed-loop goodput keeps contact TTFT/E2E and reports all
open-loop-only schedule/rate/lag fields as N/A.

An open-loop cell that misses either gate is `invalid-loadgen`: endpoint
successes and errors remain preserved, but the cell cannot pass SLO, contributes
zero goodput, and is not a valid serving-system measurement. Reports and public
verification retain this category separately from errors, failures, and skips.

The current reference plan deterministically schedules 78,911 requests and has
a preregistered upper bound of about 3.93 billion input-plus-output tokens.
Those are safety bounds, not a price quote; validate the exact plan and runtime
before spending. Do not mutate it or present a preserved v1 plan as the current
reference protocol. Any new plan is a new versioned measurement
input with its own hash and claim scope.

At exit, the CLI prints JSON containing `run_dir`, campaign `status`,
`invalid_loadgen`, and `slo_failed`. Exit code `0` means `status` is `completed`
and `slo_failed` is zero. Exit code `1` preserves the report and means at least
one of those conditions failed: `status: invalid-loadgen` with a nonzero
`invalid_loadgen` count identifies load-generation invalidity; a zero invalid
count with nonzero `slo_failed` identifies an ordinary SLO failure; and
`status: completed-with-errors` identifies retained execution or warm-up
errors. Status, invalid-loadgen evidence, and SLO evidence remain separate in
the manifest.

## 4. Compare exact compatible runs

```bash
uv run cavada-eval perf compare \
  runs/performance/llm-serving-v2/RUN_A \
  runs/performance/llm-serving-v2/RUN_B \
  --output runs/performance/comparisons/COMPARISON_ID

uv run cavada-eval verify runs/performance/comparisons/COMPARISON_ID \
  --source-run runs/performance/llm-serving-v2/RUN_A \
  --source-run runs/performance/llm-serving-v2/RUN_B
```

Comparison rejects modified plans/workloads, invalid bundles, duplicate runtime
IDs, and campaigns with no shared completed cells. Use distinct runtime IDs for
every model, engine, GPU topology, or material configuration.

Only the intersection of completed block-cells is compared. Skipped and
non-shared cells remain listed per runtime. Output-token throughput ratios are
emitted only when every run uses the same model artifact and revision; across
different tokenizers the individual observations remain visible, but the ratio
is `null` rather than pretending the token units are equivalent.

The source runs are required, in recorded order, for semantic verification.
Without them, `verify` checks the comparison bundle and its deterministic
presentation but reports `semantic_valid: false` and
`authenticity: recorded-source-hashes-only`.

## 5. Export public evidence

Do not publish a run directory: it retains raw responses and restricted runtime
evidence. Create a fail-closed sanitized bundle instead:

```bash
uv run cavada-eval perf export RUN_DIR public-performance.tar.gz
```

This produces a clearly labeled development export. An official export also
requires the exact independent post-run approval described in
[performance result publication](PERFORMANCE_RELEASE.md). Extract the archive
and run `cavada-eval verify` on the extracted directory before distribution.

## Artifacts

Each immutable run contains plan/runtime/workload snapshots, `requests.jsonl`,
raw `responses.jsonl`, `observations.jsonl`, `warmups.jsonl`, `cells.jsonl`,
`events.jsonl`, `cells.csv`, `summary.json`, HTML/PDF reports, accessible SVG
figures, manifest, checksums, bundle, optional signature, and verification.
Referenced prompt assets are read into a hash-checked immutable cache before
execution; request construction never reopens a mutable source prompt.

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

See `PERFORMANCE_PROTOCOL_V2.md` for current normative rules. The commit-anchored
v1.0 contract and inputs remain byte-frozen for hash-only verification; current
producer, export, public-verification, and comparison paths accept v2 only.
Quality, safety, privacy, and compliance evaluations remain separate benchmark
suites.
