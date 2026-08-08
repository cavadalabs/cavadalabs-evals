# CavadaLabs LLM Serving Performance Protocol v1.1

## Status and scope

This protocol defines reproducible, generation-only measurements for an
OpenAI-compatible streaming LLM endpoint. It covers latency, throughput,
capacity, long context, concurrency, token usage, failures, and optional cost.
It does not score response quality and does not control the inference engine.

A run may be described as conforming to “CavadaLabs LLM Serving Performance
Protocol v1.1” only when its verified bundle reports `completed`. This is a
procedural claim, not a certification, capacity guarantee, or proof of safety.

## Normative requirements

1. Validate the complete plan, hash-pinned workload, and runtime descriptor
   before network access. Version changed plans/workloads and never alter a
   completed run.
2. Permit only public or synthetic v1 workloads. API credentials are read only
   from the named environment variable and never stored.
3. Run the inference engine outside this repository. Record its immutable
   revision, model artifact revision, exact model identity, numeric format,
   quantization, GPU type/count, tensor parallelism, maximum context, container
   digest when used, and a credential-free launch command.
4. Use streaming, temperature zero, provider usage reporting, and exact model
   identity. A missing/mismatched identity or missing token usage is an error.
5. Treat `context_tokens` as declared input tokens and `output_tokens` as the
   requested maximum generation. Skip cells whose sum exceeds the runtime's
   declared maximum context window.
6. In `iso-prompt` mode, send identical prompt material and report observed
   tokenizer differences. In `iso-token` mode, reject observations outside the
   preregistered token tolerance.
7. Keep warm-up observations separate. Execute repeated randomized blocks and
   preserve their order, requests, raw streaming events, transport evidence,
   errors, and per-request observations.
8. Closed-loop cells maintain bounded concurrent users. Open-loop cells issue
   requests at a preregistered offered rate and report client queue delay; they
   must not hide overload by converting to closed-loop behavior.
9. Do not retry measured transport requests. A retry changes the workload and
   is therefore a separate observation, not recovery of the original sample.
10. Enforce preregistered request, token, duration, timeout, context, output,
    and in-flight limits. Preserve partial evidence on interruption.
11. Report TTFT, end-to-end latency, derived TPOT, server-native generation
    tokens/second, client-derived generation tokens/second, server-native
    prompt tokens/second, request/input/output end-to-end throughput, queue
    delay, error taxonomy, goodput, cost when priced, and p50/p90/p95/p99
    distributions. Report bootstrap intervals for primary medians and latency
    tail estimates, and warn when p99 is weakly resolved. Never label
    end-to-end output throughput as model generation speed.
12. Apply aggregate SLO gates and per-request goodput thresholds separately.
    A completed campaign may fail its SLO; execution status and SLO result must
    never be conflated.
13. Compare only exact shared cells from verified runs with identical plan,
    workload, and workload-asset hashes. Runtime IDs must be unique.
14. Attribute results to the complete recorded runtime and topology, not to a
    GPU or model alone. Client/network bottlenecks and uncontrolled colocated
    workloads are limitations that must be disclosed.
15. Verify the closed artifact set before reporting completion. Never call an
    unverified, cancelled, partially failed, or all-skipped campaign conforming.

## Measurement definitions

- **TTFT:** client elapsed time from request start to the first non-empty text
  stream event.
- **E2E latency:** client elapsed time from request start through stream end.
- **TPOT:** `(E2E - TTFT) / (reported output tokens - 1)`; derived, not direct
  token timestamps.
- **Server-native generation tokens/s:** provider-reported generated tokens
  divided by provider-reported generation time. The protocol recomputes this
  value rather than trusting a provider's precomputed rate, and rejects it when
  the provider token count conflicts with usage.
- **Client-derived generation tokens/s:** `(reported output tokens - 1) /
  (E2E - TTFT)`. This is a transport-observed cross-check, not a replacement
  for valid server-native timing.
- **Server-native prompt tokens/s:** provider-reported prompt tokens divided by
  provider-reported prompt-processing time.
- **Request throughput:** successful requests divided by the measured wall-time
  window.
- **End-to-end token throughput:** provider-reported input or output tokens
  divided by the measured campaign window. It includes prompt processing,
  scheduling, transport, and generation and must not be interpreted as decode
  or generation speed.
- **Goodput:** successful requests satisfying the per-request TTFT, E2E,
  minimum-output, and input-token rules, divided by the measured window.
- **Client queue delay:** actual request start minus scheduled open-loop start.

Inter-chunk time is diagnostic only because one stream event is not necessarily
one token. All client times use the load generator's monotonic clock. Reports
publish the relative difference between server-native and client-derived
generation rates whenever both are available so timing collapse, buffering,
or incompatible provider semantics remain visible.

## Comparability and publication

Publish the plan and workload hashes, complete runtime descriptor, endpoint
topology, load-generator location/specification, block-level results, sample
counts, errors, SLOs, limitations, and verified bundle hash. Comparisons should
use the same client host and network path wherever possible. Report every
preregistered cell, including skipped and failed cells; do not select only the
best block or load point.

The initial reference plan includes smaller scaling points plus 128k and 256k
input contexts and requests up to 8k output tokens. A runtime needs at least
270,336 total tokens to execute 256k-input/8k-output cells; unsupported cells
are explicitly skipped rather than silently shortened.
