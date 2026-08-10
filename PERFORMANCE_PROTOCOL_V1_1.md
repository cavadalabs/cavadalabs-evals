# CavadaLabs LLM Serving Performance Protocol v1.1

## Status and scope

This historical-development snapshot defines reproducible, generation-only measurements for an
OpenAI-compatible streaming LLM endpoint. It covers latency, throughput,
capacity, long context, concurrency, token usage, failures, and optional cost.
It does not score response quality and does not control the inference engine.

A development run may be described as using “CavadaLabs LLM Serving
Performance Protocol v1.1” only when its verified bundle reports `completed`.
This is a procedural development claim, not a release, official result,
certification, capacity guarantee, or proof of safety.

No repository commit, tag, or ref contains this v1.1 snapshot. It is retained
only to interpret the active reduced development presets, which record
`plan_version = "1.0.0"` and `report_version = "1.0.0"`. Version 1.0 remains
the immutable commit-anchored historical contract and its bundles retain their
recorded version. New reference work uses version 2.

## Normative requirements

1. Validate the complete plan, hash-pinned workload, workload assets, runtime
   descriptor, and applicable system evidence before network access. Version
   changed plans/workloads and never alter a completed run.
2. Permit only public or synthetic, versioned, hash-pinned workloads. API
   credentials are read only from the named environment variable and never
   stored.
3. Run the inference engine outside this repository. Record immutable engine
   and model revisions, exact model identity, numeric format, quantization,
   accelerator identity/topology, tensor parallelism, maximum context,
   container or binary digest, load generator, network relationship, and a
   credential-free launch command.
4. Use streaming, temperature zero, provider usage reporting, and exact model
   identity. A missing/mismatched identity or missing token usage is an error.
5. Treat `context_tokens` as declared input tokens and `output_tokens` as the
   requested maximum generation. Skip cells whose sum exceeds the runtime's
   declared maximum context window.
6. In `iso-prompt` mode, send identical prompt material and report observed
   tokenizer differences. In `iso-token` mode, reject observations outside the
   preregistered token tolerance.
7. Preregister the prefix-cache policy as `diverse`, `shared`, or
   `unspecified`. A `diverse` campaign must derive a deterministic unique cache
   nonce from its seed and request identity; never claim cache diversity from
   prompt order alone. A commit-anchored v1.0 plan that omits this field is
   `unspecified`.
8. Keep warm-up observations separate. Execute repeated randomized blocks and
   preserve their order, requests, raw streaming events, transport evidence,
   errors, and per-request observations.
9. Closed-loop cells maintain bounded concurrent users. Open-loop cells issue
   requests at a preregistered offered rate using the declared `fixed` or
   `poisson` arrival distribution and preserved seed; they must report client
   queue delay and must not hide overload by converting to closed-loop behavior.
   A commit-anchored v1.0 plan that omits the distribution uses `fixed` arrivals.
10. Do not retry measured transport requests. A retry changes the workload and
    is therefore a separate observation, not recovery of the original sample.
11. Enforce preregistered request, token, duration, timeout, context, output,
    and in-flight limits. Preserve partial evidence on interruption and stop
    scheduling after a fatal identity or evidence mismatch.
12. Report TTFT, end-to-end latency, derived TPOT, derived decode tokens/second,
    request/input/output throughput, queue delay, error taxonomy, goodput, cost
    when priced, and p50/p90/p95/p99 distributions. Report bootstrap intervals
    for latency tails. A p99 gate is unresolved below its preregistered minimum
    observation count; warn when fewer than 1,000 observations support it. A
    commit-anchored v1.0 plan that omits the minimum retains its historical minimum of
    one and must retain the weak-resolution warning.
13. Apply aggregate SLO gates and per-request goodput thresholds separately. A
    completed campaign may fail its SLO; execution status and SLO result must
    never be conflated.
14. Compare only verified runs with identical protocol, plan, workload, and
    workload-asset hashes. Compare exact shared completed cells, and enumerate
    every skipped, errored, and non-shared cell for every runtime.
15. Attribute results to the complete recorded runtime, server, load generator,
    and topology, not to a GPU or model alone. Client/network bottlenecks and
    uncontrolled colocated workloads are limitations that must be disclosed.
16. Verify the closed artifact set and reconcile every planned, scheduled,
    accepted, response, warm-up, and measured outcome before reporting
    completion. Never call an unverified, cancelled, partially failed, or
    all-skipped campaign conforming.
17. This unanchored v1.1 development contract cannot support an official or
    rankable result. Use the current version 2 reference contract and satisfy
    every independent release gate for official-capable work.

## Measurement definitions

- **TTFT:** client elapsed time from request start to the first non-empty text
  stream event.
- **E2E latency:** client elapsed time from request start through stream end.
- **TPOT:** `(E2E - TTFT) / (reported output tokens - 1)`; derived, not direct
  token timestamps.
- **Decode tokens/s:** `(reported output tokens - 1) / (E2E - TTFT)`.
- **Request throughput:** successful requests divided by the measured wall-time
  window.
- **Token throughput:** provider-reported input or output tokens divided by the
  same window.
- **Goodput:** successful requests satisfying the per-request TTFT, E2E,
  minimum-output, and input-token rules, divided by the measured window.
- **Client queue delay:** actual request start minus scheduled open-loop start.

Inter-chunk time is diagnostic only because one stream event is not necessarily
one token. All times use the load generator's monotonic clock.

## Comparability and publication

Publish the exact protocol snapshot and hash, plan and workload hashes,
complete runtime descriptor, endpoint topology, load-generator
location/specification, block-level results, sample counts, errors, SLOs,
limitations, and verified bundle hash. Comparisons should use the same client
host and network path wherever possible. Report every preregistered cell,
including skipped and failed cells; do not select only the best block or load
point.

The reduced v1.1 development path retains the exact commit-anchored v1.0 preset
plans. Plans that omit the development extension fields use `unspecified`
prefix-cache policy, fixed open-loop arrivals, and a minimum p99 sample count of
one, with the weak-resolution warning preserved. The version 2 reference plan
defines the current larger, official-capable matrix separately.
