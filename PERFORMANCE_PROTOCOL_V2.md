# CavadaLabs LLM Serving Performance Protocol v2.0

## Status and scope

This protocol measures a complete LLM serving system under a versioned plan,
workload, runtime, load generator and network path. It covers latency,
throughput, open-loop load fidelity, failures, provider token usage and optional
cost. It does not establish response quality, safety, legal compliance,
hardware efficiency or universal deployment capacity.

A bundle conforms to this protocol only when its evidence is complete and its
semantic verifier succeeds. An open-loop cell whose load generator misses its
preregistered dispatch contract has status `invalid-loadgen`: its raw evidence
remains diagnostic, but it is not valid serving-system evidence and cannot pass
an SLO or contribute goodput.

Protocol v1.0 artifacts retain their original definitions and hash-only verifier
semantics. Version 2.0 applies only to plans that declare
`plan_version = "2.0.0"` and `profile = "llm-serving-v2"`.

This v2 artifact was amended before its first release: the repository preflight
found no tag, immutable run or published registry entry that referenced its
previous working-tree hash. Commit-anchored v1.0 artifacts remain byte-for-byte
frozen.

## Normative requirements

1. Validate the complete versioned, hash-pinned plan, workload, assets and
   runtime before creating a run or contacting an endpoint.
2. Never alter a released protocol, plan, workload or completed run. Preserve
   every version according to its original contract.
3. Use one monotonic load-generator clock and preserve, separately, every
   planned arrival, scheduler/worker start, effective transport dispatch, first
   non-empty text event and stream completion timestamp.
4. Preserve raw schedules, requests, streaming events, transport evidence,
   queueing, errors and terminal outcomes. Never retry a measured request
   silently.
5. Keep warm-up, closed-loop, open-loop, skipped, error and invalid-loadgen
   evidence separate. `invalid-loadgen` is not a model or server failure.
6. Closed-loop cells maintain bounded concurrent users. Open-loop cells follow
   their fixed or seeded Poisson schedule independently of response completion;
   never lower the offered rate or turn saturation into closed-loop behavior.
7. Report both contact latency, measured from dispatch, and scheduled latency,
   measured from planned arrival. Contact latency retains the endpoint and
   transport SLO diagnostic; open-loop goodput uses scheduled latency, and the
   final SLO verdict also requires a valid load generator.
8. For every open-loop cell report offered, dispatched and completed request
   counts and rates, dispatch-rate fidelity, dispatch-lag distribution and the
   number of completions inside the preregistered measurement window.
9. Apply the plan's load-generator gates before interpreting serving metrics.
   A cell is `invalid-loadgen` when dispatch-rate fidelity is below its minimum,
   dispatch-lag p95 exceeds its maximum, or any dispatch lag exceeds its
   absolute maximum.
10. An `invalid-loadgen` cell has `slo_passed = false`, zero goodput and an
    explicit failed-gate reason. Preserve its endpoint outcomes and contact
    latencies as invalid diagnostics; do not present them as capacity evidence.
11. Require exact model identity and provider-reported prompt/output token
    usage. Do not estimate missing official evidence.
12. Enforce preregistered request, token, duration, timeout, context, output and
    in-flight limits. Preserve partial evidence after interruption or failure.
13. Reconstruct schedule, dispatch lag, scheduled latency, rates,
    load-generator validity, SLO and goodput from raw evidence in both the
    restricted and public verifiers.
14. Compare only verified runs with identical protocol, plan, workload and
    exact shared cells. Never rank an `invalid-loadgen` cell.
15. Publish every measured, errored, skipped and invalid-loadgen cell. Keep the
    artifact set closed, immutable and verifiable offline.

## Measurement definitions

For an open-loop cell, let `T` be its preregistered measurement duration,
`window_start` its batch start and `window_end = window_start + T`.

- **Planned arrival:** `window_start + preregistered arrival offset`.
- **Effective dispatch:** the monotonic timestamp immediately before the
  transport opens the request.
- **First token:** the first non-empty text stream event.
- **Completion:** the terminal transport timestamp, including terminal errors.
- **Client queue (`client_queue_ms`):** `scheduler/worker start - planned
  arrival`; retained as a separate scheduler diagnostic with its historical
  meaning.
- **Dispatch lag (`dispatch_lag_ms`):** `effective transport dispatch - planned
  arrival`; this is the value used by the v2 load-generator validity gates.
- **Contact TTFT/E2E:** `first token - dispatch` and `completion - dispatch`.
- **Scheduled TTFT/E2E:** `first token - planned arrival` and `completion -
  planned arrival`.
- **Measurement window:** the preregistered arrival window `T`. Counts at
  exactly `window_end` are included; counts at `window_end + 1 ns` are not.
- **Throughput window:** elapsed monotonic wall time from `window_start` through
  the final terminal measured outcome, including drain after `T`.
- **Offered request rate:** scheduled arrivals divided by `T`.
- **Achieved dispatch rate:** contacted requests dispatched no later than
  `window_end`, divided by `T`.
- **Rate fidelity:** achieved dispatch rate divided by offered request rate.
- **Completions within the window:** terminal requests completed no later than
  `window_end`; report their count and rate separately from successful results.
- **Goodput:** successful requests satisfying the scheduled TTFT/E2E,
  minimum-output and token-match rules, divided by `T`, but always zero for an
  `invalid-loadgen` cell. A request scheduled within `T` remains in this
  numerator when it completes during drain.
- **Successful request throughput:** all successful measured requests divided
  by the throughput window.
- **Input/output token throughput:** provider-reported measured input/output
  token totals divided by the throughput window.

Closed-loop cells have no arrival window or offered-rate contract. Their
goodput uses contact TTFT/E2E, their throughput window is their actual elapsed
measurement time, and open-loop-only aggregates (offered/dispatched/completed
window counts and rates, scheduled latency, dispatch lag, rate fidelity and
load-generator gates) are `null`/N/A. `load_generator_valid` is `null` and
`load_generator_gates` is empty; no synthetic fidelity is published.

The reference v2 plan preregisters a minimum dispatch-rate fidelity of `0.98`,
a dispatch-lag p95 ceiling of `100 ms`, and an absolute dispatch-lag ceiling of
`1,000 ms`. These are load-generator validity gates, not serving SLOs.

## Publication and claims

Publish protocol and plan hashes, the configured offered load, observed
dispatch and completion rates, queue/dispatch-lag distributions, every failed
load-generator gate, endpoint errors, SLO results and bundle verification
instructions. Permitted wording is limited to observed serving-system behavior
under the exact recorded configuration. Do not attribute results solely to a
model or accelerator, and do not present invalid-loadgen observations as valid
serving performance.
