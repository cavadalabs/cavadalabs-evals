# Operations

Use `doctor`, `validate`, and `estimate` before network access. Use `smoke` for
development, `regression` for paired changes, `redteam` for fixed adversarial
suites, `performance` for streaming/load evidence, `offline` for loopback-only
execution, and `official` only with an approved suite and clean committed source.

Set hard target-call, judge-call, elapsed-time, cost, concurrency, and request-
rate budgets. If a process is killed before bundle finalization, use `resume`
with the same suite, endpoints, revisions, parameters, and source commit. A
finalized bundle cannot be resumed or overwritten.

`load` and `soak` modes use the same bounded concurrency, request-rate, call,
token, cost, and elapsed-time ceilings. Mark cases with `performance_phase` as
`cold`, `warmup`, `steady`, or `soak`; phase distributions remain separate.

Store restricted bundles encrypted with least-privilege access and configured
retention. Store public exports separately. Verify after copying or restoring.
Exercise backup, restore, credential rotation, provider outage, judge outage,
incident, deletion, and legal-hold procedures outside the benchmark runner.
