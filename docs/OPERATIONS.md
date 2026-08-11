# Operations

Use `doctor`, `validate`, and `estimate` before a behavior run. `doctor` is a
local diagnostic, not a release or security approval. Use `run --preset ...`
for behavior quality and safety, and `perf run --preset ...` for generation-only
serving performance. Never describe one as the other.

Use behavior `smoke` for development, `regression` for paired changes,
`run --mode redteam` for a fixed adversarial suite, and `offline` for loopback-only
execution. Use `official` only with an approved suite, a clean matching source
checkout, and every required evidence record.

Target-call and judge-call limits are enforced before dispatch. Elapsed-time,
provider-token, and estimated-cost limits are run-validity and stop-scheduling
guards: a request already accepted by the provider can finish beyond them, and
its evidence is retained while the run fails closed. Use concurrency one plus
provider-side quotas when an operational spend ceiling must not admit in-flight
overshoot. Every run directory and run ID is immutable. Retain an interrupted
run as evidence and restart under a new run ID; resume attempts fail closed.

For serving load and soak work, use an immutable versioned performance plan.
Warm-up, closed-loop, open-loop, queueing, measured observations, errors, and
skipped cells remain separate. Never retry a measured request silently.

Store restricted bundles encrypted with least-privilege access and configured
retention. Store public exports separately. Verify after copying or restoring.
Exercise backup, restore, credential rotation, provider outage, judge outage,
incident, deletion, and legal-hold procedures outside the benchmark runner.
Repository schemas and attestations record these controls; they do not provision
or test the organization's storage and incident systems.
