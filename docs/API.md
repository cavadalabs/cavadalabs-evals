# Python API

The CLI is the primary operator interface. The typed Python surface for embedded
use is deliberately small, but this pre-1.0 package does not yet promise API
stability:

```python
from cavada_eval.protocol import audit_suite, load_suite

suite = load_suite("suites/template")
print(audit_suite(suite))
```

`load_suite(path, official=True)` performs suite-local official validation. It
does not validate endpoint, environment, authorization, storage, or release
evidence; `run(..., official=True)` performs those checks and reloads the suite
before network access. `run(...)` requires explicit endpoint, identity,
revision, judge, repetition, budget, and evidence values and returns the unique
run directory.

`compare_runs(...)` accepts verified compatible behavior bundles.
`verify_bundle(...)` validates the closed artifact set, checksum file, and each
SHA-256. If an HMAC file is present, signer authentication requires the matching
shared key; an absent key leaves the signature unverified.

The dedicated serving API loads a versioned plan and runtime independently,
then calls `run_performance_campaign(plan, runtime, repo_root=...)`. Official
runs also pass `system_evidence_path=...` and `execution_record_path=...`; the
latter is validated and snapshotted before network access.
`compare_performance_runs(...)` accepts two or more verified campaigns with
identical protocol, plan, and workload evidence and exact shared cells. See
the current [Performance Protocol v2](../PERFORMANCE_PROTOCOL_V2.md) before
embedding these functions. The unanchored historical-development v1.1 contract remains available in
[Performance Protocol v1.1](../PERFORMANCE_PROTOCOL_V1_1.md).

Modules use strict type checking. All Python symbols, including the examples
above, may change before 1.0; prefer the CLI for automation. Protocol, schema,
report, adapter, metric, and suite versions remain independently pinned in
artifacts.
