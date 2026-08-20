# Python API

## Offline demo JSON contract

`cavada-eval demo` writes one JSON object to standard output and exits with
status 0 only after producing a passing, verified local bundle. It never makes
an external network request and never represents an official benchmark.

Stable fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `status` | string | `passed` after the demo and bundle verification succeed. |
| `official` | boolean | Always `false`; the fixture is onboarding material. |
| `external_network_used` | boolean | Always `false`; the judge uses loopback only. |
| `verification.valid` | boolean | Whether integrity, reconstructed behavior semantics, and declared assurance all verify. |
| `verification.integrity_valid` | boolean | Whether the closed file set, hashes, identity envelope, and available internal HMAC verify. |
| `verification.semantic_valid` | boolean | Whether results, metrics, gates, ledgers, and derived reports reconstruct from preserved bytes. |
| `verification.assurance_valid` | boolean | Whether the declared candidate or official assurance policy is satisfied. |
| `verification.failures` | array of strings | Combined failures; empty on success. |
| `verification.signature` | string | `absent`, `unverified`, `valid`, or `invalid`. |

Informative fields are local absolute paths and may change on every run:
`run`, `report`, `metrics`, and `failures`. `verification.files` is the current
number of files covered by the bundle and may change as report contents evolve.

Current example, with paths shortened for readability:

```json
{
  "status": "passed",
  "official": false,
  "external_network_used": false,
  "run": "/work/runs/demo-v1/<run-id>",
  "report": "/work/runs/demo-v1/<run-id>/report_public.html",
  "metrics": "/work/runs/demo-v1/<run-id>/metrics.json",
  "failures": "/work/runs/demo-v1/<run-id>/failures.jsonl",
  "verification": {
    "valid": true,
    "integrity_valid": true,
    "semantic_valid": true,
    "assurance_valid": true,
    "integrity_failures": [],
    "semantic_failures": [],
    "assurance_failures": [],
    "failures": [],
    "signature": "absent",
    "files": 32
  }
}
```

Consumers should branch only on the stable fields and treat paths and file
counts as run-specific values.

The CLI is the stable operator interface. The typed Python surface for embedded
use is deliberately small:

```python
from pathlib import Path

from cavada_eval.behavior_verify import verify_behavior_run
from cavada_eval.comparison import compare_runs
from cavada_eval.performance import (
    compare_performance_runs,
    load_performance_plan,
    load_performance_runtime,
    run_performance_campaign,
)
from cavada_eval.protocol import audit_suite, load_suite
from cavada_eval.runner import run

suite = load_suite("suites/example")
print(audit_suite(suite))
verification = verify_behavior_run(Path("runs/example/run-id"))
```

`load_suite(path, official=True)` performs all official preflight validation
before network access. `run(...)` requires explicit endpoint, identity,
revision, judge, repetition, budget, authorization, and official-engagement
values; it returns the
immutable run directory. `compare_runs(...)` accepts only verified compatible
bundles. `verify_behavior_run(...)` uses the canonical integrity, semantic, and
assurance verifier. The lower-level `artifacts.verify_bundle(...)` checks only
the closed artifact set, checksum file, optional internal HMAC, and SHA-256s;
it must not be used to accept behavior claims.

The dedicated serving API loads a versioned plan and runtime independently,
then calls `run_performance_campaign(plan, runtime, repo_root=...)`.
`compare_performance_runs(...)` accepts two or more verified campaigns with
identical plan/workload hashes and exact shared cells. See
`PERFORMANCE_PROTOCOL.md` before embedding these functions.

Modules use strict type checking, but pre-1.0 symbols outside these entry points
may change between engine minor versions. Protocol, schema, report, adapter,
metric, and suite versions remain independently pinned in artifacts.
