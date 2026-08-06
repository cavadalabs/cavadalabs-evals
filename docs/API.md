# Python API

The CLI is the stable operator interface. The typed Python surface for embedded
use is deliberately small:

```python
from pathlib import Path

from cavada_eval.artifacts import verify_bundle
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
verification = verify_bundle(Path("runs/example/run-id"))
```

`load_suite(path, official=True)` performs all official preflight validation
before network access. `run(...)` requires explicit endpoint, identity,
revision, judge, repetition, budget, authorization, and official-engagement
values; it returns the
immutable run directory. `compare_runs(...)` accepts only verified compatible
bundles. `verify_bundle(...)` validates the closed artifact set, checksum file,
optional HMAC signature, and every SHA-256.

The dedicated serving API loads a versioned plan and runtime independently,
then calls `run_performance_campaign(plan, runtime, repo_root=...)`.
`compare_performance_runs(...)` accepts two or more verified campaigns with
identical plan/workload hashes and exact shared cells. See
`PERFORMANCE_PROTOCOL.md` before embedding these functions.

Modules use strict type checking, but pre-1.0 symbols outside these entry points
may change between engine minor versions. Protocol, schema, report, adapter,
metric, and suite versions remain independently pinned in artifacts.
