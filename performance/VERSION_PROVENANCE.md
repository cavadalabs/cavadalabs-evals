# Performance version provenance

This inventory records the offline Git/object audit performed on 2026-08-10.
It is evidence about this checkout, not a release announcement.

| Contract | Provenance status | Protocol SHA-256 | Plan schema | Manifest schema |
| --- | --- | --- | --- | --- |
| v1.0 | Historical and commit-anchored at `9fd83112f0fd62e7dd1832cb50eb1c4a3671cbd7`; the golden fixture is integrity-only, non-official, and non-rankable | `a754416f07c1a0f0436614543fdfa45dee95a2f20ab93116af1f4f47ea5ae97a` | `performance-plan.schema.json` — `a1cde1a4b3cfd7cc9907f0b5669505d322839d6efcbf452598699a04c6f150dc` | `performance-manifest.schema.json` — `c0ac65f3e0434c9793142c993a9da2abc2a66e8342243bab5493fca7bb5f3101` |
| v1.1 | Historical-development and unanchored: no local commit, tag, ref, or immutable run contains this snapshot; it is never official or rankable | `567a4156fe0745d63b4701a09b25a2213c65e707439fbc050f510230e62e1f0a` | `performance-plan-1.1.0.schema.json` — `7dfa0ad4cd786a74cfa309addec12068ad844a17e9c12afcf5a2ade8c9e4f290` | `performance-manifest-1.1.0.schema.json` — `b6c4843a09983824ec993ff9579e090d38cf7d2db3a4af9face0983e6df57f41` |
| v2.0 | Current development contract; no release anchor or benchmark result is claimed by this inventory | `de0797dc92944aab8a1e51e0e6d8e1a6ceb709f839eb80b669ec68d1c887b832` | `performance-plan-2.0.0.schema.json` — `718c5b44189cdcc31a344496fe349cde95859d5379b9fe47a7e0d0b5de33e4ea` | `performance-manifest-2.0.0.schema.json` — `f014118817e582c6cba25495db316386df75022a98000a8f586097b9a8ae5b2b` |

The v1.1 runner output deliberately records protocol `1.1.0` with plan and
report versions `1.0.0`. The plan schema contract `1.1.0` names the accepted
historical-development extension shape; it does not pretend that the recorded
legacy `plan_version` field changed. An unchanged commit-anchored v1.0 plan
validates only the frozen v1.0 plan schema. A development plan using any v1.1
extension (`prefix_cache_policy`, `open_loop_arrival_distribution`, or
`minimum_p99_observations`) validates only the v1.1 extension schema. A v2 plan
validates only the v2 schema. Manifest schemas are disjoint on the recorded
protocol version.

The v1.1 schema fixes the missing development contract; it does not retroactively
create release provenance. The v1.0 protocol, schemas, plan inputs, and golden
bundle bytes remain unchanged.
