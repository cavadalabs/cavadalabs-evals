# Architecture

The trust boundary is the CavadaLabs artifact format, not a metric vendor.

```text
suite validation -> generation -> deterministic metrics -> optional engines
                 -> identity-blinded judges -> case aggregation -> gates
                 -> restricted/public reports -> bundle verification/signing
```

The protocol core owns schemas, lifecycle, status semantics, hashes, statistics,
gates, artifacts, reports, and verification. Target, judge, metric, external
benchmark, storage, and signing integrations are adapters. An adapter must
declare supported modalities and never silently transform unsupported content.

Filesystem storage is intentionally the first implementation. A future object
store must preserve create-once run IDs, append-only evidence, content hashes,
restricted/public separation, retention metadata, and WORM semantics. A service,
database, or distributed scheduler is justified only by measured multi-user or
throughput requirements.
