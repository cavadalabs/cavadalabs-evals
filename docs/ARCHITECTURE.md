# Architecture

The trust boundary is the CavadaLabs artifact format, not a metric vendor.

```text
suite validation -> generation -> deterministic metrics -> optional engines
                 -> identity-blinded judges -> case aggregation -> gates
                 -> restricted/public artifacts -> bundle hashing/verification
```

The protocol core owns schemas, lifecycle, status semantics, hashes, statistics,
gates, artifacts, reports, and verification. Target and judge transports must
declare their capabilities and never silently transform unsupported content.

The built-in bundle mechanism provides a closed file set, SHA-256 hashes, and
optional shared-key HMAC integrity. It is not an organizational asymmetric
release-signing system. Public-release authority and production storage remain
outside the local filesystem implementation.

Filesystem storage is intentionally the first implementation. A future object
store must preserve create-once run IDs, append-only evidence, content hashes,
restricted/public separation, retention metadata, and WORM semantics. A service,
database, or distributed scheduler is justified only by measured multi-user or
throughput requirements.
