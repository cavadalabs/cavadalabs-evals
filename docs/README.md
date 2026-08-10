# Documentation

Choose the shortest path for the work you are doing.

## Run an evaluation

1. Start with the credential-free [offline demo](../examples/README.md#offline-first-run).
2. Read the bounded claims and execution rules in [methodology](METHODOLOGY.md).
3. Use [operations](OPERATIONS.md) for real endpoints and [troubleshooting](TROUBLESHOOTING.md) when preflight fails.

## Benchmark LLM serving

1. Read the current normative [performance protocol v2](../PERFORMANCE_PROTOCOL_V2.md).
   The unanchored historical-development
   [v1.1 protocol](../PERFORMANCE_PROTOCOL_V1_1.md) and commit-anchored
   [v1.0 protocol](../PERFORMANCE_PROTOCOL_V1_0.md) apply only to bundles that
   record those versions.
2. Follow the operator workflow in [performance](PERFORMANCE.md).
3. Record server, accelerator, engine, load-generator, and network facts using [system evidence](SYSTEM_EVIDENCE.md).
4. Use [performance result publication](PERFORMANCE_RELEASE.md) to create a sanitized, verifiable export; never publish a run directory.

## Author a suite or adapter

- [Architecture](ARCHITECTURE.md) explains the artifact flow and trust boundaries.
- [Adapters](ADAPTERS.md) defines supported import and execution boundaries.
- [Multimodal](MULTIMODAL.md) lists capabilities that fail closed until an adapter supplies the required evidence.
- [Python API](API.md) documents the deliberately small embedded surface.

## Review, govern, and publish

- [Threat model](THREAT_MODEL.md) covers secrets, evidence integrity, endpoints, and artifact disclosure.
- [Compliance evidence](COMPLIANCE.md) remains separate from quality and safety scores.
- [Publication inventory](PUBLICATION_INVENTORY.md) is the current rights and redistribution gate.
- [Public release](PUBLIC_RELEASE.md) is the repository and package release procedure.
- [Results registry](../results/README.md) defines submissions, independent reproductions, and append-only corrections; it ships empty rather than inventing a baseline.

## Readiness status

- [Readiness assessment](FINAL_AUDIT.md) records the dated capability and release boundaries; current protocols, code, tests, and registries remain authoritative.

The repository is a pre-1.0 developer preview. `official` means conformity to
the named protocol and retained evidence, not certification or universal
fitness.
