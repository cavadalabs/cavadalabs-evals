# Public results registry

`registry.json` is the version 2 machine-readable index of public results,
independent reproductions, and signed corrections. It is intentionally empty:
this repository ships no sample score and makes no public performance claim.

The registry is evidence, not an approval mechanism. A result may use
`assurance: "official"` only after the applicable post-run release process has
produced matching public evidence. Performance v2 entries follow the current
[Performance Protocol v2](../PERFORMANCE_PROTOCOL_V2.md). Behavior entries bind `public_release.json`,
engagement, decisions, claims, and validity. Version 2 performance entries bind
the sanitized public archive, bundle, manifest, restricted source hashes, and
exact independent approval recorded by `perf export`. The immutable `rankable`
field records eligibility at publication; effective rankability additionally
requires that the record is unexpired, not withdrawn, and not superseded.
Performance results are eligible only when the verified publication is
official, completed, and contains no errored or `invalid-loadgen` measured
cell. A development publication remains non-official and non-rankable, retains
its complete limitations, and cannot carry release evidence or make an
official claim.

## Submit a result

1. Publish only a sanitized, immutable behavior or performance export at a
   stable HTTPS URL. Never publish a restricted run directory.
2. Append one schema-valid record without changing earlier records. Copy
   compatibility and release fields from the verified export, never from its
   human-readable report.
3. For every version 2 performance record, place the immutable public archive at
   `results/artifacts/<archive-sha256>.tar.gz`, or pass an explicit
   `--artifact RESULT_ID=ARCHIVE` mapping. The validator does not download URLs.
4. Run the validator against both the proposed and previous registries. A pull
   request must include the bundle-verifier result, declared conflicts and
   limitations, and the immutable archive SHA-256.

Maintainers verify evidence and artifact availability. An independent
reproduction is a separate result with separate evaluator control; review of a
submission is not itself a reproduction.

For performance v2, `evaluated_system` is exactly
`<runtime.expected_model> on <runtime.engine>`. The measurement identity is
`performance-publication`, version `2.0.0`, with the SHA-256 of
`schemas/performance-publication-2.0.0.schema.json`. `conditions_sha256` is the
public manifest's system-evidence SHA-256, or the SHA-256 of the JSON literal
`null` when system evidence is absent.

## Exact reproductions

Every result records one exact compatibility projection: protocol, benchmark,
inputs, measurement contract, parameters, declared test conditions, and source
commit. These values are copied from immutable run evidence, never reconstructed
from a report. A reproduction must repeat that object field-for-field, bind the
original bundle SHA-256, publish a distinct bundle, and include independently
controlled evaluator, conflict, comparison, and attestation evidence. A
different compatibility projection is a new result, not a reproduction.

## Corrections

Published records are append-only. Never edit, reorder, or remove an existing
result, reproduction, or correction. Append a signed `notice`, `withdraw`, or
`supersede` record; a supersession names its replacement while preserving both
artifacts. Expiry remains in the historical record and automatically prevents
current ranking without rewriting evidence. The validator reports the
effective current rankable result IDs after structural and semantic
verification.

Validate semantic links and claim rules with:

```bash
uv run python scripts/validate_results_registry.py
```

When changing a published registry, also supply the previous released file:

```bash
uv run python scripts/validate_results_registry.py \
  --previous path/to/previous-registry.json
```

CI and release validation perform this comparison automatically and resolve
content-addressed archives from `results/artifacts/`. An explicit `--artifact`
mapping is useful when reviewing a candidate archive outside that directory.

The byte-identical empty version 1 registry is preserved at
`tests/fixtures/results-registry-v1.json`, and its frozen shape remains
`schemas/results-registry.schema.json`. Because it contained no records, the
canonical index made a one-time migration to version 2; a non-empty version 1
registry cannot use that exception. Version 2 is defined by
`schemas/results-registry-2.0.0.schema.json`. Validation dispatches on
`registry_version`. For version 2 performance records it hashes the supplied
archive bytes, safely stages the closed bundle, runs the public semantic
verifier, and checks the registry projection against the exact manifest,
release, status, cells, source, and limitations.
