# Publishing performance results

Never publish a run directory. It contains the endpoint, API-key environment
name, runtime launch evidence, raw streaming responses, transport details, and
error messages.

Current official publications follow [Performance Protocol v2](../PERFORMANCE_PROTOCOL_V2.md).

## Development export

A completed, hash-valid, fully reconciled non-official run can be projected to
a public development bundle:

```bash
uv run cavada-eval perf export RUN_DIR public-performance.tar.gz
```

The export revalidates the immutable plan, frozen protocol snapshot, runtime, workload, assets,
cells, request/response/outcome reconciliation, summary, and optional system
evidence before creating the archive. It includes only selected observations,
numeric result tables, public system evidence, reproducibility inputs, and an
independently verifiable bundle. It is labeled `development`; it is not an
official result.

The public manifest records the evaluation start and finish times. Its token
and cost totals cover measured observations only (`includes_warmup=false`);
warm-up counts remain visible, but restricted warm-up responses and usage are
not published.

Verify after extraction:

```bash
mkdir public-performance
tar -xzf public-performance.tar.gz -C public-performance
uv run cavada-eval verify public-performance
```

`verify` checks both the closed file set and the result semantics. It reports
authenticity as `unverified` unless a trusted signature or registry entry is
available; a self-consistent archive alone does not establish who produced it.
The printed `report_html` path is safe to open because the report is rebuilt
only from the sanitized public projection. The restricted run directory is
never safe to publish.

The machine-readable terms have narrow meanings:

- `official` means the exact run and approval satisfy the named protocol; it
  is not certification.
- `rankable` means an official publication was eligible when recorded and is
  still current; expiry, withdrawal, or supersession removes current rankability
  without deleting history.
- `semantic_valid` means the verifier reconstructed the claims from the
  required evidence, not merely that file hashes matched.
- `authenticity` states what bound the evidence to a producer; `unverified` or
  `recorded-source-hashes-only` is not an identity attestation.
- `invalid-loadgen` is preserved load-generator invalidity, not a model or
  server failure and never capacity evidence.
- `N/A` means a field is not applicable in that context or its evidence is
  unavailable; the surrounding field identifies which case applies.

## Controlled offline contributor path

The following checkout-only smoke creates synthetic temporary artifacts. It
contacts no external endpoint and produces no publishable benchmark result:

```bash
FIXTURE_ROOT=$(mktemp -d tmp/performance-readiness.XXXXXX)
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run pytest -q \
  --basetemp "$FIXTURE_ROOT/public" \
  tests/test_performance_release.py::test_v2_closed_loop_public_projection_keeps_open_loop_aggregates_not_applicable
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run pytest -q \
  --basetemp "$FIXTURE_ROOT/compare" \
  tests/test_performance_comparison.py::test_performance_comparison_withholds_ratios_across_model_revisions
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run pytest -q \
  --basetemp "$FIXTURE_ROOT/registry" \
  tests/test_results_registry.py::test_registry_cli_resolves_the_exact_content_addressed_archive

PUBLIC_DIR=$(dirname "$(find "$FIXTURE_ROOT/public" -name public_manifest.json -print -quit)")
LEFT_RUN=$(dirname "$(find "$FIXTURE_ROOT/compare" -path '*/left/manifest.json' -print -quit)")
RIGHT_RUN=$(dirname "$(find "$FIXTURE_ROOT/compare" -path '*/right/manifest.json' -print -quit)")
REGISTRY=$(find "$FIXTURE_ROOT/registry" -path '*/results/registry.json' -print -quit)

uv run cavada-eval verify "$PUBLIC_DIR"
test -f "$PUBLIC_DIR/report.html" -a -f "$PUBLIC_DIR/report.pdf" -a -f "$PUBLIC_DIR/cells.csv"
uv run cavada-eval perf compare "$LEFT_RUN" "$RIGHT_RUN" --output "$FIXTURE_ROOT/comparison"
uv run cavada-eval verify "$FIXTURE_ROOT/comparison" --source-run "$LEFT_RUN" --source-run "$RIGHT_RUN"
uv run python scripts/validate_results_registry.py "$REGISTRY" \
  --previous tests/fixtures/results-registry-v1.json
```

The single-run and registry fixtures exercise Performance v2. The compatible
comparison pair is a controlled historical v1 fixture used only to exercise
the same verifier path; it is `legacy-hash-only`, non-official, and
non-rankable. Real v2 comparisons use the identical `perf compare` and
source-bound `verify` commands with two exact v2 runs.

## Official export

An official run additionally needs a current, independent post-run approval
bound to the exact immutable result:

```bash
uv run cavada-eval perf export RUN_DIR public-performance.tar.gz \
  --release-approval /restricted/release-approval.json
```

The approval is a JSON object with exactly these fields:

```json
{
  "release_version": "2.0.0",
  "release_id": "stable-release-id",
  "status": "approved",
  "run_id": "exact manifest run_id",
  "bundle_sha256": "64 lowercase hex characters",
  "manifest_sha256": "64 lowercase hex characters",
  "configuration_id": "exact cfg-sha256 identifier",
  "engagement_id": "exact run engagement ID",
  "engagement_sha256": "exact run engagement SHA-256",
  "execution_owner_id": "stable executor identity",
  "approver_id": "different qualified reviewer identity",
  "independent": true,
  "conflicts": [],
  "conflict_mitigation": "",
  "permitted_claims": [
    "Bounded LLM serving performance under the named protocol, plan, workload, runtime, hardware configuration, and network conditions."
  ],
  "limitations_acknowledged": true,
  "review_evidence": "review.txt",
  "review_evidence_sha256": "64 lowercase hex characters",
  "qualification_evidence": "qualification.txt",
  "qualification_evidence_sha256": "64 lowercase hex characters",
  "approved_at": "ISO-8601 time at or after run completion",
  "expires_at": "future ISO-8601 time"
}
```

Evidence paths are relative to the approval file, must remain inside that
restricted evidence package, and must match their SHA-256 values. The approver
must differ from the execution owner. The approval's engagement ID/hash and
execution owner must exactly match the run's byte-exact engagement and
execution-record snapshots, and its expiry cannot outlive the engagement.
Conflicts require a non-placeholder mitigation. The approval file is read once
and its digest is computed from those same bytes. It and its review evidence
stay restricted; the public manifest retains only their hashes, bounded
engagement ID, reviewer identity, permitted claim, and validity window.

Official means conforming to the named performance protocol. It does not mean
certified hardware, response quality, safety, legal compliance, energy use, or
universal deployment capacity.
