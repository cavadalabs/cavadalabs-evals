# CavadaLabs Evals

Local-first, auditable evaluation protocol for text, RAG, structured outputs,
conversations, agents, tools, images, audio, video, and documents. The core uses
Python's standard library; optional metric engines remain adapters so historical
artifacts do not depend on a vendor database or framework.

## Status

The engine is an active pre-1.0 implementation. The MEMO4345 suite remains
`candidate`; it cannot produce an official result until independent calibration
and the required governance evidence exist. `official` means conformance to the
versioned protocol, never universal safety, correctness, or legal certification.

## Quick start

```bash
uv sync
uv run cavada-eval doctor
uv run cavada-eval init customer-support-v1
uv run cavada-eval validate suites/customer-support-v1
uv run cavada-eval estimate suites/customer-support-v1 --repetitions 3 --judge-repetitions 3
```

Run a development benchmark:

```bash
uv run cavada-eval run suites/memo4345-v1 \
  --mode smoke \
  --endpoint http://127.0.0.1:8097/chat \
  --model-label ministral-14b \
  --expected-model ministral-3-14b-vision-local \
  --model-revision local-build-id \
  --judge-endpoint http://127.0.0.1:8013/v1 \
  --judge-model ministral-8b-judge \
  --expected-judge-model ministral-8b-judge \
  --judge-revision local-build-id \
  --max-cases 10
```

Useful commands:

```text
init doctor list profiles program validate audit estimate run resume redteam
annotations annotations-ingest annotations-agreement annotations-adjudicate
judge-qualify pilot-audit compare pairwise report verify promote export controls
import-external retention-record
```

API keys are read from named environment variables only. Endpoint credentials
and query values are never written to manifests. Official non-public data needs
a recorded external-destination authorization before it can reach an external
target or judge. Non-public official bundles also require a current storage
attestation covering encryption, immutability, access logging, retention, and
tested backup/restore. Every official run also requires hash-linked,
independently approved evidence for the exact qualified judge configuration.
Approved suites additionally carry hash-pinned calibration and independent
approval evidence; a status string alone cannot satisfy the release gate.

## Artifacts

Final runs contain restricted evidence and sanitized public reports:

```text
manifest.json                 protocol, suite, SUT, judge, source and environment
protocol_snapshot.md          normative protocol used by the run
suite_snapshot.toml           exact suite configuration
dataset_card.md               governance and coverage
asset_inventory.json          content hashes and safe media metadata
requests.jsonl                restricted request ledger
raw_responses.jsonl           restricted raw SUT outputs
judgments.jsonl               restricted raw judge evidence
engine_results.jsonl          optional metric-engine evidence
case_results.jsonl            observation results
metrics.json                  aggregate statistics, performance and gates
category_results.csv          tabular category results
failures.jsonl                non-pass evidence
summary.json                  report data
junit.xml                     CI export
report.html / report.pdf      restricted reports
report_public.html / .pdf     sanitized reports
figures/*.svg                 accessible static charts
bundle.json / checksums.txt   content-addressed bundle
signature.json                optional HMAC signature
verification.json             final integrity verification
```

## Security defaults

- released datasets and rubrics are immutable;
- official suites require pinned hashes, governance, calibration, independent
  review, a present and hash-verified semantic-contamination evidence file,
  network allowlists, clean Git
  state, and verified model revisions;
- local media is checked for path escape, symlinks, type mismatch, size, image
  pixels, WAV duration, active file formats, and active PDF content;
- reports are static, escaped, self-contained, and contain no active JavaScript;
- optional DeepEval telemetry, dotenv loading, legacy key files, update checks,
  error reporting, and cloud synchronization are disabled before import;
- custom suite Python is never executed directly.

Read [PROTOCOL.md](PROTOCOL.md), [SECURITY.md](SECURITY.md),
[IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md),
[OFFICIAL_EVALUATION_PROGRAM.md](OFFICIAL_EVALUATION_PROGRAM.md),
[program/POLICY.md](program/POLICY.md),
[program/SOURCE_POLICY.md](program/SOURCE_POLICY.md), and the `docs/` directory
before operating an official benchmark.

## Development verification

```bash
uv run ruff check .
uv run mypy src
uv run pytest
uv run python scripts/generate_sbom.py --output dist/sbom.cdx.json
uv build
uv run python scripts/generate_provenance.py
```

The MIT license applies to source code. Every dataset, rubric, media asset, and
third-party benchmark keeps its own declared license and redistribution terms.
