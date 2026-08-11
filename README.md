# CavadaLabs Evals

Local-first, auditable evidence engine for development text-behavior evaluations
and LLM serving benchmarks. The core uses Python's standard library so artifacts
do not depend on a vendor database or framework.

## Status

This is an active pre-1.0 developer preview. The supported surfaces are the
development-only text behavior engine and the generation-only `llm-serving-v2`
reference benchmark. The public results registry contains no accepted baseline
or independent reproduction. `official` means conformance to the versioned
protocol, never universal safety, correctness, or legal certification.

## Installation

Python 3.11 or newer is required. From a source checkout, install the locked
development environment with `uv sync --frozen`. Once a distribution is
published, install the dependency-free package with
`python -m pip install cavadalabs-evals`.

## Quick start

Prove the complete local artifact path first. This uses a temporary loopback
fixture, no credentials, and no external network:

```bash
uv sync --frozen
uv run cavada-eval doctor
uv run python examples/offline_demo.py
```

The printed bundle is a transport/protocol demonstration, not model-quality
evidence. For a real suite, create and validate a versioned copy before any
endpoint contact:

```bash
uv run cavada-eval init customer-support-v1
uv run cavada-eval validate suites/customer-support-v1
uv run cavada-eval estimate suites/customer-support-v1 --repetitions 3 --judge-repetitions 3
```

Run a development benchmark:

```bash
uv run cavada-eval run suites/cavada-core-assistant-text-v1 \
  --mode smoke \
  --endpoint http://127.0.0.1:8097/chat \
  --model-label local-model \
  --expected-model local-model-reported-id \
  --model-revision local-build-id \
  --judge-endpoint http://127.0.0.1:8013/v1 \
  --judge-model ministral-8b-judge \
  --expected-judge-model ministral-8b-judge \
  --judge-revision local-build-id \
  --max-cases 10
```

Use a versioned execution preset instead of choosing sample sizes and
repetitions manually:

```bash
uv run cavada-eval presets
uv run cavada-eval run suites/cavada-core-assistant-text-v1 \
  --preset quick \
  --endpoint http://127.0.0.1:8000/v1 \
  --model-label local-model \
  --expected-model local-model \
  --model-revision immutable-model-revision \
  --request-model local-model \
  --judge-endpoint http://127.0.0.1:8010/v1 \
  --judge-model local-judge \
  --expected-judge-model local-judge \
  --judge-revision immutable-judge-revision
```

`run` evaluates response behavior with suite metrics and judges. `perf run`
uses a separate generation-only workload and measures serving performance; it
does not score response correctness or safety.

| Behavior preset | Cases | Target / judge repetitions | Official eligibility |
| --- | ---: | ---: | --- |
| `smoke` | up to 25 | 1 / 1 | no |
| `quick` | up to 100 | 1 / 1 | no |
| `standard` | up to 1,000 | 2 / 2 | no |
| `reference` | all | 3 / 3 | only with every official gate |

Reduced behavior subsets are selected deterministically across categories,
risks, severities, languages, and splits without separating scenario groups.
Explicit CLI parameters may make a development preset stricter, but never turn
it into a reference or official result.

Useful commands:

```text
init doctor list program validate estimate run
judge-qualify pilot-audit compare verify promote export controls
retention-record
perf validate | perf run | perf compare | perf export
```

Run a generation-only serving benchmark against an externally managed engine:

```bash
uv run cavada-eval perf validate --preset reference \
  --runtime /secure/path/runtime.toml \
  --system-evidence /secure/path/system-evidence.json
uv run cavada-eval perf run /secure/path/runtime.toml --preset reference
```

Validation is offline. Performance commands accept only the current v2
`reference` preset. Follow the additional evidence and execution steps in
[docs/PERFORMANCE.md](docs/PERFORMANCE.md). The reference plan covers closed-loop
users, open-loop offered load, concurrency 1–64, input contexts through
128k/256k, and requested outputs through 8k. Its normative rules are in
[Performance Protocol v2](PERFORMANCE_PROTOCOL_V2.md). The commit-anchored
[v1.0 protocol](PERFORMANCE_PROTOCOL_V1_0.md), plans, workload, schemas, and
golden fixture remain byte-frozen for hash-only verification; current producer,
export, public-verification, and comparison paths do not accept v1.0.

Inference engines remain external. Client-side serving measurements do not
establish model quality, hardware utilization, or energy use.

API keys are read from named environment variables only. Endpoint credentials
and query values are never written to manifests. Official non-public data needs
a recorded external-destination authorization before it can reach an external
target or judge. Non-public official bundles also require a current storage
attestation covering encryption, immutability, access logging, retention, and
tested backup/restore. Every official run also requires hash-linked,
independently approved evidence for the exact qualified judge configuration.
Approved suites additionally carry hash-pinned calibration and independent
approval evidence. Official execution requires a current engagement record
hash-linked to the exact suite and SUT. Public export then requires a separate,
post-run release approval linked to the immutable bundle; status strings alone
cannot satisfy either gate.

```bash
uv run cavada-eval export runs/SUITE/RUN public.tar.gz --public \
  --engagement /restricted/engagement.json \
  --release-approval /restricted/release-approval.json
```

The public archive includes `public_release.json` with the bounded claim scope,
expiry, evidence hashes, decision statuses, and hashes of every exported file.
It does not expose restricted reviewer evidence. The engagement, approval, and
their referenced evidence files must remain together in their restricted
directories so every package-local SHA-256 can be checked.

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

Performance campaigns use a separate generation-only artifact set documented
in `docs/PERFORMANCE.md`; judge latency is never included in serving results.

## Security defaults

- released datasets and rubrics are immutable;
- official suites require pinned hashes, governance, calibration, independent
  review, a present and hash-verified semantic-contamination evidence file,
  network allowlists, clean Git
  state, and verified model revisions;
- referenced local assets are checked for path escape, symlinks, type mismatch,
  size, and active content; this trust-boundary validation is not a claim that
  media benchmark support is maintained;
- reports are static, escaped, self-contained, and contain no active JavaScript;
- official runs require an exact approved engagement; public exports require
  independent post-run statistical, security, privacy/legal, disclosure, and
  release decisions;
- automatic error reporting is disabled;
- custom suite Python is never executed directly.

Read [PROTOCOL.md](PROTOCOL.md), [SECURITY.md](SECURITY.md),
[IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md),
[OFFICIAL_EVALUATION_PROGRAM.md](OFFICIAL_EVALUATION_PROGRAM.md),
[program/POLICY.md](program/POLICY.md),
[program/SOURCE_POLICY.md](program/SOURCE_POLICY.md), and the `docs/` directory
before operating an official benchmark.

Community participation is governed by [CONTRIBUTING.md](CONTRIBUTING.md),
[GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and
[RESULTS_POLICY.md](RESULTS_POLICY.md). Repository publication does not make a
suite or result official. The first public push must also satisfy the
[publication inventory](docs/PUBLICATION_INVENTORY.md).

## Development verification

```bash
uv sync --frozen
uv lock --check
uv run ruff check .
uv run mypy src
uv run pytest
uv run python scripts/check_secrets.py
uv run python scripts/validate_results_registry.py
uv run python scripts/check_release.py
uv run cavada-eval perf validate --preset reference
uv build
uv run python scripts/check_distribution.py
uv run python scripts/generate_sbom.py --wheel dist/*.whl --output dist/sbom.cdx.json
uv run python scripts/generate_provenance.py
```

The Apache License 2.0 applies to source code. Every dataset, rubric, media
asset, and third-party benchmark keeps its own declared license and
redistribution terms.
