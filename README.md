# CavadaLabs Evals

CavadaLabs Evals turns a dataset, prompt, target, and evaluator into a
reconstructible client report. The normal path is small; the same core retains
raw evidence, verifies derived metrics, and keeps failures, execution errors,
invalid evaluations, and skipped cases separate.

## Install and run an offline eval

```bash
pip install 'cavadalabs-evals[reports]'
cavada-eval init customer-support-eval
cd customer-support-eval
cavada-eval plan eval.toml
cavada-eval run eval.toml
cavada-eval report runs/latest
cavada-eval verify runs/latest
```

`init` creates five files: `eval.toml`, `data/example.jsonl`, `custom.py`,
`README.md`, and `.gitignore`. The generated target is a trusted local callable,
so the complete quickstart is offline and needs no key.

For an OpenAI-compatible endpoint, the essential configuration is:

```toml
version = "1"
name = "customer-support"
profile = "client"
seed = 42

[dataset]
type = "jsonl"
path = "data/support.jsonl"
classification = "synthetic"

[[prompts]]
name = "baseline"
template = "{question}"

[[targets]]
name = "qwen-local"
type = "openai-compatible"
base_url = "http://127.0.0.1:8000/v1"
model = "qwen3"
revision = "local-build-1"
api_key_env = "LOCAL_API_KEY"

[[evaluators]]
type = "exact-match"
expected_field = "answer"

[run]
max_requests = 1000

[output]
directory = "runs"
formats = ["json", "html"]
```

`plan` materializes and validates the dataset, renders prompts, checks target
capabilities and request limits, and prints the exact matrix without contacting
an endpoint.

## Python API

```python
from cavada_eval import evaluate
from cavada_eval.evaluators import exact_match
from cavada_eval.targets import OpenAICompatibleTarget

result = evaluate(
    target=OpenAICompatibleTarget(
        base_url="http://127.0.0.1:8000/v1",
        model="qwen3",
        api_key_env="LOCAL_API_KEY",
    ),
    dataset="data/support.jsonl",
    prompt="{question}",
    evaluators=[exact_match("answer")],
)

print(result.path)
print(result.summary)
```

A Python iterable or factory can replace the file; a sync or async callable can
replace the endpoint or evaluator. Local factories are trusted code and are not
sandboxed.

## Prompt and target matrix

Add more `[[prompts]]` and `[[targets]]` tables to evaluate their Cartesian
product against the same frozen cases. Each cell gets a deterministic identity,
its own canonical behavior bundle, a confidence interval, and paired comparison
against compatible cells. Cavada does not collapse the matrix into a composite
AI score.

Each completed experiment contains `plan.snapshot.toml`,
`plan.normalized.json`, `dataset.snapshot.jsonl`, cell evidence under `cells/`,
`summary.json`, `verification.json`, and a standalone `report.html`.

Start with the [quickstart](docs/QUICKSTART.md), then see the
[configuration reference](docs/CONFIGURATION.md), [Python API](docs/PYTHON_API.md),
and [client workflows](docs/CLIENT_WORKFLOWS.md). Versioned suites, qualification,
approvals, publication, and registries remain available as
[advanced/official workflows](docs/OPERATIONS.md).

## Status

The engine is an active pre-1.0 developer preview. Included datasets are
synthetic templates and smoke tests, not representative or official benchmark
suites. `official` means conformance to the versioned protocol, never universal
safety, correctness, or legal certification.

The 0.4 development line is software-conformance-ready for behavior evidence:
its official engine can reconstruct a closed judge-qualification package and
separately report bundle integrity, reconstructed semantics, and requested
assurance. This is readiness of the verification software, not approval of a
suite or result. The repository currently has:

| Evidence state | Current public count |
| --- | ---: |
| Software conformance-ready engine | 1 |
| Real approved suites | 0 |
| Real official runs | 0 |
| Public-release approvals | 0 |
| Independent reproductions | 0 |
| Verified registry records | 0 |

Accordingly, `doctor` reports `structural_ready=true`,
`official_engine_ready=true`, `verified_official_suite_count=0`, and
`official_ready=false`. The synthetic offline `conformance-fixture` proves that
the machinery executes; it is non-rankable, authorizes no model or benchmark
claim, and is not a substitute for any state in the table above.

Private AI remains isolated outside the canonical 0.4 line. Blinded pairwise
output judging with retained A/B and B/A decisions is unsupported. Serving
performance remains a separate development protocol; performance official
assurance is outside this milestone.

## Advanced: create and validate a versioned suite

```bash
uv sync
uv run cavada-eval doctor
uv run cavada-eval init customer-support-v1 --suites-root suites
uv run cavada-eval validate suites/customer-support-v1
uv run cavada-eval estimate suites/customer-support-v1 --repetitions 3 --judge-repetitions 3
```

## Use a real endpoint

Installed wheels keep the core dependency-free. Professional PDF generation is
an explicit capability: install `cavadalabs-evals[reports]`. A run that requires
PDF evidence fails before contacting an endpoint when that extra is unavailable;
the framework never emits a placeholder PDF.

Run a development benchmark:

```bash
uv run cavada-eval run suites/security-privacy-smoke-v1 \
  --preset smoke \
  --endpoint http://127.0.0.1:8000/v1 \
  --model-label local-model \
  --expected-model local-model \
  --model-revision immutable-model-revision \
  --request-model local-model \
  --judge-endpoint http://127.0.0.1:8010/v1 \
  --judge-model independent-judge \
  --expected-judge-model independent-judge \
  --judge-revision immutable-judge-revision
```

Use a versioned execution preset instead of choosing sample sizes and
repetitions manually:

```bash
uv run cavada-eval presets
uv run cavada-eval run /path/to/versioned-suite \
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

For security work, start with the candidate smoke suite above and follow the
[security evaluation guide](docs/SECURITY_EVALUATION.md). The guide separates
prompt-observable behavior from supply-chain, access-control, deployment, and
operational evidence so a passing model response is never reported as complete
system security.

| Preset | Behavior cases | Target / judge repetitions | Performance scope | Official eligibility |
| --- | ---: | ---: | --- | --- |
| `smoke` | up to 25 | 1 / 1 | endpoint check | no |
| `quick` | up to 100 | 1 / 1 | 98 requests, 12 cells | no |
| `standard` | up to 1,000 | 2 / 2 | 825 requests, 34 cells | no |
| `reference` (`full`) | all | 3 / 3 | complete reference plan | only with every official gate |

Reduced behavior subsets are selected deterministically across categories,
risks, severities, languages, and splits without separating scenario groups.
Explicit CLI parameters may make a development preset stricter, but never turn
it into a reference or official result.

Main client commands:

```text
init plan run benchmark compare report verify doctor
```

Advanced suite and protocol commands remain available for compatibility:

```text
list profiles program validate audit estimate resume redteam
annotations annotations-ingest annotations-agreement annotations-adjudicate
judge-qualify judge-qualify-package pilot-audit promote export controls
import-external retention-record
perf validate | perf run | perf compare
```

`compare` performs paired statistical comparison of already evaluated outcomes.
Blinded output judging with retained A/B and B/A orders is not supported.

Run a generation-only serving benchmark against an externally managed engine:

```bash
uv run cavada-eval perf validate performance/plans/llm-serving-v1.toml \
  --runtime /secure/path/runtime.toml
uv run cavada-eval perf run performance/plans/llm-serving-v1.toml \
  /secure/path/runtime.toml

# Or select the immutable built-in plan by preset:
uv run cavada-eval perf run /secure/path/runtime.toml --preset quick
```

The versioned plan covers closed-loop users, open-loop offered load, concurrency
1–64, input contexts through 128k/256k, and requested outputs through 8k. See
[PERFORMANCE_PROTOCOL.md](PERFORMANCE_PROTOCOL.md) and
[docs/PERFORMANCE.md](docs/PERFORMANCE.md). Inference engines remain external.

API keys are read from named environment variables only. Endpoint credentials
and query values are never written to manifests. Official non-public data needs
a recorded external-destination authorization before it can reach an external
target or judge. Non-public official bundles also require a current storage
attestation covering encryption, immutability, access logging, retention, and
tested backup/restore. Every official run also requires hash-linked,
independently approved evidence for the exact qualified judge configuration.
That evidence is a strict, closed, content-addressed package containing the
qualification run bundle, corpus and support bytes, blueprint, approvals,
recorded judge evidence, and approver-qualification evidence. Verification
recalculates qualification metrics and gates from those bytes; fields such as
`passed=true` are never accepted as proof. The qualification run receives base
integrity and semantic verification without recursively requiring its own
official judge qualification, after which qualification-specific assurance is
applied.

Build the production package from a closed staging tree containing
`source-suite/`, `corpus/`, `run/`, `qualification/`, and the referenced
reviewer evidence. The command publishes only after canonical reconstruction:

```bash
uv run cavada-eval judge-qualify-package /secure/qualification-staging \
  /secure/judge-qualification-evidence
```

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

The still-empty results registry also has a strict v2 format for future public
records. A v2 record points to an exact deterministic, content-addressed public
evidence tar and is checked by the same behavior and release verifiers. Records
and lifecycle events are append-only; withdrawal, correction, supersession, and
expiry preserve prior evidence. A conformance record must remain non-rankable
and claim-free. Registry v1 remains readable and intentionally empty.

Offline verification checks the archive bytes, closed file set, hashes,
semantic reconstruction, release binding, and expected attestation subject.
For a real public official record, cryptographic provenance verification is a
separate online step using GitHub Artifact Attestations and `gh attestation
verify`. HMAC bundle signatures are internal shared-secret integrity controls;
they are not public signatures and do not replace GitHub/Sigstore verification.

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
engine_results.jsonl          reserved; non-empty engine runs are not M1-verifiable
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
signature.json                optional internal HMAC integrity control
verification.json             integrity, semantic and assurance verification
```

`events.jsonl` is bounded diagnostic progress evidence only. It is integrity
checked but is not used for scores, claims, public export, or ranking, because
concurrent event order is not a semantic input. Non-empty DeepEval metric-engine
behavior runs currently fail before network access: their outputs do not yet
have canonical semantic reconstruction and are therefore unsupported in M1.

Performance campaigns use a separate generation-only artifact set documented
in `docs/PERFORMANCE.md`; judge latency is never included in serving results.

## Security defaults

- released datasets and rubrics are immutable;
- official suites require pinned hashes, governance, calibration, independent
  review, a present and hash-verified semantic-contamination evidence file,
  network allowlists, clean Git
  state, and verified model revisions;
- local media is checked for path escape, symlinks, type mismatch, size, image
  pixels, WAV duration, active file formats, and active PDF content;
- reports are static, escaped, self-contained, and contain no active JavaScript;
- official runs require an exact approved engagement; public exports require
  independent post-run statistical, security, privacy/legal, disclosure, and
  release decisions;
- optional DeepEval telemetry, dotenv loading, legacy key files, update checks,
  error reporting, and cloud synchronization are disabled before import;
- custom suite Python is never executed directly.

Read [PROTOCOL.md](PROTOCOL.md), [SECURITY.md](SECURITY.md),
[IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md),
[OFFICIAL_EVALUATION_PROGRAM.md](OFFICIAL_EVALUATION_PROGRAM.md),
[program/POLICY.md](program/POLICY.md),
[program/SOURCE_POLICY.md](program/SOURCE_POLICY.md), and the `docs/` directory
before operating an official benchmark.

Community participation is governed by [CONTRIBUTING.md](CONTRIBUTING.md),
[GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and
[RESULTS_POLICY.md](RESULTS_POLICY.md). See [ROADMAP.md](ROADMAP.md) for the
short Now / Next / Later plan. Repository publication does not make a
suite or result official. The first public push must also satisfy the
[publication inventory](docs/PUBLICATION_INVENTORY.md).

## Development verification

```bash
uv run ruff check .
uv run mypy src
uv run pytest
uv run python scripts/generate_sbom.py --output dist/sbom.cdx.json
uv build
uv run python scripts/generate_provenance.py
```

The Apache License 2.0 applies to source code and repository-authored synthetic
assets unless a file declares otherwise. Every third-party benchmark keeps its
own license and redistribution terms.
