# Repository capability and readiness status

Status snapshot: 2026-08-07. Package version: `0.3.0` (alpha).

This is a public capability map, not a certification checklist. A repository
mechanism is not evidence that a model, suite, deployment, or organization has
passed it. Current behavior is defined by the versioned protocols, schemas, and
code; external approvals cannot be completed by code or tests.

Status terms:

- **Available**: a repository implementation and automated checks exist.
- **Gated**: the repository validates evidence, but accountable external
  evidence is not present here.
- **Not demonstrated**: no accepted result or independent reproduction is
  registered in this repository.

## Current readiness

| Area | Repository status | Evidence and boundary |
|---|---|---|
| Protocol design | Available | `PROTOCOL.md`, current [Performance Protocol v2](PERFORMANCE_PROTOCOL_V2.md), and `AGENTS.md` define separate behavior and serving-performance protocols; commit-anchored [v1.0](PERFORMANCE_PROTOCOL_V1_0.md) remains byte-frozen for hash-only verification of recorded bundles. |
| Behavior execution | Available, externally gated for official use | `src/cavada_eval/runner.py`, `src/cavada_eval/protocol.py`, and schemas implement validation, deterministic-first evaluation, blinded judging, immutable run directories, evidence preservation, and fail-closed official checks. No suite in `program/registry.toml` is currently `official_capable`. |
| Statistical analysis | Available, externally gated | Distinct-case aggregation, Wilson intervals, and paired comparisons are implemented. Valid claims still require a frozen sampling plan, adequate data, qualified judges, and independent statistical review. |
| Serving performance | Available, externally gated | `src/cavada_eval/performance.py` implements validated closed/open-loop campaigns and exact-cell comparison under [Performance Protocol v2](PERFORMANCE_PROTOCOL_V2.md). Measurements are client-side serving evidence; calibrated utilization, power, energy, and production load-generator validation are absent. |
| Hardware evidence | Schema and validation available | `schemas/performance-system-evidence.schema.json` records system configuration. Self-reported configuration is not calibrated telemetry and does not justify attributing a result to a GPU alone. |
| Reports and exports | Available; presentation assurance not demonstrated | Behavior and performance runs can emit machine-readable artifacts, HTML, PDF, CSV/JSONL, and figures. Accessibility, visual quality, and publication suitability have not been independently audited. |
| Artifact integrity | Available; release identity gated | Bundles use a closed file set and SHA-256 verification; optional HMAC is local integrity evidence, not organizational release signing. Official public export has post-run approval gates. |
| Onboarding and packaging | Available; release gate blocked | The project has an installable wheel, CLI, examples, CI configuration, and distribution checks. A clean hosted release rehearsal and the external decisions in `docs/PUBLICATION_INVENTORY.md` are still required. |
| Public credibility | Not demonstrated | `results/registry.json` intentionally contains no accepted benchmark result or independent reproduction. |
| Publication | Gated | `scripts/check_release.py --release` fails closed while any required publication-inventory decision is `blocked`. Nothing in this status document authorizes publication. |

## Implemented safeguards

- Complete suite and performance-plan validation occurs before endpoint calls.
- Official behavior runs require exact source, suite, dataset, rubric, target,
  judge, authorization, applicable storage, and approval evidence.
- Deterministic hard failures precede and cannot be overridden by a judge.
- Target identity is withheld from judges; malformed judge output remains
  `invalid`, separate from target failure.
- Raw requests, responses, stream events, errors, invalid cases, and skipped
  cases are retained in restricted run evidence.
- Run directories and finalized bundles are not overwritten. Official behavior
  runs cannot be resumed; a failed official attempt requires a new run.
- Official pass-rate gates use their declared confidence-bound metric.
- Behavior comparisons require compatible verified bundles.
- Performance comparisons revalidate immutable inputs and compare exact shared
  cells from matching plan and workload hashes.
- Official public behavior and performance exports require a verified source
  bundle and a current approval bound to the exact artifacts and permitted
  claims. Development exports remain labeled non-official.
- Quality, safety, security, privacy, fairness, performance, and legal evidence
  remain separate; no combined compliance score is produced.

These safeguards describe code paths. Their effectiveness for a particular run
must be established by that run's verified evidence and by the required human
and organizational reviews.

## Current suite and result status

- `cavada-core-assistant-text-v1@0.8.1` is a draft development suite using the
  public synthetic dataset
  `suites/cavada-core-assistant-text-v1/dataset-0.8.0.jsonl`.
- `security-privacy-smoke-v1` is a candidate suite, not an official suite.
- Every registry entry currently has `official_capable = false`.
- The public results registry has no accepted baseline or independent
  reproduction. Repository fixtures and mock runs are test evidence, not model
  benchmark results.

## External evidence required before an official result

- Independently reviewed datasets, rubrics, labels, adjudication, contamination
  analysis, judge qualification, statistical plan, and thresholds.
- Lawful data rights, engagement authorization, privacy/legal applicability,
  transfer decisions, and accountable residual-risk acceptance.
- Restricted encrypted immutable storage and operational access, retention,
  backup, recovery, incident, deletion, and audit evidence.
- Independent security, methodology, disclosure, and release review.
- Organizational release identity, protected repository controls, immutable
  tags, and signed/timestamped provenance where claimed.
- For strict hardware or energy claims: calibrated synchronized collectors,
  validated network and load-generator capacity, and a frozen reference plan.

## Verification entry points

Run these from a clean checkout before treating a commit as a release candidate:

```console
uv sync --frozen
uv lock --check
uv run ruff check .
uv run mypy src
uv run pytest
uv run python scripts/check_secrets.py
uv run python scripts/check_release.py
uv run python scripts/validate_results_registry.py
uv run cavada-eval doctor
uv run cavada-eval program
uv run cavada-eval perf validate --preset reference
uv build
uv run python scripts/check_distribution.py
```

Passing these commands establishes repository checks for that exact commit. It
does not close the external gates above. The authoritative publication decision
is `docs/PUBLICATION_INVENTORY.md`; release validation must remain fail-closed
while that inventory contains a required `blocked` row.
