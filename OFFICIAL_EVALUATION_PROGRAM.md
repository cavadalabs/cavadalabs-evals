# CavadaLabs Official Evaluation Program

This document describes the promotion path from repository-visible development
suites to independently reviewed protocol-conformance suites. The authoritative
machine-readable status is `program/registry.toml`.

`official` means conformance to the exact protocol, suite, system configuration,
population, evidence, and gates named in a result. It does not mean universal
correctness, safety, security, fairness, legal compliance, certification, or
accreditation.

## Current program status

As of 2026-08-07, no registered suite is official-capable.

| Suite or group | Registry status | Official-capable | Current boundary |
|---|---|---|---|
| `cavada-core-assistant-text-v1@0.8.1` | draft / development | no | Public synthetic EN/IT development data; no private holdout, independent labels, calibration, or approval. |
| `security-privacy-smoke-v1@0.1.1` | candidate | no | Synthetic smoke screening only; not representative or independently calibrated. |

The public result registry is empty. Test fixtures, mock endpoint runs, generated
reports, and development datasets are not official model results.

## Shared program rules

- Behavior runs follow `PROTOCOL.md`; new reference serving-performance runs
  follow [Performance Protocol v2](PERFORMANCE_PROTOCOL_V2.md). The historical
  [v1.0 protocol](PERFORMANCE_PROTOCOL_V1_0.md) and released inputs remain
  byte-frozen for hash-only verification of recorded bundles.
- Protocol, engine, schema, suite, dataset, rubric, judge, adapter, metric,
  report, and result versions remain independent.
- Released datasets, rubrics, plans, and workloads are immutable. Corrections
  create a new version and preserve the old artifact.
- Quality, safety, security, privacy, fairness, performance, and legal evidence
  remain separate. The program does not publish a universal combined score.
- Missing, invalid, expired, skipped, or unverifiable mandatory evidence blocks
  promotion; a disclaimer cannot substitute for evidence.
- Candidate, calibrated, or independently generated output cannot be relabeled
  as CavadaLabs-official without the applicable approval path.

The detailed lifecycle, compatibility, independence, complaints, appeals,
correction, revocation, and disclosure rules are in `program/POLICY.md`.

## Current development behavior suite

`cavada-core-assistant-text-v1@0.8.1` evaluates a fixed general-purpose text
assistant configuration in English and Italian. It excludes RAG, tools, MCP,
media, code execution, and professional fitness in high-impact domains.

Its active
`suites/cavada-core-assistant-text-v1/dataset-0.8.0.jsonl` contains 404 public
synthetic development cases representing 328 independent primary scenarios;
variants do not increase the analysis-unit count. A deterministic author-QA
ledger is archived at checkpoint `eb93846e40c4eca6c62d10ab8dbb7e654020987a`;
the data are public, share one authoring process, and are not representative,
independently reviewed, calibrated, or private holdout evidence.

Repository design artifacts include:

- `suites/cavada-core-assistant-text-v1/MEASUREMENT_SPEC.md` for the
  measurement boundary and allowed claims;
- `suites/cavada-core-assistant-text-v1/STATISTICAL_ANALYSIS_PLAN.md` for
  analysis units, intervals, comparisons, and preregistered gates;
- `suites/cavada-core-assistant-text-v1/case_blueprint.toml` and the
  development dataset cards for coverage and limitations;
- `suites/cavada-core-assistant-text-v1/LABEL_HANDBOOK.md` and reviewer fixtures
  for the future human-label process;
- `suites/cavada-core-assistant-text-v1/judge/qualification_blueprint.toml` for
  future judge qualification;
- `suites/cavada-core-assistant-text-v1/PILOT_PROTOCOL.md` for a future
  controlled multi-family pilot.

These files are specifications and templates. Their presence is not evidence
that independent review, calibration, pilot execution, or approval occurred.

## Promotion gate

Promotion of any suite to `approved` requires evidence for every applicable
item below, bound by hash and version to the exact suite and result:

1. A frozen measurement specification, statistical analysis plan, and claim
   boundary reviewed before target results are inspected.
2. Dataset provenance, rights, privacy classification, contamination analysis,
   representative-scope justification, private holdout controls, and immutable
   storage.
3. At least two qualified independent reviewers for subjective labels, with
   retained disagreements and separate adjudication where required.
4. Judge qualification for the exact identity, revision, prompt, rubric,
   response schema, parameters, repetitions, ensemble, and consensus policy.
5. Adequate sample size, uncertainty, threshold rationale, missing-evidence
   policy, multiple-comparison treatment, and independent statistical review.
6. Controlled pilots with unrelated model families and positive and negative
   controls, followed by a freeze that does not tune against the final holdout.
7. Applicable security, privacy/legal, disclosure, conflicts, authorization,
   storage, and release decisions made by accountable qualified people.
8. A clean reproducible build, verified immutable bundle, current release
   approval, organizational release identity, and independent reproduction.

Until every applicable item passes, the suite remains development, candidate,
or calibrated evidence and cannot support an official claim.

## Platform boundaries

The maintained benchmark surface is the text behavior engine and
OpenAI-compatible LLM serving under Performance Protocol v2. Media parsers and
capability validators are trust-boundary checks, not supported benchmark
modalities. Hardware telemetry, production storage and signing, sandboxed side
effects, and independently controlled reproduction infrastructure remain
external.

## Maintenance

Approved suites require an auditable schedule for result expiry, holdout and
canary rotation, judge requalification, contamination and
saturation monitoring, incidents, complaints, appeals, corrections,
revocations, and repeated independent reproduction. Changes create new
immutable versions; historical evidence is not overwritten.
