# Development dataset card 0.8.0

Status: draft development material; not approved benchmark evidence.

## Contents and analysis units

- 404 synthetic evaluation rows: 202 public and 202 practice.
- 328 independent primary scenarios: 164 per split and 164 per language.
- 76 required variants: robustness/fairness pairs and benign refusal-boundary
  neighbors.
- 40 independent distribution-shift scenarios represented by 44 probes; four
  privacy scenarios contain an additional benign neighbor.
- Primary-scenario categories: 36 each for eight modules and 20 each for
  robustness and fairness-overrefusal.
- Primary expected behaviors: 184 answer, 44 abstain, 44 refuse, 44
  safe-complete, and 12 redirect.

Every row declares `scenario_role`. Each group has exactly one `primary`; each
`variant` references that primary. Gates, Wilson intervals, bootstrap samples,
and category counts use scenario groups. A failed required variant fails its
scenario, but no variant or model repetition increases statistical sample size.
Case-level results remain available as diagnostics.

The shift probes are linked to in-distribution construct references with the
same category, language, locale, split, and expected behavior. The runner
reports paired rates, a bootstrap interval, discordant outcomes, and exact
McNemar evidence. These synthetic pairs do not establish real-world
out-of-distribution robustness or deployment representativeness.

## Provenance

The cases are deterministic CavadaLabs synthetic authoring produced from
`scripts/build_core_development_dataset.py`. No third-party benchmark text was
copied. Four base cases use reserved `example.test` placeholders and describe
no natural people. Independent authorship, native-language, and rights review
remain pending.

Version `0.8.0` supersedes `0.7.0` without modifying its dataset or rubric. The
behavioral content is unchanged; this release adds explicit analysis-unit
metadata and fail-closed scenario aggregation. No result is official.

## Integrity

```console
uv run python scripts/build_core_development_dataset.py \
  suites/cavada-core-assistant-text-v1/dataset-0.8.0.jsonl \
  --suite-version 0.8.0 --check
uv run python scripts/audit_dataset_quality.py \
  suites/cavada-core-assistant-text-v1 \
  suites/cavada-core-assistant-text-v1/review/author-qa-0.8.0.json --check
uv run cavada-eval validate suites/cavada-core-assistant-text-v1
uv run cavada-eval program
```

Dataset SHA-256 at creation:
`f292e44def21de0ae81d317326578f2cf90d74dda2bd61477509ff67aef88dd3`.

The author-QA ledger covers all 404 rows and 328 scenarios with zero automated
errors, zero refusal-neighbor gaps, and zero token-containment candidates. It
explicitly declares that it is not independent approval.

## Known limitations

- All 404 rows require independent human review; criteria are author-gold.
- All cases are repository-visible and assumed contaminated.
- There is no calibration split, private holdout, restricted adversarial
  holdout, holdout canary, or approved semantic-contamination study yet.
- Every primary-scenario category remains below its preregistered official
  minimum.
- Distribution-shift coverage is synthetic and construct-matched, not sampled
  from real deployments.
- Independent native-language and ambiguity review, embedding-based semantic
  analysis, and external statistical review remain pending. The suite's
  `dataset_integrity` gate is intentionally `pending`.
- Results must be labeled development results and cannot support certification,
  legal compliance, universal correctness, safety, security, fairness, or
  production-fitness claims.
