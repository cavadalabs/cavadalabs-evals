# Development dataset card 0.7.0

Status: draft development material; not approved benchmark evidence.

Superseded by version `0.8.0`; retained for reproducibility.

## Contents

- 404 synthetic cases: 202 public and 202 practice.
- 202 English (`en-US`) and 202 Italian (`it-IT`) cases.
- Ten modules with 36 cases each, plus 52 privacy, 44 security, and 56 safety
  cases.
- 216 answer, 44 abstain, 44 refuse, 88 safe-complete, and 12 redirect expected
  behaviors.
- 24 critical, 124 high, 200 medium, and 56 low severity cases.
- 44 domain-and-register shift probes, each linked to one in-distribution
  construct reference with the same category, language, locale, split, and
  expected behavior.

The shift set covers all ten modules in both languages and splits. Privacy has
four additional authorized-use neighbors so that every new refusal has a
matched benign case. The runner reports paired baseline and shifted pass rates,
their bootstrap interval, discordant outcomes, and an exact McNemar test. These
synthetic pairs test declared transformations; they do not establish real-world
out-of-distribution robustness or deployment representativeness.

## Provenance

The cases are deterministic CavadaLabs synthetic authoring produced from
`scripts/build_core_development_dataset.py`. No third-party benchmark text was
copied. Four base cases use reserved `example.test` placeholders and describe
no natural people. Independent authorship, native-language, and rights review
remain pending.

Version `0.7.0` supersedes `0.6.0` without modifying its dataset or rubric. All
identifiers and scenario groups are versioned. No result from this release is
official.

## Integrity

```console
uv run python scripts/build_core_development_dataset.py \
  suites/cavada-core-assistant-text-v1/dataset-0.7.0.jsonl \
  --suite-version 0.7.0 --check
uv run python scripts/audit_dataset_quality.py \
  suites/cavada-core-assistant-text-v1 \
  suites/cavada-core-assistant-text-v1/review/author-qa-0.7.0.json \
  --dataset dataset-0.7.0.jsonl --suite-version 0.7.0 --check
uv run cavada-eval validate suites/cavada-core-assistant-text-v1
uv run cavada-eval program
```

Dataset SHA-256 at creation:
`35db70ea9df7e819b667bd2534369ab68e1358b95e12680652eb3392930135ff`.

The author-QA ledger covers all 404 cases with zero automated errors, zero
refusal-neighbor gaps, and zero token-containment candidates. It explicitly
declares that it is not independent approval.

## Known limitations

- All 404 rows require independent human review; criteria are author-gold.
- All cases are repository-visible and assumed contaminated.
- There is no calibration split, private holdout, restricted adversarial
  holdout, holdout canary, or approved semantic-contamination study yet.
- Every category remains below the preregistered 80-case official minimum.
- Distribution-shift coverage is synthetic and construct-matched, not sampled
  from real deployments.
- Independent native-language and ambiguity review, embedding-based semantic
  analysis, and external statistical review remain pending. The suite's
  `dataset_integrity` gate is intentionally `pending`, so official validation
  fails until detector identity, revision, cross-split review, and report hash
  are approved and pinned.
- Results must be labeled development results and cannot support certification,
  legal compliance, universal correctness, safety, security, fairness, or
  production-fitness claims.
