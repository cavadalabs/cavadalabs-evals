# Development dataset card 0.6.0

Status: draft development material; not approved benchmark evidence.

Superseded by version `0.7.0`; retained for reproducibility.

## Contents

- 360 synthetic cases: 180 public and 180 practice.
- 180 English (`en-US`) and 180 Italian (`it-IT`) cases.
- 32 base cases in each module, plus 12 privacy, 8 security, and 20 safety
  benign refusal-boundary cases.
- 192 answer, 40 abstain, 40 refuse, 80 safe-complete, and 8 redirect expected
  behaviors.
- 24 critical, 112 high, 168 medium, and 56 low severity cases.

Each of the 40 refusal cases now has a matched benign neighbor in the same
scenario group. The pair roles are `restricted` and `benign`, covering purpose
limitation, tenant boundaries, sensitive inference, hidden-instruction
disclosure, social engineering, violence, wrongdoing, sexual content involving
minors, hate, and weapons. This supports bounded over-refusal measurement; it
does not establish population fairness or universal safety.

## Provenance

The cases are deterministic CavadaLabs synthetic authoring produced from
`scripts/build_core_development_dataset.py`. No third-party benchmark text was
copied. Four base cases use reserved `example.test` placeholders and describe
no natural people. Independent authorship, native-language, and rights review
remain pending.

Version `0.6.0` supersedes `0.5.1` without modifying it. All identifiers and
scenario groups are versioned. No result from this release is official.

## Integrity

```console
uv run python scripts/build_core_development_dataset.py \
  suites/cavada-core-assistant-text-v1/dataset-0.6.0.jsonl \
  --suite-version 0.6.0 --check
uv run python scripts/audit_dataset_quality.py \
  suites/cavada-core-assistant-text-v1 \
  suites/cavada-core-assistant-text-v1/review/author-qa-0.6.0.json \
  --dataset dataset-0.6.0.jsonl --suite-version 0.6.0 --check
uv run cavada-eval validate suites/cavada-core-assistant-text-v1
uv run cavada-eval program
```

Dataset SHA-256 at creation:
`628a00db335d8c3133fc9b742ae9b8e1f68bb2ef813aaf6ee55d1ca2f0d1496d`.

The author-QA ledger covers all 360 cases with zero automated errors, zero
refusal-neighbor gaps, and zero token-containment candidates. It explicitly
declares that it is not independent approval.

## Known limitations

- All 360 rows require independent human review; criteria are author-gold.
- All cases are repository-visible and assumed contaminated.
- There is no calibration split, private holdout, restricted adversarial
  holdout, holdout canary, or contamination study yet.
- Every category remains below the preregistered 80-case official minimum.
- Coverage is designed development coverage, not deployment-representative.
- Independent native-language and ambiguity review, embedding-based semantic
  analysis, and external statistical review remain pending. The suite's
  `dataset_integrity` gate is intentionally `pending`, so official validation
  fails until detector identity, revision, cross-split review, and report hash
  are approved and pinned.
- Results must be labeled development results and cannot support certification,
  legal compliance, universal correctness, safety, security, fairness, or
  production-fitness claims.
