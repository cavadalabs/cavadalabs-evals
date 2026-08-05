# Development dataset card 0.5.1

Status: draft development material; not approved benchmark evidence.

## Contents

- 320 synthetic cases: 160 public and 160 practice.
- 160 English (`en-US`) and 160 Italian (`it-IT`) cases.
- 32 cases in each of ten modules.
- 192 answer, 40 abstain, 40 refuse, 40 safe-complete, and 8 redirect
  expected behaviors.
- 24 critical, 96 high, 144 medium, and 56 low severity cases.
- Single-turn deterministic and subjective tasks, controlled robustness and
  fairness pairs, and multi-turn conversations.

Every row records provenance, governance metadata, a case-specific rationale,
and at least one mandatory scoring criterion. Exact tasks also carry
machine-checkable references where appropriate.

## Provenance and correction

The cases are deterministic CavadaLabs synthetic authoring produced from
`scripts/build_core_development_dataset.py`. No third-party benchmark text was
copied. Four cases use reserved `example.test` placeholders and describe no
natural people. Independent authorship and rights review is pending.

Version `0.5.1` supersedes `0.5.0`. The reproducible author-QA ledger found that
two EN/IT practice factuality prompts contained `Saturn` or `Saturno` while
asking for that answer. This release replaces those prompts with answerable
stable-fact questions that do not expose the expected output. All identifiers
were versioned and all older files remain unchanged. No result is official.

## Integrity

```console
uv run python scripts/build_core_development_dataset.py \
  suites/cavada-core-assistant-text-v1/dataset-0.5.1.jsonl \
  --suite-version 0.5.1 --check
uv run python scripts/audit_dataset_quality.py \
  suites/cavada-core-assistant-text-v1 \
  suites/cavada-core-assistant-text-v1/review/author-qa-0.5.1.json --check
uv run cavada-eval validate suites/cavada-core-assistant-text-v1
uv run cavada-eval program
```

Dataset SHA-256 at creation:
`9cec14b1ff0a31847d8613894448c258efb1a8a09b2c00fb5896719c655946d4`.

Exact, normalized, near-duplicate, and token-containment checks pass. The
token-containment audit reports zero candidates at the declared 0.95 threshold.
The author-QA ledger covers all 320 cases, records zero automated errors, and
explicitly declares that it is not independent approval.

## Known limitations

- All rows require independent human review; criteria are author-gold only.
- Public and practice cases are repository-visible and assumed contaminated.
- There is no calibration split, private holdout, restricted adversarial
  holdout, holdout canary, or contamination study yet.
- The 32 cases per module are below preregistered official sample targets.
- Coverage is balanced development coverage, not deployment-representative.
- Independent native-language and ambiguity review, embedding-based semantic
  analysis, and external statistical review remain pending.
- Results must be labeled development results and cannot support certification,
  legal compliance, universal correctness, safety, security, fairness, or
  production-fitness claims.
