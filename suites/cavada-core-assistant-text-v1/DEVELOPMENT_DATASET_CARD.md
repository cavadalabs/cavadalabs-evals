# Development dataset card 0.2.0

Status: draft development material; not approved benchmark evidence.

## Contents

- 320 synthetic cases: 160 public and 160 practice.
- 160 English (`en-US`) and 160 Italian (`it-IT`) cases.
- 32 cases in each of ten modules.
- 188 answer, 44 abstain, 40 refuse, 40 safe-complete, and 8 redirect
  expected behaviors.
- 24 critical, 96 high, 144 medium, and 56 low severity cases.
- Single-turn deterministic and subjective tasks, controlled robustness and
  fairness pairs, and multi-turn conversations.

Every row records its scenario group, module, category, subcategory, risk,
severity, difficulty, operating condition, language, locale, split, expected
behavior and reason, tags, source, license, authorship, personal-data class,
ambiguity, review status, rationale, and weight. Structured-output cases also
carry exact expected values and closed JSON schemas.

## Provenance and rights

The cases are deterministic CavadaLabs synthetic authoring produced from
`scripts/build_core_development_dataset.py`. No third-party benchmark text was
copied. Four cases use reserved `example.test` email placeholders; they do not
describe natural people. Independent authorship and rights review is pending.

## Integrity

The active file is `dataset-0.2.0.jsonl`. Regenerate it only as a new semantic
suite version; the generator refuses to overwrite an existing file. Verify the
checked-in artifact with:

```console
uv run python scripts/build_core_development_dataset.py \
  suites/cavada-core-assistant-text-v1/dataset-0.2.0.jsonl --check
uv run cavada-eval validate suites/cavada-core-assistant-text-v1
```

Dataset SHA-256 at creation:
`49704d873a1b16c91230145f68e354f817726ca201de8342e36f828b7d48fb60`.

## Known limitations

- All rows require independent human review; they are author labels only.
- Public and practice cases are repository-visible and assumed contaminated.
- There is no calibration split, private holdout, restricted adversarial
  holdout, holdout canary, or contamination study yet.
- The 32 cases per module are below the preregistered official sample targets
  and cannot clear official dataset-quality or power gates.
- Coverage is deliberately balanced development coverage, not a prevalence or
  deployment-representative sample.
- Native-language review, ambiguity testing, solvability review, cross-suite
  semantic duplicate analysis, grader-gaming analysis, and external statistical
  review remain pending.
- Results on this dataset must be labeled development results and cannot support
  claims of certification, legal compliance, universal correctness, safety,
  security, fairness, or production fitness.

The immutable `dataset.jsonl` file contains the four inactive `0.1.0`
authoring fixtures and remains only for historical reproducibility.
