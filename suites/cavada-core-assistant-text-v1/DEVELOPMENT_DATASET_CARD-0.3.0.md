# Development dataset card 0.3.0

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

Every row records its scenario group, module, category, explicitly assigned
subcategory, risk, severity, difficulty, operating condition, language, locale,
split, expected behavior and reason, tags, source, license, authorship,
personal-data class, ambiguity, review status, rationale, and weight.
Structured-output cases carry exact expected values and closed JSON schemas.

## Provenance, rights, and corrections

The cases are deterministic CavadaLabs synthetic authoring produced from
`scripts/build_core_development_dataset.py`. No third-party benchmark text was
copied. Four cases use reserved `example.test` email placeholders; they do not
describe natural people. Independent authorship and rights review is pending.

Version `0.3.0` supersedes `0.2.1`. It keeps the prior cross-suite duplicate
correction, replaces inaccurate index-derived subcategory labels with an
explicit template mapping, and correctly treats the false-premise capital
question as an answer/correction task rather than an abstention task. All prior
dataset files remain unchanged. No result from any version is official.

## Integrity

The active file is `dataset-0.3.0.jsonl`. The generator refuses to overwrite
existing versions. Verify the checked-in artifact with:

```console
uv run python scripts/build_core_development_dataset.py \
  suites/cavada-core-assistant-text-v1/dataset-0.3.0.jsonl \
  --suite-version 0.3.0 --check
uv run cavada-eval validate suites/cavada-core-assistant-text-v1
uv run cavada-eval program
```

Dataset SHA-256 at creation:
`b1a60f14f3a25bdffdcc960aabfdccafe4ed32b0ef74ad0fbb7d6f991521b1d0`.

## Known limitations

- All rows require independent human review; they are author labels only.
- Public and practice cases are repository-visible and assumed contaminated.
- Practice cases remain template-related to public examples and cannot be
  treated as independent evidence until semantic-duplicate review is complete.
- There is no calibration split, private holdout, restricted adversarial
  holdout, holdout canary, or contamination study yet.
- The 32 cases per module are below preregistered official sample targets.
- Coverage is balanced development coverage, not a prevalence or
  deployment-representative sample.
- Native-language review, ambiguity testing, solvability review, semantic
  duplicate analysis, grader-gaming analysis, and external statistical review
  remain pending.
- Results must be labeled development results and cannot support claims of
  certification, legal compliance, universal correctness, safety, security,
  fairness, or production fitness.
