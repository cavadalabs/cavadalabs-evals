# Development dataset card 0.5.0

Status: draft development material; not approved benchmark evidence.

Superseded by version `0.5.1`; retained unchanged for reproducibility. The
author QA ledger failed two factuality cases because their prompts exposed the
expected answer verbatim.

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
and at least one mandatory scoring criterion. The runner supplies those
criteria to the identity-blinded judge. Exact tasks also carry machine-checkable
expected strings, numbers, JSON values, schemas, or PII-output prohibitions.

## Provenance, rights, and corrections

The cases are deterministic CavadaLabs synthetic authoring produced from
`scripts/build_core_development_dataset.py`. No third-party benchmark text was
copied. Four cases use reserved `example.test` email placeholders; they do not
describe natural people. Independent authorship and rights review is pending.

Version `0.5.0` supersedes `0.4.0`. It retains all earlier corrections and
replaces each mechanically prefixed practice clone with a separately worded
EN/IT scenario for the same preregistered construct. This removes the known
public/practice pseudoreplication without changing category counts, expected
behaviors, gates, or scoring criteria. The two splits still share the same
synthetic authoring process and are not independent human evidence. All prior
dataset files remain unchanged. No result from any version is official.

## Integrity

The historical file is `dataset-0.5.0.jsonl`. The generator refuses to overwrite
existing versions. Verify the checked-in artifact with:

```console
uv run python scripts/build_core_development_dataset.py \
  suites/cavada-core-assistant-text-v1/dataset-0.5.0.jsonl \
  --suite-version 0.5.0 --check
uv run cavada-eval validate suites/cavada-core-assistant-text-v1
uv run cavada-eval program
```

Dataset SHA-256 at creation:
`eb527d0820ce3af4f3c53bf0c77005fb48c4d3d5db37f73ccd37004c75af595c`.

The exact, normalized, near-duplicate, and token-containment checks pass. The
token-containment audit reports zero candidates at the declared 0.95 threshold.
The reproducible `review/author-qa-0.5.0.json` ledger records per-case
solvability evidence and lexical leakage, shortcut, grader-gaming, and
evaluation-awareness checks. Its status is development author QA, not
independent approval. Its recorded status is `fail-development-qa`; version
`0.5.1` corrects the two findings without mutating this dataset.

## Known limitations

- All rows require independent human review; criteria are author-gold only.
- Public and practice cases are repository-visible and assumed contaminated.
- There is no calibration split, private holdout, restricted adversarial
  holdout, holdout canary, or contamination study yet.
- The 32 cases per module are below preregistered official sample targets.
- Coverage is balanced development coverage, not a prevalence or
  deployment-representative sample.
- Independent native-language and ambiguity review, embedding-based semantic
  analysis, and external statistical review remain pending. The author QA
  checks are necessary development evidence but cannot close those gates.
- Results must be labeled development results and cannot support claims of
  certification, legal compliance, universal correctness, safety, security,
  fairness, or production fitness.
