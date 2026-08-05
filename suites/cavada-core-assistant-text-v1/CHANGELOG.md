# Suite changelog

## 0.8.1 - 2026-08-05

- Added fail-closed paths and SHA-256 fields for the calibration report and its
  independent approval without changing the `0.8.0` dataset, rubric, cases,
  gates, or measurement semantics.
- Updated the preregistered pilot campaign to the new suite-configuration hash;
  no pilot had been executed under `0.8.0`.
- No independent review, calibration, approval, or assurance claim changed.

## 0.8.0 - 2026-08-05

- Declared exactly one primary case per scenario group and 76 non-independent
  variants with explicit primary references.
- Changed gates, confidence intervals, bootstrap samples, and slices to use 328
  scenario groups rather than 404 evaluation rows.
- Kept case-level results and paired shift diagnostics without allowing them to
  inflate statistical sample size.
- Corrected the 1,840-scenario blueprint allocation to 164 public, 164
  practice, 320 calibration, and 1,192 holdout primary scenarios.
- Versioned the measurement specification and statistical plan to `0.3.0`.
- No independent review, calibration, approval, or assurance claim changed.

## 0.7.0 - 2026-08-05

- Added 44 EN/IT domain-and-register shift probes across all ten modules and
  both development splits.
- Linked every probe to a validated construct reference with matching category,
  locale, split, and expected behavior.
- Added four benign privacy neighbors so every refusal remains boundary-paired.
- Added paired shift reporting with bootstrap uncertainty and exact McNemar
  evidence; invalid pairs are counted and excluded fail-closed.
- Versioned the fixed 1,840-case blueprint allocation to 202 public, 202
  practice, 320 calibration, and 1,116 holdout cases.
- No independent review, calibration, approval, or assurance claim changed.

## 0.6.0 - 2026-08-05

- Added 40 matched benign neighbors for all 40 refusal cases across ten major
  privacy, security, and safety refusal categories, EN/IT, and both splits.
- Added explicit restricted/benign pair roles and shared scenario groups for
  over-refusal measurement.
- Versioned the fixed 1,840-case blueprint allocation to 180 public, 180
  practice, 320 calibration, and 1,160 holdout cases.
- Extended development QA to fail when any refusal lacks its benign neighbor.
- No independent review, calibration, approval, or assurance claim changed.

## 0.5.1 - 2026-08-05

- Corrected two EN/IT practice factuality prompts that exposed their expected
  answer verbatim.
- Added immutable per-case development QA ledgers for solvability, leakage,
  shortcut, grader-gaming, and evaluation-awareness checks.
- Preserved the failing `0.5.0` QA evidence and every historical dataset.
- No independent review, calibration, approval, or assurance claim changed.

## 0.5.0 - 2026-08-05

- Replaced all 160 practice prompt clones with separately worded EN/IT
  scenarios while preserving the preregistered constructs and case balance.
- Reduced public/practice token-containment duplicate candidates from 160 to
  zero at the declared 0.95 review threshold.
- Preserved every historical dataset and added a reproducibility check for the
  new immutable artifact.
- No independent review, calibration, approval, or assurance claim changed.

## 0.4.0 - 2026-08-05

- Added non-empty mandatory criteria to every case and included them in judge
  requests.
- Added deterministic references for additional exact translation, sorting,
  factual, numeric, and privacy-minimization cases.
- Corrected the synthetic complaint prompt to include content that can actually
  be summarized without reproducing its contact detail.
- No independent review, calibration, approval, or assurance claim changed.

## 0.3.0 - 2026-08-05

- Replaced index-derived subcategory labels with an explicit reviewed mapping
  for every generated template.
- Corrected the false-premise capital question from `abstain` to `answer`.
- Preserved the `0.2.1` cross-suite duplicate correction.
- No calibration, approval, or assurance claim changed.

## 0.2.1 - 2026-08-05

- Replaced one safety prompt that exactly duplicated a case in
  `security-privacy-smoke-v1`.
- Assigned new case and scenario identifiers to the corrected immutable
  dataset release.
- Added program-level exact, normalized, and high-similarity cross-suite
  duplicate rejection.
- No calibration, approval, or assurance claim changed.

## 0.2.0 - 2026-08-05

- Added 320 synthetic public and practice development cases.
- Superseded after cross-suite integrity validation found one exact duplicate.

## 0.1.0 - 2026-08-05

- Added four schema and authoring fixtures.
