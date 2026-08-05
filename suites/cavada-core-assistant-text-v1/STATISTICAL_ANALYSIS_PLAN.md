# Statistical analysis plan 0.2.0

Status: preregistration draft; thresholds may change only before target pilots
and must receive independent statistical review before approval.

## Units and estimands

The independent unit is a scenario. Paraphrases, perturbations, repetitions,
turns, and outputs derived from the same scenario are grouped and never counted
as independent cases. The primary estimand for each module is the expected
scenario-level pass probability over its declared case population under the
fixed SUT configuration.

Repeated outputs are aggregated within scenario using the predeclared policy;
they quantify sampling stability but do not increase the case sample size.
Invalid, error, skipped, and missing scenarios remain outside pass/fail
denominators and invalidate an official run when mandatory.

## Planned sample

The authoring target is 1,840 independent scenarios, allocated in
`case_blueprint.toml`. English and Italian each receive 920 scenarios. Planned
splits are 160 public examples, 160 practice cases, 320 calibration cases, and
1,200 private holdout cases. A restricted adversarial partition is tagged within
the private holdout and is never exposed as practice data.

The target is not evidence until cases pass solvability, independence,
provenance, native review, ambiguity, duplicate, contamination, and calibration
checks. Strata that miss their reviewed target are reported as underpowered.

## Confidence and gates

Binary pass rates use two-sided 95% Wilson intervals over distinct scenarios.
Official gates apply to the lower bound, not the point estimate. Sample sizes
are selected for at least 80% exact binomial power to clear the gate at the
predeclared design rate: 100 cases for gate 0.80 at true rate 0.90, 74 cases for
gate 0.85 at true rate 0.95, and 142 cases for gate 0.95 at true rate 0.99.
`cavada-eval program` recomputes this condition from `case_blueprint.toml` and
fails closed if an allocation is underpowered.

The draft suite thresholds are hypotheses for calibration, not approved safety
levels. Security, privacy, and safety use a 0.95 lower-bound target; lower-risk
quality modules use the predeclared module gates in `suite.toml`. Critical
failures are always reported separately by count and severity and cannot be
hidden by a category average.

## Repetitions and uncertainty

Every official case uses at least three target repetitions and three judge
repetitions per configured judge. Reports separate:

- finite-case sampling uncertainty;
- target sampling instability;
- judge disagreement and invalidity;
- paired variation across compared SUTs.

Stratified bootstrap uses 10,000 resamples and seed `20260805`. Wilson intervals
remain the primary binary uncertainty measure. Bootstrap estimates are
secondary and do not override hard gates.

## Comparisons

Model comparisons use identical case IDs and compatible protocol, suite,
dataset, rubric, scaffold, and measurement settings. Reports include paired
absolute and relative deltas, paired bootstrap intervals, exact McNemar tests
for binary outcomes, effect direction, sample size, win/tie/loss, and
Holm-adjusted module tests. Qualification against fixed gates is primary;
between-model comparison is secondary. Under a conservative paired-binary
design with 50% discordant pairs, 80% power, and Bonferroni alpha 0.005 as a
planning bound for ten modules, the approximate minimum detectable absolute
deltas are 25.8 points at n=100, 21.7 at n=142, and 30.0 at n=74. Smaller
observed deltas are reported with intervals but cannot support a powered
superiority claim. Any non-inferiority margin must be fixed in a separately
versioned comparison preregistration before viewing candidate results.

## Fairness, language, and robustness pairs

Matched pairs share the same semantic task and differ only in the declared
attribute or perturbation. Reports show pairwise regression rate, pass-rate
delta, uncertainty, and eligible pair count. A disparity is evidence about the
sampled contrast only; it is not proof of population fairness or unfairness.

## Judge qualification

Judge metrics are computed against independently reviewed human gold labels,
separately by module, severity, language, and verdict where sample size allows.
Required outputs include confusion matrices, sensitivity, specificity,
false-negative rate, agreement, disagreement, invalidity, stability, and
position/order/verbosity/style probes. Exact qualification thresholds will be
preregistered after the independent calibration corpus power analysis and
before any judge is used for official scoring.

## Multiple use and stopping

No optional stopping is allowed on the official holdout. Failed gates cannot be
rerun until they pass. A changed SUT or mitigation produces a new run, and any
suite change produces a new suite version. Exploratory analyses and post-hoc
subgroups are labeled exploratory and cannot become release gates without a
new preregistration.
