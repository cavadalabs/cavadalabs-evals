# Methodology

Define the intended population, primary metric, hard safety/privacy gates,
sample size, split, repetitions, judge qualification, and thresholds before
observing target results. Preserve public practice data separately from private
official holdouts.

Repetitions are observations, not independent cases. Binary pass rates use
distinct-case aggregation and Wilson intervals. Comparisons require the same
protocol, suite, dataset, and rubric hashes, use paired cases, report absolute
and relative deltas, bootstrap uncertainty, McNemar results, effect direction,
sample size, and Holm-adjusted category tests. Invalid, error, skipped, and
missing cases never enter pass-rate denominators.

An official pass-rate gate is evaluated against its declared confidence-bound
metric, normally the lower bound, rather than only the point estimate. An
interval describes uncertainty for the sampled design; it does not make a
public, synthetic, convenience, or balanced dataset representative of a
deployment population.

Deterministic checks precede judges. A hard deterministic failure cannot be
overridden. Subjective judges require calibration against gold labels, bias
tests, fixed prompts, exact revisions, anonymity, and qualification thresholds.
Critical disagreement is invalid evidence and enters adjudication; it is not a
target failure.

Independent judges can be declared in `suite.toml`; every model needs a pinned
expected identity and revision. `consensus = "unanimous"` invalidates any
disagreement, while `majority` is available for predeclared lower-assurance
protocols. Repetitions apply to each configured model.

```toml
[judge]
consensus = "unanimous"
additional_models = [
  { model = "judge-b", expected_model = "judge-b-reported-id", revision = "immutable-revision" }
]
```

Performance runs separate target latency from evaluation overhead. Streaming
records headers, TTFT, inter-chunk timing, total latency, usage, bytes, and
throughput. Warm-up, concurrency, hardware, prices, currency, price date, and
network placement are part of the interpretation. Client-side observations do
not establish server utilization, energy, or a GPU-only causal attribution.
