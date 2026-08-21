# Client workflows

All client workflows normalize into the canonical evidence runner and semantic
verifier. They do not create official claims, approvals, rankings, or registry
records.

## Prompt, endpoint, and JSONL

Create a plan with one JSONL dataset, one prompt template, one
OpenAI-compatible target, and one deterministic evaluator. Then run:

```bash
cavada-eval plan eval.toml
cavada-eval run eval.toml
cavada-eval report runs/latest
cavada-eval verify runs/latest
```

Planning is the dry run: it validates all local inputs and budgets before any
endpoint contact. Execution preserves the raw request/response evidence and
provider-reported usage.

## Multiple prompts and targets

Two `[[prompts]]` and two `[[targets]]` produce four deterministic cells. The
report includes per-cell pass rates and confidence intervals, target and prompt
summaries, error breakdowns, latency and observed cost, plus paired comparisons
for shared cases. Cells with incompatible cases are not pooled. No composite
score is generated.

See [`examples/02_prompt_matrix`](../examples/02_prompt_matrix/).

## Dataset factory, target callable, evaluator callable

All three can live in one local Python module referenced with
`module:callable`. This is the smallest extension point and needs no plugin
registration. The module is trusted code: review it like any other project
source before running `plan`.

See [`examples/03_dataset_factory`](../examples/03_dataset_factory/).

## Resume an interrupted run

```bash
cavada-eval run eval.toml --resume
```

The latest experiment is resumed only when its normalized plan, dataset hash,
and cell matrix still match. Completed cells are semantically verified and are
not repeated. A finalized valid run is returned unchanged. Runs are never
overwritten.

## Client endpoint benchmark

The client benchmark facade materializes a small config into the existing
generation-only performance core:

```bash
cavada-eval benchmark benchmark.toml --plan
cavada-eval benchmark benchmark.toml --output-root runs
```

The first command validates and shows the materialized plan without contacting
the endpoint. A run retains requests, responses, observations, warm-ups, cells,
events, manifest, summary, and report. It reports only observed metrics:
request counts, errors, throughput, latency percentiles, TTFT and token rates
when supported, and provider usage. Cost is absent without an explicit pricing
source. Small samples carry a warning.

Optional benchmark cost needs an explicit `[target.pricing]` table with
`currency`, `source`, `effective_at`, `input_per_million`, and
`output_per_million`; there is no built-in price catalog.

This is client serving evidence, not the official performance protocol. It
does not start an inference engine or claim response quality, safety,
compliance, hardware causality, energy use, or universal capacity.

See [`examples/05_client_benchmark`](../examples/05_client_benchmark/).

## External data and endpoints

Loopback HTTP is allowed. Other endpoints require HTTPS. `public` and
`synthetic` data may be sent after validation; non-public classifications need
an explicit, unexpired authorization whose destination list covers every
external host. Cavada checks this before network access.

Keep API values only in the named environment variables. Configs and results
retain the environment-variable name, never its value. Never put secrets or
unnecessary personal data in a dataset.

## Result interpretation

- `fail`: the target ran and an evaluator criterion failed.
- `error`: target, transport, or execution failed.
- `invalid`: evidence or evaluator output was malformed or insufficient.
- `skipped`: execution policy intentionally did not evaluate the case.
- `unsupported`: a declared capability or artifact type is not reconstructible.

Errors and invalid cases remain visible and are not relabeled as model
failures. Verification recomputes metrics and reports from preserved bytes;
matching checksums alone are not enough.

## Advanced boundary

Client evidence requires no qualification package, reviewer approval, public
registry, attestation, or publication lifecycle. Those controls remain in the
[advanced operations guide](OPERATIONS.md) for official workflows. Pairwise
A/B+B/A output judging, Private AI, and performance official assurance are not
part of the client facade.
