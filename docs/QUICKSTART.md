# Client evaluation quickstart

This path produces client/candidate evidence. It does not require suite
approval, judge qualification, publication approval, or registry access.

## 1. Install

Python 3.11 or newer is required. The `reports` extra enables the PDF reports
used by advanced suite and performance workflows; client behavior evals always
produce standalone HTML.

```bash
pip install 'cavadalabs-evals[reports]'
```

From a source checkout, prefix commands with `uv run` after `uv sync --frozen`.

## 2. Create an offline project

```bash
cavada-eval init customer-support-eval
cd customer-support-eval
```

The generated project contains:

```text
eval.toml
data/example.jsonl
custom.py
README.md
.gitignore
```

`custom.py` contains a deterministic local target. Factories are trusted local
code and are not sandboxed.

## 3. Inspect the exact work before running

```bash
cavada-eval plan eval.toml
```

Planning materializes the selected dataset, rejects duplicate IDs, renders
every prompt, checks target/evaluator capabilities, computes deterministic cell
IDs, and enforces `max_requests`. It does not call a target or read an API key.
The JSON output includes the case count, prompt variants, targets, evaluators,
cell count, request count, concurrency, output directory, and warnings.

## 4. Run, report, and verify

```bash
cavada-eval run eval.toml
cavada-eval report runs/latest
cavada-eval verify runs/latest
```

`run` prints the immutable experiment directory and per-cell result table. `runs/latest` is a small path
pointer, not a mutable run. `report` checks the evidence before returning the
standalone HTML path. `verify` independently reports:

- bundle integrity;
- reconstructed semantics;
- client or quick assurance;
- failures for each layer.

The experiment retains its normalized plan, original plan, dataset snapshot,
per-cell canonical behavior bundles, summary, verification result, and HTML
report. The report keeps model failures separate from execution errors, invalid
evaluations, skipped cases, and unsupported evidence.

## Use an endpoint

Replace the generated callable target with:

```toml
[[targets]]
name = "local-model"
type = "openai-compatible"
base_url = "http://127.0.0.1:8000/v1"
model = "qwen3"
revision = "local-build-1"
api_key_env = "LOCAL_API_KEY"
```

The key value is read only at execution and is never written to the result.
When the environment variable is absent, planning reports a warning and the
run stops before any network call. HTTPS is required for non-loopback targets.
Non-public data also requires an explicit authorization that covers every
external destination; see [client workflows](CLIENT_WORKFLOWS.md#external-data-and-endpoints).

## Add a matrix

Repeat `[[prompts]]` and `[[targets]]` tables. Cavada evaluates:

```text
selected cases x prompt variants x targets x repetitions
```

Planning shows the total before execution. Compatible cells receive paired
comparisons in `summary.json` and `report.html`; incompatible evidence is not
aggregated.

## Profiles

- `quick`: local development evidence with an explicit weak-claim warning.
- `client`: recommended default; frozen inputs, raw evidence, semantic
  verification, confidence intervals, and a client report.
- `official`: advanced protocol path only. The simple plan loader refuses to
  create official evidence.

The repository currently has no real approved suite, real official result, or
independent reproduction. See [operations](OPERATIONS.md) only when the advanced
official workflow is actually required.
