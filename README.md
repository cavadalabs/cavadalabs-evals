# CavadaLabs Evals

Internal, local-first evaluation protocol for models, RAG systems, chatbots and agents.

## Status

The runner is usable. The imported MEMO4345 suite remains `candidate` until every quarantined label is resolved and an official calibration run passes. The CLI refuses `--official` runs for candidate suites, dirty source trees, missing model identities, insecure remote HTTP endpoints or non-approved cases.

## Setup

```bash
uv sync
uv run cavada-eval validate suites/memo4345-v1
uv run cavada-eval audit suites/memo4345-v1
```

Development run against MEMO4345:

```bash
uv run cavada-eval run suites/memo4345-v1 \
  --endpoint http://127.0.0.1:8097/chat \
  --model-label ministral-14b \
  --expected-model ministral-3-14b-vision-local \
  --judge-endpoint http://127.0.0.1:8013/v1 \
  --judge-model ministral-8b-judge \
  --max-cases 10
```

API keys are read only from `TARGET_API_KEY` and `JUDGE_API_KEY` unless different environment-variable names are provided. They are never written to artifacts.

Each run produces an immutable directory containing:

```text
manifest.json
raw_responses.jsonl
judgments.jsonl
case_results.jsonl
metrics.json
category_results.csv
failures.jsonl
report.html
```

## What “official” means

An official run proves that the recorded artifacts conform to the versioned CavadaLabs protocol. It is not proof that a system is perfectly safe, legally compliant, or correct for inputs outside the tested distribution.

GDPR and AI Act controls live in `standards/control_catalog.toml`. Behavioral tests provide evidence for some controls; legal basis, contracts, DPIAs, ROPA, governance and approvals remain separate evidence.

## DeepEval

DeepEval 3.x is an optional metric engine, installed with `uv sync --group deepeval`. The CavadaLabs artifact format and integrity gates do not depend on it. This keeps historical runs readable even if the engine changes.

DeepEval telemetry is opt-out and it can read `.env`/legacy key files when imported. Any CavadaLabs integration must set `DEEPEVAL_TELEMETRY_OPT_OUT=true`, `DEEPEVAL_DISABLE_DOTENV=1`, `DEEPEVAL_DISABLE_LEGACY_KEYFILE=1`, `DEEPEVAL_UPDATE_WARNING_OPT_IN=false`, and `ERROR_REPORTING=false` before importing it. Official runs must never log in to or sync with Confident AI unless a separate data-transfer authorization is recorded.

