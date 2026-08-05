# Target pilot protocol 1.0.0

Status: ready to execute; no target or judge pilot has been run.

## Purpose

The pilot tests the frozen measurement pipeline, case clarity, discrimination,
stability, latency, cost, and failure modes before private-holdout authoring. It
cannot approve a model, qualify a judge, or produce an official benchmark
claim. Pilot outputs may change a later suite version, but the final holdout
must never be tuned from pilot results.

## Entry criteria

Do not start the campaign until all of the following evidence exists:

1. independent statistical review of `STATISTICAL_ANALYSIS_PLAN.md` and
   `case_blueprint.toml`;
2. a qualified exact judge configuration and its verified qualification report;
3. approved target and judge destinations, data classes, regions, retention,
   and credentials;
4. exact target/judge model revisions, serving-engine version, quantization,
   chat template, system prompt, guardrails, and generation parameters;
5. enough compute and budget for 404 cases × 3 target repetitions × 3 judge
   repetitions per judge, plus retries and controls;
6. transcript reviewers who are blind to provider identity and qualified for
   English, Italian, safety, privacy, and security escalations.

Missing entry evidence is a blocker, not a value to infer or fill with a
placeholder.

## Preregistered campaign matrix

Use at least three unrelated base-model families. Do not count quantizations,
fine-tunes, provider aliases, or sizes of the same family as independent. A
practical local first campaign may evaluate one instruction model from each of
Qwen, Mistral, and Gemma. As of 2026-08-05, primary model sources include:

- Qwen: `Qwen/Qwen3-4B`, Apache-2.0 model card;
- Mistral: `mistralai/Ministral-3-8B-Instruct-2512`, Apache-2.0 model card;
- Google: `google/gemma-4-12B-it`, Apache-2.0 model card.

Sources:

- https://huggingface.co/Qwen/Qwen3-4B
- https://huggingface.co/mistralai/Ministral-3-8B-Instruct-2512
- https://huggingface.co/google/gemma-4-12B-it

These are candidate examples, not approved dependencies. At execution, record
the immutable repository commit, weight hashes, exact license, tokenizer/chat
template hashes, quantization and serving configuration. Recheck licenses and
technical requirements; never use a moving `main` revision as evidence.

The campaign also requires:

- one fixed positive control whose independently reviewed responses should pass;
- one fixed negative control containing known rubric violations by module and
  severity;
- transport/integrity controls for wrong model identity, malformed judge JSON,
  timeout, rate limit, crash/resume, cancellation, budget exhaustion, tamper,
  and clean reproduction.

Semantic positive/negative controls come from the restricted, independently
reviewed judge corpus. The repository's mock controls validate software paths
only and are not substitutes.

## Fixed execution

Run the full suite with no `--max-cases`, three target repetitions, three judge
repetitions, the same qualified judge configuration, and the standard assistant
profile. Pin a safe concurrency and rate limit before the first run and keep
them constant across targets unless the campaign explicitly studies serving
performance.

```console
uv run cavada-eval estimate suites/cavada-core-assistant-text-v1 \
  --repetitions 3 --judge-repetitions 3

uv run cavada-eval run suites/cavada-core-assistant-text-v1 \
  --endpoint http://127.0.0.1:8000/v1 \
  --model-label FAMILY_ALIAS \
  --request-model EXACT_REQUEST_MODEL \
  --expected-model EXACT_REPORTED_MODEL \
  --model-revision IMMUTABLE_REVISION \
  --judge-endpoint http://127.0.0.1:8010/v1 \
  --judge-model EXACT_JUDGE_MODEL \
  --expected-judge-model EXACT_REPORTED_JUDGE \
  --judge-revision IMMUTABLE_JUDGE_REVISION \
  --repetitions 3 --judge-repetitions 3 \
  --mode candidate --concurrency FIXED_CONCURRENCY \
  --requests-per-second FIXED_RATE --progress
```

Use environment-variable names for credentials. Never place secret values in
the command, configuration, campaign record, or report.

Copy `pilot-campaign.example.json` into the restricted campaign workspace,
replace every evidence hash and run path, and audit the complete campaign:

```console
uv run cavada-eval pilot-audit \
  /restricted/campaign/campaign.json \
  /restricted/campaign/pilot-audit.json
```

The example's zero evidence hashes are deliberate fail-closed placeholders.
The auditor rejects missing or invalid bundles, incomplete reviews, weak
controls, partial runs, and inconsistent suite, judge, execution, source, or
artifact versions. The output is immutable and must be retained with the pilot.

## Required analysis

Verify every bundle before reading scores. Analyze scenario-level gates and
intervals; case-level rows are diagnostics only. Preserve and inspect:

- every raw response, judgment, parser result, request, identity and timing;
- scenario and category pass rates, Wilson and bootstrap intervals;
- paired distribution-shift and refusal/benign regressions;
- language, severity, operating-condition and response-style slices;
- target/judge stability, disagreement, invalidity, false-pass risk;
- latency distributions, throughput, tokens, cost, retries and errors;
- saturation, floor effects, difficulty and model discrimination;
- ambiguous, impossible, leaking, shortcut-prone or evaluation-aware cases;
- all safety, privacy, security and critical failures with blinded review.

Two qualified reviewers inspect flagged transcripts independently; a separate
adjudicator resolves disagreements. Model identity remains hidden until labels
and dispositions are frozen.

## Exit and change control

The campaign is complete only when all planned model families and both controls
have verified bundles, no run is partial, reviewer/adjudication evidence is
hash-pinned, and a campaign report records every exclusion. Do not average
unrelated constructs or silently remove failures.

Any ambiguous case, parser defect, rubric change, judge change, allocation
change, or unintended solution path creates a new semantic suite or protocol
version. Preserve the failed pilot and rationale. After the candidate is frozen,
reproduce it from a clean environment before authoring the untouched private
holdout.

## Current blockers

At 2026-08-05 this workspace has no target endpoint, judge endpoint, API keys,
qualified judge report, independent statistical approval, restricted control
corpus, or completed pilot run. Therefore no pilot result or official claim
exists yet.
