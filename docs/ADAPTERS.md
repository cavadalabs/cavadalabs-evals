# Adapter requirements

Run `cavada-eval profiles` to inspect every benchmark shape and whether the
built-in runner can execute it in official mode. Profiles with `built_in=false`
need an approved, pinned adapter and calibration evidence; the runner fails
closed instead of inventing a proxy score.

An adapter declares input/output modalities, endpoint protocol, authentication,
streaming, usage reporting, identity evidence, revision evidence, response
limits, retryable statuses, timeouts, and data destinations. Unsupported content
fails before a request. Official adapters verify reported target and judge
identity and preserve raw protocol evidence.

External benchmark adapters must pin upstream name, version/commit, license,
dataset checksum, evaluator checksum, configuration, invocation, and imported
results. No official run downloads a mutable dataset or executable. Candidates
include lm-evaluation-harness, garak, CyberSecEval, AgentDojo, PrivacyLens,
Presidio, and licensed MLCommons practice/official workflows.

## Offline result import

`cavada-eval import-external DESCRIPTOR.json OUTPUT_DIR` performs no network
access. It validates every local input before creating `OUTPUT_DIR`, copies the
descriptor and original upstream JSON into the verified bundle, and records the
raw artifact SHA-256. Imported bundles always have `official=false` and
`assurance=development-import`; an adapter never converts upstream evidence into
an official CavadaLabs result.

Two versioned descriptors are built in:

- `lm-evaluation-harness-results/1.0.0` for the persisted aggregate
  `results_*.json` format from
  [lm-evaluation-harness](https://github.com/EleutherAI/lm-evaluation-harness).
- `vllm-bench-serve/1.0.0` for one single-run JSON produced by
  [`vllm bench serve`](https://docs.vllm.ai/en/latest/cli/bench/serve/).

Both require an exact model ID, revision and artifact SHA plus runtime name,
version and revision. These values remain upstream/operator evidence: the
adapter verifies agreement with identity fields present in the artifact, but
does not contact a registry or endpoint to strengthen them.

### lm-evaluation-harness

Create a descriptor next to the immutable upstream result:

```json
{
  "adapter_version": "lm-evaluation-harness-results/1.0.0",
  "artifact": "results_2026-08-07.json",
  "artifact_sha256": "<sha256 of results_2026-08-07.json>",
  "source": {
    "name": "lm-evaluation-harness",
    "version": "<exact installed lm-eval version>",
    "commit": "<full lm-evaluation-harness source commit>",
    "license": "MIT",
    "dataset_sha256": "<sha256 of the frozen dataset evidence>",
    "evaluator_sha256": "<sha256 of the frozen evaluator source>",
    "invocation": "lm_eval --model hf --model_args pretrained=org/model,revision=<revision> --tasks hellaswag --output_path results"
  },
  "identity": {
    "model_id": "org/model",
    "model_revision": "<exact revision>",
    "model_sha": "<artifact config.model_sha>",
    "runtime_name": "hf",
    "runtime_version": "<exact runtime version>",
    "runtime_revision": "<exact runtime build or source revision>"
  },
  "suite": {
    "id": "lm-eval-core",
    "version": "1.0.0",
    "sha256": "<sha256 of the frozen suite definition>"
  },
  "evaluation_repository_commit": "<full commit resolving artifact git_hash>",
  "outcomes": {
    "hellaswag": {
      "status": "pass",
      "reason": "frozen gate acc_norm,none >= 0.70"
    }
  }
}
```

The adapter requires the task identity maps (`configs`, `versions`, `n-shot`,
`higher_is_better`, `n-samples`, and `task_hashes`) and checks the installed
`lm_eval` version, abbreviated evaluation-repository commit, and available
model/runtime identity against the artifact. The artifact's `git_hash` describes
the working repository, not reliably the installed lm-eval source, so the two
commits remain separate. Some backends omit model revision and artifact SHA from
the persisted format; those descriptor fields remain declared evidence bound to
the raw artifact hash. Aggregate lm-eval scores do not
contain a universal pass gate, so a task missing from `outcomes` becomes
`invalid`; no threshold is inferred. Every mapping must contain one of `pass`,
`fail`, `invalid`, `error`, or `skipped` and a non-empty reason. Mapping an
unknown task is rejected as a likely typo.

### vLLM bench serve

The serving descriptor has the same `source`, `identity`, `suite`, `artifact`,
and `artifact_sha256` fields, with these adapter-specific fields:

```json
{
  "adapter_version": "vllm-bench-serve/1.0.0",
  "artifact": "vllm-result.json",
  "artifact_sha256": "<sha256 of vllm-result.json>",
  "source": {
    "name": "vllm",
    "version": "<exact installed vLLM version>",
    "commit": "<exact vLLM repository commit>",
    "license": "Apache-2.0",
    "dataset_sha256": "<sha256 of the frozen workload evidence>",
    "evaluator_sha256": "<sha256 of the frozen vLLM benchmark source>",
    "invocation": "vllm bench serve --backend openai-chat --model org/model --save-result --save-detailed ..."
  },
  "identity": {
    "model_id": "org/model",
    "model_revision": "<exact revision>",
    "model_sha": "<exact model artifact SHA>",
    "runtime_name": "vllm",
    "runtime_version": "<exact server version>",
    "runtime_revision": "<exact server source or image revision>"
  },
  "suite": {
    "id": "serving-grid",
    "version": "1.0.0",
    "sha256": "<sha256 of the frozen suite definition>"
  },
  "cell_id": "ctx1024-out128-c64",
  "cell_sha256": "<sha256 of the frozen exact cell definition>",
  "endpoint_backend": "openai-chat",
  "outcome": {
    "status": "pass",
    "reason": "all frozen cell SLOs passed"
  }
}
```

The deterministic mapping takes precedence over the declared outcome:

- inconsistent request counts are `invalid`;
- upstream failures with a complete `errors` vector (`--save-detailed`) are
  `error`;
- failures without matching evidence are `invalid`;
- zero successful observations are `invalid`;
- only a complete, error-free cell may retain a declared `pass` or `fail`;
- completed work cannot be declared `skipped`.

The upstream JSON currently has no schema-version field and does not carry the
server build or model revision. This adapter therefore pins one conservative
single-run field set and records those identities from the descriptor as
declared evidence. JSONL append files, sweep summaries, multi-run summaries and
multi-turn results are rejected until separate versioned fixtures and mappings
exist. Use one descriptor per cell; do not flatten unlike cells into one score.

Unknown upstream fields are not interpreted, but are preserved byte-for-byte in
`upstream_artifact.json`. Inputs containing secret-like material are rejected;
remove credentials, not evidence, before import.

## Adding an external adapter

External imports are code-backed and versioned; a free-form descriptor is
rejected. Add one adapter constant and one deterministic mapping in
`external.py`, plus a minimal upstream JSON fixture and a test proving exact
source commit, dataset/evaluator hashes, model/runtime identity, outcome
accounting, raw-artifact preservation, and rejection before output on mismatch.
Do not download or execute the upstream tool in the adapter. New mappings stay
development-only until their methodology and license are independently
reviewed.

DeepEval 3.x is optional. CavadaLabs sets all documented local privacy controls
before import and does not log in or synchronize. Built-in deterministic
DeepEval metrics are supported; LLM-based DeepEval metrics are rejected until
they use an identity- and destination-verifying CavadaLabs judge adapter.
