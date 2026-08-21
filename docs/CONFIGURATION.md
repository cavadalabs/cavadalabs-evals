# Experiment plan configuration

Client experiment plans are strict TOML. Unknown fields, wrong types,
non-finite values, duplicate names, unsafe paths, and secret-like values fail
closed. Version 1 is the only supported client plan version.

## Complete shape

```toml
version = "1"
name = "customer-support"
description = "Compare customer-support prompts on the approved local cases."
profile = "client" # quick | client
seed = 42

[dataset]
type = "jsonl" # jsonl | csv | factory
path = "data/support.jsonl"
classification = "synthetic" # public | synthetic | internal | confidential | restricted
id_field = "id"
# split = "holdout"
# split_field = "split"
# sample = 100
# limit = 500

[[prompts]]
name = "baseline"
template = "{question}"

[[targets]]
name = "qwen"
type = "openai-compatible"
base_url = "http://127.0.0.1:8000/v1"
model = "qwen3"
revision = "local-build-1"
api_key_env = "LOCAL_API_KEY"
capabilities = ["text"]
stream = false

[[evaluators]]
type = "exact-match"
expected_field = "answer"

[run]
concurrency = 4
timeout_seconds = 60
retries = 2
repetitions = 1
max_cases = 500
max_requests = 10000
max_cost = 0
max_tokens = 0
max_elapsed_seconds = 0
rate_limit = 0
fail_fast = false
resume = false
# external_authorization = "authorization.json"

[output]
directory = "runs"
formats = ["json", "html"]
```

Zero disables an optional budget. `max_requests` is always positive and is
checked during planning. `run.retries` applies to every endpoint in the matrix.

## Dataset

Use exactly one file or factory:

```toml
[dataset]
type = "factory"
factory = "my_project.datasets:support_dataset"
classification = "internal"
```

Factories are imported from the project containing the plan, run during
planning, and treated as trusted local code. Selection order is deterministic:
materialize, validate IDs, filter `split`, seeded `sample`, then `limit` and
`run.max_cases`. JSONL must be strict UTF-8 JSON; CSV uses its header names.

## Prompts

Each prompt needs a unique `name` and exactly one rendering mode.

Template:

```toml
[[prompts]]
name = "concise"
system = "Answer correctly and concisely."
template = "{question}"
```

Static text:

```toml
[[prompts]]
name = "health-check"
static = "Reply with READY."
```

Chat:

```toml
[[prompts]]
name = "chat"
messages = [
  { role = "system", content = "Answer from the supplied facts." },
  { role = "user", content = "{question}" },
]
```

Trusted callable:

```toml
[[prompts]]
name = "custom"
factory = "custom:render_prompt"
```

The prompt name, frozen content or callable source identity, and hash are part
of cell identity.

## Targets

OpenAI-compatible endpoint:

```toml
[[targets]]
name = "local-model"
type = "openai-compatible"
base_url = "http://127.0.0.1:8000/v1"
model = "qwen3"
revision = "server-build-42"
api_key_env = "LOCAL_API_KEY"
capabilities = ["text"]
```

The base URL cannot contain credentials, a query, or a fragment. Secrets remain
in environment variables and are redacted from artifacts.

Trusted callable:

```toml
[[targets]]
name = "local-rag"
factory = "custom:local_rag"
model = "local-rag"
revision = "git-abc123"
capabilities = ["text", "retrieval"]
```

Recorded target:

```toml
[[targets]]
name = "recorded"
type = "recorded"
path = "data/responses.jsonl"
model = "recorded-fixture"
revision = "fixture-1"
```

Each recorded row has one `case_id` and a `response`, for example:

```json
{"case_id":"ticket-001","response":{"output":"Use the reset link.","usage":{"total_tokens":12}}}
```

For observed endpoint pricing, add all fields below. This is evidence metadata,
not a built-in price catalog:

```toml
[targets.pricing]
currency = "USD"
source = "contract-2026-08"
effective_at = "2026-08-01T00:00:00Z"
input_per_million = 0.10
output_per_million = 0.40
```

## Evaluators

Supported config types are:

- `exact-match` and `normalized-match`;
- `contains` and `forbidden-terms`;
- `regex`;
- `json-valid` and `json-fields`;
- `token-f1`;
- `retrieval`;
- a trusted callable via `factory`.

Examples:

```toml
[[evaluators]]
type = "contains"
required = ["reset link"]
forbidden = ["password is"]
case_sensitive = false

[[evaluators]]
type = "retrieval"
expected_field = "documents"
k = 5
threshold = 1.0
precision_threshold = 0.8
```

An evaluator's required capabilities must be declared by every paired target.
Missing evidence is invalid or unsupported; it is never silently scored as
zero.

## Profiles and assurance

`quick` and `client` use the same runner and verifier with different policy
labels. `client` is the recommended default. The simple facade deliberately
rejects `profile = "official"`; official evidence requires the advanced,
versioned suite workflow and its independent assurance artifacts.
