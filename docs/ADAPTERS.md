# Execution boundaries

The maintained benchmark surface is text behavior and generation-only LLM
serving. Media parsing and capability validation remain fail-closed trust
boundaries; they are not public benchmark support.

Target and judge transports declare endpoint protocol, authentication,
streaming, usage reporting, identity and revision evidence, response limits,
retryable statuses, timeouts, and data destinations. Unsupported content fails
before a request; raw protocol evidence is preserved.

## Private AI Workspace target

`target.kind = "private-ai"` evaluates the complete CavadaLabs Private AI
Workspace path instead of calling its underlying model endpoint. The adapter
creates private browser-folder sources, uploads a hash-pinned corpus, waits for
the source job and document indexing, then sends every case through
`/v1/chat/rag`. It preserves the native NDJSON events and structured citation
objects; it never derives citations by parsing answer text.

```toml
[target]
kind = "private-ai"
capabilities = ["text"]
corpus = "corpus.jsonl"
corpus_sha256 = "<lowercase SHA-256>"
workspace_id_env = "PRIVATE_AI_WORKSPACE_ID"
reasoning_mode = "instant"
retrieval_limit = 12
```

The corpus is JSONL with one regular, in-suite asset per row. All four fields
are required and every asset hash is checked before network access:

```json
{"id":"policy","source":"approved","path":"documents/policy.txt","sha256":"<lowercase SHA-256>"}
```

The bearer token comes from the run's `--target-key-env`; the optional
workspace header comes from `target.workspace_id_env`. Neither value is written
to run artifacts. `target_setup.json` records the adapter version, corpus and
asset hashes, created source IDs, and credential-free request evidence.
Use a dedicated evaluation workspace because each run creates isolated private
sources and retains them for audit.

The adapter accepts only text cases in this version. A completed `done` event,
non-empty answer, structured stream, and non-error terminal status are required.
`permission_denied`, `retrieval_unavailable`, and `runtime_unavailable` are
execution errors, never scored answers. Model identity is taken from the final
Private AI usage event and remains subject to the runner's exact expected-model
check.

Private AI targets are candidate-only in this adapter version. Official runs
fail closed until the protocol defines canonical corpus snapshots and setup
evidence; a verified candidate bundle must not be presented as an official
result.
