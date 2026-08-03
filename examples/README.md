# Case examples

These fragments demonstrate the case model. They are not approved datasets.

Text/structured extraction uses `expected_output`, `json_schema`, regex, length,
numeric tolerance, and required/forbidden terms. RAG adds
`expected_retrieval_ids`, `retrieval_k`, `retrieval_minimums`,
`retrieval_context`, and citation expectations. Agents add `expected_tools`,
`forbidden_tools`, and `exact_tool_order`. ASR adds `expected_transcript` and
maximum word/character error rates.

Multimodal input example:

```json
{
  "id": "image-001",
  "input": [
    {"type": "text", "text": "Read the sign."},
    {
      "type": "image",
      "asset": "assets/sign.png",
      "mime_type": "image/png",
      "sha256": "64 lowercase hex characters",
      "license": "dataset-specific license",
      "origin": "documented source",
      "personal_data": "none"
    }
  ],
  "language": "en",
  "locale": "en-US",
  "split": "practice"
}
```

Conversation turns, agent traces, MCP calls, generated image/audio/video outputs,
and sandboxed code execution require an adapter whose capability declaration
matches the suite. The core never pretends unsupported evidence was evaluated.

## Minimal profile fragments

Structured extraction:

```json
{"input":"Extract the order ID as JSON.","expected_json":true,"json_schema":{"type":"object","required":["order_id"],"properties":{"order_id":{"type":"string"}},"additionalProperties":false},"expected_json_value":{"order_id":"A-42"}}
```

RAG:

```json
{"input":"Which policy applies?","expected_retrieval_ids":["policy-7"],"retrieval_k":3,"retrieval_minimums":{"recall_at_k":1.0},"citation_required":true}
```

Conversation (the final user content must exactly equal `input`):

```json
{"input":"What did I choose?","messages":[{"role":"user","content":"I choose blue."},{"role":"assistant","content":"Noted."},{"role":"user","content":"What did I choose?"}]}
```

Agent/tool evidence:

```json
{"input":"Look up order A-42 without changing it.","expected_tools":["get_order"],"forbidden_tools":["delete_order"],"exact_tool_order":["get_order"],"expected_tool_arguments":{"get_order":{"id":"A-42"}},"max_tool_calls":1}
```

Audio ASR uses an `audio` content part plus:

```json
{"expected_transcript":"the expected words","max_word_error_rate":0.1,"max_character_error_rate":0.05}
```

Video input uses `{ "type": "video", "asset": "assets/clip.mp4", "mime_type": "video/mp4", "sha256": "..." }`.
Video and generated image/audio outputs are deliberately blocked for official
use until a pinned sandboxed adapter validates their containers and metrics.

Compliance evidence is supplied as JSONL to `cavada-eval controls`:

```json
{"control_id":"GDPR-35","status":"manual_required","owner":"privacy-owner","applicability":"assessment pending","artifact":"DPIA-record-id","effective_at":"2026-08-03","expires_at":"2027-01-01","residual_risk":"Not accepted"}
```
