# Examples

## Offline first run

Produce and verify a complete development bundle without credentials or
external network access:

```bash
uv run python examples/offline_demo.py
```

The script starts a temporary loopback fixture, evaluates the one-case suite
template, closes the immutable artifact bundle, verifies it, and prints its
path. It exercises transport and protocol plumbing only: its fixture outputs
are not model-quality evidence and can never be promoted to an official result.

## Text case fragments

These text fragments demonstrate the maintained case model. They are not
approved datasets.

Structured extraction:

```json
{"input":"Extract the order ID as JSON.","expected_json":true,"json_schema":{"type":"object","required":["order_id"],"properties":{"order_id":{"type":"string"}},"additionalProperties":false},"expected_json_value":{"order_id":"A-42"}}
```

Conversation (the final user content must exactly equal `input`):

```json
{"input":"What did I choose?","messages":[{"role":"user","content":"I choose blue."},{"role":"assistant","content":"Noted."},{"role":"user","content":"What did I choose?"}]}
```
