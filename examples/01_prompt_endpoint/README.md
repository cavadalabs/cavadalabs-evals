# Prompt + endpoint + JSONL

This uses a synthetic loopback endpoint and makes no external request.

```bash
python ../_loopback_openai.py --port 8765 &
server_pid=$!
trap 'kill "$server_pid"' EXIT
cavada-eval plan eval.toml
cavada-eval run eval.toml
cavada-eval report runs/latest
cavada-eval verify runs/latest
```

Expected: one cell, two cases, a verified client experiment, and
`runs/prompt-endpoint/<experiment-id>/report.html`.
