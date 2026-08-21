# Two prompts by two endpoint configurations

Start two synthetic endpoints, then run the four-cell matrix:

```bash
python ../_loopback_openai.py --port 8765 & first=$!
python ../_loopback_openai.py --port 8766 & second=$!
trap 'kill "$first" "$second"' EXIT
cavada-eval plan eval.toml
cavada-eval run eval.toml
cavada-eval report runs/latest
```

Expected: four deterministic cells, per-prompt and per-target summaries, and
paired comparisons over the two shared cases.
