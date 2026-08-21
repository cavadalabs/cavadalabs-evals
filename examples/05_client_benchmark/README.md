# Client endpoint benchmark

The environment value below is a disposable loopback placeholder. It is not
stored in the result or sent outside the machine.

```bash
python ../_loopback_openai.py --port 8765 &
server_pid=$!
trap 'kill "$server_pid"' EXIT
export CAVADA_EXAMPLE_KEY=synthetic-loopback-only
cavada-eval benchmark benchmark.toml --plan
cavada-eval benchmark benchmark.toml --output-root runs
```

Expected: concurrency 1 and 2 cells, separate warm-up and measured ledgers,
latency/throughput/error metrics, and a small-sample warning. This client
benchmark is not performance official evidence and does not score quality.
