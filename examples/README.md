# Client examples

These examples use synthetic data and either a trusted local callable or the
shared loopback OpenAI-compatible server. They create client/candidate evidence,
not official results.

1. [`01_prompt_endpoint`](01_prompt_endpoint/) — JSONL, prompt, endpoint,
   deterministic evaluator, report, and verification.
2. [`02_prompt_matrix`](02_prompt_matrix/) — two prompts by two endpoint
   configurations and paired cell comparisons.
3. [`03_dataset_factory`](03_dataset_factory/) — dataset, target, and evaluator
   callables in one local Python file.
4. [`04_callable_target`](04_callable_target/) — async callable target.
5. [`05_client_benchmark`](05_client_benchmark/) — client concurrency sweep
   using the existing performance core.

Start the loopback server from an endpoint example with:

```bash
python ../_loopback_openai.py --port 8765
```

It binds only to `127.0.0.1`, needs no key, and supports normal chat completion
and SSE streaming requests. It is a test fixture, not a model server.
