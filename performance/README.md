# Performance package

This directory contains versioned, non-secret inputs for the dedicated LLM
serving engine. `plans/` defines preregistered cells and gates; `workloads/`
contains hash-pinned public or synthetic prompts. Machine/runtime descriptors
belong outside the repository and start from `runtime.example.toml`.

## Synthetic workload card

- ID/revision: `llm-serving-synthetic-v1@1.0.0`
- Owner/origin: CavadaLabs, generated in-house on 2026-08-06
- License: repository Apache License 2.0
- Classification: synthetic; no intended personal data
- Purpose: prompt-length scaling, long-context serving, latency, throughput,
  capacity, and tokenizer-difference observation
- Contents: repeated neutral filler plus a fixed instruction at declared 128,
  512, 2k, 8k, 32k, 64k, 128k, and 256k input-token targets
- Known limitation: declared token targets are approximate across tokenizers;
  the reference plan is therefore `iso-prompt`, not strict `iso-token`
- Prohibited use: response-quality, safety, factuality, privacy, fairness, legal
  compliance, or exact equal-token claims

Changing any row requires a new workload revision, a new hash in a newly
versioned plan, and updated documentation. Never edit released inputs in place.
