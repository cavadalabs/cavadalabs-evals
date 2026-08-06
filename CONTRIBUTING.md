# Contributing

Start with the offline golden path:

```bash
uv sync
uv run cavada-eval demo
uv run pytest -q tests/test_demo.py
```

All code, configuration, documentation, errors, and report labels must be in
English. Good first contributions include documentation fixes, deterministic
metric edge cases, adapter contract fixtures, report accessibility, and
additional synthetic demo cases. Look for `good first issue` and `help wanted`
on GitHub.

## Repository map

- `src/cavada_eval/`: CLI, execution, metrics, statistics, reports, and adapters.
- `suites/`: immutable suite examples, the offline demo, and the secure template.
- `performance/`: generation-only serving plans and runtime example.
- `schemas/`: versioned artifact and governance contracts.
- `tests/`: focused regression and integrity tests.
- `docs/`: architecture, operations, methodology, security, and compliance notes.
- `program/` and `standards/`: official-program policy and control mappings.

## Make a focused change

Run one test while iterating:

```bash
uv run pytest -q tests/test_performance.py::test_collapsed_sse_decode_timing_is_omitted
```

Before opening a pull request, run:

```bash
uv run pytest
uv run ruff check .
uv run mypy src
uv run cavada-eval doctor
uv build
```

To add a deterministic metric, implement it in `src/cavada_eval/metrics.py`,
record its definition and version, add one edge-case test, and state whether a
failure is hard or soft. To add an adapter, document capabilities,
authentication, egress, identity verification, timeouts, response limits, and
data-transfer behavior; add a local contract fixture before integration tests.

To propose a suite, copy `suites/template/`, create a new semantic version, and
complete its dataset card and review evidence. Never modify a released dataset
or rubric. Preserve the old release, recompute hashes, and recalibrate.

Pull requests touching `PROTOCOL.md`, `AGENTS.md`, `schemas/`, `standards/`,
suite governance, signing, or official-run gates require designated protocol
and security owners. Never add real secrets, customer data, private holdouts,
or licensed third-party datasets to a public pull request.

Unless explicitly marked otherwise, an intentional contribution submitted for
inclusion is licensed under Apache License 2.0 as described in `LICENSE`.
