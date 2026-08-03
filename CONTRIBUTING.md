# Contributing

All code, configuration, documentation, errors, and report labels must be in
English. Run `uv run pytest`, `uv run ruff check .`, `uv run mypy src`,
`uv run cavada-eval doctor`, and `uv build` before requesting review.

Never modify a released dataset or rubric. Copy the suite to a new semantic
version, document the change, recompute hashes, recalibrate, and preserve the
old release. New metrics require a definition, version, edge-case tests,
parameters in the manifest, and an explicit hard/soft-fail policy. New adapters
must document capabilities, authentication, egress, identity verification,
timeouts, response limits, and data-transfer behavior.

Pull requests touching `PROTOCOL.md`, `AGENTS.md`, `schemas/`, `standards/`,
suite governance, signing, or official-run gates require designated protocol
and security owners. Never add real secrets, customer data, private holdouts,
or licensed third-party datasets to a public pull request.
