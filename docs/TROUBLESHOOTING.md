# Troubleshooting

Run `cavada-eval doctor` first. It reports missing schemas, optional engines,
and environment prerequisites without printing secret values.

- **Configuration error:** run `cavada-eval validate SUITE` and fix every
  reported schema, path, identity, governance, or capability error.
- **Transport failure:** confirm the endpoint, its model identity response,
  content type, body limit, authorization environment variable, and allowlist.
- **Official run refused:** official mode requires a clean Git tree, pinned
  dataset and rubric hashes, approved lifecycle evidence, identity checks,
  storage attestation for non-public data, and explicit egress authorization.
- **Budget exhausted:** resume the preserved run with a larger explicit budget;
  completed observations are reused and are not duplicated.
- **Bundle verification failed:** treat the bundle as untrusted. Do not edit it;
  rerun from the immutable suite or restore it from the governed evidence store.
- **Optional DeepEval import failed:** install the locked `deepeval` dependency
  group. CavadaLabs disables telemetry, cloud sync, dotenv, and key-file loading
  before importing it.

Never work around a failed official preflight. Candidate runs may diagnose the
problem, but cannot be relabeled as official evidence.
