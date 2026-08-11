# Troubleshooting

Run `cavada-eval doctor` first. It performs a fast local-environment check and
reports development and official readiness separately without printing secret
values. Run `cavada-eval program` for the complete, slower registry and
cross-suite validation.

- **Configuration error:** run `cavada-eval validate SUITE` and fix every
  reported schema, path, identity, governance, or capability error.
- **Transport failure:** confirm the endpoint, its model identity response,
  content type, body limit, authorization environment variable, and allowlist.
- **Official run refused:** official mode requires a clean Git tree, pinned
  dataset and rubric hashes, approved lifecycle evidence, identity checks,
  storage attestation for non-public data, and explicit egress authorization.
- **Budget exhausted:** preserve the failed bundle and start a new run with a
  larger explicit budget. Run directories are immutable and cannot be resumed.
- **Bundle verification failed:** treat the bundle as untrusted. Do not edit it;
  rerun from the immutable suite or restore it from the governed evidence store.

Never work around a failed official preflight. Candidate runs may diagnose the
problem, but cannot be relabeled as official evidence.
