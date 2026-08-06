# Threat model

Protected assets include private holdouts, customer prompts, model outputs,
retrieved context, tool traces, personal data, credentials, rubrics, signing
keys, reports, and official result integrity.

Threat actors include malicious dataset authors, compromised providers, prompt
attackers, curious operators, supply-chain attackers, insiders, compromised
judges, and models attempting to influence their evaluator.

Principal threats and controls:

| Threat | Required control |
|---|---|
| Dataset path or symlink escape | resolved local paths, regular files, no symlinks |
| Media/parser exploitation | allowlists, limits, active-content rejection, sandbox before richer parsing |
| Prompt/judge injection | fixed rubric, target identity hiding, structured output, deterministic hard gates |
| Benchmark tampering | pinned hashes, immutable run paths, bundle hashes, signature, source evidence |
| Data exfiltration | classification, offline mode, egress allowlist, authorization record, telemetry off |
| Secret or PII disclosure | secret scan, restricted artifacts, sanitized public reports, DLP hooks |
| Benchmark gaming | private holdouts, canaries, contamination record, version rotation |
| Judge bias | calibration, independent models, A/B and B/A, disagreement invalidation |
| Denial of service/cost | response limits, timeouts, rate limit, bounded concurrency and budgets |
| Dependency compromise | lockfile, CI, dependency review, SBOM, build provenance and signed release |

Residual risks include novel parser bugs, unknown attacks, provider compromise,
judge error, incomplete data coverage, operator misuse, and missing external
governance. Public multi-tenant operation requires an independent penetration
test and provisioned KMS/RBAC/WORM controls.
