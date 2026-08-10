# Threat model

Protected assets include private holdouts, customer prompts, model outputs,
retrieved context, tool traces, personal data, credentials, rubrics, signing
keys, reports, and official result integrity.

Threat actors include malicious dataset authors, compromised providers, prompt
attackers, curious operators, supply-chain attackers, insiders, compromised
judges, and models attempting to influence their evaluator.

Principal threats and current boundaries:

| Threat | Repository control | External boundary |
|---|---|---|
| Dataset path or symlink escape | resolved local paths, regular-file checks, no symlinks | operating-system and storage policy |
| Media/parser exploitation | allowlists, limits, magic-byte checks, active-content rejection | sandbox required before richer parsing |
| Prompt/judge injection | fixed rubric, target-identity hiding, structured output, deterministic hard gates | qualified judges and independent review |
| Benchmark tampering | pinned hashes, unique run paths, closed-set bundle hashes, source evidence | immutable storage and organizational signing |
| Data exfiltration | classification, loopback-only mode, host allowlist, authorization record | enforceable network policy, DLP, and approved destinations |
| Secret or PII disclosure | repository secret scan and restricted/public artifact split | historical scan, DLP, privacy review, and incident response |
| Benchmark gaming | contamination metadata and versioned rotation fields | private holdouts, canaries, and controlled access |
| Judge bias | calibration interfaces, independent-model support, A/B and B/A, disagreement handling | human gold data and qualification approval |
| Denial of service or cost | body limits, timeouts, rate limits, bounded concurrency and budgets | provider and infrastructure limits |
| Dependency compromise | lockfile, pinned CI actions, dependency review configuration, SBOM and provenance scripts | trusted builders, signed releases, and response process |

Residual risks include novel parser bugs, unknown attacks, provider compromise,
judge error, incomplete data coverage, operator misuse, and missing external
governance. Public multi-tenant operation requires an independent penetration
test and provisioned KMS/RBAC/WORM controls.

Optional HMAC protects integrity for holders of one shared secret; it is not an
asymmetric public release identity. Configuration records and attestations are
claims to verify, not proof that deployment controls are operating.
