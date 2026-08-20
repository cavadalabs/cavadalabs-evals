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
| Benchmark tampering | pinned hashes, immutable run paths, closed bundles, layered semantic reconstruction, source evidence |
| Self-asserted qualification or approval | closed qualification package, transitive hashes, metric/gate reconstruction, independent approver evidence |
| Coherent hashes over contradictory evidence | mandatory behavior semantic reconstruction for candidate and official bundles |
| Public archive substitution | deterministic content-addressed tar, strict closed file set, append-only registry binding |
| Forged public provenance | exact GitHub Artifact Attestation subject and canonical workflow verification; HMAC is internal only |
| Registry history rewrite | immutable archive digests and append-only records and lifecycle events |
| Data exfiltration | classification, offline mode, egress allowlist, authorization record, telemetry off |
| Secret or PII disclosure | secret scan, restricted artifacts, sanitized public reports, DLP hooks |
| Benchmark gaming | private holdouts, canaries, contamination record, version rotation |
| Judge bias | calibration, independent models, identity blinding, disagreement invalidation |
| Denial of service/cost | response limits, timeouts, rate limit, bounded concurrency and budgets |
| Dependency compromise | lockfile, CI, dependency review, SBOM, build provenance and signed release |

Residual risks include novel parser bugs, unknown attacks, provider compromise,
judge error, incomplete data coverage, operator misuse, and missing external
governance. Public multi-tenant operation requires an independent penetration
test and provisioned KMS/RBAC/WORM controls.

Offline registry checks verify the archive bytes, safe paths, hashes, behavior
semantics, assurance, release binding, and expected attestation identity. They
do not prove a Sigstore signature. `gh attestation verify` performs the separate
online GitHub verification; a downloaded bundle may support a separately
configured offline cryptographic check in the future. The current public
registry contains no real result.

The bundled Git object proof binds the declared commit to the exact executed
Python and `uv.lock` bytes. It does not by itself prove that commit belongs to
the public CavadaLabs repository; repository and workflow provenance remains an
online attestation check.

Paired statistical comparison of already evaluated outcomes is supported.
Blinded output judging with retained A/B and B/A orders is not supported.
Private AI is outside the canonical line, and performance official assurance is
outside the behavior M1 milestone.
