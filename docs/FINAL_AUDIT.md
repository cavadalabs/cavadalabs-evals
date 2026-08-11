# Repository readiness assessment

Status snapshot: 2026-08-07. Reviewed package version: `0.3.0` (alpha).

## Conclusion

The repository contains a substantial local implementation of the behavior and
LLM serving-performance protocols. It is not yet ready for an official public
benchmark release.

No suite in `program/registry.toml` is currently marked `official_capable`, and
`results/registry.json` contains no accepted result or independent
reproduction. The publication inventory also contains unresolved blocking
decisions. Therefore this repository does not currently substantiate an
“Official CavadaLabs result,” a production-readiness claim, or a 10/10
readiness score.

## Capability status

| Area | Assessment |
|---|---|
| Protocol | Versioned behavior and serving-performance protocols exist, with fail-closed rules and separate claims. |
| Implementation | Core validation, execution, evidence preservation, comparison, and export paths exist and are exercised by repository tests. A clean-checkout verification is still required for any release candidate. |
| Hardware science | System configuration evidence and client-side serving metrics exist. Calibrated synchronized utilization, power, energy, network, and load-generator evidence does not. |
| Results presentation | HTML, PDF, JSON, JSONL, CSV, JUnit, and accessible figures are generated and covered by local visual, responsive, structural-accessibility, and publication-path QA. Independent accessibility conformance has not been established. |
| Onboarding | Packaging, CLI help, examples, and CI configuration exist. Hosted installation and release workflows have not been demonstrated by an approved public release. |
| Public credibility | No accepted public baseline or independent reproduction is registered. |
| Publication | Blocked by the current decisions in `docs/PUBLICATION_INVENTORY.md` and by the absence of required organizational and independent evidence. |

## What repository checks can establish

The test, lint, type, schema, secret, build, distribution, registry, and mock
endpoint checks can establish that the corresponding implementation behaves as
specified for the tested commit. Bundle verification can establish closed-set
file integrity and hashes; optional HMAC can establish integrity for holders of
the shared key.

Those checks do not establish dataset rights, representative sampling, human
label validity, judge validity, legal compliance, production security,
organizational independence, hardware calibration, accessibility conformance,
or an asymmetric release identity.

## Release blockers

- Complete the ownership, privacy, contractual, redistribution, organization,
  and historical-identity decisions in `docs/PUBLICATION_INVENTORY.md`.
- Complete independent dataset/rubric review, calibration, judge qualification,
  statistical review, security review, and reproduction for any suite proposed
  as official.
- Provision and evidence the restricted storage, authorization, signing, and
  operational controls required by the applicable protocol.
- Validate the exact release commit from a clean checkout and preserve the
  resulting artifacts and provenance.
- For hardware, utilization, or energy claims, add calibrated synchronized
  collectors and validate the benchmark topology and load generator.

## Sources of truth

- Normative behavior rules: `PROTOCOL.md` and `AGENTS.md`.
- Normative serving rules for new reference runs:
  [Performance Protocol v2](../PERFORMANCE_PROTOCOL_V2.md); commit-anchored
  [v1.0 protocol](../PERFORMANCE_PROTOCOL_V1_0.md) artifacts remain byte-frozen
  for hash-only verification of their recorded bundles.
- Program and suite status: `program/registry.toml` and each `suite.toml`.
- Public result status: `results/registry.json`.
- Publication decision: `docs/PUBLICATION_INVENTORY.md`.
- Current capability map and verification commands:
  `IMPLEMENTATION_CHECKLIST.md`.

An official result means conformance to the exact named protocol, suite,
configuration, evidence, and gates. It is not certification, accreditation,
legal compliance, or a universal quality or safety claim.
