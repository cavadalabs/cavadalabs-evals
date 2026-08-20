# Changelog

## Unreleased (0.4.0.dev0)

- Started the canonical `next/0.4` line from the public `main` history for the
  official-conformance milestone.
- Added one fail-closed behavior verifier shared by CLI verification, runner
  finalization, release, and registry paths. Verification result v2 separates
  integrity, reconstructed semantics, and requested assurance for every known
  behavior bundle; unknown artifacts are unsupported rather than vacuously
  semantic-valid.
- Added a strict, closed judge-qualification evidence package that preserves
  the qualification run, corpus and support bytes, blueprint, approvals,
  recorded judge evidence, and approver qualifications. Qualification metrics
  and gates are reconstructed from bytes without trusting `passed=true`, and
  base semantic verification avoids recursive qualification.
- Added the empty, strict results registry v2 with deterministic
  content-addressed public evidence tar archives, append-only records and
  lifecycle events, canonical behavior/release verification, and fail-closed
  non-rankable conformance records. Historical empty registry v1 remains
  readable.
- Added exact official public-archive attestation in the release workflow using
  the already pinned GitHub Artifact Attestations action. Each newly added
  archive is reconstructed and content-addressed first; synthetic conformance
  archives are excluded. Offline validation checks the expected subject
  binding; real public records require separate online GitHub/Sigstore
  verification. HMAC remains an internal integrity control.
- Added public release approval v2 with exact protocol binding, explicit
  revocation state, and claim-free conformance-fixture approval.
- Added a fully offline, synthetic, non-claiming official-path conformance fixture.
  It tests the software path but is not an approved suite, official result,
  public release, independent reproduction, or registry record.
- Added immutable preregistration approvals, reconstructible calibration,
  versioned strict official schemas, and released-asset byte checks.
- `doctor` now distinguishes structural readiness, official-engine readiness,
  verified official suites, and overall official readiness. Current state is
  engine-ready with zero verified official suites and `official_ready=false`.
- Withdrew the public pairwise-judging command until its A/B and B/A runtime is
  qualified; paired statistical comparison of completed runs remains supported.
- Private AI remains outside the canonical line. Performance official assurance
  is outside this behavior milestone.
- Non-empty DeepEval metric-engine behavior runs now fail before network access
  until their engine evidence has canonical semantic reconstruction. Progress
  events remain integrity-checked diagnostic evidence and never drive claims.

- Distinguish configured server context capacity, prompt target, actual provider
  input, requested output, and actual output in cross-context performance
  matrices and report schema 1.3.1.

All notable changes follow semantic versioning. Protocol, engine, schema,
report, and suite versions are released independently.

- Performance matrices can attach validated, hash-preserved per-run GPU
  telemetry and report lifecycle energy, board power, utilization, VRAM, and
  thermal evidence without using temperature as an execution gate.
- Added `cavada-eval perf matrix` for verified cross-context model × topology
  reports with completeness gates, dense HTML/PDF matrices, exact CSV/JSON,
  server-timing eligibility, and bootstrap intervals for median metrics.
- Performance protocol 1.1 establishes an explicit token-rate contract:
  server-native generation and prompt-processing rates are recomputed from raw
  provider counts/timings, client-derived generation remains a cross-check,
  and end-to-end throughput is no longer presented as generation speed.
- Performance comparisons now provide dense model-by-cell metric matrices and
  a complete sticky-header results grid in HTML, with matching matrix tables in
  PDF and the expanded exact metrics preserved in JSON and CSV.

## 0.3.1 - 2026-08-06

- Added a complete offline `cavada-eval demo`, a deterministic synthetic demo
  suite, a generated result visual, a contributor map, and a short roadmap.
- Performance protocol 1.0.1 now omits misleading client decode timing when a
  buffered SSE burst conflicts with provider-reported generation duration.

## 0.3.0 - 2026-08-06

- Changed the source-code license from MIT to Apache License 2.0 before public
  community contributions.
- Added versioned smoke, quick, standard, and reference presets with stable,
  stratified, scenario-group-safe quality-suite selection and dedicated quick
  and standard LLM serving plans.
- Added community governance, conduct, support, result/trademark policy,
  citation metadata, issue and pull-request templates, dependency updates, and
  a tag-gated GitHub release workflow with provenance and SBOM attestations.
- Added the dedicated generation-only LLM serving performance protocol, strict
  plan/runtime/workload validation, closed/open-loop load generation, 128k/256k
  context and 8k output reference cells, tail latency/goodput/cost reporting,
  verified artifacts, exact-cell comparison, CLI commands, and Codex workflow.
- Official execution now requires an effective engagement record bound to the
  exact suite and SUT; public export requires a separate post-run approval bound
  to the verified bundle, claims, expiry, and independent review decisions.

## 0.2.0 - 2026-08-03

- Added the normative protocol, implementation checklist, schemas, suite lifecycle, governance validation, normalized duplicate detection, and secure multimodal assets.
- Added deterministic structured, retrieval, transcript, tool, and text metrics.
- Added streaming performance evidence, budgets, bounded concurrency, retry, rate limiting, crash resume, paired statistics, and blind A/B plus B/A evaluation.
- Added signed/verifiable bundles, restricted/public HTML and PDF reports, SVG figures, JUnit, comparison, export, and control-evidence reports.
- Added secure optional DeepEval integration with telemetry and cloud sync disabled before import.

## 0.1.0 - 2026-08-03

- Initial local-first CavadaLabs evaluation protocol and candidate suite support.
