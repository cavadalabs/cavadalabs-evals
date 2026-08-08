# Changelog

All notable changes follow semantic versioning. Protocol, engine, schema,
report, and suite versions are released independently.

## Unreleased

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
