# CavadaLabs Official Evaluation Program

This document defines the path from a development suite to a governed,
reproducible CavadaLabs evaluation. The engine, artifact format, security
controls, and claims policy are shared. Measurement objectives, datasets,
rubrics, calibration, gates, and approvals remain specific to each suite.

`official` means conformance to the exact protocol, suite, system
configuration, population, and gates named in the report. It never means
universal correctness, safety, security, fairness, or legal certification.

## Program architecture

- Use one versioned protocol and artifact contract.
- Keep quality, performance, security, privacy, fairness, and legal evidence
  separate; never publish one universal score.
- Register each suite with a fixed measurement target, supported modality,
  population, exclusions, assurance level, and expiry policy.
- Preserve immutable inputs, raw outputs, judgments, failures, manifests,
  hashes, source revisions, and environment evidence.
- Assign accountable protocol, data, statistics, security, privacy/legal,
  release, and signing owners before approving a suite.

## Creating an official suite

1. Define the SUT boundary, intended decisions, population, deployment
   conditions, API contract, exclusions, and allowed claims.
2. Preregister constructs, primary metrics, hard gates, sampling units,
   repetitions, confidence intervals, missing-data policy, and power analysis.
3. Create versioned development, calibration, and restricted holdout splits.
   Record source, rights, personal-data class, rationale, review method, and
   provenance for every case.
4. Test exact, normalized, semantic, cross-split, and cross-suite duplication;
   record contamination evidence and holdout rotation controls.
5. Obtain blind independent labels, preserve disagreements, and adjudicate with
   qualified reviewers appropriate to each language and risk domain.
6. Qualify the exact judge identity, revision, prompt, rubric, schema,
   sampling, ensemble, and consensus configuration against human-gold data.
7. Pilot across unrelated target-model families plus positive and negative
   controls. Inspect failures, ambiguity, serving degradation, stability,
   latency, cost, and unintended solution paths.
8. Freeze dataset, rubric, analysis plan, judge configuration, thresholds, and
   evidence hashes. Reproduce from a clean environment.
9. Obtain independent statistical, security, privacy/legal, disclosure, and
   release approval for the bounded claims.
10. Publish only the sanitized export generated under `RESULTS_POLICY.md` and
    retain restricted evidence in approved immutable storage.

Any material change requires a new suite version. Any judge configuration
change requires requalification. Released datasets and rubrics are immutable.

## Suite families

The registry may describe text, multilingual, RAG, agent/tool/MCP, safety,
privacy/fairness, performance, image, audio, video, and high-impact domain
suites. A planned entry is a roadmap declaration, not implemented coverage.
Each modality needs its own safe decoder, metrics, reviewers, licensing, threat
model, and system boundary before it can be claimed as supported.

## External benchmarks

External datasets and adapters remain subject to their own licenses, access
terms, transfer restrictions, task versions, and contamination limitations.
References in the registry do not authorize redistribution or establish
coverage. Imported material must pass the source policy and external-import
validation before use.

## Current public release

The repository includes a replaceable suite template, a small synthetic
security/privacy smoke suite, and synthetic LLM-serving workloads. They are
development examples only: none is representative, calibrated, approved, or
official-capable. Users must create and govern a versioned suite for their
actual measurement target.
