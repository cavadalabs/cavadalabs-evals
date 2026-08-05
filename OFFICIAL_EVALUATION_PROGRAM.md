# CavadaLabs Official Evaluation Program

This document is the implementation roadmap for turning the evaluation engine
into a governed family of high-assurance suites. The engine, artifact format,
security controls, and claims protocol are shared. Measurement objectives,
datasets, rubrics, calibration, gates, and approval evidence remain specific to
each suite.

Status:

- `[x]` repository evidence exists and is verified.
- `[ ]` repository work remains.
- `[!]` accountable external evidence or authority is required.

No suite result establishes universal correctness, safety, security, fairness,
or legal compliance. `official` means conformance to the exact protocol, suite,
system configuration, population, and gates named in the report.

## 1. Program architecture

- [x] Use one CavadaLabs protocol and artifact contract.
- [x] Keep deterministic, judge, statistical, performance, security, and
  compliance evidence separate.
- [x] Add a machine-readable suite registry and support matrix.
- [x] Add a program-level version and compatibility policy.
- [x] Define common assurance levels for development, candidate, calibrated,
  approved, and independently reproduced evidence.
- [x] Define a common naming and versioning policy for modular suites.
- [x] Define deprecation, revocation, incident correction, and result-expiry
  policies.
- [!] Assign protocol owner, data steward, statistical reviewer, security owner,
  privacy/legal owner, release approver, and signing authority.

Planned suite families:

```text
core-assistant-text
multilingual-text
rag-system
agent-and-mcp
safety-security
privacy-fairness
performance-cost
vision-language
audio-language
video-language
image-generation
domain-healthcare
domain-legal
domain-finance
domain-education
domain-public-sector
```

These suites may share cases only through explicitly versioned source modules.
They must not emit one combined universal score.

## 2. First release: `cavada-core-assistant-text-v1`

The first high-assurance suite evaluates a general-purpose conversational
assistant through a fixed text API contract. It covers English and Italian,
single-turn and multi-turn interactions, and no external tools or retrieval.
RAG, agents, MCP, and multimodal systems receive separate suites because their
scaffolding changes the measurement target.

### Measurement specification

- [x] Define the intended users, deployment contexts, exclusions, and decisions
  supported by results.
- [x] Define the SUT boundary, standard system prompt policy, API contract,
  context policy, reasoning controls, refusal policy, and token budget.
- [x] Define measurement constructs and observable criteria.
- [x] Define quality, instruction following, factuality, abstention, robustness,
  privacy, security, safety, fairness, over-refusal, and multi-turn modules.
- [x] Define English and Italian locale coverage using native authoring and
  review; do not treat machine translation as equivalent evidence.
- [x] Define realistic, best-case, worst-case, and adversarial operating
  conditions.
- [x] Define allowed claims, prohibited claims, limitations, and result expiry.

### Statistical design

- [x] Predeclare one primary metric and any hard gates per construct.
- [x] Derive sample sizes from the desired confidence-bound claims and minimum
  detectable effects.
- [x] Define independent sampling units and correlated conversation/scenario
  groups.
- [x] Define repetitions, stochastic-variation decomposition, bootstrap seeds,
  and confidence levels.
- [x] Define paired comparison, non-inferiority, multiple-testing, and missing
  evidence policies.
- [x] Prevent arbitrary aggregation across unrelated constructs.
- [x] Publish the power analysis and threshold rationale before target pilots.
- [!] Obtain independent statistical review of the frozen analysis plan.

### Dataset and holdout design

Development progress: version `0.8.0` now contains 404 versioned synthetic
public/practice rows representing 328 independent primary scenarios with
balanced EN/IT and module coverage. The 76 required variants cannot increase
statistical sample size. They remain
unreviewed, public, underpowered development material; calibration and private
holdout authoring have not started. Every active case now carries explicit
mandatory criteria passed to the judge, with deterministic references where
the requested output is unambiguous. The practice split now uses distinct
scenarios and token-containment audit reports zero candidates at the declared
0.95 threshold. Both splits still share one synthetic authoring process;
independent review and deeper semantic-contamination analysis remain required.
Forty-four matched benign cases now pair every refusal across ten major privacy,
security, and safety categories, both languages, and both splits. The immutable
`review/author-qa-0.8.0.json` ledger applies deterministic
per-case solvability, leakage, shortcut, grader-gaming, and evaluation-awareness
checks, verifies complete refusal-neighbor coverage, and passes with zero
automated errors. The retained `0.5.0` ledger records the two factuality
shortcut failures that caused the corrective release. These are reproducible
development evidence only and do not replace independent review.
Official validation now also requires a hash-pinned semantic detector identity,
revision, present evidence report, comparison-corpus and candidate-pair hashes,
and completed independent cross-split/cross-suite review. The evidence schema
and fail-closed verifier exist; the approved embedding analysis has not yet been
performed.
The active development set also includes 40 independent synthetic
domain-and-register shift scenarios represented by 44 linked probes. Paired
reporting is implemented, but this is designed construct coverage rather than
representative deployment-shift evidence.

- [x] Create a case blueprint by construct, category, severity, language,
  locale, expected behavior, difficulty, and scenario group.
- [ ] Create separate public practice, calibration, private holdout, and
  restricted adversarial-holdout splits.
- [x] Include benign near-neighbors for every major refusal category to measure
  over-refusal.
- [x] Include deterministic, subjective, boundary, multilingual, multi-turn,
  perturbation, and distribution-shift cases.
- [x] Record source, license, authorship, rationale, ambiguity, review method,
  personal-data class, and weight for every case.
- [ ] Add unique holdout canaries, exposure records, rotation dates, and a
  contamination-response policy.
- [ ] Test exact, normalized, semantic, cross-split, and cross-suite duplicates.
- [x] Test solvability, leakage, shortcuts, grader gaming, and evaluation
  awareness.
- [!] Provision restricted storage before creating the true private holdout.
- [!] Approve every third-party license and personal-data basis before use.

### Rubric and independent labels

- [x] Produce a versioned label handbook with pass, fail, invalid, severity,
  borderline, safe-completion, refusal, and adjudication examples.
- [x] Produce reviewer training and qualification fixtures.
- [x] Produce blind annotation packages that do not identify model providers.
- [x] Preserve raw labels, rationales, disagreements, adjudications, reviewer
  qualification evidence, and conflicts of interest.
- [x] Compute raw agreement and an appropriate chance-corrected agreement
  statistic with uncertainty.
- [!] Obtain at least two independent qualified reviews for subjective cases.
- [!] Use a separate qualified adjudicator for unresolved disagreements.
- [!] Use native-language and domain specialists for language- or
  high-impact-specific cases.

### Judge qualification

Development progress: the engine now reports distinct-case confusion counts,
failure sensitivity, specificity, false-pass/false-fail rates, invalidity,
repeat stability, and module/severity/language slices. A machine-validated
2,252-item qualification blueprint is preregistered; the independently labeled
restricted corpus does not yet exist. A fail-closed assembler now validates the
exact allocation, evidence hashes, verdict balance, and four-family minimum,
then creates a hash-pinned recorded-response suite outside the repository. The
`judge-qualify` gate consumes only a verified finalized run and applies the
preregistered module-level Wilson lower bounds, zero-invalid, two-repetition,
and 0.95 repeat-stability requirements while preserving all diagnostic slices.
Official execution also refuses to start unless the exact qualification report
has a current, independent, hash-linked approval. Any judge model, revision,
endpoint, prompt, rubric, schema, sampling, ensemble, or consensus change
requires new qualification evidence.

- [ ] Create a separate calibration corpus of human-gold responses across
  constructs, severities, languages, styles, lengths, and model families.
- [ ] Add pass, fail, invalid, borderline, reference-leakage, verbosity,
  position, order, style, and self-preference probes.
- [ ] Measure confusion matrices, sensitivity, specificity, false-negative
  rates, calibration, stability, and inter-judge agreement.
- [ ] Set predeclared qualification gates per construct and severity.
- [ ] Qualify every exact judge identity, revision, prompt, rubric, and sampling
  configuration.
- [ ] Require requalification after any judge, prompt, rubric, or policy change.
- [!] Obtain human-gold calibration labels and independent approval of judge
  qualification results.

### Pilot and freeze

The executable campaign, model-family independence rule, control requirements,
fixed command, transcript review, exit criteria, and current external blockers
are preregistered in
`suites/cavada-core-assistant-text-v1/PILOT_PROTOCOL.md`. The `pilot-audit`
command verifies complete compatible bundles, controls, and hash-pinned review
evidence. This does not mark a pilot item complete; no target or qualified
judge endpoint is available.

- [ ] Run pilots across at least three unrelated model families plus deliberate
  positive and negative controls.
- [ ] Inspect transcripts for parser failures, ambiguous tasks, impossible
  cases, leakage, degraded serving, and unintended solution paths.
- [ ] Measure difficulty, discrimination, saturation, category balance,
  stability, latency, and cost.
- [ ] Revise only through documented candidate versions; never tune against the
  final holdout.
- [ ] Run identity mismatch, malformed judge, timeout, rate limit, crash/resume,
  cancellation, budget, tamper, and reproducibility exercises.
- [ ] Freeze dataset, rubric, label handbook, judge configuration, gates, and
  protocol hashes.
- [ ] Reproduce the release candidate from a clean environment.
- [!] Obtain independent reproduction on separately controlled infrastructure.

## 3. External benchmark and threat intelligence adapters

- [x] Create a pinned license/API/transfer review matrix for each adapter.
- [ ] Add an Inspect AI adapter for agentic, tool, MCP, multimodal, and sandboxed
  evaluations without changing CavadaLabs artifacts.
- [ ] Add a garak adapter for exploratory discovery; promote accepted failures
  only into fixed, versioned suites.
- [ ] Add pinned imports for compatible academic tasks through
  lm-evaluation-harness.
- [x] Evaluate MLCommons AILuminate integration without redistributing hidden or
  restricted material.
- [x] Evaluate AgentDojo, CyberSecEval, PrivacyLens, Presidio, and future public
  benchmarks under their current licenses and data-transfer terms.
- [ ] Map security cases to OWASP LLM 2025, OWASP Agentic 2026, MITRE ATLAS, and
  relevant ENISA controls.
- [!] Obtain licenses, service authorizations, or protected benchmark access
  where required.

## 4. Platform gaps required by later suite families

- [ ] Add an approved sandbox adapter for untrusted code, tools, parsers, and
  custom metrics.
- [ ] Add normalized external RAG retrieval traces with source hashes, ranks,
  scores, and authorization boundaries.
- [ ] Add observable agent state, permission, side-effect, and task-completion
  traces.
- [ ] Add an MCP test harness for schemas, trust boundaries, tool poisoning,
  description injection, authentication, and least privilege.
- [ ] Add pinned language identification with licensed calibration data.
- [ ] Add bounded image, audio, and video decoder workers outside the main
  evaluator process.
- [ ] Add qualified OCR, VQA, grounding, ASR, diarization, audio/video, safety,
  privacy, fairness, and generation metrics.
- [ ] Add cryptographic C2PA verification and sanitized preview generation.
- [ ] Add calibrated hardware, GPU/VRAM, and energy collectors.
- [!] Approve the sandbox, media, biometric, safety, fairness, and high-impact
  datasets and models before official use.

## 5. Legal, standards, and organizational evidence

- [ ] Maintain dated mappings to NIST AI RMF, NIST AI 600-1, NIST AI 800-2,
  OWASP, MITRE ATLAS, GDPR, EU AI Act, and the GPAI Code of Practice.
- [ ] Prepare licensed mapping workbooks for ISO/IEC 42001, ISO/IEC 23894,
  ISO/IEC 42005, ISO/IEC 27001/27701, and applicable AI measurement standards.
- [ ] Define whether CavadaLabs is acting as developer, deployer, evaluator,
  testing laboratory, or certification body for every engagement.
- [ ] Define impartiality, conflict-of-interest, complaints, appeals, report
  correction, revocation, surveillance, and disclosure procedures.
- [ ] Evaluate an ISO/IEC 17025 laboratory path separately from any ISO/IEC
  17065 certification scheme; do not describe internal protocol conformance as
  accreditation.
- [!] Obtain counsel-approved applicability, DPIA/FRIA/ROPA/legal-basis,
  transfer, contract, copyright, and residual-risk evidence where applicable.
- [!] Obtain any accreditation or certification-body recognition before making
  the corresponding market claim.

## 6. Production evidence infrastructure

- [!] Configure the official Git remote, protected paths, required independent
  reviews, and immutable tags.
- [!] Provision organizational asymmetric signing and trusted timestamps.
- [!] Provision KMS, secrets management, RBAC, DLP, regional controls,
  append-only/WORM evidence storage, audit logs, backup, and restore testing.
- [!] Provision restricted holdout and encrypted cache storage with retention,
  legal hold, deletion, and incident procedures.
- [!] Complete independent security review and penetration testing before
  public multi-tenant operation.

## 7. Approval gate for an official suite

Promotion to `approved` requires all applicable items below:

- [ ] frozen measurement specification and analysis plan;
- [ ] complete dataset card, provenance ledger, and license register;
- [ ] private holdout and contamination evidence;
- [ ] rubric and label handbook;
- [ ] human-review and adjudication report;
- [ ] judge qualification report;
- [ ] power analysis and threshold rationale;
- [ ] multi-model baseline and negative-control report;
- [ ] red-team and security findings disposition;
- [ ] clean reproducible build and verified golden bundle;
- [ ] pinned dataset, rubric, suite, judge, adapter, and protocol hashes;
- [!] independent statistical, security, privacy/legal, and release approvals;
- [!] signed release, immutable evidence storage, and independent reproduction.

Candidate or calibrated output must never be relabeled as official. A failed or
expired external approval blocks promotion rather than becoming a warning.

## 8. Maintenance

- [ ] Monitor saturation, contamination, evaluator drift, model gaming,
  regulatory changes, incidents, and appeals.
- [ ] Rotate holdouts and canaries under a predeclared schedule.
- [ ] Requalify judges and adapters after relevant changes.
- [ ] Publish new immutable versions instead of editing released suites.
- [ ] Expire, deprecate, revoke, or supersede results with an auditable reason.
- [ ] Repeat independent review and reproduction at the declared assurance
  interval.

## Primary references

- NIST AI RMF and Generative AI Profile
- NIST AI 800-2 initial public draft, *Practices for Automated Benchmark
  Evaluations of Language Models*
- Regulation (EU) 2024/1689 and the GPAI Code of Practice
- Regulation (EU) 2016/679 and EDPB Opinion 28/2024
- OWASP Top 10 for LLM Applications 2025 and Agentic Applications 2026
- MITRE ATLAS
- ISO/IEC 42001:2023, 23894:2023, 42005:2025, 17025:2017, and applicable
  licensed standards

References guide engineering evidence. They do not create endorsement,
accreditation, certification, or legal compliance by themselves.
