# CavadaLabs Evals Implementation Checklist

This file is the implementation source of truth for the CavadaLabs Evaluation
Protocol. A checked item requires repository evidence or an automated test.

Status legend:

- `[x]` implemented and verified in this repository.
- `[ ]` repository work still required.
- `[!]` external evidence or authority required; code alone cannot complete it.

An `official` result means conformance to a named protocol and suite version. It
never means universal correctness, universal safety, or legal certification.

## 1. Protocol and claims

- [x] Define `official` narrowly as protocol conformance.
- [x] Keep quality, security, privacy, safety, reliability, and legal evidence separate.
- [x] Publish normative English definitions for suite, case, observation, run, repetition, target, judge, gate, invalid, error, skipped, and official.
- [x] Define protocol, engine, schema, suite, dataset, rubric, and report versions independently.
- [x] Define compatibility and migration rules for every versioned artifact.
- [x] Define fail-closed official-run invalidation rules.
- [x] Define approved wording and prohibited claims for commercial reports.
- [x] Record known limitations and excluded scope in every report.

## 2. Repository governance and release engineering

- [x] Keep the source in Git and reject official runs from dirty trees.
- [x] Lock Python dependencies with `uv.lock`.
- [x] Add `SECURITY.md` with vulnerability reporting and supported versions.
- [x] Add `CONTRIBUTING.md` with suite and protocol change rules.
- [x] Add `CHANGELOG.md` and semantic release policy.
- [x] Add `CODEOWNERS` template and protected-path guidance.
- [x] Add an explicit code license and separate dataset licensing policy.
- [x] Add reproducible package-build and artifact-verification commands.
- [x] Generate an SBOM for releases.
- [x] Generate unsigned local/CI build provenance with current-version artifact hashes.
- [x] Add CI for tests, build, lint, type checks, dependency audit, secret scan, and smoke benchmark.
- [x] Prevent untrusted pull requests from receiving benchmark or provider secrets.
- [!] Configure the official Git remote, protected default branch, required reviews, and immutable release tags.
- [!] Provision organizational signing identities and a trusted timestamp service.
- [!] Sign release provenance and packages with the provisioned organizational identity.

## 3. Schemas and suite lifecycle

- [x] Reject missing suite fields, duplicate case IDs, duplicate inputs, path traversal, and invalid enums.
- [x] Pin dataset and rubric SHA-256 for official runs.
- [x] Publish machine-readable schemas for suite configuration, cases, assets, judgments, metrics, manifests, pilot campaigns, and control evidence.
- [x] Reject unknown security-sensitive fields in official mode.
- [x] Validate numeric limits, URI schemes, MIME types, hashes, timestamps, and identifiers.
- [x] Implement suite lifecycle: `draft`, `candidate`, `calibrated`, `approved`, `deprecated`, `retired`.
- [x] Add suite promotion validation and a `promote` command.
- [x] Require hash-pinned calibration and independent-approval files with exact suite, holdout, pilot, labeling, statistics, contamination, gate, source, and expiry evidence.
- [x] Refuse incompatible protocol/schema/suite comparisons by default without mutating released artifacts.
- [!] Approve and publish any future cross-version compatibility mapping as a new governed protocol artifact.
- [x] Add a complete, English suite template.
- [x] Add schema compatibility and historical MEMO regression tests.

## 4. Dataset governance and benchmark integrity

- [x] Require per-case source and review method for official runs.
- [x] Scan suite material for common secret patterns.
- [x] Require dataset-level owner, purpose, intended use, prohibited use, license, origin, and creation date.
- [x] Require per-case locale, language, tags, risk domain, severity, and provenance.
- [x] Support public, practice, calibration, and private holdout splits.
- [x] Prevent official reports from exposing private holdout inputs.
- [x] Add exact and normalized duplicate detection.
- [x] Add optional near-duplicate detection with a documented threshold.
- [x] Record contamination checks, canaries, known leaks, and rotation date.
- [x] Produce coverage tables for category, risk, severity, language, locale, split, and expected behavior.
- [x] Record sampling weights and reject invalid or negative weights.
- [x] Record personal-data classification, legal basis reference, retention, and transfer restrictions.
- [x] Add dataset quality gates for missing fields, imbalance, ambiguity, and unresolved reviews.
- [x] Add dataset-card generation.
- [!] Obtain licenses or permissions for third-party benchmark data before redistribution.
- [!] Complete independent human review for subjective gold labels before high-assurance approval.

## 5. Target, judge, and adapter integrity

- [x] Support generic JSON and OpenAI-compatible text targets.
- [x] Require expected target and judge identity/revision in official mode.
- [x] Abort official runs on model identity mismatch.
- [x] Hide target identity from the judge.
- [x] Treat malformed judge output as invalid.
- [x] Define a versioned adapter contract and capability declaration.
- [x] Add preflight capability and endpoint checks.
- [x] Record complete sanitized request parameters, system prompts, templates, and standard adapter headers that affect output.
- [!] Approve and record any product-specific output-affecting headers when a product adapter is added.
- [x] Verify target and judge response content types and maximum body sizes.
- [x] Enforce telemetry-off and cloud-sync-off settings before importing optional engines.
- [x] Integrate DeepEval as an optional metric adapter without changing the CavadaLabs artifact format.
- [x] Add recorded-response and mock-HTTP fixtures for deterministic offline tests.
- [!] Permit local callable/custom-code adapters only after provision of an approved OS-level sandbox.
- [x] Add external benchmark adapter metadata with license, version, checksum, and result import validation.
- [!] Implement and approve product-specific adapters for lm-evaluation-harness, garak, CyberSecEval, AgentDojo, PrivacyLens, Presidio, and MLCommons after current API/license/data-transfer review.

## 6. Deterministic metrics

- [x] Run deterministic checks before LLM judges.
- [x] Implement non-empty, secret-pattern, required-term, forbidden-term, and JSON parse checks.
- [x] Add JSON Schema validation and field-level structured-output accuracy.
- [x] Add exact match, normalized match, token F1, set precision/recall/F1, and numeric tolerance.
- [x] Add regex, length, citation presence, citation format, and allowed-tool checks.
- [!] Add output language identification only with a pinned, calibrated multilingual classifier and licensed validation data.
- [x] Add retrieval hit rate, recall@k, precision@k, MRR, and nDCG@k.
- [x] Add agent tool-name, argument, order, permission, and call-count assertions over supplied traces.
- [!] Assert real side effects only after an approved sandboxed agent adapter can observe them safely.
- [x] Add configurable weighted and hard-fail metric semantics without a combined compliance score.
- [x] Record metric implementation version and parameters in every result.
- [x] Provide tests for empty, Unicode, malformed, adversarial, and boundary inputs.

## 7. Judge methodology and calibration

- [x] Require strict pass/fail JSON, score, and reason.
- [x] Preserve all raw judge outputs and disagreements.
- [x] Fail official observations on judge disagreement.
- [x] Version and hash judge prompts, rubrics, response schemas, and sampling parameters.
- [x] Implement blind pairwise evaluation in both A/B and B/A order.
- [x] Add single-answer, pointwise, pairwise, and reference-based judge modes.
- [x] Support multiple independent judge models and explicit consensus policies.
- [x] Produce judge agreement, disagreement, and score-distribution metrics.
- [x] Compute per-judge confusion matrices and qualification gates when cases contain gold verdicts.
- [x] Require hash-linked, unexpired independent approval of the exact qualified judge configuration before an official run starts.
- [!] Produce independently labeled calibration datasets for each official judge and risk severity.
- [!] Qualify position, verbosity, style, self-preference, and reference-leakage bias using independently reviewed calibration data.
- [x] Define judge qualification thresholds per suite.
- [!] Set risk-severity-specific thresholds after independent calibration data exists.
- [x] Route unresolved critical disagreements to an adjudication queue without converting them to model failures.
- [!] Obtain independent human adjudication evidence for critical subjective categories.

## 8. Statistical validity and comparisons

- [x] Aggregate repeated observations at distinct-case level to avoid pseudoreplication.
- [x] Report a 95% Wilson interval for binary pass rate.
- [x] Apply official gates to confidence-interval lower bounds when configured.
- [x] Support configurable confidence levels and deterministic bootstrap seeds.
- [x] Add stratified bootstrap confidence intervals across cases.
- [x] Add paired model comparison with paired bootstrap or permutation tests.
- [x] Add McNemar testing for paired binary outcomes.
- [x] Report absolute delta, relative delta, effect size, uncertainty, and sample size.
- [x] Add multiple-comparison correction.
- [x] Add non-inferiority gates and minimum detectable effect metadata.
- [x] Add hierarchical grouping for users, conversations, and scenarios.
- [x] Add variance and stability analysis across repetitions.
- [x] Keep invalid, error, skipped, and missing observations outside pass-rate denominators and visibly report them.
- [x] Refuse comparisons across incompatible suite/protocol versions unless an explicit mapping exists.
- [x] Add power and minimum-sample-size guidance to suite audit output.

## 9. Reliable and efficient execution

- [x] Use immutable unique run directories.
- [x] Preserve partial evidence after model or judge failures.
- [x] Separate generation, deterministic evaluation, judging, aggregation, gating, reporting, and signing stages.
- [x] Add request IDs and idempotency keys.
- [x] Add retries with bounded exponential backoff for explicitly retryable failures.
- [x] Add bounded request/stream timeouts and record header/first-byte and total timing where the standard-library adapter exposes them.
- [!] Add distinct connection and idle timeout controls for provider SDK adapters that expose those phases.
- [x] Add resumable journal/checkpoints without duplicating observations.
- [x] Record an explicit target/judge cache-disabled policy in every manifest.
- [!] Enable cross-run content-addressed caches only after encrypted restricted-cache storage, retention, and invalidation policies are provisioned.
- [x] Add bounded concurrency and per-endpoint rate limiting.
- [x] Preserve a cancelled run on operator interruption and emit a stable cancellation exit status.
- [!] Add deployment-specific SIGTERM and job-cancellation integration after the target runtime is selected.
- [x] Add hard budgets for requests, tokens, judge calls, elapsed time, and estimated cost.
- [x] Add deterministic case ordering or record the randomized seed and order.
- [x] Add dry-run, smoke, regression, candidate, official, pairwise, red-team, performance, offline, and monitoring modes.
- [x] Add progress events suitable for terminal and CI without leaking prompts or secrets.
- [x] Add crash/resume, retry/idempotency, and budget-interruption tests.
- [!] Add provider-specific connection/idle-timeout and deployment-signal integration tests with their adapters.

## 10. Performance, cost, and resource benchmarking

- [x] Measure target latency separately from evaluation overhead.
- [x] Record time to first token/byte, inter-token latency, total latency, and tokens per second where streaming is available.
- [x] Report p50, p90, p95, p99, min, max, mean, median, and dispersion.
- [x] Measure request throughput and success/error rates under bounded concurrency.
- [x] Separate cold-start, warm-up, and steady-state samples.
- [x] Record input/output tokens and provider-reported usage.
- [x] Record pricing source, effective date, currency, input/output rates, and estimated cost.
- [x] Record platform, CPU count, system memory, and available GPU identity evidence.
- [!] Add calibrated GPU/VRAM utilization and energy telemetry through approved hardware-specific collectors.
- [x] Add configurable load and soak profiles with safety limits.
- [x] Produce quality/latency/cost Pareto comparisons.
- [x] Reuse and validate the existing CavadaLabs TTFT/TPS/cost benchmark logic.

## 11. Text, RAG, conversation, agent, MCP, and code coverage

- [x] Add task profiles for generation, classification, extraction, translation, summarization, and structured output.
- [x] Add retriever-only, generator-only, and end-to-end RAG profiles.
- [x] Preserve complete raw retrieval evidence and configurable source/tool/ID fields; compute retrieval and citation metrics.
- [!] Standardize normalized rank/score/source-hash traces for each external RAG adapter before official use.
- [x] Add multi-turn conversation cases with explicit state and turn boundaries.
- [x] Add role adherence, knowledge retention, consistency, recovery, and cross-turn privacy checks.
- [!] Add approved agent trace adapters covering plans, state transitions, side effects, task completion, and step efficiency.
- [x] Add deterministic tool name, argument, order, permission, call-count, and excessive-agency gates.
- [!] Add an approved MCP harness for server schemas, trust boundaries, description injection, and permission tests.
- [x] Catalog sandboxed code, embedding, reranking, clustering, and semantic-search profiles and block unsupported official execution.
- [!] Provision bounded code, embedding, reranking, clustering, and semantic-search execution adapters and validation datasets.

## 12. Multimodal asset security and data model

- [x] Define ordered content parts for text, image, audio, video, document, tool call, and tool result.
- [x] Store assets by content hash and never trust filenames for identity.
- [x] Validate magic bytes, MIME allowlists, extension consistency, size, PNG/JPEG dimensions, PNG CRC/chunks, and WAV duration; block formats needing richer parsing.
- [!] Validate video frame count/duration/codecs and compressed media only inside an approved bounded parser sandbox.
- [x] Block path traversal, symlink escape, device files, remote URLs, and unsupported schemes in official mode.
- [x] Block archives and rich media parsers, and enforce byte, pixel, duration, chunk, and body limits before supported parsing.
- [x] Separately record detected sensitive metadata and keep original assets restricted.
- [x] Reject active SVG, PDF/Office/archive content, embedded executables, and unsupported rich formats in official mode.
- [!] Provision and integrate an OS-level restricted parser/custom-metric sandbox with enforceable network, CPU, memory, filesystem, and time limits.
- [x] Record asset license, origin, consent/provenance, personal-data class, and SHA-256.
- [x] Keep restricted originals out of sanitized public reports.
- [x] Add malformed and adversarial media fixtures and tests.

## 13. Image evaluation

- [x] Catalog image-to-text, text-plus-image-to-text, text-to-image, editing, and retrieval profiles; enable safe PNG/JPEG input-to-text and block unsupported outputs.
- [x] Provide reusable character/word error-rate primitives for pinned OCR adapter output.
- [!] Approve and pin OCR, VQA, chart/document QA, grounding, caption, hallucination, and image-generation metric models plus licensed calibration data.
- [!] Approve image safety/privacy/bias classifiers and high-risk policy datasets before emitting image safety gates.
- [x] Detect C2PA markers and explicitly report `c2pa_verified=false` rather than treating absence as falsity.
- [!] Integrate an approved cryptographic C2PA verifier and trusted certificate policy.
- [!] Generate contact sheets/failure galleries only after an approved metadata-stripping, re-encoding preview sandbox exists.

## 14. Audio evaluation

- [x] Catalog audio-to-text, text-to-audio, audio-to-audio, and audio-plus-text profiles; enable bounded WAV input-to-text and block unsupported outputs.
- [x] Add ASR word and character error rates and record WAV sample rate, channels, sample width, frames, and duration.
- [!] Approve pinned punctuation/timestamp/language-ID, diarization, speaker attribution, speech-translation, TTS quality/similarity/prosody, clipping/silence, and real-time-factor adapters.
- [!] Approve audio safety, hidden-command, biometric, and voice-cloning consent datasets and classifiers.
- [!] Parse compressed audio codecs and record normalization transforms only through the approved media sandbox.

## 15. Video evaluation

- [x] Catalog video-to-text, text-to-video, video-editing, and audio-video profiles and block official execution without a sandboxed adapter.
- [!] Approve video temporal/action/tracking/counting/grounding/QA, consistency, editing, subtitle, sync, safety, and privacy metric adapters and datasets.
- [!] Record codec, frame rate, resolution, duration, audio streams, transforms, and bounded sampling evidence through the approved video sandbox.

## 16. Safety, security, privacy, and fairness

- [x] Add direct and indirect prompt-injection suites.
- [x] Add jailbreak, system-prompt extraction, sensitive-data disclosure, insecure-output, excessive-agency, and resource-consumption suites.
- [x] Add candidate RAG poisoning, cross-tenant leakage, tool-output injection, and resource-consumption tests.
- [!] Add MCP poisoning tests after the approved MCP harness is available.
- [x] Add PII-like output, cross-tenant, deletion-workflow, retention, transfer-authorization, and egress controls.
- [!] Add calibrated memorization/extraction, membership-inference, and re-identification attacks only for systems where accountable privacy review authorizes them.
- [x] Add misuse, toxicity, bias, discrimination, self-harm, violence, sexual content, child safety, medical, legal, financial, and civic-integrity profiles.
- [x] Add category, risk, severity, language, locale, split, disability-tagged case coverage and disparity outputs.
- [!] Add representative dialect, geography, age, disability, and intersectional datasets with lawful provenance and independent fairness review.
- [x] Keep the fixed `redteam` mode and its comparable suite score separate from exploratory evidence.
- [!] Operate adaptive red-team campaigns in an authorized external environment and version accepted findings into fixed suites.
- [x] Map OWASP GenAI risks to executable suites and evidence.
- [x] Keep attack payloads and critical failures restricted by default.

## 17. Compliance evidence

- [x] Start an engineering evidence catalog for GDPR and EU AI Act controls.
- [x] Define an evidence schema with jurisdiction, source version, applicability, owner, status, artifact, expiry, and residual risk.
- [x] Add GDPR profiles for principles/accountability, legal basis, special categories, transparency, data-subject rights, automated decisions, privacy by design, processors, ROPA, security, breaches, DPIA, and international transfers.
- [x] Add EU AI Act profiles for applicability/classification, prohibited practices, literacy, risk management, data governance, documentation, records, transparency, oversight, accuracy, robustness, cybersecurity, QMS, deployer duties, FRIA, and GPAI duties where applicable.
- [x] Add NIST AI RMF/GenAI, OWASP GenAI, ISO/IEC 42001, ISO/IEC 23894, ISO 27001/27701, NIS2, DORA, and sector-profile mapping stubs without copying unlicensed standards text.
- [x] Add a dated, machine-validated evidence crosswalk, preserve superseded OWASP mappings, and provide license-safe ISO and engagement-governance templates.
- [x] Require an approved, unexpired engagement hash-linked to the exact suite and SUT before official execution.
- [x] Generate a control-evidence report that never emits a combined compliance score.
- [x] Distinguish automated pass/fail, manual required, not applicable, missing, and expired evidence.
- [x] Version legal sources and record the effective date used by a run.
- [!] Obtain counsel-approved applicability, legal basis, DPIA, ROPA, FRIA, contracts, transfer assessments, and residual-risk acceptance.

## 18. Artifact security, privacy, and retention

- [x] Redact endpoint query values and reject credentials embedded in URLs.
- [x] Read API keys from named environment variables and omit them from artifacts.
- [x] Escape dynamic text in the current HTML report.
- [x] Add repository/dataset/output secret-pattern scanning and opt-in PII-like output checks.
- [!] Connect organization-specific DLP policies only after an approved local or authorized external DLP service is provisioned.
- [x] Split restricted evidence from sanitized/public reports.
- [x] Add encryption-at-rest integration points and record encryption state.
- [x] Add retention, legal-hold, deletion, tombstone, and cryptographic-erasure records.
- [x] Add role/access metadata and audit-log references.
- [x] Add egress allowlists and explicit external-judge authorization records with approver, purpose, destination, region, and expiry.
- [x] Require a current immutability/WORM attestation before non-public bundles can be official.
- [!] Provision and test the production append-only/WORM object-store adapter.
- [x] Hash a closed artifact set, verify checksums, reject unlisted files, and optionally HMAC-sign bundles containing the final manifest.
- [!] Replace shared-secret HMAC release signing with the provisioned organizational asymmetric signing identity and trusted timestamp.
- [x] Add backup/restore and disaster-recovery evidence fields.
- [!] Provision production KMS, RBAC, WORM storage, backup, restore, and incident-response systems.

## 19. Reports, visualizations, and exports

- [x] Produce manifest, raw responses, judgments, case results, metrics, category CSV, failures, and HTML.
- [x] Produce methodology, protocol snapshot, suite snapshot, dataset card, environment, request ledger, checksums, and verification result.
- [x] Produce self-contained restricted HTML and sanitized public HTML.
- [x] Block public export until a post-run approval hash-links the verified bundle, engagement, permitted claims, expiry, limitations, and independent review decisions.
- [x] Produce PDF, JSON, CSV, JSONL, JUnit, and machine-readable comparison exports.
- [x] Add overall score with confidence interval and sample size.
- [x] Add category charts plus risk/severity/language/locale/split tables and disparity charts.
- [x] Add pass/fail/invalid/error/skipped and failure-severity distributions.
- [x] Add paired delta, win/tie/loss, effect-size, non-inferiority, and regression comparison tables/exports.
- [x] Add latency percentile/CDF, throughput, cost, resource evidence, and quality-latency-cost comparison outputs.
- [x] Add repetition stability, judge agreement, judge calibration, failure-severity, and slice-disparity charts.
- [!] Add multi-run trend storage/plots only after an approved results registry is provisioned.
- [!] Add restricted multimodal previews only after the approved safe re-encoding/sanitization sandbox is available.
- [x] Include executive summary, SUT identity/configuration, methodology, gates, limitations, excluded scope, known gaps, and reproduction command.
- [x] Make all plots accessible with titles, labels, legends, color-safe palettes, and tabular equivalents.

## 20. CLI and developer experience

- [x] Provide English `validate`, `audit`, and `run` commands with meaningful exit codes.
- [x] Add `init`, `doctor`, `list`, `estimate`, `resume`, `compare`, `report`, `verify`, `promote`, `export`, and `redteam` commands.
- [x] Add a fail-closed `pilot-audit` command for the preregistered multi-family campaign, controls, review evidence, and exact run compatibility.
- [x] Add configuration files for models, judges, protocols, and authorized destinations without storing secrets.
- [x] Add clear preflight output and a no-network dry run.
- [x] Add shell-safe reproduction commands that reference environment-variable names only.
- [x] Add examples for text, RAG, agent, conversation, structured extraction, image, audio, video, and compliance evidence.
- [x] Add troubleshooting, threat-model, privacy, methodology, adapter, metric, and report documentation.
- [x] Add stable exit codes for pass, gate failure, invalid run, configuration error, transport failure, budget exhaustion, and cancellation.
- [x] Add Python API documentation and typed public interfaces.

## 21. Verification and official release gate

- [x] Existing unit and mock end-to-end tests pass.
- [x] Source distribution and wheel build successfully.
- [x] All repository-implementable checklist items are checked and tested.
- [x] Full test, build, schema, package, secret, dependency, and artifact-verification checks pass from a clean checkout.
- [!] Approve an independently labeled calibration fixture, then preserve its deterministic verified golden bundle.
- [x] A deliberately failing fixture fails the correct gate and preserves evidence.
- [x] A corrupt bundle fails verification.
- [x] A crash/resume fixture completes without duplicate observations.
- [x] A multimodal malicious-asset fixture is rejected before parsing.
- [x] The final repository audit records all remaining `[!]` external obligations.
- [!] Complete an independent security review and penetration test before public multi-tenant operation.
- [!] Complete legal and organizational approval before any compliance claim.
