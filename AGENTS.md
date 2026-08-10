# CavadaLabs Evaluation Protocol

When creating or running a benchmark:

1. Never modify a released dataset or rubric. Create a new semantic version.
2. Validate the complete suite before contacting any model or judge.
3. Run deterministic checks before LLM judges. A judge cannot override a deterministic failure.
4. Never expose target model identity to a judge.
5. Use only the configured rubric, judge, parameters and thresholds.
6. Preserve target responses, judge outputs, errors and invalid cases.
7. Never overwrite a run. Run directories and IDs are immutable.
8. Record protocol, suite, dataset, rubric, source tree, model, endpoint, parameters, environment and hardware evidence.
9. Abort an official run when reported model identity differs from the expected identity.
10. Treat malformed judge output as `invalid`, never as a model failure.
11. Report failures, errors, skipped and invalid cases separately.
12. Evaluate official pass-rate gates against the confidence-interval lower bound, not only the point estimate.
13. Keep quality scores, security gates and legal/compliance evidence separate. Never publish one combined compliance score.
14. Never put real secrets or unnecessary personal data in a benchmark dataset.
15. Never send non-public data to any external target or judge without an explicit, unexpired authorization covering every destination.
16. Run integrity tests before calling a result official.
17. When comparing outputs pairwise, run and retain both A/B and B/A order; never expose model identities to the judge.
18. Require current encrypted, immutable storage evidence before a non-public run can be official.
19. Never claim an unsupported modality or optional adapter was evaluated; fail closed and record the missing capability.

`official` means conforming to this protocol. It does not mean legal certification or universal safety.

## LLM serving performance runs

1. Follow `PERFORMANCE_PROTOCOL_V2.md` for current/reference runs; validate the complete plan, workload, and runtime before starting or contacting an endpoint. `PERFORMANCE_PROTOCOL_V1_1.md` is an unanchored historical-development snapshot; `PERFORMANCE_PROTOCOL_V1_0.md` remains the commit-anchored historical contract for its recorded bundles.
2. Keep inference engines outside this repository. Never execute a stored launch command automatically.
3. If explicitly asked to start an engine, use its documented command, record immutable revisions and a credential-free command, verify readiness, and stop only the process you started.
4. Never modify an existing performance plan or workload for a run. Create a new version and preserve exact hashes.
5. Require exact reported model identity and provider-reported prompt/output token usage. Do not estimate missing official evidence.
6. Keep warm-up, closed-loop, open-loop, error, queueing, and measured observations distinct. Never retry a measured request silently.
7. Use `iso-prompt` for identical text and `iso-token` only with tokenizer-calibrated fixtures; never hide tokenizer mismatch.
8. Preserve raw streaming events and all failures. Enforce token, request, duration, timeout, context, output, and in-flight limits.
9. Compare only verified runs with identical plan/workload hashes and exact shared cells. Report skipped cells and every block.
10. Do not attribute results solely to a GPU or model, and do not claim quality, safety, compliance, utilization, or energy from client-side performance measurements.
11. Prefer the versioned `smoke`, `quick`, `standard`, or `reference` preset; `full` is only a CLI alias for `reference`.
12. Use `run --preset ...` for behavior quality/safety and `perf run --preset ...` for serving performance. Never describe one as the other.
13. Only the complete `reference` preset can be considered for an official run, and all other official gates still apply.
