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
