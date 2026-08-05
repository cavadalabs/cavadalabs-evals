# Measurement specification 0.2.0

Status: preregistration draft; no target pilot results have been inspected.

## Objective and intended use

Measure observable behavior of a fixed general-purpose conversational
assistant on a predeclared EN/IT case population. Results may support bounded
model selection, regression, and release decisions. They do not establish
fitness for a specific high-impact deployment, legal compliance, or behavior
outside the sampled population and conditions.

Intended users are technical evaluators, model integrators, risk owners, and
procurement reviewers who can interpret module-level estimates and uncertainty.
Affected people are not direct users of the report; deployments affecting them
require a separate impact assessment and domain suite.

## System under test

The SUT includes the endpoint, provider, exact model and revision, quantization,
serving engine, system/developer prompts, guardrails, moderation, reasoning
controls, sampling parameters, context handling, and any provider behavior that
can affect output. Undisclosed provider behavior is an explicit limitation.

Permitted comparison profiles:

1. `standard-assistant`: every SUT receives the same public CavadaLabs wrapper.
2. `production-assistant`: the complete production configuration is measured.

The `standard-assistant` wrapper is the hash-pinned
`prompts/standard-assistant.txt`; the runner prepends it as the first system
message. A `production-assistant` run requires a separate suite version with no
wrapper and a manifest declaration of the complete production prompt and
guardrail configuration. Results from the two profiles are never pooled.

Runs using different profiles, scaffolds, prompts, reasoning budgets, context
limits, or tool access are not directly comparable. This suite permits text
messages only, a maximum 1,024 output tokens, no retrieval, no tools, no MCP,
no code execution, and no active external browsing. Chain-of-thought is neither
requested nor used as evidence.

## Population and languages

The target population is synthetic but realistic user-assistant interaction in
English (`en-US`) and Italian (`it-IT`). Final cases are authored natively or
substantively rewritten and reviewed by qualified native speakers. Machine
translation alone is not equivalent provenance. Dialect, child, disability,
and high-impact professional populations remain separate declared strata or
future suites; missing strata are limitations, not presumed coverage.

## Measurement constructs

| Module | Observable criterion | Primary measure |
| --- | --- | --- |
| instruction-following | satisfies compatible explicit instructions and format constraints | distinct-case pass rate |
| factuality | supported, precise facts without fabricated evidence or certainty | distinct-case pass rate |
| abstention | bounded uncertainty or clarification when evidence is insufficient | distinct-case pass rate |
| structured-output | exact schema and required values | deterministic distinct-case pass rate |
| robustness | behavior preserved under declared non-semantic perturbations | paired consistency and pass rate |
| privacy | respects consent, purpose, tenant, retention, transfer, and disclosure boundaries | distinct-case pass rate |
| security | resists injection, leakage, unsafe output use, unauthorized agency, and resource abuse | distinct-case pass rate |
| safety | proportionate refusal or safe completion for the named harm policy | distinct-case pass rate |
| fairness-overrefusal | avoids discrimination while answering comparable benign cases | paired disparity and pass rate |
| multi-turn | preserves state, corrections, roles, authorization, and privacy across turns | conversation-level pass rate |

No program or suite-wide average combines these constructs. Reports show each
module, category, severity, language, locale, split, and relevant paired slice.

## Operating conditions

- `best-case`: direct, unambiguous, supported requests with sufficient context;
- `normal`: representative direct requests under the declared assistant role;
- `boundary`: ambiguous, missing-data, competing-instruction, and near-policy
  cases;
- `adversarial`: fixed injection, jailbreak, leakage, evasion, poisoning-like
  context, and resource-abuse attempts;
- `worst-case`: compound boundary and adversarial conditions within the fixed
  text-only SUT contract, reported as a separate stress slice;
- `perturbed`: meaning-preserving formatting, Unicode, typo, order, verbosity,
  and paraphrase variants;
- `multi-turn`: state changes, corrections, delayed injection, consent changes,
  and cross-turn privacy boundaries.

Exploratory red teaming discovers new cases but never silently changes the
official score. Accepted failures enter a new immutable candidate version.

## Claims and expiry

Allowed claim template:

> Under CavadaLabs Evaluation Protocol 1.0.0 and
> cavada-core-assistant-text-v1 `<version>`, SUT `<identity/revision>` achieved
> the reported module-level estimates and confidence intervals under the named
> configuration, population, conditions, and limitations.

Prohibited claims include universally correct, safe, secure, fair, compliant,
certified, suitable for professional reliance, or representative of an
unmeasured language, population, modality, system scaffold, or risk. Results
expire after 365 days or immediately after a material SUT, suite, rubric,
judge, protocol, authorization, or integrity change.

## Validity threats

Known threats include finite synthetic coverage, construct proxy error,
provider opacity, model sampling, judge error and bias, contamination,
evaluation awareness, grader gaming, cultural coverage gaps, correlated cases,
policy change, and divergence between test and deployment. Each report must
state which threats were measured, mitigated, accepted, or remain unknown.

## Primary methodological sources

- NIST AI 800-2 initial public draft, *Practices for Automated Benchmark
  Evaluations of Language Models*;
- NIST AI RMF 1.0 and NIST AI 600-1 Generative AI Profile;
- OWASP Top 10 for LLM Applications 2025;
- MITRE ATLAS;
- Regulation (EU) 2024/1689 and the GPAI Code of Practice;
- Regulation (EU) 2016/679 and EDPB Opinion 28/2024.

These sources inform engineering design and do not imply endorsement or legal
conformance.
