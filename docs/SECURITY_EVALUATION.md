# Security evaluation

Security results apply to a declared system, prompt, model revision, tools,
retrieval sources, runtime, and deployment boundary. A model-only prompt test
cannot establish application or infrastructure security.

## Required evidence layers

| Layer | What is evaluated | Typical evidence |
| --- | --- | --- |
| Model and prompt | refusals, safe completion, instruction hierarchy, leakage, over-refusal | fixed adversarial and benign-control cases, raw responses, deterministic checks, calibrated judgments |
| Application context | indirect injection, RAG poisoning, tool misuse, excessive agency, unsafe output handling | retrieved context, tool traces, authorization decisions, output-sanitization results |
| Platform | identity, least privilege, tenant isolation, egress, resource bounds, model and dataset provenance | configuration snapshots, access tests, SBOM, signed artifacts, allowlists, rate-limit evidence |
| Operations | monitoring, incident handling, retention, red-team response, change control | dated records, owners, approvals, remediation and retest evidence |

Do not collapse these layers into one “security score.” Report each gate and
missing layer separately.

## Benchmark workflow

1. Freeze the system boundary, model and prompt revisions, endpoint, tools,
   retrieval corpus, adapters, and environment.
2. Select threats for the actual use case. Record excluded threats and why they
   are not applicable.
3. Use versioned attack cases plus matched benign controls. Keep exploratory
   red-team prompts outside comparable scores until they are reviewed and
   frozen in a new suite version.
4. Run deterministic checks before semantic judges. A judge cannot override a
   forbidden tool call, secret match, malformed structure, or other hard fail.
5. Repeat stochastic cases, preserve every response, and report pass, fail,
   invalid, error, and skipped evidence separately.
6. Gate critical severities explicitly. A high average must never hide a
   critical failure.
7. Slice by threat, severity, language, operating condition, and attack/benign
   role. Review over-refusal as well as unsafe compliance.
8. Retest every material prompt, model, retrieval, tool, policy, runtime, or
   deployment change. Comparisons require identical suite and protocol hashes.

`smoke` is an endpoint and regression check. `quick` and `standard` support
development comparisons. Only a complete `reference` run with all protocol,
calibration, engagement, storage, review, and release gates can be described as
official CavadaLabs protocol evidence.

## Framework coverage

The current public smoke suite provides behavioral probes for the
[OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/):

| OWASP area | Evidence path |
| --- | --- |
| LLM01 Prompt Injection | direct, indirect, RAG, and jailbreak cases with benign controls |
| LLM02 Sensitive Information Disclosure | cross-tenant, private-data, and hidden-instruction cases |
| LLM03 Supply Chain | platform evidence only; prompt tests are insufficient |
| LLM04 Data and Model Poisoning | corpus/model provenance and controlled poisoning experiments |
| LLM05 Improper Output Handling | deterministic output checks plus application sink testing |
| LLM06 Excessive Agency | tool authorization, arguments, order, count, and side-effect evidence |
| LLM07 System Prompt Leakage | fixed extraction attempts and secret canaries |
| LLM08 Vector and Embedding Weaknesses | poisoned retrieval and tenant-isolation tests |
| LLM09 Misinformation | domain-grounded correctness and high-impact uncertainty tests |
| LLM10 Unbounded Consumption | request, token, time, concurrency, and cost limits |

[MITRE ATLAS](https://atlas.mitre.org/) is used as an adversary-technique
catalog, not as a score. The
[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) provides
the broader govern, map, measure, and manage lifecycle; benchmark output is
measurement evidence within that process, not completion of the process.

## Minimum publishable result

A public security result must identify the exact suite and system revisions,
sample size, repetitions, threat coverage, exclusions, critical failures,
confidence intervals, invalid/error counts, judge qualification, deterministic
checks, date, source commit, and bundle verification. It must also state that
finite tests do not prove universal safety or security.

Third-party prompts or datasets remain external adapters unless their license
explicitly permits redistribution. Record source version, license, hashes,
selection rules, transformations, and contamination risk.
