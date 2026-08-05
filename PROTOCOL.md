# CavadaLabs Evaluation Protocol 1.0.0

This document is normative for runs that claim conformance to CavadaLabs
Evaluation Protocol 1.0.0. `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY`
are to be interpreted as requirements language.

## Definitions

- **System Under Test (SUT)**: the complete fixed system receiving benchmark
  inputs and returning outputs, including prompts, models, retrieval, tools,
  guardrails, and configuration.
- **Suite**: a versioned benchmark specification containing configuration,
  dataset, rubric, metrics, gates, and governance metadata.
- **Case**: one independently identified scenario in a suite.
- **Observation**: one execution of one case against one fixed SUT.
- **Repetition**: another observation of the same case and SUT configuration.
- **Run**: an immutable collection of observations produced by one invocation.
- **Target**: the SUT endpoint or adapter.
- **Judge**: an evaluator that scores an output under a fixed rubric. A judge is
  not part of the SUT.
- **Deterministic metric**: an evaluator whose result is fully determined by its
  versioned implementation, parameters, case, and output.
- **Gate**: a threshold declared before execution that determines whether a run
  satisfies a named requirement.
- **Invalid**: evidence exists but cannot support a pass/fail decision, for
  example malformed judge output or judge disagreement.
- **Error**: execution failed before a valid evaluation result was produced.
- **Skipped**: a case was intentionally not executed and the reason was recorded.
- **Official run**: a run that satisfies every mandatory protocol integrity
  check and all declared gates using an approved suite.

## Required execution order

An official run MUST execute these stages in order:

1. validate the complete suite and all local assets;
2. verify exact judge qualification and independent approval, then capture
   source, environment, SUT, judge, and authorization evidence;
3. generate and preserve target responses;
4. run deterministic metrics;
5. run judges only when deterministic hard gates pass;
6. aggregate distinct cases without treating repetitions as independent cases;
7. apply predeclared gates;
8. generate restricted evidence and sanitized reports;
9. hash and verify the final artifact bundle;
10. sign the manifest when a configured signing identity is available.

## Status rules

- `pass` means all mandatory metrics for the observation passed.
- `fail` means at least one valid mandatory metric failed.
- `invalid`, `error`, and `skipped` MUST be reported separately and MUST NOT be
  counted as passes or failures.
- An official run MUST fail closed when any required case is invalid, errors, or
  is skipped.
- A deterministic hard failure MUST NOT be overridden by an LLM judge.
- A model or judge identity mismatch MUST abort an official run.
- An official run MUST verify a passing, unexpired independent approval whose
  hash links the exact judge qualification report. The qualified judge model,
  revision, endpoint, prompt, rubric, response schema, sampling, ensemble, and
  consensus configuration MUST exactly match the run.
- Semantic-contamination approval MUST resolve to a suite-local evidence file
  whose hash, dataset hash, comparison-corpus hash, detector identity and
  revision, candidate-pair evidence, independent-review evidence, cross-split
  scope, and cross-suite scope are verified before execution.

## Versions and compatibility

Protocol, engine, schema, report, suite, dataset, rubric, metric implementation,
adapter, target revision, and judge revision are independently versioned.
Official comparisons require compatible protocol and suite versions. A mapping
between versions MUST be explicit, versioned, and included in the comparison
bundle. Released datasets and rubrics MUST NOT be modified in place.

## Claims

Allowed wording:

> Results produced in conformance with CavadaLabs Evaluation Protocol 1.0.0,
> suite `<name>@<version>`, within the scope and limitations stated in the report.

The following claims are prohibited unless supported by a separate accountable
assessment: universally correct, perfectly safe, risk free, legally compliant,
certified, unbiased, secure against every attack, or valid outside the tested
scope.

## Data and external services

Official runs MUST NOT contain real secrets. Non-public inputs MUST NOT be sent
to external targets, judges, telemetry, or synchronization services without a
recorded authorization identifying purpose, destination, region, approver, and
expiry. Public reports MUST NOT disclose private holdout inputs or restricted
failure payloads.

## Known measurement limitations

Finite datasets cannot cover all future inputs. Model and judge outputs may be
stochastic. Judge models can be biased or wrong. Public benchmarks may be
contaminated. Statistical confidence describes sampled observations and does
not prove safety or correctness outside the declared population and conditions.
