# CavadaLabs Evaluation Program Policy 1.0.0

This policy governs the program registry and suite families. `PROTOCOL.md`
governs individual official runs. If they conflict, the stricter fail-closed
requirement applies and the conflict must be corrected through a versioned
release.

## Versioning and names

Program, registry, protocol, engine, schema, suite, dataset, rubric, metric,
adapter, judge, and report versions are independent. New program suites use
`cavada-<family>-v<major>` identifiers and semantic artifact versions. Existing
pre-program suites remain candidate-only unless migrated into a new governed
suite; migration never silently changes historical results.

A program major version changes when claims, assurance semantics, required
evidence, or compatibility rules change incompatibly. Minor versions may add
backward-compatible suite families or evidence fields. Patch versions correct
non-semantic documentation or implementation defects. A defect that could
change results requires a new affected artifact version and a correction or
revocation notice.

## Compatibility

Results are comparable only when the protocol and suite declare compatibility
and every measurement-relevant artifact is identical or covered by an explicit,
versioned mapping. Same-name or same-major versions alone do not prove result
comparability. Cross-major comparison fails closed until an approved mapping is
included in the comparison bundle.

## Assurance levels

1. `development`: incomplete or planned evidence; no performance claim.
2. `candidate`: runnable and versioned, but not independently calibrated or
   approved; development claims only.
3. `calibrated`: technical calibration evidence passed; external approval may
   still be incomplete; no official claim.
4. `approved`: all protocol, suite, independent review, authorization, storage,
   and release gates passed; CavadaLabs protocol-conformance claims are allowed.
5. `independently-reproduced`: an approved result was reproduced by a separately
   controlled qualified evaluator under a compatible protocol.

Assurance cannot be inferred from a score. It is determined only by evidence
status. Missing, expired, invalid, skipped, or unverifiable mandatory evidence
blocks the level rather than becoming a disclaimer.

## Results and claims

Every result names its suite, version, SUT, configuration, population,
conditions, date, and limitations. No program-level universal score exists.
Constructs such as quality, safety, privacy, security, fairness, performance,
and compliance evidence remain separate.

Results expire after the registry period unless the suite defines a shorter
period. Expiry does not alter historical evidence; it prevents current-use
claims. A material SUT, scaffold, provider, prompt, guardrail, retrieval, tool,
policy, or deployment change requires a new run.

## Correction, revocation, and lifecycle

- `deprecated`: still verifiable, but no longer recommended for new claims.
- `retired`: not accepted for new runs.
- `corrected`: a replacement report identifies the defect and affected result.
- `revoked`: a result cannot support its original claim because integrity,
  identity, methodology, authorization, or mandatory evidence failed.

Corrections and revocations are additive signed records. Released bundles are
never overwritten. Public notices identify affected IDs without disclosing
restricted cases. Appeals and complaints must be recorded, assigned to an
independent decision maker, and resolved without the commercial owner deciding
the technical outcome alone.

## Roles and independence

The organization assigns the roles in `roles.example.toml`. One person may hold
multiple operational roles only when the conflict-of-interest assessment allows
it. The release approver cannot replace independent label, statistical,
security, privacy/legal, or reproduction evidence. AI-generated review is never
represented as independent human review.
