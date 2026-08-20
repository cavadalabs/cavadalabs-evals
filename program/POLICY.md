# CavadaLabs Evaluation Program Policy 1.1.0

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

## Engagement classification and authorization

Every engagement starts with a restricted record conforming to
`schemas/engagement.schema.json`, based on `configs/engagement.example.json`.
It identifies the system owner, measurement target, jurisdictions, requested
and permitted claims, and whether CavadaLabs acts as developer, provider,
deployer, evaluator, testing laboratory, scheme owner, or certification body.
Roles are not interchangeable. An `approved` engagement requires accountable
applicability evidence, conflict assessment, authorization, and a future expiry;
it is hash-linked to the exact protocol, suite artifacts, SUT identity, and SUT
revision before official execution. The repository's example is deliberately
non-approving.

Commercial ownership cannot approve technical validity. Case authors cannot
provide the sole label review; implementers cannot provide the sole security
review; the original decision maker cannot decide an appeal; and an evaluator
cannot call itself independent when financial, organizational, model-provider,
dataset-author, or delivery relationships would reasonably impair impartiality.
Conflicts are disclosed, mitigated, or the work is refused. AI assistance may
support operations but cannot fill an accountable or independent role.

## Complaints and appeals

Complaints and appeals receive immutable IDs, timestamps, scope, evidence,
owner, confidentiality classification, deadlines, actions, and outcome. Receipt
is acknowledged; relevant evidence is preserved; no original artifact is
overwritten. An appeal is decided by a competent person independent of the
original decision and commercial owner. The disposition identifies affected
reports, corrective action, notification duties, and whether a correction,
withdrawal, suspension, or revocation record is required. Retaliation is
prohibited. Contractual and legal escalation routes remain engagement-specific.

## Disclosure and surveillance

Before release, disclosure review separates public claims from restricted
datasets, payloads, personal data, vulnerabilities, reviewer identities, model
credentials, and client-confidential evidence. Public statements include the
suite, version, SUT, conditions, date, expiry, limitations, and assurance level;
they never imply endorsement, accreditation, certification, or legal compliance
without the corresponding authority.

Public export is a post-run decision, not a pre-approval of unknown results. A
release record conforming to `schemas/release-approval-2.0.0.schema.json` links the
verified bundle, manifest, and engagement and records independent statistical,
security, privacy/legal, disclosure, and release decisions. The release
decision maker is distinct from the technical reviewers and from execution and
commercial owners. The public archive carries only a sanitized release record
and hashes of its public files; restricted reviewer evidence remains outside it.

An engagement records whether post-release surveillance is required. When it
is, the plan defines responsible owner, monitored changes, contamination,
evaluator drift, saturation, incidents, complaints, model or scaffold changes,
review frequency, expiry, and triggers for requalification, rerun, correction,
suspension, or revocation. One-time benchmark reports are snapshots and are not
silently converted into continuing certification.

## Laboratory and certification paths

Internal protocol conformance is an evaluation result, not accreditation.
ISO/IEC 17025 is evaluated only as a possible testing-laboratory competence
path with an authorized copy and accreditation-body scoping. ISO/IEC 17065 is a
separate certification-body and scheme path involving certification decisions,
surveillance, complaints, appeals, marks, and external recognition. Laboratory
testing does not authorize product certification, and a management-system
certificate does not certify a model or benchmark result. Until the applicable
path is licensed, implemented, independently assessed, and formally recognized,
CavadaLabs uses only bounded evaluation and protocol-conformance wording.
