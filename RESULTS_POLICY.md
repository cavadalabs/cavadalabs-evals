# Results and trademark policy

The Apache License 2.0 grants rights to the source code, not permission to imply
CavadaLabs endorsement or certification.

## Describing results

Every public result must identify the repository version or commit, protocol,
suite and dataset versions, complete evaluated system and runtime, execution
preset, date, relevant hashes, assurance level, limitations, and a verifiable
result bundle.

The evidence states are cumulative and must be named precisely: software
conformance-ready, suite approved, run official, public release approved,
independently reproduced, and verified registry record. None may be inferred
from an earlier state. At present this repository has an operational
conformance-ready behavior engine, but zero real approved suites, zero real
official results, zero public-release approvals, zero independent
reproductions, and zero verified registry records.

`CavadaLabs Evals-compatible` may describe an independently produced artifact
that passes the published schemas and verifier. `Official CavadaLabs result` may
be used only for an unmodified verified bundle whose manifest records an official
run and whose current release approval permits that exact wording.

A future registry v2 result must reference an exact content-addressed public
evidence archive, pass canonical integrity, semantic, assurance, and release
verification, and retain append-only publication lifecycle events. Withdrawn,
corrected, superseded, and expired records remain historical evidence but are
not current results. A conformance fixture is always non-rankable and cannot
authorize model or benchmark claims.

Offline archive verification does not establish public signing provenance.
Public official records require online GitHub Artifact Attestation verification
of the exact archive subject and canonical workflow identity. Downloaded
Sigstore-bundle verification is not yet a supported registry mode. An optional
HMAC is only an internal shared-secret integrity check and must never be
presented as a public signature.

Publication is deliberately two-phase. Release tag N freezes and attests a new
content-addressed archive while it remains outside the registry. A later reviewed
change may add a registry record bound to tag N's exact subject, commit and
workflow only after online verification succeeds; tag N+1 then publishes that
append-only registry state. A record is never accepted on the promise that the
same workflow will attest it later.

Never describe a development, smoke, quick, standard, candidate, expired,
modified, unverifiable, or independently generated result as CavadaLabs-official.
Do not claim certification, accreditation, universal correctness, universal
safety, legal compliance, or regulatory approval unless a separate competent
authority explicitly provides it.

Blinded pairwise output judging with retained A/B and B/A orders is unsupported.
Private AI is not part of the canonical 0.4 line. Serving-performance official
assurance is outside the behavior M1 milestone.

## Marks

`CavadaLabs`, its logos, and confusingly similar branding are trademarks or
source identifiers of CavadaLabs. Factual nominative references are allowed.
Forks and modified distributions must not use branding that implies sponsorship,
and must prominently identify their changes.
