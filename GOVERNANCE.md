# Governance

CavadaLabs maintains the project. The current maintainer of record is
`@davoddino`; additional maintainers must be named in `CODEOWNERS` before they
exercise merge or release authority.

## Decisions

- Routine fixes and documentation use normal pull-request review.
- Changes to protocols, schemas, suite lifecycle, result claims, security gates,
  official execution, signing, or release policy require an explicit maintainer
  decision and passing CI.
- Released datasets, rubrics, plans, and schemas are immutable. Corrections use a
  new version and preserve the affected historical artifact.
- A score, majority vote, commercial interest, or maintainer status cannot
  replace evidence required by `PROTOCOL.md`.

Significant methodology changes should begin as a public proposal describing the
problem, alternatives, compatibility impact, threats to validity, and migration.
Security-sensitive details remain private until coordinated disclosure permits
publication.

## Roles and independence

Code ownership controls repository review; it does not establish independent
benchmark review. Calibration, legal, statistical, security, release, and appeal
roles remain subject to `program/POLICY.md` and may require people independent of
CavadaLabs or the evaluated system.

The repository currently names one maintainer and has no second qualified,
independent reviewer formally designated for governance decisions. Passing CI
or a synthetic fixture cannot fill that role. Until such a reviewer is named
and the relevant approval is recorded, the repository has no real approved
suite, official result, public-release approval, or independent reproduction.

## Releases

Maintainers release semantic versions from protected, reviewed commits. A release
tag must match the package version, pass CI, produce an SBOM and provenance, and
remain immutable. Security corrections receive a new release; published tags and
artifacts are never silently replaced.

The software readiness sequence is distinct from evidence governance:

1. software conformance-ready;
2. suite approved;
3. run official;
4. public release approved;
5. independently reproduced;
6. verified registry record.

No earlier state implies a later one. Registry lifecycle changes are append-only
and preserve withdrawn, corrected, superseded, and expired evidence.
