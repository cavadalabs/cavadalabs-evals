# Governance

CavadaLabs maintains the project. The current maintainer of record is
`@davoddino`; additional maintainers must be named in `.github/CODEOWNERS`
before they exercise merge or release authority.

`.github/CODEOWNERS` records intended review ownership. It does not prove that
branch protection, required reviews, repository signing, or immutable tags are
enabled on a hosting service.

## Decisions

- Routine fixes and documentation use normal pull-request review.
- Changes to protocols, schemas, suite lifecycle, result claims, security gates,
  official execution, signing, or release policy require an explicit maintainer
  decision and passing CI.
- Released datasets, rubrics, plans, and schemas are immutable. Corrections use a
  new version and preserve the affected historical artifact.
- A score, majority vote, commercial interest, or maintainer status cannot
  replace evidence required by `PROTOCOL.md`.

Significant methodology changes should begin as a reviewable proposal describing
the problem, alternatives, compatibility impact, threats to validity, and
migration. Security-sensitive details remain private until coordinated
disclosure permits publication.

## Roles and independence

Code ownership controls repository review; it does not establish independent
benchmark review. `program/roles.example.toml` is a template, not evidence that
roles have been assigned. Calibration, legal, statistical, security, release,
and appeal roles remain subject to `program/POLICY.md` and may require people
independent of CavadaLabs or the evaluated system.

## Releases

A public release requires a protected and reviewed commit, a tag matching the
package version, passing release checks, an SBOM, provenance, and an immutable
published tag. The current repository publication inventory remains the release
decision gate. Security corrections receive a new version; published tags and
artifacts are never silently replaced.
