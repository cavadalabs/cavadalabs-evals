# Source, license, and adapter policy

This policy governs external material reviewed for the CavadaLabs Evaluation
Program. Mention is not permission to copy, publish, transfer, train on, or call
a source. A source may enter an official suite only
when its declared use, exact version, license, attribution, data rights,
transfer path, security controls, and suite-specific validity have all been
approved.

Rules:

1. Pin software and mutable threat data to an immutable commit or release.
2. Review every imported task and dataset separately; a framework license does
   not override the license of bundled data, models, images, or benchmarks.
3. Do not commit private prompts, restricted datasets, paid standards, API
   credentials, or material whose redistribution right is unclear.
4. Treat network services as data transfers. Official use requires contracts,
   DPA/transfer review, retention and training terms, region, subprocessors,
   incident handling, and an approved data-flow record.
5. Use discovery scanners only to propose candidate cases. A discovered prompt
   affects official scores only after independent review and a new suite version.
6. Reference laws, standards, and taxonomies without claiming certification,
   endorsement, legal compliance, or complete control coverage.
7. Preserve notices and trademark requirements. “Mapped to” never means
   “endorsed by.”
8. Re-review sources before every adapter upgrade and immediately after a
   license, API, ownership, or terms change.

Approval meanings:

- `reference-approved`: may inform mappings and methodology by citation only.
- `adapter-candidate`: exact pinned software may be evaluated in isolation;
  this is not approval of its bundled tasks or data.
- `legal-review-required`: no official ingestion or redistribution.
- `service-authorization-required`: no official network call or data transfer.
- `blocked`: prohibited until the stated condition changes.

The program owner, legal/privacy owner, security owner, and data steward must
sign the eventual suite source manifest. The repository cannot substitute for
those accountable approvals.
