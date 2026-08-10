# Compliance evidence

`cavada-eval controls` maps run evidence to versioned controls and emits one
status per control: `automated_pass`, `automated_fail`, `manual_required`,
`not_applicable`, `missing`, or `expired`. It never produces a combined
compliance score.

`automated_pass` means only that the catalog's specific automated assertion
passed. It does not mean that the control as a whole, an organization, or a
system complies with law or a standard.

Behavioral tests can support accuracy, robustness, privacy, cybersecurity,
record-keeping, and transparency evidence. They cannot establish legal basis,
applicability, contracts, processor terms, ROPA, DPIA, FRIA, international
transfer validity, human oversight, QMS operation, incident readiness, or
residual-risk acceptance. Those require accountable, dated, independently
stored evidence.

Legal and standard sources must be versioned by effective date. ISO content is
referenced by identifier only unless the organization owns the required license.
Profiles are selected by jurisdiction, role, use case, sector, affected people,
and system classification; unrelated controls are marked not applicable with a
reason rather than silently omitted.

`program/source-register.toml`, `standards/control_catalog.toml`, and
`standards/evidence_crosswalk.toml` are engineering snapshots. They are not
legal advice or authoritative copies. Before use, an accountable reviewer must
verify the current official source, phased applicability, role, jurisdiction,
license, interpretation, and effective date. Generated control records retain
the source version used for the mapping.
