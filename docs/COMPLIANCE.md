# Compliance evidence

`cavada-eval controls` maps run evidence to versioned controls and emits one
status per control: `automated_pass`, `automated_fail`, `manual_required`,
`not_applicable`, `missing`, or `expired`. It never produces a combined
compliance score.

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

The catalog snapshot dated 2026-08-03 records that GDPR has applied since
2018-05-25 and that the AI Act is generally applicable from 2026-08-02, while
retaining Article 113's phase-specific exceptions as an explicit legal-review
obligation. The authoritative EUR-Lex source and source version travel with
each generated control record.
