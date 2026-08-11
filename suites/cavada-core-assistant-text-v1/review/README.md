# Reviewer package

This directory contains public training and package templates. It contains no
official private holdout, reviewer identity, or completed independent label.

`reviewer_qualification.jsonl` is a draft author-gold training set. Before use
for qualification, independent EN/IT reviewers must verify every gold label,
an adjudicator must resolve disagreements, the final file must be hash-pinned,
and passing thresholds must be preregistered. The scored qualification set must
then be separated from these visible examples.

Any future blind review package must contain only randomized package IDs, scenario
evidence, response aliases, applicable rubric sections, and required form
fields. It must exclude provider/model names, endpoint metadata, prices,
latencies, other reviewers’ labels, target scores, and split names that reveal
holdout membership.

Required reviewer evidence:

- signed role, competence, native-language scope, training, conflicts, and
  confidentiality declarations;
- package hash, handbook version, rubric hash, start/end time, and tool version;
- raw independent label, criterion findings, rationale, severity, confidence,
  and escalation flags;
- immutable disagreement and adjudication records;
- agreement statistics with uncertainty and qualification outcome.

All files containing identities or restricted cases belong in approved
restricted storage, not this repository.

Superseded author-QA ledgers, including the 0.8.0 machine check, are archived at
checkpoint `eb93846e40c4eca6c62d10ab8dbb7e654020987a`. They were never
independent approval evidence and are intentionally absent from the active
checkout.
