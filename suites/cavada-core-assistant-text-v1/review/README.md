# Reviewer package

This directory contains public training and package templates. It contains no
official private holdout, reviewer identity, or completed independent label.

`reviewer_qualification.jsonl` is a draft author-gold training set. Before use
for qualification, independent EN/IT reviewers must verify every gold label,
an adjudicator must resolve disagreements, the final file must be hash-pinned,
and passing thresholds must be preregistered. The scored qualification set must
then be separated from these visible examples.

A blind annotation export must contain only randomized package IDs, scenario
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

`author-qa-0.5.0.json` preserves the failed audit that found two factuality
shortcuts. `author-qa-0.5.1.json` preserves the corrected 320-case ledger.
`author-qa-0.6.0.json` is the active 360-case ledger and also verifies complete
benign refusal-neighbor coverage. Reproduce them with
`scripts/audit_dataset_quality.py`. They record author and machine checks only;
their `not-independent` declaration prevents them from being mistaken for
approval evidence.
