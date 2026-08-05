# Cavada Core Assistant Text v1

Version: `0.5.1`; status: `draft`; assurance: `development`.

This is the first planned high-assurance CavadaLabs suite. It evaluates a fixed
general-purpose conversational assistant configuration in English and Italian.
It does not cover RAG, tools, MCP, code execution, images, audio, video, or
professional fitness in high-impact domains.

The active dataset contains 320 deterministic synthetic development cases: 160
public examples and 160 practice cases, balanced across ten modules and two
languages. They are not a calibration set, private holdout, representative
sample, independent human gold, or evidence of model quality. The four `0.1.0`
authoring fixtures remain in `dataset.jsonl` as immutable history and are not
loaded by this suite version. All superseded datasets also remain for
reproducibility. Version `0.5.1` retains all prior corrections and replaces the
practice templates with distinct EN/IT scenarios. The public and practice
splits now have no token-containment duplicate candidates at the declared 0.95
threshold, but share one synthetic authoring process and are not independent
human evidence. It also removes two factuality shortcuts detected by the
reproducible author-QA ledger. The frozen design target is 1,840 independent
cases, subject to pre-pilot statistical review.

Read `MEASUREMENT_SPEC.md`, `STATISTICAL_ANALYSIS_PLAN.md`, and
`case_blueprint.toml` before authoring cases.
`DEVELOPMENT_DATASET_CARD-0.5.1.md` records the current limitations and
regeneration command. Do not create the private holdout in this public
repository.
