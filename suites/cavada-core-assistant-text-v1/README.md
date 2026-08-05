# Cavada Core Assistant Text v1

Version: `0.2.1`; status: `draft`; assurance: `development`.

This is the first planned high-assurance CavadaLabs suite. It evaluates a fixed
general-purpose conversational assistant configuration in English and Italian.
It does not cover RAG, tools, MCP, code execution, images, audio, video, or
professional fitness in high-impact domains.

The active dataset contains 320 deterministic synthetic development cases: 160
public examples and 160 practice cases, balanced across ten modules and two
languages. They are not a calibration set, private holdout, representative
sample, independent human gold, or evidence of model quality. The four `0.1.0`
authoring fixtures remain in `dataset.jsonl` as immutable history and are not
loaded by this suite version. The superseded `dataset-0.2.0.jsonl` also remains
for reproducibility; `0.2.1` removes one accidental cross-suite duplicate. The
frozen design target is 1,840 independent cases, subject to pre-pilot
statistical review.

Read `MEASUREMENT_SPEC.md`, `STATISTICAL_ANALYSIS_PLAN.md`, and
`case_blueprint.toml` before authoring cases.
`DEVELOPMENT_DATASET_CARD-0.2.1.md` records the current limitations and
regeneration command. Do not create the private holdout in this public
repository.
