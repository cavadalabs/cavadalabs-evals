# Cavada Core Assistant Text v1

Version: `0.8.0`; status: `draft`; assurance: `development`.

This is the first planned high-assurance CavadaLabs suite. It evaluates a fixed
general-purpose conversational assistant configuration in English and Italian.
It does not cover RAG, tools, MCP, code execution, images, audio, video, or
professional fitness in high-impact domains.

The active dataset contains 404 deterministic synthetic development cases: 202
public examples and 202 practice cases across ten modules and two
languages. They are not a calibration set, private holdout, representative
sample, independent human gold, or evidence of model quality. The four `0.1.0`
authoring fixtures remain in `dataset.jsonl` as immutable history and are not
loaded by this suite version. All superseded datasets also remain for
reproducibility. These rows represent 328 independent primary scenarios (164
per split) plus 76 required variants that cannot inflate statistical sample
size. Version `0.8.0` retains all prior corrections and the 44
construct-matched domain-and-register shift probes, including matched benign
neighbors for the four new privacy refusals. Every refusal case has a benign
neighbor in EN/IT and both splits. The public and practice splits have no
token-containment duplicate candidates at the declared 0.95 threshold, but
share one synthetic authoring process and are not independent human evidence.
The dataset also removes two factuality shortcuts detected by the
reproducible author-QA ledger. The frozen design target is 1,840 independent
scenarios, subject to pre-pilot statistical review.

Read `MEASUREMENT_SPEC.md`, `STATISTICAL_ANALYSIS_PLAN.md`, and
`case_blueprint.toml` before authoring cases. `PILOT_PROTOCOL.md` defines the
fixed multi-family campaign and its external entry criteria.
`DEVELOPMENT_DATASET_CARD-0.8.0.md` records the current limitations and
regeneration command. Do not create the private holdout in this public
repository.
