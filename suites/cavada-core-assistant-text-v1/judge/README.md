# Judge qualification package

Status: preregistration draft; no judge is qualified.

The official corpus targets 2,252 independent fixed responses. Each module has
separate human-gold pass and fail samples so failure sensitivity and benign-pass
specificity are measured independently. High-risk privacy, security, and safety
modules use 142 responses per verdict: at a true rate of 0.99 this gives at
least 80% exact-binomial power to clear a 0.95 Wilson lower-bound gate. Other
module targets follow their predeclared gates and power calculations.

The corpus must be balanced to the machine-readable blueprint across English
and Italian, severity, response length, response style, and probe type. It must
contain outputs from at least four unrelated model families plus deliberate
positive and negative controls. Model family is a sampling stratum, never shown
to the judge.

`borderline` is a probe tag, not a third judge verdict. Independent human
reviewers must resolve every item to the strict operational `pass` or `fail`
rubric before it enters scored qualification. Invalid cases are removed and
reported; malformed judge output is counted as invalid evidence, never forced
to pass or fail.

The required workflow is:

1. freeze response sources and sampling strata before inspecting judge output;
2. obtain two independent EN/IT-capable human labels and separate adjudication;
3. hash and store the restricted gold corpus outside this public repository;
4. run the exact judge identity, revision, prompt, rubric, schema, temperature,
   and repetitions against the frozen recorded responses;
5. report distinct-case confusion counts, failure sensitivity, specificity,
   false-pass and false-fail rates, invalidity, repeated-case stability, and
   module/severity/language slices;
6. run reference-leakage, verbosity, position, order, style, and
   self-preference probes without pooling them into ordinary accuracy;
7. apply gates to Wilson lower bounds, not point estimates, and require all
   mandatory high-risk slices to pass;
8. requalify after any judge, prompt, rubric, schema, policy, or sampling change.

After independent review has produced the restricted JSONL items, assemble the
offline recorded-response qualification suite outside this repository:

```console
uv run python scripts/assemble_judge_calibration.py \
  suites/cavada-core-assistant-text-v1 \
  /restricted/calibration-items.jsonl \
  suites/cavada-core-assistant-text-v1/judge/qualification_blueprint.toml \
  /restricted/cavada-core-judge-qualification-v1 \
  --corpus-version 1.0.0 \
  --frozen-at 2026-08-05T18:00:00+02:00
```

The assembler rejects repository-local restricted input/output, missing or
duplicate items, invalid evidence hashes, allocation drift, verdict imbalance,
and fewer than four anonymous model-family strata. It emits a hash-pinned
`recorded` suite and never includes model/provider identity in the judge
payload. Each input line must satisfy
`schemas/judge-calibration-item.schema.json`. Assembly validates evidence
shape; it cannot establish that the referenced reviewers were independent or
qualified.

After running the assembled suite with at least two repetitions of the exact
judge configuration, apply the preregistered Wilson lower-bound, invalidity,
and repeat-stability gates without modifying the finalized run:

```console
uv run cavada-eval judge-qualify \
  /restricted/runs/JUDGE-RUN \
  suites/cavada-core-assistant-text-v1/judge/qualification_blueprint.toml \
  /restricted/cavada-core-judge-qualification-v1/corpus_manifest.json \
  /restricted/qualifications/JUDGE-RUN.json
```

The output fingerprints the exact judge identities, revisions, judge prompt,
rubric, schema, blueprint, corpus, and run manifest. Any module gate,
invalid-case gate, repetition requirement, or stability gate failure returns a
non-passing qualification result. Style, length, probe, language, severity, and
model-family slices remain visible diagnostics unless separately powered.

An independent qualified reviewer then copies
`configs/judge_approval.example.json` into restricted evidence storage,
replaces every fail-closed placeholder, and pins the qualification report's
SHA-256. Official runs require both immutable files:

```console
uv run cavada-eval run SUITE ... --official \
  --judge-qualification /restricted/qualifications/JUDGE-RUN.json \
  --judge-approval /restricted/approvals/JUDGE-RUN.json
```

The runner verifies the approval period and linkage, every qualification gate,
and the complete judge configuration before creating the run directory.

The 2,252-item target powers module-level verdict gates. Language, severity,
style, length, probe, and model-family slices remain diagnostic unless a future
version preregisters and funds separate powered gates. This package does not
replace external statistical review or independent approval.
