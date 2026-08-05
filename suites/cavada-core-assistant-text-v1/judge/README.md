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

The 2,252-item target powers module-level verdict gates. Language, severity,
style, length, probe, and model-family slices remain diagnostic unless a future
version preregisters and funds separate powered gates. This package does not
replace external statistical review or independent approval.
