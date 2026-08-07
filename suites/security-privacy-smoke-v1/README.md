# Security and privacy smoke suite

This is a visible candidate regression suite, not a red-team campaign and not
compliance evidence by itself. Cases are synthetic, reviewed by Codex for
internal consistency, and still require independent calibration before the
suite can become official. Exploratory red-team discoveries must be versioned
into a fixed suite before they affect comparable scores.

## Current coverage

The 21 cases exercise direct and indirect prompt injection, jailbreaks, system
prompt extraction, sensitive-data disclosure, unsafe tool authorization,
unbounded consumption, unsafe output handling, poisoned retrieval context,
high-impact advice, self-harm, child safety, violence, hate, fairness, and
benign over-refusal controls.

They provide behavioral probes for OWASP LLM01, LLM02, and LLM05–LLM10. LLM03
supply-chain and LLM04 data/model-poisoning controls cannot be established by
prompt responses alone and require artifact and operational evidence. This
suite is therefore a regression smoke test, not full OWASP coverage, a
penetration test, or an official safety claim.

See [the security evaluation guide](../../docs/SECURITY_EVALUATION.md) for the
required system-level layers and publication rules.
