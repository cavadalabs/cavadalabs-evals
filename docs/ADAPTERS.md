# Adapter requirements

Run `cavada-eval profiles` to inspect every benchmark shape and whether the
built-in runner can execute it in official mode. Profiles with `built_in=false`
need an approved, pinned adapter and calibration evidence; the runner fails
closed instead of inventing a proxy score.

An adapter declares input/output modalities, endpoint protocol, authentication,
streaming, usage reporting, identity evidence, revision evidence, response
limits, retryable statuses, timeouts, and data destinations. Unsupported content
fails before a request. Official adapters verify reported target and judge
identity and preserve raw protocol evidence.

External benchmark adapters must pin upstream name, version/commit, license,
dataset checksum, evaluator checksum, configuration, invocation, and imported
results. No official run downloads a mutable dataset or executable. Candidates
include lm-evaluation-harness, garak, CyberSecEval, AgentDojo, PrivacyLens,
Presidio, and licensed MLCommons practice/official workflows.

DeepEval 3.x is optional. CavadaLabs sets all documented local privacy controls
before import and does not log in or synchronize. Non-empty DeepEval
metric-engine behavior runs are unsupported in M1 and fail before network
access until their engine evidence has canonical semantic reconstruction.
