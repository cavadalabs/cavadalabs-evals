# Standards and external benchmarks

`control_catalog.toml` separates three things that must not be collapsed into one score:

1. behavioral or technical tests that this runner can execute;
2. engineering evidence that can be checked automatically only in part;
3. legal, contractual and governance evidence requiring accountable approval outside the runner.

External benchmark entries are discovery records, not dependencies. A candidate is imported only after checking its current license, dataset provenance, maintenance status, data-transfer behavior and fit for the intended system. Imported data must be pinned by version and SHA-256; the runner never downloads mutable datasets during an official run.

Current candidates include garak, CyberSecEval, AgentDojo, PrivacyLens and Microsoft Presidio. They complement CavadaLabs suites; none can establish GDPR or AI Act compliance by itself.

`risk_mappings.toml` tracks the current OWASP LLM Top 10 2026 taxonomy released
on 2026-08-03. The previous 2025 crosswalk is preserved in
`risk_mappings-owasp-llm-2025.toml`; taxonomy renumbering never rewrites old run
evidence or implies that the mapped smoke cases provide complete coverage.

`evidence_crosswalk.toml` is the dated machine-validated framework index.
`licensed_mapping.example.toml` is deliberately empty of protected ISO clause
text: populate it only from an organization-authorized current copy in a
controlled workspace. Engagement roles, claims, conflicts, appeals, disclosure,
and surveillance start from `configs/engagement.example.json` and
`program/POLICY.md`.
