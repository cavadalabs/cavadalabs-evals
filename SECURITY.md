# Security policy

## Supported versions

Only the latest tagged minor release receives security fixes. Historical run
bundles remain verifiable, but old runners must not be used for new official
evaluations after support ends.

## Reporting a vulnerability

Do not open a public issue for vulnerabilities, leaked benchmark holdouts,
personal data, credentials, or attack payloads. Report privately to the
CavadaLabs security contact configured in the official repository security
advisory settings. Include the affected version, reproduction, impact, and any
evidence already shared with third parties.

Maintainers must acknowledge receipt, restrict evidence, assess data exposure,
rotate affected credentials, preserve incident evidence, and coordinate a
release and disclosure timeline. This file is not an incident-response plan;
the accountable organization must maintain and test that plan separately.

## Security boundaries

- Benchmark datasets, media, target outputs, and custom metrics are untrusted.
- Official runs allow local files only and validate paths, types, sizes, and hashes.
- Custom Python from a suite must never be imported directly.
- Non-public evidence must not leave approved destinations.
- Public reports must never contain holdout prompts, raw outputs, secrets, or PII.
- A valid benchmark result is not proof of universal safety or legal compliance.
