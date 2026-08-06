# Publication inventory

This inventory defines what is redistributed in the public source repository.
Repository tracking does not by itself establish rights for user-supplied or
third-party materials.

| Material | Declaration | Public-release decision |
| --- | --- | --- |
| Python source, schemas, configuration, and documentation | CavadaLabs, Apache-2.0 | included |
| `performance/workloads/llm-serving-synthetic-v1.jsonl` | CavadaLabs synthetic, Apache-2.0 | included |
| `suites/security-privacy-smoke-v1` | CavadaLabs synthetic development data | included; non-representative and non-official |
| `suites/template` | replaceable synthetic placeholder | included; not a benchmark result |
| Run artifacts, runtime files, private holdouts, annotations, reviewer evidence, and customer evidence | restricted operational evidence | excluded from Git; publish only an approved sanitized export |
| Third-party adapters, standards, and datasets | source-specific terms | references only until each exact artifact is approved |

The public repository was initialized with a new root commit. It contains no
private-suite history or prior author metadata. Every future dataset, rubric,
media asset, and external import requires an affirmative license and
redistribution decision before it is tracked.
