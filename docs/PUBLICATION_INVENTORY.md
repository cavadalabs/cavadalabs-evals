# Publication inventory

This inventory controls what may be redistributed from the first public source
release. Repository tracking does not by itself establish redistribution rights.

| Material | Current declaration | Decision | Condition |
| --- | --- | --- | --- |
| Python source, schemas, configuration, and documentation | CavadaLabs, Apache-2.0 | ready | Organizational authorization is tracked separately below. |
| `performance/workloads/llm-serving-synthetic-v1.jsonl` and `llm-serving-synthetic-v2.jsonl` | CavadaLabs synthetic, Apache-2.0 | ready | Preserve notices and exact released hashes. |
| `suites/security-privacy-smoke-v1` | CavadaLabs synthetic; suite metadata says MIT but no retained MIT license text is present | blocked | Retain the applicable license and owner approval, or exclude the suite from public history. |
| `suites/template` | Replaceable synthetic placeholder whose suite metadata says proprietary | blocked | An authorized owner must approve Apache-2.0 redistribution or the public source distribution must exclude it. |
| `suites/cavada-core-assistant-text-v1` | CavadaLabs synthetic; independent rights review pending | blocked | Independently confirm the declaration or exclude the suite from public history. |
| `suites/memo4345-v1` | Imported internal-project provenance; no complete dataset governance or redistribution declaration | blocked | Pass ownership, privacy, contractual, and redistribution review or exclude the suite from public history. |
| `runs/`, operator runtime files, private holdouts, annotations, reviewer evidence, customer evidence | Restricted operational evidence | excluded | Never publish from Git; use only an approved sanitized export. |
| Third-party adapters, standards, and datasets | Source-specific terms | reference-only | Approve the exact artifact before redistributing it. |
| Repository organization approval | No retained approval for the first public push | blocked | Retain explicit approval from an authorized CavadaLabs organization owner. |
| Historical Git author email disclosure | Private maintainer email remains in Git history | blocked | The maintainer must accept disclosure or authorize a history rewrite to a no-reply address. |

Every `blocked` row prevents publishing the current complete Git tree. Deleting
material only from the latest commit is insufficient if it remains in Git
history. The publication owner must retain the stated approval or create and
maintain a history-clean public distribution that excludes the material.

The historical commits also contain the maintainer's private Git author email.
Before public push, the maintainer must explicitly accept that disclosure or
authorize a one-time history rewrite to the GitHub no-reply address. Future
commits in this checkout use the no-reply address.
