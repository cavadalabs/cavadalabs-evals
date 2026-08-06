# Publication inventory

This inventory controls what may be redistributed from the first public source
release. Repository tracking does not by itself establish redistribution rights.

| Material | Current declaration | Public-release decision |
| --- | --- | --- |
| Python source, schemas, configuration, and documentation | CavadaLabs, Apache-2.0 | ready after organizational approval |
| `performance/workloads/llm-serving-synthetic-v1.jsonl` | CavadaLabs synthetic, Apache-2.0 | ready |
| `suites/security-privacy-smoke-v1` | CavadaLabs synthetic, historically MIT | ready as candidate smoke data; never representative or official |
| `suites/template` | replaceable synthetic placeholder | ready as a non-result template |
| `suites/cavada-core-assistant-text-v1` | CavadaLabs synthetic; independent rights review pending | blocked until the declaration is independently confirmed or the suite is excluded from public history |
| `suites/memo4345-v1` | imported internal-project provenance; no complete dataset governance or redistribution declaration | blocked until ownership, privacy, contractual, and redistribution review passes or the suite is excluded from public history |
| `runs/`, operator runtime files, private holdouts, annotations, reviewer evidence, customer evidence | restricted operational evidence | never publish from Git; use only an approved sanitized export |
| Third-party adapters, standards, and datasets | source-specific terms | references only until each exact artifact is approved |

The two blocked suites prevent publishing the current complete Git tree as a
public repository. Deleting them only from the latest commit is insufficient if
they remain in Git history. The publication owner must either approve their
rights with retained evidence or create and maintain a history-clean public
distribution that excludes them.

The historical commits also contain the maintainer's private Git author email.
Before public push, the maintainer must explicitly accept that disclosure or
authorize a one-time history rewrite to the GitHub no-reply address. Future
commits in this checkout use the no-reply address.

