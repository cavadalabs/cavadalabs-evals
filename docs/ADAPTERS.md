# Execution boundaries

The maintained benchmark surface is text behavior and generation-only LLM
serving. Media parsing and capability validation remain fail-closed trust
boundaries; they are not public benchmark support.

Target and judge transports declare endpoint protocol, authentication,
streaming, usage reporting, identity and revision evidence, response limits,
retryable statuses, timeouts, and data destinations. Unsupported content fails
before a request; raw protocol evidence is preserved.
