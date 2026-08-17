Add an optional `--protocol-transcript <PATH>` flag to `qos_client`.

When present, append one JSON Lines record for every enclave protocol wire attempt and one for its response. Each record must include the endpoint URI, wire encoding, direction (`request` or `response`), and the complete `ProtocolMsg` payload. Compatibility retries must appear as separate attempts in order.

The flag must work for every command that sends an enclave protocol message. Preserve existing behavior and terminal output when it is absent. Do not use global mutable state or environment variables to carry the option. Tests must not make real HTTP requests.

Follow the repository's existing patterns and keep unrelated refactoring out of scope. Run the focused `qos_client` tests when you are done.
