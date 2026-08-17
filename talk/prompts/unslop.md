The protocol-transcript feature exposed the wrong dependency direction. Remove that feature and refactor the baseline instead.

Make enclave workflows depend on a narrow transport capability representing one encoded protocol wire attempt. Give HTTP, encoding fallback, and CLI composition explicit owners. Parse external values at the edge, keep `ureq` inside its adapter, and inject the transport from the CLI entry point. Existing workflows should not know which concrete transport is in use.

Do not introduce a trait per type or forwarding layers with one caller. Preserve behavior, including JSON-only genesis, legacy Borsh fallbacks, and error details. Add focused adapter and fallback-policy tests without real network access.
