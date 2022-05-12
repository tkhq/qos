.PHONY: test
test:
	cargo test -- --nocapture

.PHONY: enclave
enclave:
	cargo run --bin qos-core -- --usock ./dev.sock

.PHONY: host
host:
	cargo run --bin qos-host

.PHONY: client
client:
	cargo run --bin qos-cli
