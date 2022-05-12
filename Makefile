.PHONY: test
test:
	cargo test -- --nocapture

.PHONY: enclave
enclave:
	cargo run --bin qos-core \
		-- \
		--usock ./dev.sock

.PHONY: host
host:
	cargo run --bin qos-host \
		-- \
		--host-ip 127.0.0.1 \
		--host-port 3000 \
		--usock ./dev.sock

.PHONY: clientecho
clientecho:
	cargo run --bin qos-client \
		echo \
		--host-ip 127.0.0.1 \
		--host-port 3000 \
		--echo-data "vape nation"

.PHONY: client
client:
	cargo run --bin qos-client
