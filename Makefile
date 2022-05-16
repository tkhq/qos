.PHONY: test
test:
	cargo test -- --nocapture

.PHONY: enclave
enclave:
	cargo run --bin qos-core \
		-- \
		--usock ./dev.sock

.PHONY: local-host
local-host:
	cargo run --bin qos-host \
		-- \
		--host-ip 127.0.0.1 \
		--host-port 3000 \
		--usock ./dev.sock

.PHONY: vm-host
vm-host:
	cargo run \
		--bin qos-host \
		--features vm \
		-- \
		--host-ip 127.0.0.1 \
		--host-port 3000 \
		--cid 16 \
		--port 6969

.PHONY: local-client-echo
local-client-echo:
	cargo run --bin qos-client \
		echo \
		--host-ip 127.0.0.1 \
		--host-port 3000 \
		--data "vape nation"

.PHONY: vm-client-echo
vm-client-echo:
	cargo run \
		--bin qos-client \
		--features vm \
		echo \
		--host-ip 127.0.0.1 \
		--host-port 3000 \
		--data "vape nation"

.PHONY: local-client-describe-nsm
local-client-describe-nsm:
	cargo run --bin qos-client \
		describe-nsm \
		--host-ip 127.0.0.1 \
		--host-port 3000

.PHONY: vm-client-describe-nsm
vm-client-describe-nsm:
	cargo run \
		--bin qos-client \
		--features vm \
		describe-nsm \
		--host-ip 127.0.0.1 \
		--host-port 3000

.PHONY: client
client:
	cargo run --bin qos-client

.PHONY: image
image:
	docker build -t tkhq/qos .