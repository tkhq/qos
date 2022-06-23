.PHONY: test
test:
	cargo test -- --nocapture

.PHONY: local-enclave
local-enclave:
	cargo run --bin qos-core \
		-- \
		--usock ./dev.sock \

.PHONY: vm-enclave
vm-enclave:
	OPENSSL_DIR=/usr cargo run \
		--bin qos-core \
		--features vm \
		-- \
		--cid 16 \
		--port 6969

.PHONY: local-host
local-host:
	cargo run --bin qos-host \
		-- \
		--host-ip 127.0.0.1 \
		--host-port 3000 \
		--usock ./dev.sock

.PHONY: vm-host
vm-host:
	OPENSSL_DIR=/usr cargo run \
		--bin qos-host \
		--features vm \
		-- \
		--host-ip 127.0.0.1 \
		--host-port 3000 \
		--cid 16 \
		--port 6969

.PHONY: vm-client-describe-nsm
vm-client-describe-nsm:
	OPENSSL_DIR=/usr cargo run \
		--bin qos-client \
		--features vm \
		describe-nsm \
		--host-ip 127.0.0.1 \
		--host-port 3000

.PHONY: local-client-describe-nsm
local-client-describe-nsm:
	cargo run --bin qos-client \
		describe-nsm \
		--host-ip 127.0.0.1 \
		--host-port 3000

.PHONY: gen-att-doc
gen-att-doc:
	OPENSSL_DIR=/usr cargo run --bin gen_att_doc

.PHONY: image
image:
	docker build -t tkhq/qos .