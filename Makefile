.PHONY: test
test:
	cargo test -- --nocapture

.PHONY: client
client:
	cargo run --manifest-path ./qos-client/Cargo.toml --bin qos-client

.PHONY: local-enclave
local-enclave:
	cargo run --bin qos-core \
		-- \
		--usock ./dev.sock \
		--mock

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

.PHONY: vm-describe-nsm
vm-describe-nsm:
	OPENSSL_DIR=/usr cargo run \
		--bin qos-client \
		--manifest-path ./qos-client/Cargo.toml \
		--features vm \
		describe-nsm \
		--host-ip 127.0.0.1 \
		--host-port 3000

.PHONY: local-describe-nsm
local-describe-nsm:
	cargo run --bin qos-client \
		--manifest-path ./qos-client/Cargo.toml \
		describe-nsm \
		--host-ip 127.0.0.1 \
		--host-port 3000

.PHONY: vm-describe-pcr
vm-describe-pcr:
		OPENSSL_DIR=/usr cargo run \
		--bin qos-client \
		--manifest-path ./qos-client/Cargo.toml \
		describe-pcr \
		--host-ip 127.0.0.1 \
		--host-port 3000

.PHONY: local-describe-pcr
local-describe-pcr:
	cargo run --bin qos-client \
		--manifest-path ./qos-client/Cargo.toml \
		describe-pcr \
		--host-ip 127.0.0.1 \
		--host-port 3000

.PHONY: local-req-att-doc
local-req-att-doc:
	cargo run --bin qos-client \
		--manifest-path ./qos-client/Cargo.toml \
		request-attestation-doc \
		--host-ip 127.0.0.1 \
		--host-port 3000

.PHONY: gen-att-doc
gen-att-doc:
	OPENSSL_DIR=/usr cargo run --bin gen_att_doc

.PHONY: image
image:
	docker build -t tkhq/qos .

.PHONY: lint
lint:
	cargo +nightly version
	cargo clippy --fix --allow-dirty
	cargo +nightly fmt