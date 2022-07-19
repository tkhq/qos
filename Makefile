REGISTRY := 339735964233.dkr.ecr.us-east-1.amazonaws.com

.PHONY: local-enclave
local-enclave:
	cargo run --bin qos-core \
		--features mock \
		-- \
		--usock ./dev.sock \
		--ephemeral-file ./qos-core/src/protocol/attestor/static/boot_e2e_mock_eph.secret \
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

.DEFAULT_GOAL := all
default: all

.PHONY: all
all: host client core

.PHONY: clean
clean:
	cargo clean

.PHONY: host
host: clean build-host push-host

.PHONY: client
client: clean build-client push-client

.PHONY: core
core: clean build-core push-core

.PHONY: build-host
build-host:
	docker build \
		--file images/host/Dockerfile \
		--tag $(REGISTRY)/qos/host \
		$(PWD)

.PHONY: push-host
push-host:
	docker push $(REGISTRY)/qos/host

.PHONY: build-client
build-client:
	docker build \
		--file images/client/Dockerfile \
		--tag $(REGISTRY)/qos/client \
		$(PWD)

.PHONY: push-client
push-client:
	docker push $(REGISTRY)/qos/client

.PHONY: build-core
build-core:
	docker build \
		--file images/client/Dockerfile \
		--tag $(REGISTRY)/qos/core \
		$(PWD)

.PHONY: push-core
push-core:
	docker push $(REGISTRY)/qos/core

.PHONY: lint
lint:
	cargo +nightly version
	cargo clippy --fix --allow-dirty
	cargo +nightly fmt