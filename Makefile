REGISTRY := 339735964233.dkr.ecr.us-east-1.amazonaws.com
BUCKET := tkhq-development-qos-resources

LOCAL_EPH_PATH := ./local-enclave/qos.ephemeral.key

.PHONY: local-enclave
local-enclave:
	@# Remove the directory where we default to setting up the enclave file system
	rm -rf ./local-encalve
	@# Start the enclave with mock feature and mock flag so we can use the MockNSM
	cargo run --bin qos_core \
		--features mock \
		-- \
		--usock ./dev.sock \
		--mock

.PHONY: sample-app-dangerous-dev-boot
local-dangerous-dev-boot:
	@# This is a bit confusing: the mock attestation doc contains the mock eph secret
	@# because it is hardcoded. However, when attempting to decrypt quorum shares
	@# the enclave will look in the local file system for the key, not the
	@# attestation doc; so we need to point to the key on the local
	@# file system and use that for encrypting the key shares. In other words,
	@# the local enclave will write the eph secret to LOCAL_EPH_PATH and we are
	@# telling the client to look at that same file and use that key for encryption.
	cargo run --bin qos-client \
		-- \
		dangerous-dev-boot \
		--host-ip 127.0.0.1 \
		--host-port 3000 \
		--restart-policy never \
		--unsafe-eph-path-override $(LOCAL_EPH_PATH) \
		--pivot-path ./target/debug/sample_app

.PHONY: vm-enclave
vm-enclave:
	OPENSSL_DIR=/usr cargo run \
		--bin qos_core \
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

.PHONY: build-host
build-host:
	docker build \
		--file images/host/Dockerfile \
		--tag $(REGISTRY)/qos/host \
		$(PWD)

.PHONY: push-host
push-host:
	docker push $(REGISTRY)/qos/host

.PHONY: client
client: clean build-client push-client

.PHONY: build-client
build-client:
	docker build \
		--file images/client/Dockerfile \
		--tag $(REGISTRY)/qos/client \
		$(PWD)

.PHONY: push-client
push-client:
	docker push $(REGISTRY)/qos/client

.PHONY: core
core: clean build-core push-core

.PHONY: build-core
build-core:
	docker build \
		--file images/core/Dockerfile \
		--tag $(REGISTRY)/qos/core \
		$(PWD)

.PHONY: push-core
push-core:
	docker push $(REGISTRY)/qos/core

.PHONY: sample-app
sample-app: clean clean-sample-app build-sample-app push-sample-app

.PHONY: clean-sample-app
clean-sample-app:
	rm -f ./pivot.executable

.PHONY: build-sample-app
build-sample-app:
	docker build \
		--file images/sample-app/Dockerfile \
		--tag $(REGISTRY)/qos/sample-app \
		$(PWD); \
	docker rm -f qos-sample-app; \
	docker create \
		--name qos-sample-app \
		$(REGISTRY)/qos/sample-app; \
	docker cp qos-sample-app:/usr/local/bin/sample-app ./pivot.executable

.PHONY: push-sample-app
push-sample-app:
	PIVOT_HASH=0x$(shell shasum -a256 "./pivot.executable" | cut -d ' ' -f1); \
	BUCKET="tkhq-development-qos-resources" ; \
	echo $$PIVOT_HASH; \
	aws s3 cp ./pivot.executable s3://$${BUCKET}/$${PIVOT_HASH}/pivot.executable

.PHONY: lint
lint:
	cargo +nightly version
	cargo clippy --fix --allow-dirty
	cargo +nightly fmt

.PHONY: test-all
test-all:
	@# The integration tests rely on binaries from other crates being built, so
	@# we build all the workspace targets.
	cargo build --all
	@# Run all tests, including tests marked `ignore`
	cargo test --all-targets