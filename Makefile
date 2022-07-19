REGISTRY := 339735964233.dkr.ecr.us-east-1.amazonaws.com
BUCKET := tkhq-development-qos-resources

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