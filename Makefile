include src/macros.mk

REGISTRY := local
.DEFAULT_GOAL :=
.PHONY: default
default: \
	out/qos_client/index.json \
	out/qos_host/index.json \
	out/qos_enclave/index.json \
	out/reshard_host/index.json \
	out/reshard_app/index.json

.PHONY: test
test: out/.common-loaded
	$(call run,make test)

.PHONY: lint
lint: out/.common-loaded
	$(call run,make lint)

.PHONY: format
format: out/.common-loaded
	$(call run,make fmt)

.PHONY: docs
docs: out/.common-loaded
	$(call run,cargo doc)

.PHONY: build-linux-only
build-linux-only: out/.common-loaded
	$(call run,make build-linux-only)

.PHONY: shell
shell: out/.common-loaded
	docker run \
		--interactive \
		--tty \
		--volume .:/home/qos \
		--workdir /home/qos \
		--user $(shell id -u):$(shell id -g) \
		qos-local/common:latest \
		/bin/bash

out/nitro.pcrs: out/qos_enclave.tar
	@$(call run,/src/scripts/extract_oci_file.sh qos_enclave.tar nitro.pcrs)

out/qos_enclave/index.json: \
	out/common/index.json \
	src/images/qos_enclave/Containerfile \
	$(shell git ls-files \
		src/init \
		src/qos_enclave \
		src/qos_core \
		src/qos_aws \
		src/qos_system \
	)
	$(call build,qos_enclave)

out/qos_host/index.json: \
	out/common/index.json \
	src/images/qos_host/Containerfile \
	$(shell git ls-files \
		src/qos_host \
		src/qos_core \
	)
	$(call build,qos_host)

out/qos_client/index.json: \
	out/common/index.json \
	src/images/qos_client/Containerfile \
	$(shell git ls-files \
		src/qos_client \
		src/qos_p256 \
		src/qos_nsm \
		src/qos_hex \
		src/qos_crypto \
		src/qos_core \
	)
	$(call build,qos_client)

out/common/index.json: \
	src/images/common/Containerfile
	$(call build,common)

out/.common-loaded: out/common/index.json
	cd ./out/common && tar -cf - . | docker load
	touch ./out/.common-loaded

out/reshard_host/index.json: \
	out/common/index.json \
	src/images/reshard_host/Containerfile \
	$(shell git ls-files \
		src/Cargo.toml \
		src/Cargo.lock \
		src/reshard/host \
		src/qos_core \
		src/qos_net \
		src/generated)
	$(call build,reshard_host)

out/reshard_app/index.json: \
	out/common/index.json \
	src/images/reshard_app/Containerfile \
	$(shell git ls-files \
		src/Cargo.toml \
		src/Cargo.lock \
		src/reshard/app \
		src/generated \
		src/qos_p256 \
		src/qos_crypto \
		src/qos_nsm \
		src/qos_hex \
		src/attestation)
	$(call build,reshard_app)
