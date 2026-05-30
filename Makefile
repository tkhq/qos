include src/macros.mk

PIVOT_BIN ?= pivot_download
PIVOT_ARGS ?= [http://objdump.katona.me/program.bin,109.123.250.238:80]
REGISTRY := local
CARGO_WORKSPACE_FILES := Cargo.toml Cargo.lock
.DEFAULT_GOAL :=
.PHONY: default
default: \
	out/qos_client/index.json \
	out/qos_host/index.json \
	out/qos_enclave/index.json \
	out/qos_bridge/index.json \
	out/qos_enclave_egress/index.json \
	out/qos_bridge_egress/index.json \
	out/signed_echo/index.json

.PHONY: test
test: out/.common-loaded
	$(call run,make -C src test)

.PHONY: lint
lint: out/.common-loaded
	$(call run,make -C src lint)

.PHONY: format
format: out/.common-loaded
	$(call run,make -C src fmt)

.PHONY: docs
docs: out/.common-loaded
	$(call run,cargo doc)

.PHONY: build-linux-only
build-linux-only: out/.common-loaded
	$(call run,make -C src build-linux-only)

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

qemu: out/nitro.eif /tmp/vhost4.socket
	qemu-system-x86_64 -M nitro-enclave,vsock=c,id=hello-world -kernel out/nitro.eif -nographic -m 4G --enable-kvm -cpu host -chardev socket,id=c,path=/tmp/vhost4.socket

.PHONY: stop
stop:
	-killall qemu-system-x86_64
	-killall vhost-device-vsock
	rm -f /tmp/vhost4.socket

/tmp/vhost4.socket:
	vhost-device-vsock --vm guest-cid=4,forward-cid=1,forward-listen=3000+9001+9002,socket=/tmp/vhost4.socket &

.PHONY: host
host:
	cargo run --locked -p qos_host --features qemu -- \
		--host-ip 0.0.0.0 \
		--host-port 3001 \
		--cid 1 \
		--port 9001

.PHONY: bridge
bridge: target/x86_64-unknown-linux-musl/release-panic-abort/egress
	cargo run -p qos_bridge --locked --bin ingress --features egress,qemu -- \
		--cid 1 \
		--control-url http://127.0.0.1:3001/qos \
		--vsock-to-host false \
		--egress-bin-path target/x86_64-unknown-linux-musl/release-panic-abort/egress

.PHONY: boot
boot:
	cd src/integration && cargo run --locked -p integration --example boot_enclave -- ../../target/x86_64-unknown-linux-musl/release/examples/$(PIVOT_BIN) $(PIVOT_ARGS)

# used for egress testing as our pivot, expects a single http url for file download
target/x86_64-unknown-linux-musl/release/examples/pivot_download: \
	src/integration/examples/pivot_download.rs \
	src/integration/Cargo.toml \
	Cargo.toml
	cargo build --release --locked --target x86_64-unknown-linux-musl -p integration --example pivot_download

# used for egress testing as our separate egress host proxy
target/x86_64-unknown-linux-musl/release-panic-abort/egress: \
	src/qos_bridge/Cargo.toml \
	src/qos_bridge/src/bin/egress.rs \
	src/qos_bridge/src/*.rs \
	Cargo.toml
	cargo build --profile release-panic-abort --features egress,qemu --locked --target x86_64-unknown-linux-musl -p qos_bridge --bin egress

out/nitro.eif: \
	src/images/qemu/Containerfile \
	Cargo.toml \
	Cargo.lock \
	$(shell git ls-files src/init src/qos_core src/qos_bridge)
	docker build -t qos-qemu-base -f src/images/qemu/Containerfile . --output type=tar,dest=out/nitro.tar
	tar -xf out/nitro.tar -C out && rm -f out/nitro.tar

out/qos_enclave/index.json: \
	out/common/index.json \
	$(CARGO_WORKSPACE_FILES) \
	src/images/qos_enclave/Containerfile \
	$(shell git ls-files \
		src/init \
		src/qos_enclave \
		src/qos_core \
		src/qos_bridge \
		src/qos_aws \
		src/qos_system \
	)
	$(call build,qos_enclave)

out/qos_enclave_egress/index.json: \
	out/common/index.json \
	$(CARGO_WORKSPACE_FILES) \
	src/images/qos_enclave_egress/Containerfile \
	$(shell git ls-files \
		src/init \
		src/qos_enclave \
		src/qos_core \
		src/qos_aws \
		src/qos_system \
	)
	$(call build,qos_enclave_egress)

out/qos_host/index.json: \
	out/common/index.json \
	$(CARGO_WORKSPACE_FILES) \
	src/images/qos_host/Containerfile \
	$(shell git ls-files \
		src/qos_host \
		src/qos_core \
	)
	$(call build,qos_host)

out/qos_client/index.json: \
	out/common/index.json \
	$(CARGO_WORKSPACE_FILES) \
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

out/qos_bridge/index.json: \
	out/common/index.json \
	$(CARGO_WORKSPACE_FILES) \
	src/images/qos_bridge/Containerfile \
	$(shell git ls-files \
		src/qos_bridge \
		src/qos_host \
		src/qos_core \
		src/qos_hex \
		src/qos_nsm \
	)
	$(call build,qos_bridge)

out/qos_bridge_egress/index.json: \
	out/common/index.json \
	$(CARGO_WORKSPACE_FILES) \
	src/images/qos_bridge_egress/Containerfile \
	$(shell git ls-files \
		src/qos_bridge \
		src/qos_host \
		src/qos_core \
		src/qos_hex \
		src/qos_nsm \
	)
	$(call build,qos_bridge_egress)

out/signed_echo/index.json: \
	out/common/index.json \
	$(CARGO_WORKSPACE_FILES) \
	src/images/signed_echo/Containerfile \
	$(shell git ls-files \
		src/signed_echo \
		src/qos_p256 \
		src/qos_hex \
	)
	$(call build,signed_echo)

out/common/index.json: \
	src/images/common/Containerfile
	$(call build,common)

out/.common-loaded: out/common/index.json
	cd ./out/common && tar -cf - . | docker load
	touch ./out/.common-loaded
