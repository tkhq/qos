include src/macros.mk

REGISTRY := local
CARGO_WORKSPACE_FILES := Cargo.toml Cargo.lock
.DEFAULT_GOAL :=
.PHONY: default
default: \
	out/qos_client/index.json \
	out/qos_host/index.json \
	out/qos_enclave/index.json \
	out/qos_bridge/index.json

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

.PHONY: nested-nitro-rawhide-parent
nested-nitro-rawhide-parent:
	./src/qos_test_harness/scripts/build_nested_nitro_rawhide_parent.sh

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

qemu: out/nitro.eif
	qemu-system-x86_64 -M nitro-enclave,vsock=c,id=hello-world -kernel out/nitro.eif -nographic -m 4G --enable-kvm -cpu host -chardev socket,id=c,path=/tmp/vhost4.socket

.PHONY: qemu-stop
qemu-stop:
	-killall qemu-system-x86_64
	-killall vhost-device-vsock
	rm -f /tmp/vhost4.socket

/tmp/vhost4.socket:
	vhost-device-vsock --vm guest-cid=4,forward-cid=1,forward-listen=9001,socket=/tmp/vhost4.socket &

out/nitro.tar: Containerfile.qemu src/init/* /tmp/vhost4.socket
	docker build -t qos-qemu-base -f Containerfile.qemu . --output type=tar,dest=out/nitro.tar

out/nitro.eif: out/nitro.tar
	tar -xf out/nitro.tar -C out

out/qos_enclave/index.json: \
	out/common/index.json \
	$(CARGO_WORKSPACE_FILES) \
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

out/common/index.json: \
	src/images/common/Containerfile
	$(call build,common)

out/.common-loaded: out/common/index.json
	cd ./out/common && tar -cf - . | docker load
	touch ./out/.common-loaded
