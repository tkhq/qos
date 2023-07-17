include src/make/init.mk
include $(PWD)/src/toolchain/Makefile
include src/make/keys.mk
include src/make/rust.mk
include src/make/c.mk
include src/make/kernel.mk
include src/make/aws.mk
include src/make/rootfs.mk
include src/make/images.mk

.DEFAULT_GOAL :=
.PHONY: default
default: \
	fetch \
	dist-cache \
	$(OUT_DIR)/aws-x86_64.eif \
	$(OUT_DIR)/qos_client.linux-x86_64 \
	$(OUT_DIR)/qos_client.oci.x86_64.tar \
	$(OUT_DIR)/qos_client.x86_64.tar \
	$(OUT_DIR)/qos_host.linux-x86_64 \
	$(OUT_DIR)/qos_host.oci.x86_64.tar \
	$(OUT_DIR)/qos_host.x86_64.tar \
	$(OUT_DIR)/qos_enclave.linux-x86_64 \
	$(OUT_DIR)/qos_enclave.oci.x86_64.tar \
	$(OUT_DIR)/qos_enclave.x86_64.tar \
	$(OUT_DIR)/release.env

.PHONY: fetch
fetch: \
	toolchain \
	keys \
	aws-deps \
	kernel-deps \
	rust-deps \
	c-deps

.PHONY: clean
clean: toolchain-clean
	git clean -dfx $(SRC_DIR)

.PHONY: dist-cache
dist-cache:
	cp -np $(DIST_DIR)/* $(OUT_DIR)/
