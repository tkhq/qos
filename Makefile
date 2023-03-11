TARGET := aws
include $(PWD)/src/toolchain/Makefile

ifeq ($(TARGET), aws)
DEFAULT_GOAL := $(OUT_DIR)/$(TARGET)-$(ARCH).eif
else ifeq ($(TARGET), generic)
DEFAULT_GOAL := $(OUT_DIR)/$(TARGET)-$(ARCH).bzImage
endif

ifneq ("$(wildcard $(ROOT)/src/toolchain)","")
	clone := $(shell git submodule update --init --recursive)
endif

.DEFAULT_GOAL :=
.PHONY: default
default: \
	toolchain \
	$(DEFAULT_GOAL) \
	$(OUT_DIR)/qos_client.$(PLATFORM).$(ARCH) \
	$(OUT_DIR)/qos_client_sc.$(PLATFORM).$(ARCH) \
	$(OUT_DIR)/qos_client.oci.$(ARCH).tar \
	$(OUT_DIR)/qos_host.$(PLATFORM).$(ARCH) \
	$(OUT_DIR)/qos_host.oci.$(ARCH).tar \
	$(OUT_DIR)/release.env \
	$(OUT_DIR)/manifest.txt

.PHONY: sign
sign: $(DIST_DIR)/manifest.txt
	set -e; \
	git config --get user.signingkey 2>&1 >/dev/null || { \
		echo "Error: git user.signingkey is not defined"; \
		exit 1; \
	}; \
	fingerprint=$$(\
		git config --get user.signingkey \
		| sed 's/.*\([A-Z0-9]\{16\}\).*/\1/g' \
	); \
	gpg --armor \
		--detach-sig  \
		--output $(DIST_DIR)/manifest.$${fingerprint}.asc \
		$(DIST_DIR)/manifest.txt

.PHONY: verify
verify: $(DIST_DIR)/manifest.txt
	set -e; \
	for file in $(DIST_DIR)/manifest.*.asc; do \
		echo "\nVerifying: $${file}\n"; \
		gpg --verify $${file} $(DIST_DIR)/manifest.txt; \
	done;

# Clean repo back to initial clone state
.PHONY: clean
clean: toolchain-clean
	git clean -dfx $(SRC_DIR)

.PHONY: run
run: $(OUT_DIR)/$(TARGET)-$(ARCH).bzImage
	qemu-system-x86_64 \
		-m 512M \
		-nographic \
		-kernel $(OUT_DIR)/$(TARGET)-$(ARCH).bzImage

# Run linux config menu and save output
.PHONY: linux-config
linux-config:
	rm $(CONFIG_DIR)/$(TARGET)/linux.config
	make TARGET=$(TARGET) $(CONFIG_DIR)/$(TARGET)/linux.config

$(OUT_DIR)/$(TARGET)-$(ARCH).bzImage: $(CACHE_DIR)/bzImage
	cp $(CACHE_DIR)/bzImage $(OUT_DIR)/$(TARGET)-$(ARCH).bzImage

$(OUT_DIR)/$(TARGET)-$(ARCH).eif $(OUT_DIR)/$(TARGET)-$(ARCH).pcrs: \
	$(BIN_DIR)/eif_build \
	$(CACHE_DIR)/bzImage \
	$(CACHE_DIR)/rootfs.cpio \
	$(CACHE_DIR)/linux.config
	mkdir -p $(CACHE_DIR)/eif
	$(call toolchain," \
		export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 \
		export FAKETIME=1 && \
		cp $(CACHE_DIR)/bzImage $(CACHE_DIR)/eif/ && \
		cp $(CACHE_DIR)/rootfs.cpio $(CACHE_DIR)/eif/ && \
		cp $(CONFIG_DIR)/$(TARGET)/linux.config $(CACHE_DIR)/eif/ && \
		find $(CACHE_DIR)/eif -mindepth 1 -execdir touch -hcd "@0" "{}" + && \
		$(BIN_DIR)/eif_build \
			--kernel $(CACHE_DIR)/eif/bzImage \
			--kernel_config $(CACHE_DIR)/eif/linux.config \
			--cmdline 'reboot=k initrd=0x2000000$(,)3228672 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd' \
			--ramdisk $(CACHE_DIR)/eif/rootfs.cpio \
			--pcrs_output $(OUT_DIR)/$(TARGET)-$(ARCH).pcrs \
			--output $(OUT_DIR)/$(TARGET)-$(ARCH).eif; \
	")

$(OUT_DIR)/qos_host.$(PLATFORM).$(ARCH):
	$(call toolchain," \
		export RUSTFLAGS='-C target-feature=+crt-static' && \
		cd $(SRC_DIR)/qos_host \
		&& CARGO_HOME=$(CACHE_DIR)/cargo cargo build \
			--target x86_64-unknown-linux-gnu \
			--features vm \
			--no-default-features \
			--locked \
			--release \
		&& cp \
			../target/x86_64-unknown-linux-gnu/release/qos_host \
			/home/build/$@; \
	")

$(OUT_DIR)/qos_host.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/host/Dockerfile \
	$(OUT_DIR)/qos_host.$(PLATFORM).$(ARCH)
	$(call toolchain," \
		cp $(word 2,$^) $(CACHE_DIR)/ && \
		touch -hcd "@0" $(CACHE_DIR)/$(notdir $(word 2,$^)) && \
		buildah build \
		-f $< \
		--timestamp 1 \
		--build-arg BIN=$(CACHE_DIR)/$(notdir $(word 2,$^)) \
		-o type=tar$(,)dest=$@; \
	")

$(OUT_DIR)/qos_client.$(PLATFORM).$(ARCH):
	$(call toolchain," \
		export RUSTFLAGS='-C target-feature=+crt-static' && \
		cd $(SRC_DIR)/qos_client \
		&& CARGO_HOME=$(CACHE_DIR)/cargo cargo build \
			--target x86_64-unknown-linux-gnu \
			--no-default-features \
			--locked \
			--release \
		&& cp \
			../target/x86_64-unknown-linux-gnu/release/qos_client \
			/home/build/$@; \
	")

$(OUT_DIR)/qos_client_sc.$(PLATFORM).$(ARCH):
	$(call toolchain," \
		cd $(SRC_DIR)/qos_client \
		&& CARGO_HOME=$(CACHE_DIR)/cargo cargo build \
			--target x86_64-unknown-linux-gnu \
			--no-default-features \
			--features smartcard \
			--locked \
			--release \
		&& cp \
			../target/x86_64-unknown-linux-gnu/release/qos_client \
			/home/build/$@; \
	")

$(OUT_DIR)/qos_client.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/client/Dockerfile \
	$(OUT_DIR)/qos_client.$(PLATFORM).$(ARCH)
	$(call toolchain," \
		cp $(word 2,$^) $(CACHE_DIR)/ && \
		touch -hcd "@0" $(CACHE_DIR)/$(notdir $(word 2,$^)) && \
		buildah build \
		-f $< \
		-t qos/$(notdir $(word 2,$^)) \
		--timestamp 1 \
		--build-arg BIN=$(CACHE_DIR)/$(notdir $(word 2,$^)) \
		-o type=tar$(,)dest=$@; \
	")

$(CONFIG_DIR)/$(TARGET)/linux.config:
	$(call toolchain," \
		unset FAKETIME && \
		cd /cache/linux-$(LINUX_VERSION) && \
		make menuconfig && \
		cp .config /config/$(TARGET)/linux.config; \
	")

$(FETCH_DIR)/aws-nitro-enclaves-sdk-bootstrap:
	$(call git_clone,$@,$(AWS_NITRO_DRIVER_REPO),$(AWS_NITRO_DRIVER_REF))

$(KEY_DIR)/$(LINUX_KEY).asc:
	$(call fetch_pgp_key,$(LINUX_KEY))

$(FETCH_DIR)/linux-$(LINUX_VERSION).tar.sign:
	curl --url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.sign --output $@

$(FETCH_DIR)/linux-$(LINUX_VERSION).tar:
	curl --url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.xz --output $@.xz
	xz -d $@.xz

$(FETCH_DIR)/linux-$(LINUX_VERSION): \
	$(FETCH_DIR)/linux-$(LINUX_VERSION).tar \
	$(FETCH_DIR)/linux-$(LINUX_VERSION).tar.sign \
	$(KEY_DIR)/$(LINUX_KEY).asc
	$(call toolchain," \
		gpg --import $(KEY_DIR)/$(LINUX_KEY).asc && \
		gpg --verify $@.tar.sign $@.tar && \
		cd $(FETCH_DIR) && \
		tar -mxf linux-$(LINUX_VERSION).tar; \
	")

$(CACHE_DIR)/linux.config:
	cp $(CONFIG_DIR)/$(TARGET)/linux.config $@

$(CACHE_DIR)/init:
	$(call toolchain," \
		cd $(SRC_DIR)/init && \
		export RUSTFLAGS='-C target-feature=+crt-static' && \
		cargo build \
			--target x86_64-unknown-linux-gnu \
			--locked \
			--release && \
		cp target/x86_64-unknown-linux-gnu/release/init /home/build/$@ \
	")

$(BIN_DIR)/gen_init_cpio: \
	$(FETCH_DIR)/linux-$(LINUX_VERSION)
	$(call toolchain," \
		cd $(FETCH_DIR)/linux-$(LINUX_VERSION) && \
		gcc usr/gen_init_cpio.c -o /home/build/$@ \
	")

$(BIN_DIR)/gen_initramfs.sh: \
	$(FETCH_DIR)/linux-$(LINUX_VERSION) \
	$(FETCH_DIR)/linux-$(LINUX_VERSION)/usr/gen_initramfs.sh
	cat $(FETCH_DIR)/linux-$(LINUX_VERSION)/usr/gen_initramfs.sh \
	| sed 's:usr/gen_init_cpio:gen_init_cpio:g' \
	> $@
	chmod +x $@

$(CACHE_DIR)/rootfs.list: \
	$(CONFIG_DIR)/$(TARGET)/rootfs.list
	cp $(CONFIG_DIR)/$(TARGET)/rootfs.list $(CACHE_DIR)/rootfs.list

$(CACHE_DIR)/rootfs.cpio: \
	$(CACHE_DIR)/rootfs.list \
	$(CACHE_DIR)/init \
	$(FETCH_DIR)/linux-$(LINUX_VERSION) \
	$(BIN_DIR)/gen_init_cpio \
	$(BIN_DIR)/gen_initramfs.sh
	mkdir -p $(CACHE_DIR)/rootfs
ifeq ($(TARGET), aws)
	$(MAKE) TARGET=$(TARGET) $(CACHE_DIR)/nsm.ko
	cp $(CACHE_DIR)/nsm.ko $(CACHE_DIR)/rootfs/
endif
	cp $(CACHE_DIR)/init $(CACHE_DIR)/rootfs/
	$(call toolchain," \
		find $(CACHE_DIR)/rootfs \
			-mindepth 1 \
			-execdir touch -hcd "@0" "{}" + && \
		gen_initramfs.sh -o $@ $(CACHE_DIR)/rootfs.list && \
		cpio -itv < $@ && \
		sha256sum $@; \
	")

$(CACHE_DIR)/bzImage: \
	$(CACHE_DIR)/linux.config \
	$(FETCH_DIR)/linux-$(LINUX_VERSION) \
	$(CACHE_DIR)/rootfs.cpio
	$(call toolchain," \
		cd $(FETCH_DIR)/linux-$(LINUX_VERSION) && \
		cp /home/build/$(CONFIG_DIR)/$(TARGET)/linux.config .config && \
		make olddefconfig && \
		make -j$(CPUS) ARCH=$(ARCH) bzImage && \
		cp arch/$(ARCH)/boot/bzImage /home/build/$@ && \
		sha256sum /home/build/$@; \
	")

$(BIN_DIR)/eif_build:
	$(call toolchain," \
		cd $(SRC_DIR)/eif_build && \
		export CARGO_HOME=$(CACHE_DIR)/cargo && \
		cargo build \
			--locked \
			--target x86_64-unknown-linux-gnu && \
		cp target/x86_64-unknown-linux-gnu/debug/eif_build /home/build/$@; \
	")

$(CACHE_DIR)/nsm.ko: \
	$(FETCH_DIR)/linux-$(LINUX_VERSION) \
	$(FETCH_DIR)/aws-nitro-enclaves-sdk-bootstrap
	$(call toolchain," \
		cd $(FETCH_DIR)/linux-$(LINUX_VERSION) && \
		cp /home/build/$(CONFIG_DIR)/$(TARGET)/linux.config .config && \
		make olddefconfig && \
		make -j$(CPUS) ARCH=$(ARCH) bzImage && \
		make -j$(CPUS) ARCH=$(ARCH) modules_prepare && \
		cd /home/build/$(FETCH_DIR)/aws-nitro-enclaves-sdk-bootstrap/ && \
		make \
			-C /home/build/$(FETCH_DIR)/linux-$(LINUX_VERSION) \
		    M=/home/build/$(FETCH_DIR)/aws-nitro-enclaves-sdk-bootstrap/nsm-driver && \
		cp nsm-driver/nsm.ko /home/build/$@ \
	")
