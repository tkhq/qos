ifeq ("$(wildcard ./src/toolchain)","")
	gsu := $(shell git submodule update --init --recursive)
endif

TARGET := aws
include $(PWD)/src/toolchain/Makefile

KEYS := \
	449E6BFA40E1119328688F981929C2481BEAC51B \
	6B61ECD76088748C70590D55E90A401336C8AAA9 \
	D96C422E04DE5D2EE0F7E9E7DBB0DCA38D405491 \
	647F28654894E3BD457199BE38DBBDC86092693E

.DEFAULT_GOAL :=
.PHONY: default
default: \
	restore-mtime \
	dist-cache \
	$(patsubst %,$(KEY_DIR)/%.asc,$(KEYS)) \
	$(OUT_DIR)/aws-x86_64.eif \
	$(OUT_DIR)/qos_client.linux-x86_64 \
	$(OUT_DIR)/qos_host.linux-x86_64 \
	$(OUT_DIR)/qos_enclave.linux-x86_64 \
	images \
	$(OUT_DIR)/release.env

.PHONY: images
images: \
	$(OUT_DIR)/qos_host.oci.x86_64.tar \
	$(OUT_DIR)/qos_host.$(ARCH).tar \
	$(OUT_DIR)/qos_enclave.oci.x86_64.tar \
	$(OUT_DIR)/qos_enclave.$(ARCH).tar \
	$(OUT_DIR)/qos_client.oci.x86_64.tar \
	$(OUT_DIR)/qos_client.$(ARCH).tar

.PHONY: restore-mtime
restore-mtime:
	$(call toolchain," \
		git restore-mtime \
		&& echo "Git mtime restored" \
	")

.PHONY: dist-cache
dist-cache:
	cp -Rp dist/* out/

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

define oci-build
	$(call toolchain," \
		mkdir -p $(CACHE_DIR)/$(notdir $(word 2,$^)) \
		&& cp $(word 1,$^) $(word 2,$^) \
			$(CACHE_DIR)/$(notdir $(word 2,$^)) \
		&& env -C $(CACHE_DIR)/$(notdir $(word 2,$^)) \
			buildah build \
				-f Dockerfile \
				-t qos/$(notdir $(word 2,$^)) \
				--timestamp 1 \
				--format oci \
				--build-arg BIN=$(notdir $(word 2,$^)) \
				--build-arg EIF=$(notdir $(word 3,$^)) \
		&& buildah push \
			qos/$(notdir $(word 2,$^)) \
			oci:$(CACHE_DIR)/$(notdir $(word 2,$^))-oci \
		&& tar \
				-C $(CACHE_DIR)/$(notdir $(word 2,$^))-oci \
				--sort=name \
				--mtime='@0' \
				--owner=0 \
				--group=0 \
				--numeric-owner \
				-cf /home/build/$@ \
				. \
	")
endef

define tar-build
	$(call toolchain," \
		mkdir -p $(CACHE_DIR)/$(notdir $(word 2,$^))-tar \
		&& cp $(word 2,$^) $(CACHE_DIR)/$(notdir $(word 2,$^))-tar \
		&& tar \
				-C $(CACHE_DIR)/$(notdir $(word 2,$^))-tar \
				--sort=name \
				--mtime='@0' \
				--owner=0 \
				--group=0 \
				--numeric-owner \
				-cf /home/build/$@ \
				. \
	")
endef

$(KEY_DIR)/%.asc:
	$(call fetch_pgp_key,$(basename $(notdir $@)))

$(OUT_DIR)/$(TARGET)-$(ARCH).bzImage: $(CACHE_DIR)/bzImage
	cp $(CACHE_DIR)/bzImage $(OUT_DIR)/$(TARGET)-$(ARCH).bzImage

$(OUT_DIR)/$(TARGET)-$(ARCH).eif $(OUT_DIR)/$(TARGET)-$(ARCH).pcrs: \
	$(shell git ls-files src config)
	$(MAKE) $(CACHE_DIR)/linux.config
	$(MAKE) $(CACHE_DIR)/rootfs.cpio
	$(MAKE) $(CACHE_DIR)/bzImage
	$(MAKE) $(BIN_DIR)/eif_build
	mkdir -p $(CACHE_DIR)/eif
	$(call toolchain," \
		export \
			LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 \
			FAKETIME=1 \
		&& cp $(CACHE_DIR)/bzImage $(CACHE_DIR)/eif/ \
		&& cp $(CACHE_DIR)/rootfs.cpio $(CACHE_DIR)/eif/ \
		&& cp $(CONFIG_DIR)/$(TARGET)/linux.config $(CACHE_DIR)/eif/ \
		&& find $(CACHE_DIR)/eif -mindepth 1 -execdir touch -hcd "@0" "{}" + \
		&& $(BIN_DIR)/eif_build \
			--kernel $(CACHE_DIR)/eif/bzImage \
			--kernel_config $(CACHE_DIR)/eif/linux.config \
			--cmdline 'reboot=k initrd=0x2000000$(,)3228672 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd' \
			--ramdisk $(CACHE_DIR)/eif/rootfs.cpio \
			--pcrs_output $(OUT_DIR)/$(TARGET)-$(ARCH).pcrs \
			--output $(OUT_DIR)/$(TARGET)-$(ARCH).eif; \
	")

$(OUT_DIR)/qos_host.$(PLATFORM)-$(ARCH): \
	$(shell git ls-files src config)
	$(MAKE) $(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot
	$(call toolchain," \
		export \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
				-L /usr/lib/x86_64-linux-musl \
				-C target-feature=+crt-static \
			' \
		&& cd $(SRC_DIR)/qos_host \
		&& cargo build \
			--features vm \
			$(CARGO_FLAGS) \
		&& cp \
			../target/x86_64-unknown-linux-musl/release/qos_host \
			/home/build/$@; \
	")

$(OUT_DIR)/qos_host.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/host/Dockerfile \
	$(OUT_DIR)/qos_host.$(PLATFORM)-$(ARCH)
	$(call oci-build)

$(OUT_DIR)/qos_host.$(ARCH).tar: \
	$(SRC_DIR)/images/host/Dockerfile \
	$(OUT_DIR)/qos_host.$(PLATFORM)-$(ARCH)
	$(call tar-build)

$(OUT_DIR)/qos_enclave.$(PLATFORM)-$(ARCH): \
	$(shell git ls-files src/qos_enclave config)
	$(MAKE) $(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot
	$(MAKE) $(CACHE_DIR)/lib64/libssl.a
	$(call toolchain," \
		cd $(SRC_DIR)/qos_enclave \
		&& export \
			PKG_CONFIG_ALLOW_CROSS=1 \
			OPENSSL_STATIC=true \
			X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=/home/build/${CACHE_DIR}/lib64 \
			X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/home/build/${CACHE_DIR}/lib64 \
			X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR=/home/build/${CACHE_DIR}/include \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
				-L /usr/lib/x86_64-linux-musl \
				-C target-feature=+crt-static \
			' \
		&& cargo build $(CARGO_FLAGS) \
		&& cp \
			target/x86_64-unknown-linux-musl/release/qos_enclave \
			/home/build/$@; \
	")

$(OUT_DIR)/qos_enclave.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/enclave/Dockerfile
	$(MAKE) $(OUT_DIR)/qos_enclave.$(PLATFORM)-$(ARCH)
	$(MAKE) $(OUT_DIR)/aws-x86_64.eif
	mkdir -p $(CACHE_DIR)/$(notdir $(word 2,$^)) \
	&& cp $(word 3,$^) $(CACHE_DIR)/$(notdir $(word 2,$^)) \
	&& $(call oci-build)

$(OUT_DIR)/qos_enclave.$(ARCH).tar: \
	$(SRC_DIR)/images/enclave/Dockerfile \
	$(OUT_DIR)/qos_enclave.$(PLATFORM)-$(ARCH) \
	$(OUT_DIR)/aws-x86_64.eif
	$(call tar-build)

$(OUT_DIR)/qos_client.$(PLATFORM)-$(ARCH): \
	$(shell git ls-files src config)
	$(MAKE) $(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot
	$(MAKE) $(CACHE_DIR)/lib/libpcsclite.a
	$(call toolchain," \
		cd $(SRC_DIR)/qos_client \
		&& export \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
				-L /usr/lib/x86_64-linux-musl \
				-C target-feature=+crt-static \
			' \
			PCSC_LIB_DIR=/home/build/${CACHE_DIR}/lib \
			PCSC_LIB_NAME=static=pcsclite \
		&& cargo build $(CARGO_FLAGS) \
			--features smartcard \
		&& cp \
			../target/x86_64-unknown-linux-musl/release/qos_client \
			/home/build/$@; \
	")

$(OUT_DIR)/qos_client.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/client/Dockerfile \
	$(OUT_DIR)/qos_client.$(PLATFORM)-$(ARCH)
	$(call oci-build)

$(OUT_DIR)/qos_client.$(ARCH).tar: \
	$(SRC_DIR)/images/client/Dockerfile \
	$(OUT_DIR)/qos_client.$(PLATFORM)-$(ARCH)
	$(call tar-build)

$(CONFIG_DIR)/$(TARGET)/linux.config:
	$(call toolchain," \
		unset FAKETIME \
		&& cd /cache/linux-$(LINUX_VERSION) \
		&& make menuconfig \
		&& cp .config /config/$(TARGET)/linux.config; \
	")

$(CACHE_DIR)/src/aws-nitro-enclaves-sdk-bootstrap:
	$(call git_clone,$@,$(AWS_NITRO_DRIVER_REPO),$(AWS_NITRO_DRIVER_REF))

$(FETCH_DIR)/linux-$(LINUX_VERSION).tar.sign:
	curl --url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.sign --output $@

$(FETCH_DIR)/linux-$(LINUX_VERSION).tar:
	curl --url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.xz --output $@.xz
	xz -d $@.xz

$(CACHE_DIR)/src/pcsc:
	$(call git_clone,$@,$(PCSC_REPO),$(PCSC_REF))

$(CACHE_DIR)/src/openssl:
	$(call git_clone,$@,$(OPENSSL_REPO),$(OPENSSL_REF))

$(CACHE_DIR)/src/rust:
	$(call git_clone,$@,$(RUST_REPO),$(RUST_REF))

$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot: \
	$(CACHE_DIR)/src/rust
	$(call toolchain," \
		cd $(CACHE_DIR)/src/rust \
		&& git submodule update --init \
		&& ./configure \
			--set="build.rustc=/usr/bin/rustc" \
			--set="build.cargo=/usr/bin/cargo" \
			--set="target.x86_64-unknown-linux-musl.llvm-config=/usr/bin/llvm-config" \
			--set="target.x86_64-unknown-linux-musl.musl-libdir=/usr/lib/x86_64-linux-musl" \
		&& python3 x.py build \
			--stage 0 \
			--target x86_64-unknown-linux-musl \
			library \
	")

$(CACHE_DIR)/lib/libpcsclite.a: \
	$(CACHE_DIR)/src/pcsc
	$(call toolchain," \
		cd $(CACHE_DIR)/src/pcsc \
		&& export \
			CC=musl-gcc \
			CXX=musl-g++ \
			CFLAGS=-static \
			CXXFLAGS=-static \
		&& ./bootstrap \
		&& ./configure \
			--enable-static \
			--disable-polkit \
			--disable-strict \
			--disable-libsystemd \
			--disable-libudev \
			--disable-libusb \
		&& make \
		&& mkdir -p /home/build/$(CACHE_DIR)/lib \
		&& cp src/.libs/libpcsclite.a /home/build/$@ \
	")

$(CACHE_DIR)/lib64/libssl.a: \
	$(CACHE_DIR)/src/openssl
	$(call toolchain," \
		cd $(CACHE_DIR)/src/openssl \
		&& export CC='musl-gcc -fPIE -pie -static' \
		&& sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm \
		&& sudo ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic \
		&& sudo ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux \
		&& ./Configure \
			no-shared \
			no-async \
			--prefix=/home/build/$(CACHE_DIR) \
			linux-x86_64 \
		&& make depend \
		&& make \
		&& make install \
		&& touch /home/build/$@ \
	")

$(CACHE_DIR)/linux.config:
	cp $(CONFIG_DIR)/$(TARGET)/linux.config $@

$(CACHE_DIR)/init: \
	| $(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot
	$(call toolchain," \
		export \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
				-L /usr/lib/x86_64-linux-musl \
				-C target-feature=+crt-static \
			' \
		&& cd $(SRC_DIR)/init \
		&& cargo build $(CARGO_FLAGS) \
		&& cp target/x86_64-unknown-linux-musl/release/init /home/build/$@ \
	")

$(BIN_DIR)/gen_init_cpio: \
	$(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile
	$(call toolchain," \
		cd $(CACHE_DIR)/src/linux-$(LINUX_VERSION) && \
		gcc usr/gen_init_cpio.c -o /home/build/$@ \
	")

$(BIN_DIR)/gen_initramfs.sh: \
	$(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile \
	$(CACHE_DIR)/src/linux-$(LINUX_VERSION)/usr/gen_initramfs.sh
	cat $(CACHE_DIR)/src/linux-$(LINUX_VERSION)/usr/gen_initramfs.sh \
	| sed 's:usr/gen_init_cpio:gen_init_cpio:g' \
	> $@
	chmod +x $@

$(CACHE_DIR)/rootfs.list: \
	$(CONFIG_DIR)/$(TARGET)/rootfs.list
	cp $(CONFIG_DIR)/$(TARGET)/rootfs.list $(CACHE_DIR)/rootfs.list

$(CACHE_DIR)/rootfs.cpio: \
	$(CACHE_DIR)/rootfs.list \
	$(CACHE_DIR)/init \
	$(CACHE_DIR)/nsm.ko \
	$(BIN_DIR)/gen_init_cpio \
	$(BIN_DIR)/gen_initramfs.sh
	mkdir -p $(CACHE_DIR)/rootfs
	cp $(CACHE_DIR)/nsm.ko $(CACHE_DIR)/rootfs/
	cp $(CACHE_DIR)/init $(CACHE_DIR)/rootfs/
	$(call toolchain," \
		find $(CACHE_DIR)/rootfs \
			-mindepth 1 \
			-execdir touch -hcd "@0" "{}" + && \
		gen_initramfs.sh -o $@ $(CACHE_DIR)/rootfs.list && \
		cpio -itv < $@ && \
		sha256sum $@; \
	")

$(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile: \
	  $(KEY_DIR)/$(LINUX_KEY).asc \
	  | $(CACHE_DIR)/linux.config \
	    $(FETCH_DIR)/linux-$(LINUX_VERSION).tar \
	    $(FETCH_DIR)/linux-$(LINUX_VERSION).tar.sign
	$(call toolchain," \
		gpg --import $(KEY_DIR)/$(LINUX_KEY).asc \
		&& gpg --verify \
			$(FETCH_DIR)/linux-$(LINUX_VERSION).tar.sign \
			$(FETCH_DIR)/linux-$(LINUX_VERSION).tar \
		&& tar \
			-C $(CACHE_DIR)/src \
			-mxf /home/build/$(FETCH_DIR)/linux-$(LINUX_VERSION).tar; \
	")

$(CACHE_DIR)/bzImage: \
	$(CACHE_DIR)/linux.config \
	| $(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile \
	  $(CACHE_DIR)/rootfs.cpio
	$(call toolchain," \
		cd $(CACHE_DIR)/src/linux-$(LINUX_VERSION) && \
		cp /home/build/$(CONFIG_DIR)/$(TARGET)/linux.config .config && \
		make olddefconfig && \
		make -j$(CPUS) ARCH=$(ARCH) bzImage && \
		cp arch/$(ARCH)/boot/bzImage /home/build/$@ && \
		sha256sum /home/build/$@; \
	")

$(BIN_DIR)/eif_build:
	$(call toolchain," \
		cd $(SRC_DIR)/eif_build && \
		cargo build \
			--locked \
			--target x86_64-unknown-linux-gnu && \
		cp target/x86_64-unknown-linux-gnu/debug/eif_build /home/build/$@; \
	")

$(CACHE_DIR)/nsm.ko: \
	| $(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile \
	  $(CACHE_DIR)/src/aws-nitro-enclaves-sdk-bootstrap
	$(call toolchain," \
		cd $(CACHE_DIR)/src/linux-$(LINUX_VERSION) && \
		cp /home/build/$(CONFIG_DIR)/$(TARGET)/linux.config .config && \
		make olddefconfig && \
		make -j$(CPUS) ARCH=$(ARCH) bzImage && \
		make -j$(CPUS) ARCH=$(ARCH) modules_prepare && \
		cd /home/build/$(CACHE_DIR)/src/aws-nitro-enclaves-sdk-bootstrap/ && \
		make \
			-C /home/build/$(CACHE_DIR)/src/linux-$(LINUX_VERSION) \
		    M=/home/build/$(CACHE_DIR)/src/aws-nitro-enclaves-sdk-bootstrap/nsm-driver && \
		cp nsm-driver/nsm.ko /home/build/$@ \
	")
