ifeq ("$(wildcard ./src/toolchain/Makefile)","")
	gsu := $(shell git submodule update --init --recursive)
endif

TARGET := aws
include $(PWD)/src/toolchain/Makefile

KEYS := \
	449E6BFA40E1119328688F981929C2481BEAC51B \
	6B61ECD76088748C70590D55E90A401336C8AAA9 \
	D96C422E04DE5D2EE0F7E9E7DBB0DCA38D405491 \
	647F28654894E3BD457199BE38DBBDC86092693E

CACHE_FILENAMES := \
	$(CACHE_DIR_ROOT)/toolchain.tgz \
	$(CACHE_DIR)/bzImage \
	$(CACHE_DIR)/rust-libstd-musl.tgz \
	$(CACHE_DIR)/nsm.ko \
	$(CACHE_DIR)/lib/libpcsclite.a \
	$(CACHE_DIR)/libssl-static.tgz \
	$(CACHE_DIR_ROOT)/bin/gen_init_cpio \
	$(FETCH_DIR)/linux-$(LINUX_VERSION).tar.xz

.DEFAULT_GOAL :=
.PHONY: default
default: \
	cache \
	dist-cache \
	toolchain \
	$(patsubst %,$(KEY_DIR)/%.asc,$(KEYS)) \
	$(OUT_DIR)/aws-x86_64.eif \
	$(OUT_DIR)/qos_client.linux-x86_64 \
	$(OUT_DIR)/qos_host.linux-x86_64 \
	$(OUT_DIR)/qos_enclave.linux-x86_64 \
	images \
	$(OUT_DIR)/release.env \
	toolchain-profile

.PHONY: images
images: \
	$(OUT_DIR)/qos_host.oci.x86_64.tar \
	$(OUT_DIR)/qos_host.$(ARCH).tar \
	$(OUT_DIR)/qos_enclave.oci.x86_64.tar \
	$(OUT_DIR)/qos_enclave.$(ARCH).tar \
	$(OUT_DIR)/qos_client.oci.x86_64.tar \
	$(OUT_DIR)/qos_client.$(ARCH).tar

# Clean repo back to initial clone state
.PHONY: clean
clean: toolchain-clean
	git clean -dfx $(SRC_DIR)

.PHONY: dist
dist: toolchain-dist

.PHONY: reproduce
reproduce: toolchain-reproduce toolchain-profile

.PHONY: cache-filenames
cache-filenames:
	@echo $(CACHE_FILENAMES)

.PHONY: cache
cache:
ifneq ($(TOOLCHAIN_REPRODUCE),true)
	git lfs pull --include=$(subst $(space),$(,),$(CACHE_FILENAMES))
	chmod +x $(BIN_DIR)/gen_init_cpio
	touch cache/toolchain.tgz
	$(MAKE) toolchain-restore-mtime
endif

.PHONY: dist-cache
dist-cache:
ifneq ($(TOOLCHAIN_REPRODUCE),true)
	git lfs pull --include=$(DIST_DIR)
	$(MAKE) toolchain-dist-cache toolchain-restore-mtime
endif

.PHONY: run
run: $(CACHE_DIR)/bzImage
	qemu-system-x86_64 \
		-m 512M \
		-nographic \
		-kernel $(CACHE_DIR)/bzImage

# Run linux config menu and save output
.PHONY: linux-config
linux-config:
	rm $(CONFIG_DIR)/$(TARGET)/linux.config
	make TARGET=$(TARGET) $(CONFIG_DIR)/$(TARGET)/linux.config

define oci-build
	$(call toolchain-profile-start);
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
	");
	$(call toolchain-profile-stop)
endef

define tar-build
	$(call toolchain-profile-start);
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
	");
	$(call toolchain-profile-stop)
endef

$(KEY_DIR)/%.asc:
	$(call fetch_pgp_key,$(basename $(notdir $@)))

$(OUT_DIR)/$(TARGET)-$(ARCH).eif $(OUT_DIR)/$(TARGET)-$(ARCH).pcrs: \
	$(shell git ls-files src/init src/qos_core src/qos_aws src/qos_system config)
	$(MAKE) $(CACHE_DIR)/rootfs.cpio
	$(MAKE) $(CACHE_DIR)/bzImage
	$(MAKE) $(BIN_DIR)/eif_build
	$(call toolchain-profile-start)
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
	$(call toolchain-profile-stop)

$(OUT_DIR)/qos_host.$(PLATFORM)-$(ARCH): \
	$(shell git ls-files src/qos_host src/qos_core config)
	$(MAKE) $(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/libc.a
	$(call toolchain-profile-start)
	$(call toolchain," \
		export \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
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
	$(call toolchain-profile-stop)

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
	$(MAKE) $(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/libc.a
	$(MAKE) $(CACHE_DIR)/lib64/libssl.a
	$(call toolchain-profile-start)
	$(call toolchain," \
		cd $(SRC_DIR)/qos_enclave \
		&& export \
			PKG_CONFIG_ALLOW_CROSS=1 \
			OPENSSL_STATIC=true \
			X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=/home/build/${CACHE_DIR}/lib64 \
			X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/home/build/${CACHE_DIR}/lib64 \
			X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR=/home/build/${CACHE_DIR}/include \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
				-L /usr/lib/x86_64-linux-musl \
				-C target-feature=+crt-static \
			' \
		&& cargo build $(CARGO_FLAGS) \
		&& cp \
			target/x86_64-unknown-linux-musl/release/qos_enclave \
			/home/build/$@; \
	")
	$(call toolchain-profile-stop)

$(OUT_DIR)/qos_enclave.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/enclave/Dockerfile \
	$(OUT_DIR)/qos_enclave.$(PLATFORM)-$(ARCH) \
	$(OUT_DIR)/aws-x86_64.eif
	mkdir -p $(CACHE_DIR)/$(notdir $(word 2,$^))
	cp $(word 3,$^) $(CACHE_DIR)/$(notdir $(word 2,$^))
	$(call oci-build)

$(OUT_DIR)/qos_enclave.$(ARCH).tar: \
	$(SRC_DIR)/images/enclave/Dockerfile \
	$(OUT_DIR)/qos_enclave.$(PLATFORM)-$(ARCH) \
	$(OUT_DIR)/aws-x86_64.eif
	$(call tar-build)

$(OUT_DIR)/qos_client.$(PLATFORM)-$(ARCH): \
	$(shell git ls-files \
		src/qos_client \
		src/qos_p256 \
		src/qos_nsm \
		src/qos_hex \
		src/qos_crypto \
		src/qos_core \
		config \
	)
	$(MAKE) $(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/libc.a
	$(MAKE) $(CACHE_DIR)/lib/libpcsclite.a
	$(call toolchain-profile-start)
	$(call toolchain," \
		cd $(SRC_DIR)/qos_client \
		&& export \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
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
	$(call toolchain-profile-stop)

$(OUT_DIR)/qos_client.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/client/Dockerfile \
	$(OUT_DIR)/qos_client.$(PLATFORM)-$(ARCH)
	$(call oci-build)

$(OUT_DIR)/qos_client.$(ARCH).tar: \
	$(SRC_DIR)/images/client/Dockerfile \
	$(OUT_DIR)/qos_client.$(PLATFORM)-$(ARCH)
	$(call tar-build)

$(CONFIG_DIR)/$(TARGET)/linux.config:
	$(call toolchain-profile-start)
	$(call toolchain," \
		unset FAKETIME \
		&& cd /cache/linux-$(LINUX_VERSION) \
		&& make menuconfig \
		&& cp .config /config/$(TARGET)/linux.config; \
	")
	$(call toolchain-profile-stop)

$(CACHE_DIR)/src/aws-nitro-enclaves-sdk-bootstrap:
	$(call toolchain-profile-start)
	$(call git_clone,$@,$(AWS_NITRO_DRIVER_REPO),$(AWS_NITRO_DRIVER_REF))
	$(call toolchain-profile-stop)

$(FETCH_DIR)/linux-$(LINUX_VERSION).tar.sign:
	$(call toolchain-profile-start)
	curl --url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.sign --output $@
	$(call toolchain-profile-stop)

$(FETCH_DIR)/linux-$(LINUX_VERSION).tar.xz:
	$(call toolchain-profile-start)
	curl --url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.xz --output $@
	$(call toolchain-profile-stop)

$(CACHE_DIR)/src/pcsc:
	$(call toolchain-profile-start)
	$(call git_clone,$@,$(PCSC_REPO),$(PCSC_REF))
	$(call toolchain-profile-stop)

$(CACHE_DIR)/src/openssl:
	$(call toolchain-profile-start)
	$(call git_clone,$@,$(OPENSSL_REPO),$(OPENSSL_REF))
	$(call toolchain-profile-stop)

$(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/libc.a: \
	$(CACHE_DIR)/rust-libstd-musl.tgz
	$(call toolchain-profile-start)
	mkdir -p $(CACHE_DIR)/lib/rustlib
	tar -xzf $(CACHE_DIR)/rust-libstd-musl.tgz -C $(CACHE_DIR)/lib/rustlib
	find $(CACHE_DIR)/lib/rustlib -type f -exec touch {} +
	$(call toolchain-profile-stop)

$(CACHE_DIR)/rust-libstd-musl.tgz:
	$(call toolchain-profile-start)
	$(call git_clone,$(CACHE_DIR)/src/rust,$(RUST_REPO),$(RUST_REF))
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
		&& tar \
			-C /home/build/$(CACHE_DIR)/src/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/ \
			--sort=name \
			--mtime='@0' \
			--owner=0 \
			--group=0 \
			--numeric-owner \
			-czvf /home/build/$@ \
			. \
	")
	$(call toolchain-profile-stop)

$(CACHE_DIR)/lib/libpcsclite.a:
	$(MAKE) $(CACHE_DIR)/src/pcsc
	$(call toolchain-profile-start)
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
	$(call toolchain-profile-stop)

$(CACHE_DIR)/libssl-static.tgz:
	$(MAKE) $(CACHE_DIR)/src/openssl
	$(call toolchain-profile-start)
	$(call toolchain," \
		cd $(CACHE_DIR)/src/openssl \
		&& export CC='musl-gcc -fPIE -pie -static' \
		&& sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm \
		&& sudo ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic \
		&& sudo ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux \
		&& ./Configure \
			no-shared \
			no-async \
			--prefix=/ \
			linux-x86_64 \
		&& make depend \
		&& make \
		&& make install DESTDIR=$(@).tmp \
		&& touch /home/build/$@ \
		&& tar \
			-C $(@).tmp \
			--sort=name \
			--mtime='@0' \
			--owner=0 \
			--group=0 \
			--numeric-owner \
			-czvf /home/build/$@ \
			. \
	")
	$(call toolchain-profile-stop)

$(CACHE_DIR)/lib64/libssl.a: \
	$(CACHE_DIR)/libssl-static.tgz
	$(call toolchain-profile-start)
	tar -xzf $(CACHE_DIR)/libssl-static.tgz -C $(CACHE_DIR)/
	touch $(CACHE_DIR)/lib64/libssl.a
	$(call toolchain-profile-stop)

$(CACHE_DIR)/init: \
	$(shell git ls-files \
		src/init \
		src/qos_p256 \
		src/qos_aws \
		src/qos_system \
		src/qos_core \
		src/qos_nsm \
		config \
	) \
	| $(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/libc.a

	$(call toolchain-profile-start)
	$(call toolchain," \
		export \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
				-L /usr/lib/x86_64-linux-musl \
				-C target-feature=+crt-static \
			' \
		&& cd $(SRC_DIR)/init \
		&& cargo build $(CARGO_FLAGS) \
		&& cp target/x86_64-unknown-linux-musl/release/init /home/build/$@ \
	")
	$(call toolchain-profile-stop)

$(BIN_DIR)/gen_init_cpio:
	$(MAKE) $(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile
	$(call toolchain-profile-start)
	$(call toolchain," \
		cd $(CACHE_DIR)/src/linux-$(LINUX_VERSION) && \
		gcc usr/gen_init_cpio.c -o /home/build/$@ \
	")
	$(call toolchain-profile-stop)

$(BIN_DIR)/gen_initramfs.sh: \
	$(BIN_DIR)/gen_init_cpio \
	$(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile \
	$(CACHE_DIR)/src/linux-$(LINUX_VERSION)/usr/gen_initramfs.sh
	$(call toolchain-profile-start)
	cat $(CACHE_DIR)/src/linux-$(LINUX_VERSION)/usr/gen_initramfs.sh \
	| sed 's:usr/gen_init_cpio:gen_init_cpio:g' \
	> $@
	chmod +x $@
	$(call toolchain-profile-stop)

$(CACHE_DIR)/rootfs.cpio: \
	$(CONFIG_DIR)/$(TARGET)/rootfs.list \
	$(CACHE_DIR)/init \
	$(CACHE_DIR)/nsm.ko \
	$(BIN_DIR)/gen_init_cpio \
	$(BIN_DIR)/gen_initramfs.sh
	$(call toolchain-profile-start)
	mkdir -p $(CACHE_DIR)/rootfs
	cp $(CACHE_DIR)/nsm.ko $(CACHE_DIR)/rootfs/
	cp $(CACHE_DIR)/init $(CACHE_DIR)/rootfs/
	$(call toolchain," \
		find $(CACHE_DIR)/rootfs \
			-mindepth 1 \
			-execdir touch -hcd "@0" "{}" + && \
		gen_initramfs.sh -o $@ $(CONFIG_DIR)/$(TARGET)/rootfs.list && \
		cpio -itv < $@ && \
		sha256sum $@; \
	")
	$(call toolchain-profile-stop)

$(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile: \
	  $(KEY_DIR)/$(LINUX_KEY).asc \
	  $(CONFIG_DIR)/$(TARGET)/linux.config \
	  | $(FETCH_DIR)/linux-$(LINUX_VERSION).tar.xz \
	    $(FETCH_DIR)/linux-$(LINUX_VERSION).tar.sign
	$(call toolchain-profile-start)
	$(call toolchain," \
		mkdir -p $(CACHE_DIR)/src \
		&& xz -d --stdout $(FETCH_DIR)/linux-$(LINUX_VERSION).tar.xz > $(CACHE_DIR)/linux-$(LINUX_VERSION).tar \
		&& gpg --import $(KEY_DIR)/$(LINUX_KEY).asc \
		&& gpg --verify \
			$(FETCH_DIR)/linux-$(LINUX_VERSION).tar.sign \
			$(CACHE_DIR)/linux-$(LINUX_VERSION).tar \
		&& tar \
			-C $(CACHE_DIR)/src \
			-mxf /home/build/$(CACHE_DIR)/linux-$(LINUX_VERSION).tar \
		&& rm $(CACHE_DIR)/linux-$(LINUX_VERSION).tar \
	")
	$(call toolchain-profile-stop)

$(CACHE_DIR)/bzImage: \
	$(CONFIG_DIR)/$(TARGET)/linux.config \
	| $(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile \
	  $(CACHE_DIR)/rootfs.cpio
	$(call toolchain-profile-start)
	$(call toolchain," \
		cd $(CACHE_DIR)/src/linux-$(LINUX_VERSION) && \
		cp /home/build/$(CONFIG_DIR)/$(TARGET)/linux.config .config && \
		make olddefconfig && \
		make -j$(CPUS) ARCH=$(ARCH) bzImage && \
		cp arch/$(ARCH)/boot/bzImage /home/build/$@ && \
		sha256sum /home/build/$@; \
	")
	$(call toolchain-profile-stop)

$(BIN_DIR)/eif_build:
	$(call toolchain-profile-start)
	$(call toolchain," \
		cd $(SRC_DIR)/eif_build && \
		cargo build \
			--locked \
			--target x86_64-unknown-linux-gnu && \
		cp target/x86_64-unknown-linux-gnu/debug/eif_build /home/build/$@; \
	")
	$(call toolchain-profile-stop)

$(CACHE_DIR)/nsm.ko: \
	$(CONFIG_DIR)/$(TARGET)/linux.config \
	| $(CACHE_DIR)/src/linux-$(LINUX_VERSION)/Makefile \
	  $(CACHE_DIR)/src/aws-nitro-enclaves-sdk-bootstrap
	$(call toolchain-profile-start)
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
	$(call toolchain-profile-stop)
