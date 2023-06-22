.PHONY: kernel-deps
kernel-deps: \
	$(KEY_DIR)/linux.asc \
	$(FETCH_DIR)/linux.tar.sign \
	$(FETCH_DIR)/linux.tar.xz

.PHONY: kernel
kernel: $(CACHE_DIR)/bzImage

# Run linux config menu and save output
.PHONY: linux-config
linux-config:
	rm $(CONFIG_DIR)/$(TARGET)/linux.config
	make TARGET=$(TARGET) $(CONFIG_DIR)/$(TARGET)/linux.config

.PHONY: run
run: $(OUT_DIR)/$(TARGET)-$(ARCH).bzImage
	qemu-system-x86_64 \
		-m 512M \
		-nographic \
		-kernel $(OUT_DIR)/$(TARGET)-$(ARCH).bzImage

$(KEY_DIR)/linux.asc:
	@$(call fetch_pgp_key,$(LINUX_KEY))

$(FETCH_DIR)/linux.tar.xz:
	@$(call fetch_file,$(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.xz,$(LINUX_HASH))

$(FETCH_DIR)/linux.tar.sign:
	@$(call fetch_file,$(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.sign,$(LINUX_SIGN_HASH))

$(CACHE_DIR)/linux.tar: $(FETCH_DIR)/linux.tar.xz
	$(call toolchain," \
		cp /home/build/$(FETCH_DIR)/linux.tar.xz $(CACHE_DIR) \
		&& env -C $(CACHE_DIR) xz -d linux.tar.xz \
	")

$(CONFIG_DIR)/$(TARGET)/linux.config:
	$(call toolchain," \
		unset FAKETIME \
		&& cd $(CACHE_DIR)/linux \
		&& make menuconfig \
		&& cp .config /home/build/$@; \
	")

$(BIN_DIR)/gen_initramfs.sh: \
	$(CACHE_DIR)/linux/Makefile \
	$(CACHE_DIR)/linux/usr/gen_initramfs.sh
	cat $(CACHE_DIR)/linux/usr/gen_initramfs.sh \
	| sed 's:usr/gen_init_cpio:gen_init_cpio:g' \
	> $@
	chmod +x $@

$(CACHE_DIR)/linux/Makefile: \
	$(KEY_DIR)/linux.asc \
	$(CACHE_DIR)/linux.config \
	$(FETCH_DIR)/linux.tar.sign \
	$(CACHE_DIR)/linux.tar
	$(call toolchain," \
		gpg --import $(KEY_DIR)/linux.asc \
		&& gpg --verify \
			$(FETCH_DIR)/linux.tar.sign \
			$(CACHE_DIR)/linux.tar \
		&& tar \
			-C $(CACHE_DIR) \
			-mxf /home/build/$(CACHE_DIR)/linux.tar \
		&& mv $(CACHE_DIR)/linux-$(LINUX_VERSION) $(CACHE_DIR)/linux \
	")

$(CACHE_DIR)/bzImage: \
	$(CACHE_DIR)/linux.config \
	$(CACHE_DIR)/linux/Makefile \
	$(CACHE_DIR)/rootfs.cpio
	$(call toolchain," \
		cd $(CACHE_DIR)/linux && \
		cp /home/build/$(CONFIG_DIR)/$(TARGET)/linux.config .config && \
		make olddefconfig && \
		make -j$(CPUS) ARCH=$(ARCH) bzImage && \
		cp arch/$(ARCH)/boot/bzImage /home/build/$@ && \
		sha256sum /home/build/$@; \
	")
