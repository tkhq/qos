.PHONY: aws-deps
aws-deps: \
	$(FETCH_DIR)/aws-nitro-enclaves-sdk-bootstrap.tar

$(FETCH_DIR)/aws-nitro-enclaves-sdk-bootstrap.tar:
	$(call fetch_file,$(AWS_NITRO_DRIVER_URL),$(AWS_NITRO_DRIVER_HASH))

$(CACHE_DIR)/aws-nitro-enclaves-sdk-bootstrap/Makefile: \
	$(FETCH_DIR)/aws-nitro-enclaves-sdk-bootstrap.tar
	tar -xzf $< -C $(CACHE_DIR)/
	mv $(CACHE_DIR)/aws-aws-nitro-enclaves-sdk-bootstrap* $(dir $@)
	touch $@

$(OUT_DIR)/$(TARGET)-$(ARCH).eif $(OUT_DIR)/$(TARGET)-$(ARCH).pcrs: \
	$(BIN_DIR)/eif_build \
	$(CACHE_DIR)/bzImage \
	$(CACHE_DIR)/rootfs.cpio \
	$(CONFIG_DIR)/$(TARGET)/linux.config
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

$(BIN_DIR)/eif_build:
	$(call toolchain," \
		cd $(SRC_DIR)/eif_build && \
		cargo build \
			--locked \
			--target x86_64-unknown-linux-gnu && \
		cp target/x86_64-unknown-linux-gnu/debug/eif_build /home/build/$@; \
	")

$(CACHE_DIR)/nsm.ko: \
	$(CACHE_DIR)/linux/Makefile \
	$(CONFIG_DIR)/$(TARGET)/linux.config \
	$(CACHE_DIR)/aws-nitro-enclaves-sdk-bootstrap/Makefile
	$(call toolchain," \
		cd $(CACHE_DIR)/linux && \
		cp /home/build/$(CONFIG_DIR)/$(TARGET)/linux.config .config && \
		make olddefconfig && \
		make -j$(CPUS) ARCH=$(ARCH) bzImage && \
		make -j$(CPUS) ARCH=$(ARCH) modules_prepare && \
		cd /home/build/$(CACHE_DIR)/aws-nitro-enclaves-sdk-bootstrap/ && \
		make \
			-C /home/build/$(CACHE_DIR)/linux \
		    M=/home/build/$(CACHE_DIR)/aws-nitro-enclaves-sdk-bootstrap/nsm-driver && \
		cp nsm-driver/nsm.ko /home/build/$@ \
	")
