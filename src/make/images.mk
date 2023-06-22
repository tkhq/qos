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

$(OUT_DIR)/qos_host.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/host/Dockerfile \
	$(OUT_DIR)/qos_host.$(PLATFORM)-$(ARCH)
	$(call oci-build)

$(OUT_DIR)/qos_host.$(ARCH).tar: \
	$(SRC_DIR)/images/host/Dockerfile \
	$(OUT_DIR)/qos_host.$(PLATFORM)-$(ARCH)
	$(call tar-build)

$(OUT_DIR)/qos_enclave.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/enclave/Dockerfile \
	$(OUT_DIR)/qos_enclave.$(PLATFORM)-$(ARCH) \
	$(OUT_DIR)/aws-x86_64.eif
	$(call oci-build)

$(OUT_DIR)/qos_enclave.$(ARCH).tar: \
	$(SRC_DIR)/images/enclave/Dockerfile \
	$(OUT_DIR)/qos_enclave.$(PLATFORM)-$(ARCH) \
	$(OUT_DIR)/aws-x86_64.eif
	$(call tar-build)

$(OUT_DIR)/qos_client.oci.$(ARCH).tar: \
	$(SRC_DIR)/images/client/Dockerfile \
	$(OUT_DIR)/qos_client.$(PLATFORM)-$(ARCH)
	$(call oci-build)

$(OUT_DIR)/qos_client.$(ARCH).tar: \
	$(SRC_DIR)/images/client/Dockerfile \
	$(OUT_DIR)/qos_client.$(PLATFORM)-$(ARCH)
	$(call tar-build)
