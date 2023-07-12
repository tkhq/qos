.PHONY: c-deps
c-deps: \
	$(FETCH_DIR)/pcsc.tar \
	$(FETCH_DIR)/openssl.tar

$(FETCH_DIR)/pcsc.tar:
	$(call fetch_file,$(PCSC_URL),$(PCSC_HASH))

$(CACHE_DIR)/pcsc/Makefile: \
	$(FETCH_DIR)/pcsc.tar
	tar -xzf $< -C $(CACHE_DIR)/
	mv $(CACHE_DIR)/LudovicRousseau-PCSC-* $(dir $@)

$(FETCH_DIR)/openssl.tar:
	$(call fetch_file,$(OPENSSL_URL),$(OPENSSL_HASH))

$(CACHE_DIR)/openssl/Makefile: \
	$(FETCH_DIR)/openssl.tar
	tar -xzf $< -C $(CACHE_DIR)/
	mv $(CACHE_DIR)/openssl-openssl-* $(dir $@)

$(CACHE_DIR)/lib/libpcsclite.a: | \
	$(CACHE_DIR)/pcsc/Makefile
	$(call toolchain," \
		cd $(CACHE_DIR)/pcsc \
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

$(FETCH_DIR)/openssl-static-musl.tar.gz: \
	$(CACHE_DIR)/openssl/Makefile
	$(call toolchain," \
		mkdir -p $(CACHE_DIR)/$(notdir $@)-staging \
		&& export CC='musl-gcc -fPIE -pie -static' \
		&& sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm \
		&& sudo ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic \
		&& sudo ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux \
		&& cd $(CACHE_DIR)/openssl \
		&& ./Configure \
			no-shared \
			no-async \
			--prefix=/home/build/$(CACHE_DIR)/$(notdir $@)-staging \
			linux-x86_64 \
		&& make depend \
		&& make \
		&& make install \
		&& tar \
			-C /home/build/$(CACHE_DIR)/$(notdir $@)-staging \
			--sort=name \
			--mtime='@0' \
			--owner=0 \
			--group=0 \
			--numeric-owner \
			-cvf - \
			. \
		| gzip -n > /home/build/$@ \
	")

$(BIN_DIR)/gen_init_cpio: \
	$(CACHE_DIR)/linux/Makefile
	$(call toolchain," \
		env -C $(CACHE_DIR)/linux gcc usr/gen_init_cpio.c -o /home/build/$@ \
	")
