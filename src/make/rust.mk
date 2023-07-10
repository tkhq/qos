CARGO_HOME=cache/cargo
CARGO_FLAGS=--locked --no-default-features --release --target x86_64-unknown-linux-musl

.PHONY: rust-deps
rust-deps: \
	$(FETCH_DIR)/rust.tar.gz

$(FETCH_DIR)/rust.tar.gz:
	$(call git_archive,$(RUST_REPO),$(RUST_REF))

$(CACHE_DIR)/rust/x.py: \
	$(FETCH_DIR)/rust.tar.gz
	mkdir -p $(CACHE_DIR)/rust
	tar -xzf $< -C $(CACHE_DIR)/rust
	touch $@

$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot: \
	$(CACHE_DIR)/rust/x.py
	$(call toolchain," \
		cd $(CACHE_DIR)/rust \
		&& touch .git \
		&& ./configure \
			--set="build.rustc=/usr/bin/rustc" \
			--set="build.cargo=/usr/bin/cargo" \
			--set="build.submodules=false" \
			--set="target.x86_64-unknown-linux-musl.llvm-config=/usr/bin/llvm-config" \
			--set="target.x86_64-unknown-linux-musl.musl-libdir=/usr/lib/x86_64-linux-musl" \
		&& python3 x.py build \
			--stage 0 \
			--target x86_64-unknown-linux-musl \
			library \
	")

$(CACHE_DIR)/init: \
	$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot
	$(call toolchain," \
		export \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
				-L /usr/lib/x86_64-linux-musl \
				-C target-feature=+crt-static \
			' \
		&& cd $(SRC_DIR)/init \
		&& cargo build $(CARGO_FLAGS) \
		&& cp target/x86_64-unknown-linux-musl/release/init /home/build/$@ \
	")

$(OUT_DIR)/qos_client.$(PLATFORM)-$(ARCH): \
	$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot \
	$(CACHE_DIR)/lib/libpcsclite.a
	$(call toolchain," \
		cd $(SRC_DIR)/qos_client \
		&& export \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
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

$(OUT_DIR)/qos_host.$(PLATFORM)-$(ARCH): \
	$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot
	$(call toolchain," \
		export \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
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



$(OUT_DIR)/qos_enclave.$(PLATFORM)-$(ARCH): \
	$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot \
	$(CACHE_DIR)/lib64/libssl.a
	$(call toolchain," \
		cd $(SRC_DIR)/qos_enclave \
		&& export \
			PKG_CONFIG_ALLOW_CROSS=1 \
			OPENSSL_STATIC=true \
			X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=/home/build/${CACHE_DIR}/lib64 \
			X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/home/build/${CACHE_DIR}/lib64 \
			X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR=/home/build/${CACHE_DIR}/include \
			RUSTFLAGS=' \
				-L /home/build/$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/ \
				-L /home/build/$(CACHE_DIR)/rust/build/x86_64-unknown-linux-gnu/stage0-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/ \
				-L /usr/lib/x86_64-linux-musl \
				-C target-feature=+crt-static \
			' \
		&& cargo build $(CARGO_FLAGS) \
		&& cp \
			target/x86_64-unknown-linux-musl/release/qos_enclave \
			/home/build/$@; \
	")


