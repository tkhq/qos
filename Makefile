REGISTRY := local
.DEFAULT_GOAL :=
.PHONY: default
default: \
	out/qos_client.tar \
	out/qos_host.tar \
	out/qos_enclave.tar

.PHONY: test
test: out/.build-base-loaded
	$(call run,\
		cargo build --all; \
		cargo test; \
		cargo test -p qos_core; \
	)

.PHONY: lint
lint: out/.build-base-loaded
	$(call run,\
		cargo clippy -- -D warnings; \
	)

.PHONY: format
format: out/.build-base-loaded
	$(call run,\
		cargo install rustfmt-nightly; \
		rustfmt; \
	)

.PHONY: docs
docs: out/.build-base-loaded
	$(call run,\
		cargo doc; \
	)

.PHONY: shell
shell: out/.build-base-loaded
	$(call run,/bin/sh,--tty)

out/qos_enclave.tar: \
	out/.build-base-loaded \
	$(shell git ls-files \
		src/init \
		src/qos_enclave \
		src/qos_core \
		src/qos_aws \
		src/qos_system \
	)
	$(call build)

out/qos_host.tar: \
	out/.build-base-loaded \
	$(shell git ls-files \
		src/qos_host \
		src/qos_core \
	)
	$(call build)

out/qos_client.tar: \
	out/.build-base-loaded \
	$(shell git ls-files \
		src/qos_client \
		src/qos_p256 \
		src/qos_nsm \
		src/qos_hex \
		src/qos_crypto \
		src/qos_core \
	)
	$(call build)

.PHONY: build-base
build-base: out/build-base/index.json
out/build-base/index.json: src/images/Containerfile
	docker build \
		--output "\
			type=oci,\
			tar=false,\
			name=build_base,\
			dest=out/build-base" \
		--tag qos-local/build-base \
		$(NOCACHE_FLAG) \
		-f src/images/Containerfile \
		src/

out/.build-base-loaded: out/build-base/index.json
	env -C out/build-base tar -cf - . | docker load
	touch out/.build-base-loaded

ifeq ($(NOCACHE), 1)
NOCACHE_FLAG=--no-cache
else
NOCACHE_FLAG=
endif
export NOCACHE_FLAG
define build
	$(eval package := $(notdir $(basename $@)))
	$(MAKE) $(out/.build-base-loaded); \
	docker build \
		--tag $(REGISTRY)/$(package) \
		--progress=plain \
		--build-context "qos-local/build-base=oci-layout://./out/build-base" \
		--output "\
			type=oci,\
			rewrite-timestamp=true,\
			force-compression=true,\
			name=$(package),\
			dest=$@" \
		$(NOCACHE_FLAG) \
		-f src/images/$(package)/Containerfile \
		src/
endef

define run
	docker run \
		--interactive \
		--volume ./src/:/src \
		--volume ./cache/cargo/:/.cargo \
		--workdir /src \
		--env CARGOFLAGS="" \
		--env RUSTFLAGS="" \
		--env RUST_BACKTRACE=full \
		--env PATH=/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		$(2) \
		qos-local/build-base \
		/bin/sh -c "set -eux; $(1)"
endef
