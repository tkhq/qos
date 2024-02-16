REGISTRY := local
.DEFAULT_GOAL :=
.PHONY: default
default: \
	out/qos_client.tar \
	out/qos_host.tar \
	out/qos_enclave.tar

out/qos_enclave.tar: \
	build-base \
	$(shell git ls-files \
		src/init \
		src/qos_enclave \
		src/qos_core \
		src/qos_aws \
		src/qos_system \
	)
	$(call build)

out/qos_host.tar: \
	build-base \
	$(shell git ls-files \
		src/qos_host \
		src/qos_core \
	)
	$(call build)

out/qos_client.tar: \
	build-base \
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

ifeq ($(NOCACHE), 1)
NOCACHE_FLAG=--no-cache
else
NOCACHE_FLAG=
endif
export NOCACHE_FLAG
define build
	$(eval package := $(notdir $(basename $@)))
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
