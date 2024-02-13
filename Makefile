REGISTRY := local
.DEFAULT_GOAL :=
.PHONY: default
default: \
	out/qos_client.tar \
	out/qos_host.tar \
	out/qos_enclave.tar

out/qos_enclave.tar: \
	$(shell git ls-files \
		src/qos_enclave \
		src/init \
		src/qos_core \
		src/qos_aws \
		src/qos_system \
	)
	$(call build)

out/qos_host.tar: \
	$(shell git ls-files \
		src/qos_host \
		src/qos_core \
	)
	$(call build)

out/qos_client.tar: \
	$(shell git ls-files \
		src/qos_client \
		src/qos_p256 \
		src/qos_nsm \
		src/qos_hex \
		src/qos_crypto \
		src/qos_core \
	)
	$(call build)


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
