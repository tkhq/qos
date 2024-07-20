define run
	docker run \
		--interactive \
		--volume ./src/:/src \
		--volume ./out/:/out \
		--volume ./cache/cargo/:/.cargo \
		--workdir /src \
		--env RUSTFLAGS="" \
		--env CARGOFLAGS="--locked" \
		--env PATH=/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		$(2) \
		qos-local/common \
		/bin/sh -c "set -eu; $(1)"
endef

define build_context
$$( \
	self=$(1); \
	for each in $$(find out/*/index.json); do \
    	package=$$(basename $$(dirname $${each})); \
    	if [ "$${package}" = "$${self}" ]; then continue; fi; \
    	printf -- ' --build-context %s=oci-layout://./out/%s' "$${package}" "$${package}"; \
	done; \
)
endef

,:=,
define build
	$(eval NAME := $(1))
	$(eval TYPE := $(if $(2),$(2),dir))
	$(eval BASE_IMAGE := $(3))
	$(eval REGISTRY := qos-local)
	$(eval PLATFORM := linux/amd64)
	DOCKER_BUILDKIT=1 \
	SOURCE_DATE_EPOCH=1 \
	BUILDKIT_MULTIPLATFORM=1 \
	docker build \
		--tag $(REGISTRY)/$(NAME)$(if $(BASE_IMAGE),/$(BASE_IMAGE)) \
		--progress=plain \
		--platform=$(PLATFORM) \
		$(if $(BASE_IMAGE),--build-arg BASE_IMAGE=$(BASE_IMAGE)) \
		$(if $(filter common,$(NAME)),,$(call build_context,$(1))) \
		$(if $(filter 1,$(NOCACHE)),--no-cache) \
		--output "\
			type=oci,\
			$(if $(filter dir,$(TYPE)),tar=false$(,)) \
			rewrite-timestamp=true,\
			force-compression=true,\
			name=$(NAME),\
			$(if $(filter tar,$(TYPE)),dest=$@") \
			$(if $(filter dir,$(TYPE)),dest=out/$(NAME)") \
		-f src/images/$(NAME)/Containerfile \
		src/
endef
