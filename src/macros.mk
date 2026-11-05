define run
	docker run \
		--interactive \
		--volume ./src/:/qos/src \
		--volume ./Cargo.toml:/qos/Cargo.toml:ro \
		--volume ./Cargo.lock:/qos/Cargo.lock:ro \
		--volume ./rustfmt.toml:/qos/rustfmt.toml:ro \
		--volume ./out/:/out \
		--volume ./cache/cargo/:/.cargo \
		--workdir /qos \
		--env RUSTFLAGS="" \
		--env CARGOFLAGS="--locked" \
		--env PATH=/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		$(2) \
		$(LOCAL_REGISTRY)/common \
		/bin/sh -c "set -eu; $(1)"
endef

# Images built in this repo are named under qos.localhost, a reserved name
# (RFC 6761) that no public registry can serve. A missing local image fails
# the build instead of falling back to a registry pull.
LOCAL_REGISTRY := qos.localhost

# Local images a Containerfile depends on, e.g. "common linux_nitro".
define local_images
$(shell sed -n 's|^FROM $(LOCAL_REGISTRY)/\([^ ]*\).*|\1|p' src/images/$(1)/Containerfile | sort -u)
endef

,:=,
define build
	$(eval NAME := $(1))
	$(eval TYPE := $(if $(2),$(2),dir))
	$(eval PLATFORM := linux/amd64)
	$(eval LOCAL_IMAGES := $(call local_images,$(1)))
	@for image in $(LOCAL_IMAGES); do \
		test -f "out/$$image/index.json" || \
			{ echo "missing local image out/$$image for $(NAME)" >&2; exit 1; }; \
	done
	DOCKER_BUILDKIT=1 \
	SOURCE_DATE_EPOCH=1 \
	BUILDKIT_MULTIPLATFORM=1 \
	docker build \
		--tag $(LOCAL_REGISTRY)/$(NAME) \
		--progress=plain \
		--platform=$(PLATFORM) \
		$(foreach image,$(LOCAL_IMAGES),--build-context $(LOCAL_REGISTRY)/$(image)=oci-layout://./out/$(image)) \
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
		.
endef
