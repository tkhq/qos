DEBUG := false
OUT_DIR := out
VERSION := $(shell TZ=UTC0 git show --quiet --date='format-local:%Y%m%dT%H%M%SZ' --format="%cd")
RELEASE_DIR := releases/$(VERSION)
KEY_DIR := keys
SRC_DIR := src
TARGET := generic
CACHE_DIR := cache
CONFIG_DIR := config
SRC_DIR := src
USER := $(shell id -g):$(shell id -g)
ARCH := x86_64
, := ,
UNAME_S := $(shell uname -s)
CPUS := $(shell docker run -it debian nproc)
GIT_REF := $(shell git log -1 --format=%H config)
GIT_AUTHOR := $(shell git log -1 --format=%an config)
GIT_KEY := $(shell git log -1 --format=%GP config)
GIT_EPOCH := $(shell git log -1 --format=%at config)
GIT_DATETIME := \
	$(shell git log -1 --format=%cd --date=format:'%Y-%m-%d %H:%M:%S' config)

include $(PWD)/config/global.env

## Use env vars from existing release if present
ifneq (,$(wildcard $(RELEASE_DIR)/release.env))
    include $(RELEASE_DIR)/release.env
    export
endif

.DEFAULT_GOAL := release

#$(OUT_DIR)/generic/bzImage
#mkdir -p $(RELEASE_DIR)/generic
#cp $(OUT_DIR)/generic/bzImage $(RELEASE_DIR)/generic/bzImage

$(RELEASE_DIR):
	mkdir -p $(RELEASE_DIR)

.PHONY: release
release: | \
	$(RELEASE_DIR) \
	$(OUT_DIR)/release.env \
	$(OUT_DIR)/aws-nitro.eif \
	$(OUT_DIR)/aws-pcrs.txt \
	$(OUT_DIR)/qos_client \
	$(OUT_DIR)/qos_host \
	$(OUT_DIR)/manifest.txt
	cp $(OUT_DIR)/release.env $(RELEASE_DIR)/release.env
	cp $(OUT_DIR)/aws-pcrs.txt $(RELEASE_DIR)/aws-pcrs.txt
	cp $(OUT_DIR)/aws-nitro.eif $(RELEASE_DIR)/aws-nitro.eif
	cp $(OUT_DIR)/qos_host $(RELEASE_DIR)/qos_host
	cp $(OUT_DIR)/qos_client $(RELEASE_DIR)/qos_client
	cp $(OUT_DIR)/manifest.txt $(RELEASE_DIR)/manifest.txt

.PHONY: attest
attest: $(RELEASE_DIR)/manifest.txt
	rm -rf $(CACHE_DIR) $(OUT_DIR)
	$(MAKE) $(OUT_DIR)/manifest.txt
	diff -q $(OUT_DIR)/manifest.txt $(RELEASE_DIR)/manifest.txt;

.PHONY: sign
sign: $(RELEASE_DIR)/manifest.txt
	set -e; \
	git config --get user.signingkey 2>&1 >/dev/null || { \
		echo "Error: git user.signingkey is not defined"; \
		exit 1; \
	}; \
	fingerprint=$$(\
		git config --get user.signingkey \
		| sed 's/.*\([A-Z0-9]\{16\}\).*/\1/g' \
	); \
	gpg --armor \
		--detach-sig  \
		--output $(RELEASE_DIR)/manifest.$${fingerprint}.asc \
		$(RELEASE_DIR)/manifest.txt

.PHONY: verify
verify: $(RELEASE_DIR)/manifest.txt
	set -e; \
	for file in $(RELEASE_DIR)/manifest.*.asc; do \
		echo "\nVerifying: $${file}\n"; \
		gpg --verify $${file} $(RELEASE_DIR)/manifest.txt; \
	done;

# Clean repo back to initial clone state
.PHONY: clean
clean:
	git clean -dfx src/
	rm -rf cache out release/*
	docker image rm -f local/$(NAME)-build

# Launch a shell inside the toolchain container
.PHONY: toolchain-shell
toolchain-shell: $(CACHE_DIR)/toolchain.tar
	$(call toolchain,root,bash)

# Pin all packages in toolchain container to latest versions
.PHONY: toolchain-update
toolchain-update:
	docker run \
		--rm \
		--env LOCAL_USER=$(USER) \
		--platform=linux/$(ARCH) \
		--volume $(PWD)/$(CONFIG_DIR):/config \
		--volume $(PWD)/$(SRC_DIR)/toolchain/scripts:/usr/local/bin \
		--env GNUPGHOME=/cache/.gnupg \
		--env ARCH=$(ARCH) \
		--interactive \
		--tty \
		debian@sha256:$(DEBIAN_HASH) \
		bash -c /usr/local/bin/packages-update

# Source anything required from the internet to build
.PHONY: fetch
fetch: \
	$(CACHE_DIR)/toolchain.tar \
	keys \
	$(CACHE_DIR)/linux-$(LINUX_VERSION).tar \
	$(CACHE_DIR)/linux-$(LINUX_VERSION).tar.sign \
	$(CACHE_DIR)/aws-nitro-enclaves-sdk-bootstrap/.git/HEAD

# Build latest image and run in terminal via Qemu
.PHONY: run
run: default
	qemu-system-x86_64 \
		-m 512M \
		-nographic \
		-kernel $(OUT_DIR)/bzImage

# Run linux config menu and save output
.PHONY: linux-config
linux-config:
	rm $(CONFIG_DIR)/$(TARGET)/linux.config
	make $(CONFIG_DIR)/$(TARGET)/linux.config

.PHONY: keys
keys: \
	$(KEY_DIR)/$(LINUX_KEY).asc \
	$(KEY_DIR)/$(BUSYBOX_KEY).asc

$(KEY_DIR)/$(LINUX_KEY).asc:
	$(call fetch_pgp_key,$(LINUX_KEY))

$(KEY_DIR)/$(BUSYBOX_KEY).asc:
	$(call fetch_pgp_key,,$(BUSYBOX_KEY))

$(OUT_DIR)/$(TARGET):
	mkdir -p $(OUT_DIR)/$(TARGET)

$(CACHE_DIR)/$(TARGET):
	mkdir -p $(CACHE_DIR)/$(TARGET)

$(CACHE_DIR)/aws-nitro-enclaves-sdk-bootstrap/.git/HEAD: \
	$(CACHE_DIR)/toolchain.tar
	$(call toolchain,$(USER), " \
		unset FAKETIME; \
		cd /cache; \
		git clone $(AWS_NITRO_DRIVER_REPO); \
		cd aws-nitro-enclaves-sdk-bootstrap; \
		git checkout $(AWS_NITRO_DRIVER_REF); \
		git rev-parse --verify HEAD | grep -q $(AWS_NITRO_DRIVER_REF) || { \
			echo 'Error: Git ref/branch collision.'; exit 1; \
		}; \
	")

$(CACHE_DIR)/linux-$(LINUX_VERSION).tar.sign:
	curl \
		--url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.sign \
		--output $(CACHE_DIR)/linux-$(LINUX_VERSION).tar.sign

$(CACHE_DIR)/linux-$(LINUX_VERSION).tar:
	curl \
		--url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.xz \
		--output $(CACHE_DIR)/linux-$(LINUX_VERSION).tar.xz
	xz -d $(CACHE_DIR)/linux-$(LINUX_VERSION).tar.xz

$(CACHE_DIR)/linux-$(LINUX_VERSION): \
	$(CACHE_DIR)/toolchain.tar \
	$(CACHE_DIR)/linux-$(LINUX_VERSION).tar \
	$(CACHE_DIR)/linux-$(LINUX_VERSION).tar.sign
	$(call toolchain,$(USER), " \
		unset FAKETIME; \
		cd /cache && \
		gpg --import /keys/$(LINUX_KEY).asc && \
		gpg --verify linux-$(LINUX_VERSION).tar.sign && \
		tar xf linux-$(LINUX_VERSION).tar; \
	")

$(OUT_DIR)/manifest.txt: \
	$(OUT_DIR)/aws-pcrs.txt \
	$(OUT_DIR)/aws-nitro.eif \
	$(OUT_DIR)/qos_client \
	$(OUT_DIR)/qos_host \
	$(OUT_DIR)/release.env
	openssl sha256 -r $(OUT_DIR)/release.env \
		>> $(OUT_DIR)/manifest.txt;
	openssl sha256 -r $(OUT_DIR)/aws-pcrs.txt \
		> $(OUT_DIR)/manifest.txt;
	openssl sha256 -r $(OUT_DIR)/aws-nitro.eif \
		>> $(OUT_DIR)/manifest.txt;
	openssl sha256 -r $(OUT_DIR)/qos_client \
		>> $(OUT_DIR)/manifest.txt;
	openssl sha256 -r $(OUT_DIR)/qos_host \
		>> $(OUT_DIR)/manifest.txt;

$(CACHE_DIR)/toolchain.tar: \
	$(OUT_DIR)/$(TARGET) \
	$(CACHE_DIR)/$(TARGET)
	DOCKER_BUILDKIT=1 \
	docker build \
		--tag local/$(NAME)-build \
		--build-arg DEBIAN_HASH=$(DEBIAN_HASH) \
		--build-arg RUST_REF=$(RUST_REF) \
		--build-arg CARGO_REF=$(CARGO_REF) \
		--build-arg CONFIG_DIR=$(CONFIG_DIR) \
		--build-arg SCRIPTS_DIR=$(SRC_DIR)/toolchain/scripts \
		--platform=linux/$(ARCH) \
		-f $(SRC_DIR)/toolchain/Dockerfile \
		.
	docker save "local/$(NAME)-build" -o "$@"

$(CONFIG_DIR)/$(TARGET)/linux.config: \
	$(CACHE_DIR)/toolchain.tar
	$(call toolchain,$(USER)," \
		unset FAKETIME && \
		cd /cache/linux-$(LINUX_VERSION) && \
		make menuconfig && \
		cp .config /config/$(TARGET)/linux.config; \
	")

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/release.env: $(OUT_DIR)
	test "$(VERSION)"
	echo 'VERSION=$(VERSION)'            > $(OUT_DIR)/release.env
	test "$(GIT_REF)"
	echo 'GIT_REF=$(GIT_REF)'           >> $(OUT_DIR)/release.env
	test "$(GIT_AUTHOR)"
	echo 'GIT_AUTHOR=$(GIT_AUTHOR)'     >> $(OUT_DIR)/release.env
	test "$(GIT_KEY)"
	echo 'GIT_KEY=$(GIT_KEY)'           >> $(OUT_DIR)/release.env
	test "$(GIT_DATETIME)"
	echo 'GIT_DATETIME=$(GIT_DATETIME)' >> $(OUT_DIR)/release.env

$(OUT_DIR)/init: \
	$(CACHE_DIR)/toolchain.tar
	$(call toolchain,$(USER)," \
		cd /src/init/ && \
		unset FAKETIME && \
		export RUSTFLAGS='-C target-feature=+crt-static' && \
		cargo build \
			--target x86_64-unknown-linux-gnu \
			--release && \
		cp /src/init/target/x86_64-unknown-linux-gnu/release/init /out/init \
	")

$(CACHE_DIR)/linux-$(LINUX_VERSION)/usr/gen_init_cpio: \
	$(CACHE_DIR)/toolchain.tar \
	| $(CACHE_DIR)/linux-$(LINUX_VERSION)
	$(call toolchain,$(USER)," \
		cd /cache/linux-$(LINUX_VERSION) && \
		gcc usr/gen_init_cpio.c -o usr/gen_init_cpio \
	")

$(OUT_DIR)/aws/rootfs.cpio: \
	$(CACHE_DIR)/linux-$(LINUX_VERSION)/usr/gen_init_cpio \
	$(OUT_DIR)/init \
	$(OUT_DIR)/aws/nsm.ko
	$(call rootfs_build,aws)

$(OUT_DIR)/generic/rootfs.cpio: \
	$(CACHE_DIR)/linux-$(LINUX_VERSION)/usr/gen_init_cpio \
	$(OUT_DIR)/init
	$(call rootfs_build,generic)

$(OUT_DIR)/generic/bzImage: \
	$(OUT_DIR)/generic/rootfs.cpio
	$(call kernel_build,generic,$(ARCH))

$(OUT_DIR)/aws/bzImage: \
	| $(CACHE_DIR)/linux-$(LINUX_VERSION)
	$(call kernel_build,aws,$(ARCH))

$(OUT_DIR)/aws/eif_build: \
	$(CACHE_DIR)/toolchain.tar
	$(call toolchain,$(USER)," \
		unset FAKETIME && \
		cd /src/toolchain/eif_build && \
		CARGO_HOME=/cache/cargo cargo build \
			--target x86_64-unknown-linux-gnu && \
		mkdir -p /out/aws/; \
		cp target/x86_64-unknown-linux-gnu/debug/eif_build /out/aws/; \
	")

$(OUT_DIR)/qos_host: \
	$(CACHE_DIR)/toolchain.tar
	$(call toolchain,$(USER)," \
		unset FAKETIME; \
		export RUSTFLAGS='-C target-feature=+crt-static' && \
		cd /src/qos_host \
		&& CARGO_HOME=/cache/cargo cargo build \
			--target x86_64-unknown-linux-gnu \
			--features vm \
			--no-default-features \
			--release \
		&& cp /src/target/x86_64-unknown-linux-gnu/release/qos_host /out/; \
	")

$(OUT_DIR)/qos_client: \
	$(CACHE_DIR)/toolchain.tar
	$(call toolchain,$(USER)," \
		unset FAKETIME; \
		export RUSTFLAGS='-C target-feature=+crt-static' && \
		cd /src/qos_client \
		&& CARGO_HOME=/cache/cargo cargo build \
			--target x86_64-unknown-linux-gnu \
			--no-default-features \
			--release \
		&& cp /src/target/x86_64-unknown-linux-gnu/release/qos_client /out/; \
	")

$(OUT_DIR)/aws/nsm.ko: \
	$(CACHE_DIR)/toolchain.tar \
	$(OUT_DIR)/aws/bzImage \
	$(CACHE_DIR)/aws-nitro-enclaves-sdk-bootstrap/.git/HEAD
	$(call toolchain,$(USER)," \
		unset FAKETIME; \
		cd /cache/linux-$(LINUX_VERSION) && \
		cp /config/aws/linux.config .config && \
		make olddefconfig && \
		make modules_prepare && \
		cd /cache/aws-nitro-enclaves-sdk-bootstrap/ \
		&& make -C /cache/linux-$(LINUX_VERSION) M=/cache/aws-nitro-enclaves-sdk-bootstrap/nsm-driver \
		&& cp nsm-driver/nsm.ko /out/aws/nsm.ko; \
	")

$(OUT_DIR)/aws-nitro.eif $(OUT_DIR)/aws-pcrs.txt: \
	$(CACHE_DIR)/toolchain.tar \
	$(OUT_DIR)/aws/eif_build \
	$(OUT_DIR)/aws/bzImage \
	$(OUT_DIR)/aws/rootfs.cpio
	$(call toolchain,$(USER)," \
		mkdir -p /cache/aws/eif && \
		cp /out/aws/bzImage /cache/aws/eif/ && \
		cp /out/aws/rootfs.cpio /cache/aws/eif/ && \
		cp /config/aws/linux.config /cache/aws/eif/ && \
		cd /cache/aws/eif && \
		find . -mindepth 1 -execdir touch -hcd "@0" "{}" + && \
		find . -mindepth 1 -printf '%P\0' && \
		/out/aws/eif_build \
			--kernel /cache/aws/eif/bzImage \
			--kernel_config /cache/aws/eif/linux.config \
			--cmdline 'reboot=k initrd=0x2000000$(,)3228672 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd' \
			--ramdisk /cache/aws/eif/rootfs.cpio \
			--output /out/aws-nitro.eif \
			--pcrs_output /out/aws-pcrs.txt; \
	")

define fetch_pgp_key
	mkdir -p $(KEY_DIR) && \
	$(call toolchain,$(USER), " \
		for server in \
			ha.pool.sks-keyservers.net \
			hkp://keyserver.ubuntu.com:80 \
			hkp://p80.pool.sks-keyservers.net:80 \
			pgp.mit.edu \
			; do \
				echo "Trying: $${server}"; \
				gpg \
					--recv-key \
					--keyserver "$${server}" \
					--keyserver-options timeout=10 \
					--recv-keys "$(1)" \
				&& break; \
			done; \
		gpg --export -a $(1) > $(KEY_DIR)/$(1).asc; \
	")
endef

define toolchain
	docker load -i $(CACHE_DIR)/toolchain.tar
	docker run \
		--rm \
		--tty \
		--interactive \
		--user=$(1) \
		--platform=linux/$(ARCH) \
		--volume $(PWD)/$(CONFIG_DIR):/config \
		--volume $(PWD)/$(CACHE_DIR):/cache \
		--volume $(PWD)/$(KEY_DIR):/keys \
		--volume $(PWD)/$(OUT_DIR):/out \
		--volume $(PWD)/$(SRC_DIR):/src \
		--cpus $(CPUS) \
		--env GNUPGHOME=/cache/.gnupg \
		--env ARCH=$(ARCH) \
		--env KBUILD_BUILD_USER=$(KBUILD_BUILD_USER) \
		--env KBUILD_BUILD_HOST=$(KBUILD_BUILD_HOST) \
		--env KBUILD_BUILD_VERSION=$(KBUILD_BUILD_VERSION) \
		--env KBUILD_BUILD_TIMESTAMP=$(KBUILD_BUILD_TIMESTAMP) \
		--env KCONFIG_NOTIMESTAMP=$(KCONFIG_NOTIMESTAMP) \
		--env SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		--env FAKETIME_FMT=$(FAKETIME_FMT) \
		--env FAKETIME=$(FAKETIME) \
		--env CARGO_HOME=/cache/cargo \
		local/$(NAME)-build \
		bash -c $(2)
endef

define rootfs_build
	mkdir -p $(CACHE_DIR)/$(1)/rootfs
	cp $(CONFIG_DIR)/$(1)/rootfs.list $(CACHE_DIR)/$(1)/rootfs.list
	cp $(OUT_DIR)/init $(CACHE_DIR)/$(1)/rootfs/init
	$(call toolchain,$(USER)," \
		cd /cache/$(1)/rootfs && \
		find . -mindepth 1 -execdir touch -hcd "@0" "{}" + && \
		find . -mindepth 1 -printf '%P\0' && \
		cd /cache/linux-$(LINUX_VERSION) && \
		usr/gen_initramfs.sh \
			-o /out/$(1)/rootfs.cpio \
			/cache/$(1)/rootfs.list && \
		cpio -itv < /out/$(1)/rootfs.cpio && \
		sha256sum /out/$(1)/rootfs.cpio; \
	")
	touch $(OUT_DIR)/$(1)/rootfs.cpio;
endef

define kernel_build
	$(call toolchain,$(USER)," \
		unset FAKETIME && \
		cd /cache/linux-$(LINUX_VERSION) && \
		rm -rf include/config include/generated arch/x86/include/generated && \
		cp /config/$(1)/linux.config .config && \
		make olddefconfig && \
		make -j$(CPUS) ARCH=$(2) bzImage && \
		cp arch/x86_64/boot/bzImage /out/$(1)/bzImage && \
		sha256sum /out/$(1)/bzImage; \
	")
	touch $(OUT_DIR)/$(1)/bzImage;
endef
