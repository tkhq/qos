DEBUG := false
OUT_DIR := out
KEY_DIR := keys
SRC_DIR := src
TARGET := generic
CACHE_DIR := cache
CONFIG_DIR := config
SRC_DIR := src
USER := $(shell id -g):$(shell id -g)
ARCH := x86_64
TARGET_NAME := bzImage
, := ,
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	TOTAL_CPUS := $(shell sysctl -n hw.logicalcpu)
	CPUS := $(shell echo "$(TOTAL_CPUS) - 2" | bc)
endif
ifeq ($(UNAME_S),Linux)
	CPUS := $(shell nproc)
endif

include $(PWD)/config/global.env

ifeq ($(TARGET), aws)
TARGET_NAME := nitro.eif
endif

.DEFAULT_GOAL := default
.PHONY: default
default: \
	fetch \
	$(OUT_DIR)/$(TARGET)/$(TARGET_NAME)

# Clean repo back to initial clone state
.PHONY: clean
clean:
	rm -rf cache out
	docker image rm -f local/$(NAME)-build

# Launch a shell inside the toolchain container
.PHONY: toolchain-shell
toolchain-shell: $(OUT_DIR)/toolchain.tar
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
	$(CACHE_DIR)/$(TARGET) \
	$(OUT_DIR)/$(TARGET) \
	$(OUT_DIR)/toolchain.tar \
	keys \
	$(CACHE_DIR)/linux-$(LINUX_VERSION).tar.xz \
	$(CACHE_DIR)/linux-$(LINUX_VERSION).tar.sign \
	$(CACHE_DIR)/busybox-$(BUSYBOX_VERSION).tar.bz2 \
	$(CACHE_DIR)/busybox-$(BUSYBOX_VERSION).tar.bz2.sig \
	$(CACHE_DIR)/aws-nitro-enclaves-image-format/.git/HEAD \
	$(CACHE_DIR)/rust/.git/HEAD

# Build latest image and run in terminal via Qemu
.PHONY: run
run: default
	qemu-system-x86_64 \
		-m 512M \
		-nographic \
		-kernel $(OUT_DIR)/bzImage

# Run ncurses busybox config menu and save output
.PHONY: busybox-config
busybox-config:
	rm $(CONFIG_DIR)/debug/busybox.config
	make $(CONFIG_DIR)/debug/busybox.config

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

$(OUT_DIR)/$(TARGET):
	mkdir -p $(OUT_DIR)/$(TARGET)

$(CACHE_DIR)/$(TARGET):
	mkdir -p $(CACHE_DIR)/$(TARGET)


$(CACHE_DIR)/rust/.git/HEAD:
	$(call toolchain,$(USER), " \
		cd /cache; \
		git clone $(RUST_REPO); \
		cd rust; \
		git checkout $(RUST_REF); \
		git rev-parse --verify HEAD | grep -q $(RUST_REF) || { \
			echo 'Error: Git ref/branch collision.'; exit 1; \
		}; \
	")

$(CACHE_DIR)/aws-nitro-enclaves-sdk-bootstrap/.git/HEAD:
	$(call toolchain,$(USER), " \
		cd /cache; \
		git clone $(AWS_NITRO_DRIVER_REPO); \
		cd aws-nitro-enclaves-sdk-bootstrap; \
		git checkout $(AWS_NITRO_DRIVER_REF); \
		git rev-parse --verify HEAD | grep -q $(AWS_NITRO_DRIVER_REF) || { \
			echo 'Error: Git ref/branch collision.'; exit 1; \
		}; \
	")

$(CACHE_DIR)/aws-nitro-enclaves-image-format/.git/HEAD:
	$(call toolchain,$(USER), " \
		cd /cache; \
		git clone https://github.com/aws/aws-nitro-enclaves-image-format.git; \
		cd aws-nitro-enclaves-image-format; \
		git checkout $(AWS_EIF_REF); \
		git rev-parse --verify HEAD | grep -q $(AWS_EIF_REF) || { \
			echo 'Error: Git ref/branch collision.'; exit 1; \
		}; \
	")

$(CACHE_DIR)/busybox-$(BUSYBOX_VERSION).tar.bz2.sig:
	curl \
		--url $(BUSYBOX_SERVER)/busybox-$(BUSYBOX_VERSION).tar.bz2.sig \
		--output $(CACHE_DIR)/busybox-$(BUSYBOX_VERSION).tar.bz2.sig

$(CACHE_DIR)/busybox-$(BUSYBOX_VERSION).tar.bz2:
	curl \
		--url $(BUSYBOX_SERVER)/busybox-$(BUSYBOX_VERSION).tar.bz2 \
		--output $(CACHE_DIR)/busybox-$(BUSYBOX_VERSION).tar.bz2

$(CACHE_DIR)/linux-$(LINUX_VERSION).tar.sign:
	curl \
		--url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.sign \
		--output $(CACHE_DIR)/linux-$(LINUX_VERSION).tar.sign

$(CACHE_DIR)/linux-$(LINUX_VERSION).tar.xz:
	curl \
		--url $(LINUX_SERVER)/linux-$(LINUX_VERSION).tar.xz \
		--output $(CACHE_DIR)/linux-$(LINUX_VERSION).tar.xz

$(CACHE_DIR)/linux-$(LINUX_VERSION).tar:
	xz -d $(CACHE_DIR)/linux-$(LINUX_VERSION).tar.xz

$(CACHE_DIR)/linux-$(LINUX_VERSION): $(CACHE_DIR)/linux-$(LINUX_VERSION).tar
	$(call toolchain,$(USER), " \
		cd /cache && \
		gpg --import /keys/$(LINUX_KEY).asc && \
		gpg --verify linux-$(LINUX_VERSION).tar.sign && \
		tar xf linux-$(LINUX_VERSION).tar; \
	")

$(CACHE_DIR)/busybox-$(BUSYBOX_VERSION):
	$(call toolchain,$(USER), " \
		cd /cache && \
		gpg --import /keys/$(BUSYBOX_KEY).asc && \
		gpg --verify busybox-$(BUSYBOX_VERSION).tar.bz2.sig && \
		tar -xf busybox-$(BUSYBOX_VERSION).tar.bz2 \
	")

$(OUT_DIR)/toolchain.tar:
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

define toolchain
	docker load -i $(OUT_DIR)/toolchain.tar
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
		--env CARGO_HOME=/cache/cargo \
		local/$(NAME)-build \
		bash -c $(2)
endef


$(CONFIG_DIR)/debug/busybox.config:
	$(call toolchain,$(USER), " \
		cd /cache/busybox-$(BUSYBOX_VERSION) && \
		KCONFIG_NOTIMESTAMP=1 make menuconfig && \
		cp .config /config/debug/busybox.config; \
	")

$(CONFIG_DIR)/$(TARGET)/linux.config:
	$(call toolchain,$(USER)," \
		cd /cache/linux-$(LINUX_VERSION) && \
		make menuconfig && \
		cp .config /config/$(TARGET)/linux.config; \
	")

$(OUT_DIR)/busybox: \
	$(CACHE_DIR)/busybox-$(BUSYBOX_VERSION) \
	$(CACHE_DIR)/busybox-$(BUSYBOX_VERSION).tar.bz2 \
	$(CACHE_DIR)/busybox-$(BUSYBOX_VERSION).tar.bz2.sig
	$(call toolchain,$(USER)," \
		cd /cache/busybox-$(BUSYBOX_VERSION) && \
		cp /config/debug/busybox.config .config && \
		make -j$(CPUS) busybox && \
		cp busybox /out/; \
	")

$(OUT_DIR)/init:
	$(call toolchain,$(USER)," \
		cd /src/init/ && \
		RUSTFLAGS='-C target-feature=+crt-static' cargo build \
			--target x86_64-unknown-linux-gnu \
			--release && \
		cp /src/init/target/x86_64-unknown-linux-gnu/release/init /out/init \
	")


$(CACHE_DIR)/linux-$(LINUX_VERSION)/usr/gen_init_cpio: \
	$(CACHE_DIR)/linux-$(LINUX_VERSION) \
	$(CACHE_DIR)/linux-$(LINUX_VERSION) \
	$(CACHE_DIR)/linux-$(LINUX_VERSION).tar.xz \
	$(CACHE_DIR)/linux-$(LINUX_VERSION).tar.sign
	$(call toolchain,$(USER)," \
		cd /cache/linux-$(LINUX_VERSION) && \
		gcc usr/gen_init_cpio.c -o usr/gen_init_cpio \
	")

$(OUT_DIR)/$(TARGET)/rootfs.cpio: \
	$(OUT_DIR)/busybox \
	$(OUT_DIR)/init \
	$(OUT_DIR)/aws/nsm.ko \
	$(CACHE_DIR)/linux-$(LINUX_VERSION)/usr/gen_init_cpio
	mkdir -p $(CACHE_DIR)/$(TARGET)/rootfs
	cp $(CONFIG_DIR)/$(TARGET)/rootfs.list $(CACHE_DIR)/$(TARGET)/rootfs.list
	cp $(OUT_DIR)/init $(CACHE_DIR)/$(TARGET)/rootfs/init
ifeq ($(DEBUG), true)
	mv $(CACHE_DIR)/$(TARGET)/rootfs/init $(CACHE_DIR)/$(TARGET)/rootfs/real_init
	cp $(SRC_DIR)/scripts/busybox_init $(CACHE_DIR)/$(TARGET)/rootfs/init
	cp $(OUT_DIR)/busybox $(CACHE_DIR)/$(TARGET)/rootfs/bin/
	echo "file /bin/busybox /cache/rootfs/bin/busybox 0755 0 0" \
		>> $(CACHE_DIR)/$(TARGET)/rootfs.list
endif
	$(call toolchain,$(USER)," \
		cd /cache/$(TARGET)/rootfs && \
		find . -mindepth 1 -execdir touch -hcd "@0" "{}" + && \
		find . -mindepth 1 -printf '%P\0' && \
		cd /cache/linux-$(LINUX_VERSION) && \
		usr/gen_initramfs.sh \
			-o /out/$(TARGET)/rootfs.cpio \
			/cache/$(TARGET)/rootfs.list && \
		cpio -itv < /out/$(TARGET)/rootfs.cpio && \
		sha256sum /out/$(TARGET)/rootfs.cpio; \
	")

$(OUT_DIR)/$(TARGET)/bzImage: \
	$(CACHE_DIR)/linux-$(LINUX_VERSION)
	$(call toolchain,$(USER)," \
		cd /cache/linux-$(LINUX_VERSION) && \
		cp /config/$(TARGET)/linux.config .config && \
		make olddefconfig && \
		make modules_prepare && \
		make -j$(CPUS) ARCH=$(ARCH) bzImage && \
		cp arch/x86_64/boot/bzImage /out/$(TARGET) && \
		sha256sum /out/$(TARGET)/bzImage; \
	")

$(OUT_DIR)/aws/eif_build:
ifeq ($(TARGET), aws)
	$(call toolchain,$(USER)," \
		cd /cache/aws-nitro-enclaves-image-format \
		&& CARGO_HOME=/cache/cargo cargo build --example eif_build \
		&& cp target/debug/examples/eif_build /out; \
	")
endif

$(OUT_DIR)/aws/nsm.ko: \
	$(OUT_DIR)/$(TARGET)/bzImage \
	$(CACHE_DIR)/aws-nitro-enclaves-sdk-bootstrap/.git/HEAD
ifeq ($(TARGET), aws)
	$(call toolchain,$(USER)," \
		cd /cache/aws-nitro-enclaves-sdk-bootstrap/ \
		&& make -C /cache/linux-$(LINUX_VERSION) M=/cache/aws-nitro-enclaves-sdk-bootstrap/nsm-driver \
		&& cp nsm-driver/nsm.ko /out/aws/nsm.ko; \
	")
endif


$(OUT_DIR)/aws/nitro.eif: \
	$(OUT_DIR)/aws/eif_build \
	$(OUT_DIR)/$(TARGET)/bzImage \
	$(OUT_DIR)/$(TARGET)/rootfs.cpio
ifeq ($(TARGET), aws)
	$(call toolchain,$(USER)," \
		/out/eif_build \
			--kernel /out/$(TARGET)/bzImage \
			--kernel_config /config/$(TARGET)/linux.config \
			--cmdline 'reboot=k initrd=0x2000000$(,)3228672 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd' \
			--ramdisk /out/aws/rootfs.cpio \
			--output /out/aws/nitro.eif; \
	")
endif

