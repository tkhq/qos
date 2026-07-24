ARG BASE_IMAGE=fedora:rawhide
FROM ${BASE_IMAGE}

RUN set -eux; \
    printf '[main]\ninstall_weak_deps=False\nkeepcache=False\n' > /etc/dnf/dnf.conf; \
    dnf -y --setopt=install_weak_deps=False install \
        qemu-system-x86-core \
        vhost-device-vsock; \
    dnf clean all; \
    qemu-system-x86_64 -machine help | awk '{ print $1 }' | grep -qx nitro-enclave; \
    vhost-device-vsock --help 2>&1 | grep -q -- --forward-cid
