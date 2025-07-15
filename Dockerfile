###############################################################################
# Dockerfile: ubuntu-noble-image-builder  (ARM64 native)
#
# Purpose:
#   Provide a minimal but complete build environment for:
#     • Linux kernel compilation and deb-pkg packaging
#     • RootFS + EFI ESP image generation scripts
#
# Build (on an ARM64 host):
#   docker build -t ubuntu-noble-image-builder:latest .
###############################################################################
# 24.04 (arm64) base
FROM ubuntu:24.04

LABEL maintainer="Bjordis Collaku <bcollaku@qti.qualcomm.com>" \
      description="Ubuntu Noble ARM64 container for kernel + image build tooling"

#-----------------------------------------------------------
# 0. Base ENV setup
#-----------------------------------------------------------
ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC
ENV ARCH=arm64

#-----------------------------------------------------------
# 1. Install required packages
#   - Kernel tool-chain, Debian packaging
#   - GRUB & filesystem utilities
#   - 7z (comes from p7zip-full)
#-----------------------------------------------------------
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential bc bison flex libssl-dev libelf-dev libncurses-dev \
    debhelper fakeroot devscripts rsync dpkg-dev \
    grub-efi-arm64-bin grub2-common dosfstools e2fsprogs xz-utils \
    p7zip-full wget git ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

#-----------------------------------------------------------
# 2. Default entrypoint
#-----------------------------------------------------------
ENTRYPOINT ["/bin/bash"]
CMD ["-l"]

