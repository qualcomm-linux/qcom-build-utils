#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# ==============================================================================
# Script: build-ubuntu-rootfs.sh
# ------------------------------------------------------------------------------
# Description:
#   This script creates a bootable Linux root filesystem image (ubuntu.img) for
#   ARM64 platforms. The base image (URL and filenames) are derived from a
#   product config file (qcom-product.conf) when provided; otherwise, it falls
#   back to default Ubuntu settings to preserve legacy 2-argument workflows.
#
#   It performs the following operations:
#     1. Parses qcom-product.conf (if provided) or uses defaults to determine the base image.
#     2. Runs target platform-specific image preprocessing to populate rootfs/ (download,
#        extract, mount, copy-out).
#     3. Injects custom kernel and firmware packages (.deb).
#     4. Replaces resolv.conf temporarily using the host’s DNS config (for chroot).
#     5. Sets host name.
#     6. Enters chroot to install base packages and configure GRUB.
#     7. Creates a static resolv.conf at the end to ensure DNS works on the target.
#     8. Packages the final rootfs as a 6GB ext4 image.
#
# Requirements:
#   - Must be run as root (the script auto elevates via sudo if needed)
#   - Host must support losetup, ext4, and chroot tools
#
# Usage:
#   NEW: ./build-ubuntu-rootfs.sh <qcom-product.conf> <kernel_package.deb> <firmware_package.deb>
#   OLD: ./build-ubuntu-rootfs.sh <kernel_package.deb> <firmware_package.deb>
#
# Output:
#   - ubuntu.img : Flashable ext4 rootfs image
#
# Author: Bjordis Collaku <bcollaku@qti.qualcomm.com>
# ==============================================================================

set -euo pipefail

# ==============================================================================
# Step 0: Auto-elevate if not run as root
# ==============================================================================
if [[ "$EUID" -ne 0 ]]; then
    echo "[INFO] Re-running script as root using sudo..."
    exec sudo "$0" "$@"
fi

# ==============================================================================
# Globals & Argument Parsing (backward compatible)
# ==============================================================================
if [[ $# -eq 3 ]]; then
    CONF="$1"
    KERNEL_DEB="$2"
    FIRMWARE_DEB="$3"
    USE_CONF=1
elif [[ $# -eq 2 ]]; then
    CONF=""  # no config provided
    KERNEL_DEB="$1"
    FIRMWARE_DEB="$2"
    USE_CONF=0
else
    echo "Usage:"
    echo "  NEW: $0 <qcom-product.conf> <kernel_package.deb> <firmware_package.deb>"
    echo "  OLD: $0 <kernel_package.deb> <firmware_package.deb>"
    exit 1
fi

[[ -f "$KERNEL_DEB" ]] || { echo "[ERROR] Kernel package not found: $KERNEL_DEB"; exit 1; }
[[ -f "$FIRMWARE_DEB" ]] || { echo "[ERROR] Firmware package not found: $FIRMWARE_DEB"; exit 1; }

WORKDIR=$(pwd)
MNT_DIR="$WORKDIR/mnt"
ROOTFS_DIR="$WORKDIR/rootfs"
ROOTFS_IMG="ubuntu.img"
mkdir -p "$MNT_DIR" "$ROOTFS_DIR"

declare -A CFG

# ==============================================================================
# Function: parse_configuration
#   Reads qcom-product.conf into CFG[] (Key: value or KEY=value).
# ==============================================================================
parse_configuration() {
    local conf_file="$1"
    [[ -f "$conf_file" ]] || { echo "[ERROR] Config file not found: $conf_file"; exit 1; }

    while IFS= read -r line; do
        line="${line%%#*}"
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*:[[:space:]]*(.*)$ ]]; then
            k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
        elif [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
        else
            continue
        fi
        k=$(echo "$k" | tr '[:lower:]' '[:upper:]')
        v=$(echo "$v" | xargs)
        CFG["$k"]="$v"
    done < "$conf_file"
}

# ==============================================================================
# Function: image_preproccessing_iot
#   Target: iot
#   Downloads/extracts the base image, mounts, and fills $ROOTFS_DIR/.
#   Distro-specific handling is done via an inner case.
# ==============================================================================
image_preproccessing_iot() {
    case "$(echo "$DISTRO" | tr '[:upper:]' '[:lower:]')" in
      ubuntu|ubuntu-server)
        local LOOP_DEV PART_DEV
        echo "[INFO][iot][ubuntu] Downloading base image..."
        if ! wget -c "$IMG_URL" -O "$IMG_XZ_NAME"; then
            echo "[ERROR] Failed to download image from: $IMG_URL"
            exit 1
        fi

        echo "[INFO][iot][ubuntu] Extracting preinstalled image..."
        7z x "$IMG_XZ_NAME"

        echo "[INFO][iot][ubuntu] Setting up loop device..."
        LOOP_DEV=$(losetup --show --partscan --find "$IMG_NAME")
        PART_DEV="${LOOP_DEV}p1"

        if [[ ! -b "$PART_DEV" ]]; then
            losetup -d "$LOOP_DEV"
            echo "[ERROR] Partition not found: $PART_DEV"
            exit 1
        fi

        mkdir -p "$MNT_DIR" "$ROOTFS_DIR"
        mount "$PART_DEV" "$MNT_DIR"
        cp -rap "$MNT_DIR/"* "$ROOTFS_DIR/"
        umount -l "$MNT_DIR"
        losetup -d "$LOOP_DEV"
        ;;
      debian)
        echo "[ERROR][iot][debian] Not implemented yet."
        exit 1
        ;;
      *)
        echo "[ERROR][iot] Unsupported distro: $DISTRO"
        exit 1
        ;;
    esac
}

# Empty stubs for future targets
image_preproccessing_compute() { :; }
image_preproccessing_server()  { :; }

# ==============================================================================
# Step 1: Load configuration (from file or defaults) & derive image parameters
# ==============================================================================
if [[ "$USE_CONF" -eq 1 ]]; then
    parse_configuration "$CONF"
    echo "[INFO] Using configuration from: $CONF"
else
    echo "[INFO] No config provided; using default configuration for backward compatibility."
    # Defaults mirror what you'd place in qcom-product.conf
    CFG["QCOM_TARGET_PLATFORM"]="iot"
    CFG["DISTRO"]="ubuntu"
    CFG["CODENAME"]="questing"
    CFG["ARCH"]="arm64"
    CFG["VARIANT"]="server"
    CFG["CHANNEL"]="daily-preinstalled"
    CFG["STREAM"]="current"
    CFG["FLAVOR"]="ubuntu-server"
fi

# IMPORTANT: single, canonical key for target platform
TARGET_PLATFORM="${CFG[QCOM_TARGET_PLATFORM]:-iot}"

DISTRO="${CFG[DISTRO]:-ubuntu}"
CODENAME="${CFG[CODENAME]:-questing}"
ARCH="${CFG[ARCH]:-arm64}"
VARIANT="${CFG[VARIANT]:-server}"
CHANNEL="${CFG[CHANNEL]:-daily-preinstalled}"
STREAM="${CFG[STREAM]:-current}"
FLAVOR="${CFG[FLAVOR]:-ubuntu-server}"

# Derive image parameters for Ubuntu (others can be added later)
case "$(echo "$DISTRO" | tr '[:upper:]' '[:lower:]')" in
  ubuntu|ubuntu-server)
    IMG_STEM="${CODENAME}-preinstalled-${VARIANT}-${ARCH}.img"
    IMG_XZ_NAME="${IMG_STEM}.xz"
    # Ubuntu daily-preinstalled URL format (no codename directory in the path):
    # https://cdimage.ubuntu.com/<flavor>/<channel>/<stream>/<codename>-preinstalled-<variant>-<arch>.img.xz
    IMG_URL="https://cdimage.ubuntu.com/${FLAVOR}/${CHANNEL}/${STREAM}/${IMG_XZ_NAME}"
    IMG_NAME="$IMG_STEM"
    ;;
  *)
    # Leave unsupported distros to be implemented inside the respective target function later.
    IMG_STEM=""
    IMG_XZ_NAME=""
    IMG_NAME=""
    IMG_URL=""
    ;;
esac

echo "[INFO] Build Source:"
echo "  TARGET_PLATFORM=$TARGET_PLATFORM"
echo "  DISTRO=$DISTRO"
echo "  CODENAME=$CODENAME"
echo "  ARCH=$ARCH"
echo "  VARIANT=$VARIANT"
echo "  CHANNEL=$CHANNEL"
echo "  STREAM=$STREAM"
echo "  FLAVOR=$FLAVOR"
[[ -n "$IMG_URL" ]] && echo "  URL=$IMG_URL"

# ==============================================================================
# Step 2–3: Target platform switch – preprocess image to fill rootfs/
# ==============================================================================
case "$(echo "$TARGET_PLATFORM" | tr '[:upper:]' '[:lower:]')" in
  iot)
    image_preproccessing_iot
    ;;
  compute)
    image_preproccessing_compute
    ;;
  server)
    image_preproccessing_server
    ;;
  *)
    echo "[ERROR] Unsupported target platform: $TARGET_PLATFORM"
    exit 1
    ;;
esac

# ==============================================================================
# Step 4: Inject Kernel, Firmware, and Working resolv.conf
# ==============================================================================
echo "[INFO] Copying kernel and firmware packages into rootfs..."
cp "$KERNEL_DEB" "$ROOTFS_DIR/"
cp "$FIRMWARE_DEB" "$ROOTFS_DIR/"

echo "[INFO] Replacing /etc/resolv.conf with host copy for apt inside chroot..."
rm -f "$ROOTFS_DIR/etc/resolv.conf"
cp -L /etc/resolv.conf "$ROOTFS_DIR/etc/resolv.conf"

# ==============================================================================
# Step 5: Set Hostname and /etc/hosts
# ==============================================================================
echo "[INFO] Configuring hostname and /etc/hosts..."
echo "ubuntu" > "$ROOTFS_DIR/etc/hostname"

cat <<EOF > "$ROOTFS_DIR/etc/hosts"
127.0.0.1   localhost
127.0.1.1   ubuntu
EOF

chmod 644 "$ROOTFS_DIR/etc/hosts"

# ==============================================================================
# Step 6: Bind Mount System Directories for chroot
# ==============================================================================
echo "[INFO] Binding system directories..."
mount -o bind /proc "$ROOTFS_DIR/proc"
mount -o bind /sys "$ROOTFS_DIR/sys"
mount -o bind /dev "$ROOTFS_DIR/dev"
mount --bind /dev/pts "$ROOTFS_DIR/dev/pts"

# ==============================================================================
# Step 7: Enter chroot to Install Packages and Configure GRUB
# ==============================================================================
echo "[INFO] Entering chroot to install packages and configure GRUB..."
chroot "$ROOTFS_DIR" /bin/bash -c "
set -e

echo '[CHROOT] Updating APT and installing base packages...'
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y ubuntu-desktop-minimal network-manager iw net-tools

echo '[CHROOT] Disabling unnecessary services...'
ln -sf /dev/null /etc/systemd/system/systemd-networkd-wait-online.service
ln -sf /dev/null /etc/systemd/system/dev-disk-by\\\\x2dlabel-UEFI.device

echo '[CHROOT] Installing custom firmware and kernel...'
dpkg -i /$(basename "$FIRMWARE_DEB")
yes \"\" | dpkg -i /$(basename "$KERNEL_DEB")

echo '[CHROOT] Detecting installed kernel version...'
kernel_ver=\$(ls /boot/vmlinuz-* | sed 's|.*/vmlinuz-||' | sort -V | tail -n1)
crd_dtb_path=\"/lib/firmware/\$kernel_ver/device-tree/x1e80100-crd.dtb\"

echo '[CHROOT] Writing GRUB configuration...'
tee /boot/grub.cfg > /dev/null <<EOF
set timeout=5
set default=${CODENAME}_crd
menuentry \"Ubuntu ${CODENAME} IoT for X Elite CRD\" --id ${CODENAME}_crd {
    search --no-floppy --label system --set=root
    devicetree \$crd_dtb_path
    linux /boot/vmlinuz-\$kernel_ver earlycon console=ttyMSM0,115200n8 root=LABEL=system cma=128M rw clk_ignore_unused pd_ignore_unused efi=noruntime rootwait ignore_loglevel
    initrd /boot/initrd.img-\$kernel_ver
}
EOF

# Conditionally append EVK entry if its DTB is present
evk_dtb_path=\"/lib/firmware/\$kernel_ver/device-tree/hamoa-iot-evk.dtb\"

if [ -f "\$evk_dtb_path" ]; then
    echo '[CHROOT] EVK DTB detected — appending EVK GRUB menuentry...'
    tee -a /boot/grub.cfg > /dev/null <<EVK
menuentry \"Ubuntu ${CODENAME} IoT for X Elite EVK\" --id ${CODENAME}_evk {
    search --no-floppy --label system --set=root
    devicetree \$evk_dtb_path
    linux /boot/vmlinuz-\$kernel_ver earlycon console=ttyMSM0,115200n8 root=LABEL=system cma=128M rw clk_ignore_unused pd_ignore_unused efi=noruntime rootwait ignore_loglevel
    initrd /boot/initrd.img-\$kernel_ver
}
EVK
else
    echo '[CHROOT] EVK DTB not found — skipping EVK GRUB menuentry.'
fi
"

# ==============================================================================
# Step 8: Unmount chroot environment
# ==============================================================================
echo "[INFO] Unmounting system directories..."
umount -l "$ROOTFS_DIR/dev/pts"
umount -l "$ROOTFS_DIR/dev"
umount -l "$ROOTFS_DIR/sys"
umount -l "$ROOTFS_DIR/proc"

# ==============================================================================
# Step 9: Create ext4 rootfs image and write contents
# ==============================================================================
echo "[INFO] Creating ext4 rootfs image: $ROOTFS_IMG (6GB)"
truncate -s 6G "$ROOTFS_IMG"
mkfs.ext4 -L system "$ROOTFS_IMG"

echo "[INFO] Copying rootfs contents into image..."
mount -o loop "$ROOTFS_IMG" "$MNT_DIR"
cp -rap "$ROOTFS_DIR/"* "$MNT_DIR/"

echo "[INFO] Writing static /etc/resolv.conf for runtime DNS resolution..."
rm -f "$MNT_DIR/etc/resolv.conf"
echo -e 'nameserver 1.1.1.1\nnameserver 8.8.8.8' > "$MNT_DIR/etc/resolv.conf"

umount -l "$MNT_DIR"

# ==============================================================================
# Completion
# ==============================================================================
echo "[SUCCESS] Rootfs image created successfully: $ROOTFS_IMG"

