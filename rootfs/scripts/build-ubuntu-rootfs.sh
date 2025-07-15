#!/bin/bash
# ==============================================================================
# Script: build-ubuntu-rootfs.sh
# ------------------------------------------------------------------------------
# Description:
#   This script creates a bootable Ubuntu root filesystem image (ubuntu.img)
#   for ARM64 platforms such as Snapdragon X Elite CRD.
#
#   It performs the following operations:
#     1. Downloads and extracts the latest Ubuntu Noble ARM64 preinstalled image.
#     2. Mounts and extracts the root filesystem contents.
#     3. Injects custom kernel and firmware packages (.deb).
#     4. Replaces resolv.conf temporarily using the host’s DNS config (for chroot).
#     5. Setup Host Name
#     6. Enters chroot to install base packages and configure GRUB.
#     7. Creates a static resolv.conf at the end to ensure DNS works on the target.
#     8. Packages the final rootfs as a 6GB ext4 image.
#
# Requirements:
#   - Must be run as root (the script auto elevates via sudo if needed)
#   - Host must support losetup, ext4, and chroot tools
#
# Usage:
#   ./build-ubuntu-rootfs.sh <kernel_package.deb> <firmware_package.deb>
#
# Output:
#   - ubuntu.img : Flashable ext4 rootfs image (for /dev/nvme0n1p13)
#
# Author: Bjordis Collaku
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
# Step 1: Configuration and Argument Parsing
# ==============================================================================
UBUNTU_URL="https://cdimage.ubuntu.com/ubuntu-server/noble/daily-preinstalled/current/noble-preinstalled-server-arm64.img.xz"
IMG_XZ_NAME="noble-preinstalled-server-arm64.img.xz"
IMG_NAME="noble-preinstalled-server-arm64.img"
ROOTFS_IMG="ubuntu.img"
WORKDIR=$(pwd)
MNT_DIR="$WORKDIR/mnt"
ROOTFS_DIR="$WORKDIR/rootfs"

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <kernel_package.deb> <firmware_package.deb>"
    exit 1
fi

KERNEL_DEB="$1"
FIRMWARE_DEB="$2"

[[ -f "$KERNEL_DEB" ]] || { echo "[ERROR] Kernel package not found: $KERNEL_DEB"; exit 1; }
[[ -f "$FIRMWARE_DEB" ]] || { echo "[ERROR] Firmware package not found: $FIRMWARE_DEB"; exit 1; }

# ==============================================================================
# Step 2: Download and Extract Ubuntu Preinstalled Image
# ==============================================================================
echo "[INFO] Downloading Ubuntu Noble preinstalled ARM64 image..."
if ! wget -c "$UBUNTU_URL" -O "$IMG_XZ_NAME"; then
    echo "[ERROR] Failed to download image from: $UBUNTU_URL"
    exit 1
fi

echo "[INFO] Extracting preinstalled image..."
7z x "$IMG_XZ_NAME"

# ==============================================================================
# Step 3: Mount Image and Copy Root Filesystem
# ==============================================================================
echo "[INFO] Setting up loop device..."
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
export UBUNTU_FRONTEND=noninteractive
apt update
apt install -y ubuntu-desktop-minimal network-manager iw net-tools

echo '[CHROOT] Installing custom firmware and kernel...'
dpkg -i /$(basename "$FIRMWARE_DEB")
yes \"\" | dpkg -i /$(basename "$KERNEL_DEB")

echo '[CHROOT] Detecting installed kernel version...'
kernel_ver=\$(ls /boot/vmlinuz-* | sed 's|.*/vmlinuz-||' | sort -V | tail -n1)
dtb_path=\"/lib/firmware/\$kernel_ver/device-tree/x1e80100-crd.dtb\"

echo '[CHROOT] Writing GRUB configuration...'
tee /boot/grub.cfg > /dev/null <<EOF
set timeout=5
set default=noble_crd
menuentry \"Ubuntu Noble IoT for X Elite CRD\" --id noble_crd {
    set root=(hd0,gpt13)
    devicetree \$dtb_path
    linux /boot/vmlinuz-\$kernel_ver earlycon console=ttyMSM0,115200n8 root=/dev/nvme0n1p13 cma=128M rw clk_ignore_unused pd_ignore_unused efi=noruntime rootwait ignore_loglevel
    initrd /boot/initrd.img-\$kernel_ver
}
EOF
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
mkfs.ext4 "$ROOTFS_IMG"

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
echo "[SUCCESS] Ubuntu rootfs image created successfully: $ROOTFS_IMG"

