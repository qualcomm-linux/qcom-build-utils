#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# ===================================================
# build-kernel-deb.sh
#
# Ubuntu-compliant packaging tool for Linux kernel builds.
#
# This script generates a .deb package for built Linux kernel products
# (Image, .config, Device Tree Blobs, modules) targeting Ubuntu-based systems.
#
# It performs the following:
#  - Verifies required kernel build outputs
#  - Creates an Ubuntu-compliant package directory structure
#  - Copies kernel image, config, DTBs, and modules into correct locations
#  - Generates DEBIAN/control metadata for package management
#  - Creates pre-install, post-install and post-remove scripts:
#     * preinst: checks for existing package and performs cleanup of old kernel files
#     * postinst: regenerates initramfs, updates GRUB, optionally reboots
#     * postrm: ensures GRUB is updated after package removal to avoid stale entries
#  - Builds the .deb package using dpkg-deb
#  - Verifies that the .deb was created successfully
#
# Usage:
#   ./build-kernel-deb.sh <path_to_kernel_out_dir> [build_id]
#
# Example:
#   ./build-kernel-deb.sh /path/to/kernel/out/ 19085636185-1
#
# Author: Bjordis Collaku <bcollaku@qti.qualcomm.com>
# ===================================================

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script needs to be run as root. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

echo "Ensuring necessary dependencies are installed..."
# Ensure necessary dependencies are installed silently
#apt-get update -qq
#apt-get install -y -qq dpkg-dev

# Ensure the first argument is passed
if [ -z "$1" ]; then
    echo "Please enter path to kernel products"
    echo "Usage: $0 <path_to_kernel_out_dir> [build_id]"
    exit 1
fi

# Arguments
OUT_DIR="$1"
BUILD_ID="${2:-}"

# Detect base kernel version from modules directory
BASE_KERNEL_VERSION=$(basename "$OUT_DIR"/modules/lib/modules/* 2>/dev/null)

if [ -z "$BASE_KERNEL_VERSION" ] || [ ! -d "$OUT_DIR/modules/lib/modules/$BASE_KERNEL_VERSION" ]; then
    echo "Unable to detect kernel version under: $OUT_DIR/modules/lib/modules/"
    exit 1
fi

# Package kernel version: append -BUILD_ID if provided (safe: package-only)
PKG_KERNEL_VERSION="$BASE_KERNEL_VERSION"
if [ -n "$BUILD_ID" ]; then
    PKG_KERNEL_VERSION="${BASE_KERNEL_VERSION}-${BUILD_ID}"
fi

# If you actually built the kernel with the suffix and want files/paths to match,
# uncomment the next line to switch all installed paths to the suffixed version.
# NOTE: Do this ONLY if uname -r for this kernel will also include the suffix.
#BASE_KERNEL_VERSION="$PKG_KERNEL_VERSION"

DEB_DIR="linux-kernel-$PKG_KERNEL_VERSION-arm64"
DEB_PACKAGE="$DEB_DIR.deb"

IMAGE="$OUT_DIR/Image"
CONFIG="$OUT_DIR/.config"
MODULES="$OUT_DIR/modules/lib/modules/$BASE_KERNEL_VERSION"
DTB="$OUT_DIR/*.dtb"

# Print required kernel products
echo "============================================================"
echo "Required kernel products in kernel/out/ dir:"
echo "    - Image"
echo "    - .config"
echo "    - Device Tree Blob (DTB) files"
echo "    - modules/lib/modules/$BASE_KERNEL_VERSION"
echo "============================================================"

echo "Checking for the existence of each kernel product..."
# Check for the existence of each kernel product
if [ ! -f "$IMAGE" ]; then
    echo "Kernel image not found at $IMAGE"
    exit 1
fi

if [ ! -f "$CONFIG" ]; then
    echo "Kernel config not found at $CONFIG"
    exit 1
fi

if [ ! -d "$MODULES" ]; then
    echo "Kernel modules directory not found at $MODULES"
    exit 1
fi

if [ -z "$(ls -A $DTB 2>/dev/null)" ]; then
    echo "No .dtb files found in $OUT_DIR"
    exit 1
fi

echo "Creating directory structure for Debian package..."
# Create directory structure for Debian package
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/boot"
mkdir -p "$DEB_DIR/lib/firmware/$BASE_KERNEL_VERSION/device-tree"
mkdir -p "$DEB_DIR/lib/modules/$BASE_KERNEL_VERSION"

echo "Setting correct permissions for DEBIAN directory..."
# Set correct permissions for DEBIAN directory
chmod 0755 "$DEB_DIR/DEBIAN"
chmod -R g-s "$DEB_DIR/DEBIAN"

echo "Integrating kernel products into the Debian package..."
# Copy files to the package directory
echo "Copying kernel image to /boot..."
cp "$IMAGE" "$DEB_DIR/boot/vmlinuz-$BASE_KERNEL_VERSION"

echo "Copying kernel config to /boot..."
cp "$CONFIG" "$DEB_DIR/boot/config-$BASE_KERNEL_VERSION"

echo "Copying kernel modules to /lib/modules..."
cp -rap "$MODULES" "$DEB_DIR/lib/modules/"

echo "Copying device tree blobs to /boot/dtbs..."
cp "$OUT_DIR"/*.dtb "$DEB_DIR/lib/firmware/$BASE_KERNEL_VERSION/device-tree/"

echo "Creating control file..."
# Create control file
cat <<EOF > "$DEB_DIR/DEBIAN/control"
Package: linux-kernel-$PKG_KERNEL_VERSION
Source: x1e80100
Version: $PKG_KERNEL_VERSION
Architecture: arm64
Maintainer: Bjordis Collaku <bcollaku@quicinc.com>
Section: kernel
Priority: optional
Description: Linux kernel Image, dtb and modules for $BASE_KERNEL_VERSION (package build $PKG_KERNEL_VERSION)
EOF

echo "Creating preinst script..."
# Create preinst script
cat <<EOF > $DEB_DIR/DEBIAN/preinst
#!/bin/sh
set -e

kernel_version=$BASE_KERNEL_VERSION
current_kernel_version=\$(uname -r)

echo "Starting cleanup of existing kernel products matching version \$kernel_version..."

# Check for the same kernel package already installed
existing_kernel_package="linux-kernel-\$kernel_version"
if dpkg-query -W -f='${Status}' "$existing_kernel_package" 2>/dev/null | grep -q "install ok installed"; then
    echo "Detected existing Linux kernel package: \$existing_kernel_package"
    echo "Please uninstall the existing kernel package before proceeding with the installation of the new kernel:"
    echo "sudo dpkg --remove \$existing_kernel_package"
    exit 1
fi

# Delete matching kernel config file
if [ -f /boot/config-\$kernel_version ]; then
    echo "Deleting /boot/config-\$kernel_version"
    rm -f /boot/config-\$kernel_version
fi

# Delete entire device-tree folder
if [ -d /lib/firmware/\$kernel_version ]; then
    echo "Deleting /lib/firmware/\$kernel_version/"
    rm -rf /lib/firmware/\$kernel_version
fi

# Delete matching vmlinuz file
if [ -f /boot/vmlinuz-\$kernel_version ]; then
    echo "Deleting /boot/vmlinuz-\$kernel_version"
    rm -f /boot/vmlinuz-\$kernel_version
fi

# Delete matching initrd image
if [ -f /boot/initrd.img-\$kernel_version ]; then
    echo "Deleting /boot/initrd.img-\$kernel_version"
    rm -f /boot/initrd.img-\$kernel_version
fi

# Delete matching module directory
if [ -d /lib/modules/\$kernel_version ]; then
    echo "Deleting /lib/modules/\$kernel_version"
    rm -rf /lib/modules/\$kernel_version
fi

echo "Cleanup complete. Proceeding with installation."
EOF

# Make preinst script executable
chmod 0755 $DEB_DIR/DEBIAN/preinst

echo "Creating postinst script..."
# Create postinst script
cat <<EOF > $DEB_DIR/DEBIAN/postinst
#!/bin/sh
set -e

kernel_version=$BASE_KERNEL_VERSION

echo "Starting post-installation procedure for Linux kernel package version \$kernel_version..."

# Update initramfs and generate initrd image
echo "Updating initramfs and generating initrd image..."
if update-initramfs -k \$kernel_version -c; then
    echo "Successfully updated initramfs."
else
    echo "Failed to update initramfs. Continuing with the installation..."
fi


# Update GRUB bootloader
echo "Updating GRUB bootloader..."
if update-grub; then
    echo "Successfully updated GRUB."
else
    echo "Failed to update GRUB. Please check your bootloader configuration."
fi

echo "Linux kernel package version \$kernel_version installed successfully."

# Suggest rebooting the system
echo "To apply the new kernel, a system reboot is required."
EOF

# Make postinst script executable
chmod 0755 $DEB_DIR/DEBIAN/postinst

echo "Creating postrm script..."
# Create postrm script
cat <<EOF > $DEB_DIR/DEBIAN/postrm
#!/bin/sh
set -e

kernel_version=$BASE_KERNEL_VERSION

echo "Starting post-removal procedure for Linux kernel package version \$kernel_version..."

# Update GRUB bootloader after kernel removal
echo "Updating GRUB bootloader..."
if update-grub; then
    echo "Successfully updated GRUB."
else
    echo "Failed to update GRUB. Please check your bootloader configuration."
fi

echo "Post-removal procedure for Linux kernel package version \$kernel_version completed."
EOF

# Make postrm script executable
chmod 0755 $DEB_DIR/DEBIAN/postrm

echo "Building the Debian package..."
# Build the Debian package
dpkg-deb --build $DEB_DIR

# Check if the .deb package was created successfully
if [ -f "$DEB_PACKAGE" ]; then
    echo "Debian package for kernel version $BASE_KERNEL_VERSION created successfully."
else
    echo "Failed to create Debian package for kernel version $BASE_KERNEL_VERSION."
fi

# Clean up
rm -rf $DEB_DIR
