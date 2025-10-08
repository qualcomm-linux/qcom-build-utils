#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# ==============================================================================
# Script: build-ubuntu-rootfs.sh
# ------------------------------------------------------------------------------
# DESCRIPTION:
#   This script creates a bootable Linux root filesystem image for ARM64
#   platforms (e.g., Qualcomm IoT/Compute/Server reference boards).
#
#   - Supports Qualcomm product configuration file (.conf) for build parameters.
#   - Supports JSON package manifest for additional package installation
#     (via apt or local .deb) inside the rootfs.
#   - Supports injecting custom apt sources from the package manifest.
#   - Backward compatible with legacy 2-argument mode (kernel.deb, firmware.deb).
#   - Parses qcom-product.conf (if provided) or uses defaults to determine the base image.
#   - Runs target platform-specific image preprocessing to populate rootfs/.
#   - Injects custom kernel and firmware .deb packages.
#   - Installs user-specified packages from manifest (if provided).
#   - Dynamically deduces and generates base and custom package manifests
#   - Configures GRUB bootloader, hostname, DNS, and other system settings.
#   - Deploy package manifest output files
#   - Produces a flashable ext4 image (ubuntu.img).
#
# USAGE:
#   FULL:   ./build-ubuntu-rootfs.sh <qcom-product.conf> <package-manifest.json> <kernel.deb> <firmware.deb>
#   CONFIG: ./build-ubuntu-rootfs.sh <qcom-product.conf> <kernel.deb> <firmware.deb>
#   LEGACY: ./build-ubuntu-rootfs.sh <kernel.deb> <firmware.deb>
#
# ARGUMENTS:
#   <qcom-product.conf>      Optional. Product configuration file for build parameters.
#   <package-manifest.json>  Optional. JSON manifest specifying extra packages to install.
#   <kernel.deb>             Required. Custom kernel package.
#   <firmware.deb>           Required. Custom firmware package.
#
# OUTPUT:
#   ubuntu.img               Flashable ext4 rootfs image.
#
# REQUIREMENTS:
#   - Run as root (auto-elevates with sudo if needed).
#   - Host tools: wget, 7z, jq, losetup, mount, cp, chroot, mkfs.ext4, truncate, etc.
#
# AUTHOR: Bjordis Collaku <bcollaku@qti.qualcomm.com>
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
CONF=""
MANIFEST=""
KERNEL_DEB=""
FIRMWARE_DEB=""
USE_CONF=0
USE_MANIFEST=0

if [[ $# -eq 4 ]]; then
    CONF="$1"
    MANIFEST="$2"
    KERNEL_DEB="$3"
    FIRMWARE_DEB="$4"
    USE_CONF=1
    USE_MANIFEST=1
elif [[ $# -eq 3 ]]; then
    if [[ "$1" == *.conf ]]; then
        CONF="$1"
        MANIFEST=""
        KERNEL_DEB="$2"
        FIRMWARE_DEB="$3"
        USE_CONF=1
        USE_MANIFEST=0
    else
        CONF=""
        MANIFEST=""
        KERNEL_DEB="$1"
        FIRMWARE_DEB="$2"
        USE_CONF=0
        USE_MANIFEST=0
    fi
elif [[ $# -eq 2 ]]; then
    CONF=""
    MANIFEST=""
    KERNEL_DEB="$1"
    FIRMWARE_DEB="$2"
    USE_CONF=0
    USE_MANIFEST=0
else
    echo "Usage:"
    echo "  $0 <qcom-product.conf> <package-manifest.json> <kernel_package.deb> <firmware_package.deb>"
    echo "  $0 <qcom-product.conf> <kernel_package.deb> <firmware_package.deb>"
    echo "  $0 <kernel_package.deb> <firmware_package.deb>"
    exit 1
fi

[[ -f "$KERNEL_DEB" ]] || { echo "[ERROR] Kernel package not found: $KERNEL_DEB"; exit 1; }
[[ -f "$FIRMWARE_DEB" ]] || { echo "[ERROR] Firmware package not found: $FIRMWARE_DEB"; exit 1; }
if [[ "$USE_MANIFEST" -eq 1 && -n "$MANIFEST" ]]; then
    [[ -f "$MANIFEST" ]] || { echo "[ERROR] Manifest file not found: $MANIFEST"; exit 1; }
fi

WORKDIR=$(pwd)
MNT_DIR="$WORKDIR/mnt"
ROOTFS_DIR="$WORKDIR/rootfs"
ROOTFS_IMG="ubuntu.img"
mkdir -p "$MNT_DIR" "$ROOTFS_DIR"

declare -A CFG

# ==============================================================================
# Function: parse_configuration
#     Reads qcom-product.conf into CFG[] (Key: value or KEY=value).
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
#     Target: iot
#     Downloads/extracts the base image, mounts, and fills $ROOTFS_DIR/.
#     Distro-specific handling is done via an inner case.
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
if [[ "$USE_CONF" -eq 1 && -n "$CONF" ]]; then
    parse_configuration "$CONF"
    echo "[INFO] Using configuration from: $CONF"
else
    echo "[INFO] No config provided; using default configuration for backward compatibility."
    # Default mirror
    CFG["QCOM_TARGET_PLATFORM"]="iot"
    CFG["DISTRO"]="ubuntu"
    CFG["CODENAME"]="questing"
    CFG["ARCH"]="arm64"
    CFG["VARIANT"]="server"
    CFG["CHANNEL"]="daily-preinstalled"
    CFG["STREAM"]="current"
    CFG["FLAVOR"]="ubuntu-server"
fi

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
# Step 3.5: Add custom apt sources from manifest (if provided)
# ==============================================================================

# Ensure jq is installed before processing package-manifest.json
if ! command -v jq &> /dev/null; then
    echo "jq not found. Installing jq..."
    apt-get update -qq
    apt-get install -y -qq jq
fi

if [[ "$USE_MANIFEST" -eq 1 && -n "$MANIFEST" ]]; then
    echo "[INFO] Adding custom apt sources from manifest..."
    jq -c '.apt_sources[]?' "$MANIFEST" | while read -r row; do
        NAME=$(echo "$row" | jq -r '.name // "customrepo"')
        SRC_LINE=$(echo "$row" | jq -r '.source_line')
        echo "$SRC_LINE" >> "$ROOTFS_DIR/etc/apt/sources.list.d/${NAME}.list"
    done
fi

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
# Step 6: Parse Manifest (if provided) and prepare install lists
# ==============================================================================
APT_INSTALL_LIST=()
DEB_INSTALL_LIST=()

if [[ "$USE_MANIFEST" -eq 1 && -n "$MANIFEST" ]]; then
    echo "[INFO] Parsing package manifest: $MANIFEST"
    while IFS= read -r pkg; do
        name=$(echo "$pkg" | jq -r '.name')
        version=$(echo "$pkg" | jq -r '.version')
        source=$(echo "$pkg" | jq -r '.source')
        path=$(echo "$pkg" | jq -r '.path // empty')
        if [[ "$source" == "apt" ]]; then
            if [[ "$version" == "latest" ]]; then
                APT_INSTALL_LIST+=("$name")
            else
                APT_INSTALL_LIST+=("${name}=${version}")
            fi
        elif [[ "$source" == "local" ]]; then
            if [[ -n "$path" && -f "$path" ]]; then
                cp "$path" "$ROOTFS_DIR/"
                DEB_INSTALL_LIST+=("/$(basename "$path")")
            else
                echo "[WARNING] Local .deb path not found for $name: $path"
            fi
        fi
    done < <(jq -c '.packages[]' "$MANIFEST")
fi

# Prepare install script inside rootfs
cat <<EOF > "$ROOTFS_DIR/install_manifest_pkgs.sh"
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt update

echo "[CHROOT] Manifest APT packages to install:"
echo "    ${APT_INSTALL_LIST[@]}"

echo "[CHROOT] Manifest local .deb packages to install:"
echo "    ${DEB_INSTALL_LIST[@]}"

apt install -y ${APT_INSTALL_LIST[@]}
#if [ ${#DEB_INSTALL_LIST[@]} -gt 0 ]; then
#    dpkg -i ${DEB_INSTALL_LIST[@]}
#fi
EOF
chmod +x "$ROOTFS_DIR/install_manifest_pkgs.sh"

# ==============================================================================
# Step 7: Bind Mount System Directories for chroot
# ==============================================================================
echo "[INFO] Binding system directories..."
mount -o bind /proc "$ROOTFS_DIR/proc"
mount -o bind /sys "$ROOTFS_DIR/sys"
mount -o bind /dev "$ROOTFS_DIR/dev"
mount --bind /dev/pts "$ROOTFS_DIR/dev/pts"

# ==============================================================================
# Step 8: Enter chroot to Install Packages and Configure GRUB
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

# Get codename
CODENAME=\$(lsb_release -sc)

echo '[CHROOT] Capturing base package list...'
dpkg-query -W -f='\${Package} \${Version}\n' > /tmp/\${CODENAME}_base.manifest

echo '[CHROOT] Installing custom firmware and kernel...'
dpkg -i /$(basename "$FIRMWARE_DEB")
yes \"\" | dpkg -i /$(basename "$KERNEL_DEB")

echo '[CHROOT] Installing manifest packages (if any)...'
/install_manifest_pkgs.sh || true

echo '[CHROOT] Capturing post-install package list...'
dpkg-query -W -f='\${Package} \${Version}\n' > /tmp/\${CODENAME}_post.manifest

echo '[CHROOT] Sorting and computing package delta...'
sort /tmp/\${CODENAME}_base.manifest > /tmp/sorted_base.manifest
sort /tmp/\${CODENAME}_post.manifest > /tmp/sorted_post.manifest
DATE=\$(date +%Y-%m-%d)
comm -13 /tmp/sorted_base.manifest /tmp/sorted_post.manifest > /tmp/packages_\${DATE}.manifest

echo '[CHROOT] Cleaning up intermediate files...'
rm -f /tmp/\${CODENAME}_post.manifest /tmp/sorted_base.manifest /tmp/sorted_post.manifest

echo '[CHROOT] Base package list preserved as /tmp/\${CODENAME}_base.manifest'
echo '[CHROOT] Custom installed packages saved to /tmp/packages_\${DATE}.manifest'

echo '[CHROOT] Detecting installed kernel version...'
kernel_ver=\$(ls /boot/vmlinuz-* | sed 's|.*/vmlinuz-||' | sort -V | tail -n1)
crd_dtb_path=\"/lib/firmware/\$kernel_ver/device-tree/x1e80100-crd.dtb\"

echo '[CHROOT] Writing GRUB configuration...'
tee /boot/grub.cfg > /dev/null <<GRUBCFG
set timeout=5
set default=${CODENAME}_crd
menuentry \"Ubuntu ${CODENAME} IoT for X Elite CRD\" --id ${CODENAME}_crd {
    search --no-floppy --label system --set=root
    devicetree \$crd_dtb_path
    linux /boot/vmlinuz-\$kernel_ver earlycon console=ttyMSM0,115200n8 root=LABEL=system cma=128M rw clk_ignore_unused pd_ignore_unused efi=noruntime rootwait ignore_loglevel
    initrd /boot/initrd.img-\$kernel_ver
}
GRUBCFG

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
# Step 9: Unmount chroot environment
# ==============================================================================
echo "[INFO] Unmounting system directories..."
umount -l "$ROOTFS_DIR/dev/pts"
umount -l "$ROOTFS_DIR/dev"
umount -l "$ROOTFS_DIR/sys"
umount -l "$ROOTFS_DIR/proc"

# ==============================================================================
# Step 10: Create ext4 rootfs image and write contents
# ==============================================================================
echo "[INFO] Creating ext4 rootfs image: $ROOTFS_IMG (8GB)"
truncate -s 8G "$ROOTFS_IMG"
mkfs.ext4 -L system "$ROOTFS_IMG"

echo "[INFO] Copying rootfs contents into image..."
mount -o loop "$ROOTFS_IMG" "$MNT_DIR"
cp -rap "$ROOTFS_DIR/"* "$MNT_DIR/"

echo "[INFO] Writing static /etc/resolv.conf for runtime DNS resolution..."
rm -f "$MNT_DIR/etc/resolv.conf"
echo -e 'nameserver 1.1.1.1\nnameserver 8.8.8.8' > "$MNT_DIR/etc/resolv.conf"

umount -l "$MNT_DIR"

# ==============================================================================
# Step 11: Deploy package manifest
# ==============================================================================
echo "[INFO] Deploying base and custom package manifest files"
cp $ROOTFS_DIR/tmp/*.manifest .

# ==============================================================================
# Completion
# ==============================================================================
echo "[SUCCESS] Rootfs image created successfully: $ROOTFS_IMG"
