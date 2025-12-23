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
#   - Parses qcom-product.conf (if provided) or uses defaults to determine the base image.
#   - Runs target platform-specific image preprocessing to populate rootfs/.
#   - Injects custom kernel and firmware .deb packages.
#   - Installs user-specified packages from manifest (if provided).
#   - Dynamically deduces and generates base and custom package manifests
#   - Configures GRUB bootloader, hostname, DNS, and other system settings.
#   - Deploy package manifest output files
#   - Produces a flashable ext4 image (ubuntu.img).
#
# UPDATED (seed-based preprocessing):
#   - Instead of downloading/extracting an Ubuntu ISO and unsquashing minimal.squashfs,
#     preprocessing now uses a seed file (list of packages) + distro/codename from
#     qcom-product.conf to create the baseline rootfs via debootstrap.
#
# USAGE (named inputs):
#   ./build-ubuntu-rootfs.sh \
#     --product-conf qcom-product.conf \
#     --seed seed_file \
#     --kernel-package kernel.deb \
#     --firmware firmware.deb \
#     [--overlay package-manifest.json]
#
# ARGUMENTS:
#   --product-conf <qcom-product.conf>     Required. Product configuration file.
#   --seed <seed_file>                    Required. Seed file: one package per line (# comments allowed).
#   --kernel-package <kernel.deb>         Required. Custom kernel package.
#   --firmware <firmware.deb>             Required. Custom firmware package.
#   --overlay <package-manifest.json>      Optional. JSON manifest specifying extra packages/apt sources.
#
# OUTPUT:
#   ubuntu.img               Flashable ext4 rootfs image.
#
# REQUIREMENTS:
#   - Run as root (auto-elevates with sudo if needed).
#   - Host tools: debootstrap, wget, jq, losetup, mount, cp, chroot, mkfs.ext4, truncate, etc.
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
# Globals & Argument Parsing (named inputs)
# ==============================================================================
CONF=""
SEED=""
MANIFEST=""          # internal name retained (overlay JSON)
KERNEL_DEB=""
FIRMWARE_DEB=""
USE_CONF=0
USE_MANIFEST=0
TARGET=""

print_usage() {
    echo "Usage:"
    echo "  $0 --product-conf <qcom-product.conf> --seed <seed_file> --kernel-package <kernel.deb> --firmware <firmware.deb> [--overlay <package-manifest.json>]"
    echo
    echo "Arguments:"
    echo "  --product-conf   Required. qcom-product.conf"
    echo "  --seed           Required. Seed file (one package per line; supports # comments)"
    echo "  --kernel-package Required. Kernel .deb"
    echo "  --firmware       Required. Firmware .deb"
    echo "  --overlay        Optional. package-manifest.json (same schema as current manifest)"
}

# Parse named options
# NOTE: We intentionally keep parsing simple (no getopt dependency) for portability.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --product-conf)
            CONF="${2-}"; shift 2 ;;
        --seed)
            SEED="${2-}"; shift 2 ;;
        --kernel-package)
            KERNEL_DEB="${2-}"; shift 2 ;;
        --firmware)
            FIRMWARE_DEB="${2-}"; shift 2 ;;
        --overlay)
            MANIFEST="${2-}"; shift 2 ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Validate required args
if [[ -z "${CONF}" || -z "${SEED}" || -z "${KERNEL_DEB}" || -z "${FIRMWARE_DEB}" ]]; then
    echo "[ERROR] Missing required argument(s)."
    print_usage
    exit 1
fi

USE_CONF=1
USE_MANIFEST=0
if [[ -n "${MANIFEST}" ]]; then
    USE_MANIFEST=1
fi

[[ -f "$CONF" ]] || { echo "[ERROR] Config file not found: $CONF"; exit 1; }
[[ -f "$SEED" ]] || { echo "[ERROR] Seed file not found: $SEED"; exit 1; }
[[ -f "$KERNEL_DEB" ]] || { echo "[ERROR] Kernel package not found: $KERNEL_DEB"; exit 1; }
[[ -f "$FIRMWARE_DEB" ]] || { echo "[ERROR] Firmware package not found: $FIRMWARE_DEB"; exit 1; }
if [[ "$USE_MANIFEST" -eq 1 && -n "$MANIFEST" ]]; then
    [[ -f "$MANIFEST" ]] || { echo "[ERROR] Manifest/overlay file not found: $MANIFEST"; exit 1; }
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
# Function: _seed_to_debootstrap_include
#     Parses seed file into a comma-separated package list.
#     - Supports blank lines and # comments.
#     - Ensures required baseline packages exist for later stages (without changing later stages).
# ==============================================================================
_seed_to_debootstrap_include() {
    local seed_file="$1"
    local include_pkgs=()
    declare -A seen=()

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(echo "$line" | xargs)"
        [[ -z "$line" ]] && continue

        # Seed must be one package token per line
        if [[ "$line" =~ [[:space:]] ]]; then
            echo "[ERROR] Invalid seed entry (whitespace found). Use one package per line:"
            echo "        '$line'"
            exit 1
        fi

        if [[ -z "${seen[$line]+x}" ]]; then
            include_pkgs+=("$line")
            seen["$line"]=1
        fi
    done < "$seed_file"

    # These are REQUIRED for your existing later stages to run unchanged
    # (Step 8 uses lsb_release; apt/dpkg/user tools/systemctl expected present).
    local required_pkgs=(
        lsb-release
        ca-certificates
        sudo
        adduser
        passwd
        systemd-sysv
        apt
    )

    for p in "${required_pkgs[@]}"; do
        if [[ -z "${seen[$p]+x}" ]]; then
            include_pkgs+=("$p")
            seen["$p"]=1
        fi
    done

    # Output comma-separated list
    local out=""
    for p in "${include_pkgs[@]}"; do
        if [[ -z "$out" ]]; then
            out="$p"
        else
            out="${out},${p}"
        fi
    done
    echo "$out"
}

# ==============================================================================
# Function: image_preprocessing
#     Generic preprocessing: creates baseline rootfs via debootstrap + seed
#     (distro + platform agnostic; controlled via qcom-product.conf inputs).
#
#     Notes:
#       - Mirror/components can be controlled via qcom-product.conf:
#           APT_MIRROR=...
#           APT_COMPONENTS=main,universe
#       - For production, prefer setting APT_MIRROR in product-conf per distro.
# ==============================================================================
image_preprocessing() {
    echo "[INFO][preprocess] Preparing environment for debootstrap baseline rootfs..."

    # --- Ensure debootstrap is installed (silently) ---
    if ! command -v debootstrap >/dev/null 2>&1; then
        echo "[INFO][preprocess] 'debootstrap' not found. Installing debootstrap silently..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get -qq update >/dev/null 2>&1 || true
        apt-get -qq install -y debootstrap >/dev/null 2>&1 || {
            echo "[ERROR] Failed to install 'debootstrap'."
            exit 1
        }
    fi

    # NOTE: ARM64-only assumption: host is arm64 and target ARCH is arm64.
    if [[ "${ARCH}" != "arm64" ]]; then
        echo "[ERROR][preprocess] This commit assumes ARCH=arm64 only. Current ARCH=$ARCH"
        exit 1
    fi

    echo "[INFO][preprocess] Creating baseline rootfs via debootstrap using seed: $SEED"

    # Clean rootfs dir and recreate
    rm -rf "$ROOTFS_DIR"
    mkdir -p "$ROOTFS_DIR"

    # Generic defaults; recommend overriding via qcom-product.conf per distro.
    local MIRROR="${CFG[APT_MIRROR]:-http://ports.ubuntu.com/ubuntu-ports}"
    local COMPONENTS="${CFG[APT_COMPONENTS]:-main,universe}"

    local INCLUDE_LIST
    INCLUDE_LIST="$(_seed_to_debootstrap_include "$SEED")"

    echo "[INFO][preprocess] debootstrap parameters:"
    echo "  TARGET_PLATFORM=$TARGET_PLATFORM"
    echo "  DISTRO=$DISTRO"
    echo "  CODENAME=$CODENAME"
    echo "  ARCH=$ARCH"
    echo "  MIRROR=$MIRROR"
    echo "  COMPONENTS=$COMPONENTS"
    echo "  INCLUDE(from seed + required)=$INCLUDE_LIST"

    if ! debootstrap --arch="$ARCH" --variant=minbase --components="$COMPONENTS" --include="$INCLUDE_LIST" "$CODENAME" "$ROOTFS_DIR" "$MIRROR"; then
        echo "[ERROR][preprocess] debootstrap failed."
        exit 1
    fi

    # Ensure directories exist for later steps (so Step 3.5+ stays unchanged)
    mkdir -p "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev" "$ROOTFS_DIR/dev/pts"
    mkdir -p "$ROOTFS_DIR/etc/apt/sources.list.d"

    echo "[INFO][preprocess] Rootfs prepared at: $ROOTFS_DIR"
}

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
fi

TARGET_PLATFORM="${CFG[QCOM_TARGET_PLATFORM]:-iot}"
DISTRO="${CFG[DISTRO]:-ubuntu}"
CODENAME="${CFG[CODENAME]:-questing}"
ARCH="${CFG[ARCH]:-arm64}"
VARIANT="${CFG[VARIANT]:-server}"

echo "[INFO] Build Source:"
echo "  TARGET_PLATFORM=$TARGET_PLATFORM"
echo "  DISTRO=$DISTRO"
echo "  CODENAME=$CODENAME"
echo "  ARCH=$ARCH"
echo "  VARIANT=$VARIANT"

# ==============================================================================
# Step 2–3: Preprocess baseline rootfs to fill rootfs/
# ==============================================================================
image_preprocessing

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

adduser --disabled-password --gecos '' qcom
echo 'qcom:qcom' | chpasswd
usermod -aG sudo qcom

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

kernel_ver=$(basename "$KERNEL_DEB" \
  | sed 's|^linux-kernel-\(.*\)-arm64\.deb$|\1|' \
  | sed 's|-[0-9][0-9]*-[0-9][0-9]*$||')

echo '[CHROOT] Writing GRUB configuration for single DTB-agnostic entry...'
tee /boot/grub.cfg > /dev/null <<GRUBCFG
set timeout=5

menuentry \"Ubuntu ${CODENAME}\" {
    search --no-floppy --label system --set=root
    linux /boot/vmlinuz-\$kernel_ver earlycon console=ttyMSM0,115200n8 root=LABEL=system cma=128M rw clk_ignore_unused pd_ignore_unused efi=noruntime rootwait ignore_loglevel
    initrd /boot/initrd.img-\$kernel_ver
}
GRUBCFG
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
