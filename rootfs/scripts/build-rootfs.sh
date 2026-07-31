#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# ==============================================================================
# Script: build-rootfs.sh
# ------------------------------------------------------------------------------
# DESCRIPTION:
#   This script creates a bootable Linux root filesystem image for ARM64
#   platforms (e.g., Qualcomm IoT/Compute/Server reference boards).
#
#   - Supports Qualcomm product configuration file (.conf) for build parameters.
#   - Builds a deterministic baseline rootfs using debootstrap from:
#       * qcom-product.conf for DISTRO/CODENAME/ARCH (and optional apt settings)
#       * a seed file containing one package per line (# comments allowed)
#   - Supports JSON package manifest for additional package installation
#     (via apt or local .deb) inside the rootfs.
#   - Supports injecting custom apt sources from the package manifest.
#   - Optionally injects custom kernel and firmware .deb packages.
#   - Supports installing kernel packages via APT through the --overlay manifest
#     (source: apt); update-grub runs after all installs regardless of kernel path.
#   - Supports installing local .deb packages (--local-debs) with full dependency resolution
#     via a temporary local APT repository built inside the rootfs.
#   - Installs user-specified packages from seed and/or overlay manifest.
#   - Dynamically deduces and generates base and custom package manifests.
#   - Configures GRUB bootloader, hostname, DNS, and other system settings.
#   - Produces a flashable ext4 image (rootfs.img).
#
# USAGE (named inputs):
#   ./build-rootfs.sh \
#     --product-conf qcom-product.conf \
#     --seed seed_file \
#     [--kernel-package kernel.deb] \
#     [--firmware firmware.deb] \
#     [--overlay package-manifest.json] \
#     [--variant desktop] \
#     [--local-debs pkg-a.deb] \
#     [--local-debs debs/]
#
# ARGUMENTS:
#   --product-conf <qcom-product.conf>     Required. Product configuration file.
#   --seed <seed_file>                     Required. Seed file: one package per line (# comments allowed).
#   --kernel-package <kernel.deb>          Optional. Custom kernel package.
#   --firmware <firmware.deb>              Optional. Custom firmware package.
#   --overlay <package-manifest.json>      Optional. JSON manifest specifying extra packages/apt sources.
#   --variant <variant_name>               Optional. System variant (default: desktop).
#   --local-debs <path>                    Optional. A .deb file OR a directory of .deb files to install
#                                          via a local APT repo (repeatable). May be specified multiple
#                                          times. Inter-package dependencies are resolved automatically
#                                          via a temporary local APT repository built inside the rootfs.
#                                          Installed after manifest packages (--overlay).
#                                          Examples:
#                                            --local-debs mypkg.deb
#                                            --local-debs debs/
#
# OUTPUT:
#   rootfs.img                             Flashable ext4 rootfs image.
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
VARIANT_INPUT=""     # New variable to hold the variant argument
LOCAL_DEBS=()        # Array of local .deb file paths (--local-debs, repeatable)
USE_CONF=0
USE_MANIFEST=0
TARGET=""

print_usage() {
    echo "Usage:"
    echo "  $0 --product-conf <qcom-product.conf> --seed <seed_file> [--kernel-package <kernel.deb>] [--firmware <firmware.deb>] [--overlay <package-manifest.json>] [--variant <variant>] [--local-debs <pkg.deb>] ..."
    echo
    echo "Arguments:"
    echo "  --product-conf   Required. qcom-product.conf"
    echo "  --seed           Required. Seed file (one package per line; supports # comments)"
    echo "  --kernel-package Optional. Kernel .deb"
    echo "  --firmware       Optional. Firmware .deb"
    echo "  --overlay        Optional. package-manifest.json (same schema as current manifest)"
    echo "  --variant        Optional. System variant (default: desktop)"
    echo "  --local-debs     Optional. A .deb file OR a directory of .deb files to install via a"
    echo "                   local APT repo (repeatable). Specify once per path. Dependencies"
    echo "                   between packages are resolved automatically. Installed after manifest."
    echo "                   Examples: --local-debs mypkg.deb   --local-debs debs/"
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
        --variant)
            VARIANT_INPUT="${2-}"; shift 2 ;;
        --local-debs)
            if [[ -n "${2-}" ]]; then LOCAL_DEBS+=("${2-}"); fi; shift 2 ;;
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
if [[ -z "${CONF}" || -z "${SEED}" ]]; then
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
if [[ -n "$KERNEL_DEB" ]]; then
    [[ -f "$KERNEL_DEB" ]] || { echo "[ERROR] Kernel package not found: $KERNEL_DEB"; exit 1; }
fi
if [[ -n "$FIRMWARE_DEB" ]]; then
    [[ -f "$FIRMWARE_DEB" ]] || { echo "[ERROR] Firmware package not found: $FIRMWARE_DEB"; exit 1; }
fi
if [[ "$USE_MANIFEST" -eq 1 && -n "$MANIFEST" ]]; then
    [[ -f "$MANIFEST" ]] || { echo "[ERROR] Manifest/overlay file not found: $MANIFEST"; exit 1; }
fi
for _deb in "${LOCAL_DEBS[@]}"; do
    if [[ -d "$_deb" ]]; then
        : # directory — may contain zero or more .deb files; handled gracefully at copy time
    elif [[ -f "$_deb" ]]; then
        : # valid .deb file path
    else
        echo "[ERROR] --local-debs path not found (not a file or directory): $_deb"
        exit 1
    fi
done

WORKDIR=$(pwd)
MNT_DIR="$WORKDIR/mnt"
ROOTFS_DIR="$WORKDIR/rootfs_work"
ROOTFS_IMG="rootfs.img"
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
        grub-common
        grub2-common
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


    # Update debootstrap for resolute distro, latest tag: 1.0.142
    if [[ "${CODENAME}" = "resolute" ]]; then
        echo "[INFO][preprocess] Updating debootstrap to support resolute distro (v1.0.142)..."
        DEBOOTSTRAP_TMP=$(mktemp -d)
        git clone --branch 1.0.142 --depth 1 \
            https://salsa.debian.org/installer-team/debootstrap.git \
            "$DEBOOTSTRAP_TMP/debootstrap" || {
            echo "[ERROR][preprocess] Failed to clone debootstrap repository."
            rm -rf "$DEBOOTSTRAP_TMP"
            exit 1
        }
        (cd "$DEBOOTSTRAP_TMP/debootstrap" && make install) || {
            echo "[ERROR][preprocess] Failed to install debootstrap."
            rm -rf "$DEBOOTSTRAP_TMP"
            exit 1
        }
        rm -rf "$DEBOOTSTRAP_TMP"
        echo "[INFO][preprocess] debootstrap version: $(debootstrap --version)"
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
    # VARIANT Default will be handled below
fi

TARGET_PLATFORM="${CFG[QCOM_TARGET_PLATFORM]:-iot}"
DISTRO="${CFG[DISTRO]:-ubuntu}"
CODENAME="${CFG[CODENAME]:-questing}"
ARCH="${CFG[ARCH]:-arm64}"

# Changed: VARIANT is now sourced from CLI arg, defaulting to 'desktop'
VARIANT="${VARIANT_INPUT:-desktop}"

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

    # Create keyrings directory if it doesn't exist
    mkdir -p "$ROOTFS_DIR/etc/apt/keyrings"

    # Check if keyrings directory exists alongside the manifest
    MANIFEST_DIR=$(dirname "$MANIFEST")
    KEYRINGS_DIR="$MANIFEST_DIR/keyrings"

    if [[ -d "$KEYRINGS_DIR" ]]; then
        echo "[INFO] Copying keyring files from $KEYRINGS_DIR..."
        cp -v "$KEYRINGS_DIR"/*.asc "$ROOTFS_DIR/etc/apt/keyrings/" 2>/dev/null || true
    fi

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
if [[ -n "$KERNEL_DEB" ]]; then
    cp "$KERNEL_DEB" "$ROOTFS_DIR/"
fi
if [[ -n "$FIRMWARE_DEB" ]]; then
    cp "$FIRMWARE_DEB" "$ROOTFS_DIR/"
fi

echo "[INFO] Replacing /etc/resolv.conf with host copy for apt inside chroot..."
rm -f "$ROOTFS_DIR/etc/resolv.conf"
cp -L /etc/resolv.conf "$ROOTFS_DIR/etc/resolv.conf"

# ==============================================================================
# Step 5: Set Hostname and /etc/hosts
# ==============================================================================
echo "[INFO] Configuring hostname and /etc/hosts..."
echo "qcom" > "$ROOTFS_DIR/etc/hostname"

cat <<EOF > "$ROOTFS_DIR/etc/hosts"
127.0.0.1   localhost
127.0.1.1   qcom
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
# Step 6.5: Copy local .deb packages into rootfs (if provided)
# ==============================================================================
if [[ ${#LOCAL_DEBS[@]} -gt 0 ]]; then
    echo "[INFO] Copying local .deb packages into rootfs for local APT repository..."
    mkdir -p "$ROOTFS_DIR/opt/local-debs"
    for _deb in "${LOCAL_DEBS[@]}"; do
        if [[ -d "$_deb" ]]; then
            echo "[INFO]   -> directory: $_deb"
            for _f in "$_deb"/*.deb; do
                [[ -f "$_f" ]] || continue   # skip if glob matched nothing (empty dir)
                echo "[INFO]      $(basename "$_f")"
                cp "$_f" "$ROOTFS_DIR/opt/local-debs/"
            done
        else
            echo "[INFO]   -> $(basename "$_deb")"
            cp "$_deb" "$ROOTFS_DIR/opt/local-debs/"
        fi
    done
fi

# ==============================================================================
# Step 7: Bind Mount System Directories for chroot
# ==============================================================================
echo "[INFO] Binding system directories..."
mount -o bind /proc "$ROOTFS_DIR/proc"
mount -o bind /sys "$ROOTFS_DIR/sys"
mount -o bind /dev "$ROOTFS_DIR/dev"
mount --bind /dev/pts "$ROOTFS_DIR/dev/pts"

# ==============================================================================
# Step 7.5: Configure GRUB defaults
# ==============================================================================
echo "[INFO] Configuring /etc/default/grub..."

# Ensure target directories exist before writing configuration
mkdir -p "$ROOTFS_DIR/boot/grub"
mkdir -p "$ROOTFS_DIR/etc/default"

# Write GRUB defaults using quoted heredoc to prevent host-side expansion
cat <<'EOF' > "$ROOTFS_DIR/etc/default/grub"
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`

# --- DUAL OUTPUT CONFIGURATION ---
# "serial"  -> Outputs menu to the serial port
# "console" -> Outputs menu to the attached display (HDMI/DP) in text mode
GRUB_TERMINAL="serial console"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"

# Kernel parameters applied to BOTH Normal and Recovery boot modes
# (Critical hardware settings: console, rootfs, clocks, EFI)
GRUB_CMDLINE_LINUX="earlycon console=ttyMSM0,115200n8 root=LABEL=system cma=128M net.ifnames=0 rw clk_ignore_unused pd_ignore_unused rootwait ignore_loglevel"

# Kernel parameters applied ONLY to Normal boot mode
# (UX settings: quiet, splash, etc. - Left empty for verbose output)
GRUB_CMDLINE_LINUX_DEFAULT=""

# Disable UUIDs to support generic filesystem images
GRUB_DISABLE_LINUX_UUID=true
EOF

# ==============================================================================
# Step 8: Enter chroot to Install Packages and Configure GRUB
# ==============================================================================

CMD_FW_INSTALL=""
if [[ -n "$FIRMWARE_DEB" ]]; then
    CMD_FW_INSTALL="dpkg -i /$(basename "$FIRMWARE_DEB")"
else
    CMD_FW_INSTALL="echo '[CHROOT] Skipping firmware installation.'"
fi

CMD_KERNEL_INSTALL=""
if [[ -n "$KERNEL_DEB" ]]; then
    CMD_KERNEL_INSTALL="yes \"\" | dpkg -i /$(basename "$KERNEL_DEB")"
else
    CMD_KERNEL_INSTALL="echo '[CHROOT] Skipping kernel installation (no kernel package provided).'"
fi

echo "[INFO] Entering chroot to install packages and configure GRUB..."
env DISTRO="$DISTRO" CODENAME="$CODENAME" VARIANT="$VARIANT" \
    chroot "$ROOTFS_DIR" /bin/bash -c "
set -e

echo '[CHROOT] Updating APT and installing networking tools...'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  network-manager \
  wpasupplicant \
  iw \
  net-tools

# --- Desktop variant handling (right after networking tools) ---
# If VARIANT=desktop:
#   - Debian  -> install gnome-core
#   - Ubuntu  -> install ubuntu-desktop-minimal
echo '[CHROOT] Evaluating desktop variant install...'
variant_lc=\$(echo \"\${VARIANT}\" | tr '[:upper:]' '[:lower:]')
distro_lc=\$(echo \"\${DISTRO}\" | tr '[:upper:]' '[:lower:]')

if [ \"\${variant_lc}\" = \"desktop\" ]; then
  echo \"[CHROOT] Desktop variant requested for distro '\${DISTRO}'.\"
  apt-get update
  if [ \"\${distro_lc}\" = \"debian\" ]; then
    echo '[CHROOT] Installing gnome-core (Debian)...'
    apt-get install -y gnome-core
  elif [ \"\${distro_lc}\" = \"ubuntu\" ]; then
    echo '[CHROOT] Installing ubuntu-desktop-minimal (Ubuntu)...'
    apt-get install -y ubuntu-desktop-minimal
  else
    echo \"[CHROOT][WARN] Unknown distro '\${DISTRO}' for desktop variant; skipping desktop meta-package.\"
  fi
fi
# --- End desktop variant handling ---

echo '[CHROOT] Disabling unnecessary services...'
ln -sf /dev/null /etc/systemd/system/systemd-networkd-wait-online.service
ln -sf /dev/null /etc/systemd/system/dev-disk-by\\\\x2dlabel-UEFI.device

echo '[CHROOT] Capturing base package list...'
dpkg-query -W -f='\${Package} \${Version}\n' > /tmp/\${CODENAME}_base.manifest

echo '[CHROOT] Installing custom firmware and kernel...'
$CMD_FW_INSTALL
$CMD_KERNEL_INSTALL

adduser --disabled-password --gecos '' qcom
echo 'qcom:qcom' | chpasswd
usermod -aG sudo qcom

echo '[CHROOT] Installing manifest packages (if any)...'
/install_manifest_pkgs.sh || true

echo '[CHROOT] Installing local .deb packages via local APT repository (if any)...'
if ls /opt/local-debs/*.deb >/dev/null 2>&1; then
    echo '[CHROOT] Setting up local .deb APT repository...'
    apt-get install -y --no-install-recommends dpkg-dev
    cd /opt/local-debs
    dpkg-scanpackages . /dev/null > Packages
    cd /
    echo 'deb [trusted=yes] file:///opt/local-debs ./' > /etc/apt/sources.list.d/local-debs.list
    apt-get update
    LOCAL_PKG_NAMES=\$(for deb in /opt/local-debs/*.deb; do dpkg-deb --field \"\$deb\" Package; done | tr '\n' ' ')
    echo \"[CHROOT] Installing local packages: \$LOCAL_PKG_NAMES\"
    apt-get install -y \$LOCAL_PKG_NAMES
    echo '[CHROOT] Local .deb packages installed successfully.'
else
    echo '[CHROOT] No local .deb packages found; skipping.'
fi

# ==============================================================================
# Run update-grub after ALL installs (firmware, kernel via dpkg or apt, manifest,
# local-debs). This ensures GRUB sees whichever kernel was installed last,
# regardless of the delivery path.
# The zz-update-grub hook skips update-grub in a chroot because systemd is not
# running (/run/systemd/system absent), so we call it explicitly here.
# ==============================================================================
echo '[CHROOT] Creating /boot/efi directory for EFI System Partition...'
mkdir -p /boot/efi

echo '[CHROOT] Configuring /etc/fstab with EFI partition entry...'
cat <<'FSTAB_EOF' >> /etc/fstab
LABEL=system-boot	/boot/efi	vfat	defaults	0	1
FSTAB_EOF

echo '[CHROOT] Running update-grub after all package installs...'
update-grub

# ==============================================================================
# GRUB Configuration Cleanup & Standardization
# ==============================================================================

# 1. Enforce Generic Partition Search
# Replace host-detected UUIDs with stable Label searching to ensure
# the image boots on any storage medium.
sed -i 's/search --no-floppy --fs-uuid --set=root .*/search --no-floppy --label system --set=root/g' /boot/grub/grub.cfg

# 2. Clean Kernel Command Line
# Remove the host-detected root device (e.g., root=/dev/nvme0n1p1) to prevent
# conflicts with our 'root=LABEL=system' argument.
sed -i 's/root=\/dev\/[^ ]* //g' /boot/grub/grub.cfg

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
# Step 9.5: Remove build-only apt sources and caches from final image
#   - build-only sources declared in the overlay manifest ("build-only": true)
#   - local .deb repo created for --local-debs
#   - apt indices and downloads cached during the build
# ==============================================================================
if [[ "$USE_MANIFEST" -eq 1 && -n "$MANIFEST" ]]; then
    jq -c '.apt_sources[]? | select(."build-only" == true)' "$MANIFEST" | while read -r row; do
        NAME=$(echo "$row" | jq -r '.name // "customrepo"')
        SOURCE_LIST="$ROOTFS_DIR/etc/apt/sources.list.d/${NAME}.list"
        if [[ -f "$SOURCE_LIST" ]]; then
            rm -f "$SOURCE_LIST"
            echo "[INFO] Removed build-only apt source from final image: ${NAME}"
        fi
    done
fi

if [[ -f "$ROOTFS_DIR/etc/apt/sources.list.d/local-debs.list" ]]; then
    rm -f  "$ROOTFS_DIR/etc/apt/sources.list.d/local-debs.list"
    rm -rf "$ROOTFS_DIR/opt/local-debs"
    echo "[INFO] Removed local-debs apt repo from final image"
fi

rm -rf "$ROOTFS_DIR/var/lib/apt/lists/"*
rm -f  "$ROOTFS_DIR/var/cache/apt/archives/"*.deb

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

mkdir -p $MNT_DIR/etc/netplan/
cat <<EOF > "$MNT_DIR/etc/netplan/01-network-manager-all.yaml"
network:
    version: 2
    renderer: NetworkManager
EOF

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
