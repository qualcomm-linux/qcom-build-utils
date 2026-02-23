#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# ==============================================================================
# Script: build-efi-esp.sh
# ------------------------------------------------------------------------------
# Description:
#   Creates a standalone EFI System Partition filesystem image (efi.bin)
#   for ARM64 platforms with configurable FAT sector size.
#
# Key design goals:
#   - Deterministic/reproducible: avoid `grub-install` and install-layout coupling.
#   - Self-contained bootloader: generate a standalone `BOOTAA64.EFI` that embeds
#     a tiny bootstrap config and required GRUB modules.
#   - Single source of truth for the real menu: rootfs `/boot/grub/grub.cfg`.
#
# Resulting ESP contents:
#   /EFI/BOOT/BOOTAA64.EFI   (standalone GRUB for ARM64 UEFI, removable path)
#
# Embedded bootstrap config behavior:
#   - Search root filesystem by label "system"
#   - Chainload rootfs GRUB config: ($root)/boot/grub/grub.cfg
#
# Usage:
#   ./build-efi-esp.sh [--sector-size <size>] [--esp-size-mb <mb>] [--no-install]
#                     [--root-label <label>] [--out <efi.bin>]
#
# Examples:
#   ./build-efi-esp.sh
#   ./build-efi-esp.sh --sector-size 4096
#   ./build-efi-esp.sh --no-install
#
# Output:
#   efi.bin  → write/flash to an ESP partition (FAT32)
#
# Author: Bjordis Collaku <bcollaku@qti.qualcomm.com>
# ==============================================================================

set -euo pipefail

# ==============================================================================
# Step 0  Auto-elevate if not run as root
# ==============================================================================
if [[ "${EUID}" -ne 0 ]]; then
    echo "[INFO] Re-running script as root using sudo..."
    exec sudo "$0" "$@"
fi

# ==============================================================================
# Step 1  Defaults
# ==============================================================================
OUT_IMG="efi.bin"
ESP_SIZE_MB=200
SECTOR_SIZE=512
ROOT_LABEL="system"
NO_INSTALL=0

WORKDIR="$(pwd)"
MNT_DIR="$(mktemp -d -p "${WORKDIR}" efiesp.mnt.XXXXXX)"
LOOP_DEV=""

cleanup() {
    set +e
    if mountpoint -q "${MNT_DIR}"; then
        umount -l "${MNT_DIR}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${LOOP_DEV}" ]]; then
        losetup -d "${LOOP_DEV}" >/dev/null 2>&1 || true
    fi
    rm -rf "${MNT_DIR}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

print_usage() {
    cat <<EOF
Usage:
  $0 [--sector-size <bytes>] [--esp-size-mb <mb>] [--root-label <label>]
     [--out <efi.bin>] [--no-install] [-h|--help]

Notes:
  - Produces a FAT32 filesystem image (no GPT inside the file).
  - Installs a standalone ARM64 GRUB as /EFI/BOOT/BOOTAA64.EFI using grub-mkstandalone.
  - At boot, GRUB searches for rootfs by LABEL and loads its /boot/grub/grub.cfg.

EOF
}

# ==============================================================================
# Step 2  Parse args (named, strict)
# ==============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sector-size)
            SECTOR_SIZE="${2-}"; shift 2 ;;
        --esp-size-mb)
            ESP_SIZE_MB="${2-}"; shift 2 ;;
        --root-label)
            ROOT_LABEL="${2-}"; shift 2 ;;
        --out)
            OUT_IMG="${2-}"; shift 2 ;;
        --no-install)
            NO_INSTALL=1; shift ;;
        -h|--help)
            print_usage; exit 0 ;;
        *)
            echo "[ERROR] Unknown argument: $1"
            print_usage
            exit 1 ;;
    esac
done

# ==============================================================================
# Step 3  Validate inputs
# ==============================================================================
if [[ -z "${SECTOR_SIZE}" || -z "${ESP_SIZE_MB}" || -z "${ROOT_LABEL}" || -z "${OUT_IMG}" ]]; then
    echo "[ERROR] One or more required values were empty."
    exit 1
fi

if ! [[ "${SECTOR_SIZE}" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] --sector-size must be an integer, got: ${SECTOR_SIZE}"
    exit 1
fi

case "${SECTOR_SIZE}" in
    512|1024|2048|4096) ;;
    *)
        echo "[ERROR] Unsupported sector size: ${SECTOR_SIZE}. Expected one of: 512,1024,2048,4096"
        exit 1 ;;
esac

if ! [[ "${ESP_SIZE_MB}" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] --esp-size-mb must be an integer, got: ${ESP_SIZE_MB}"
    exit 1
fi

# FAT32 sizing guidance for large sectors: keep cluster count in valid range.
# Empirically, 300MB works well for 4K sector ESPs on many firmwares/tools.
if [[ "${SECTOR_SIZE}" -eq 4096 && "${ESP_SIZE_MB}" -lt 300 ]]; then
    echo "[INFO] Sector size is 4096; bumping ESP size to 300MB for FAT32 compliance."
    ESP_SIZE_MB=300
fi

echo "[INFO] Output image: ${OUT_IMG}"
echo "[INFO] ESP size: ${ESP_SIZE_MB} MB"
echo "[INFO] FAT sector size: ${SECTOR_SIZE}"
echo "[INFO] Rootfs label: ${ROOT_LABEL}"

# ==============================================================================
# Step 4  Ensure required host tools exist (optionally install)
# ==============================================================================
need_cmd() {
    command -v "$1" >/dev/null 2>&1 || return 1
}

missing=()
for c in dd losetup mkfs.vfat mount umount; do
    need_cmd "${c}" || missing+=("${c}")
done

# GRUB tooling: we require arm64-efi platform modules + grub-mkstandalone
for c in grub-mkstandalone; do
    need_cmd "${c}" || missing+=("${c}")
done

if [[ "${#missing[@]}" -gt 0 ]]; then
    echo "[INFO] Missing commands: ${missing[*]}"
    if [[ "${NO_INSTALL}" -eq 1 ]]; then
        echo "[ERROR] --no-install specified and required tools are missing."
        exit 1
    fi

    echo "[INFO] Installing required packages (Debian/Ubuntu)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y grub-efi-arm64-bin grub2-common dosfstools util-linux
fi

# Verify that arm64-efi GRUB platform dir exists (common failure in containers)
# Typical locations:
#   /usr/lib/grub/arm64-efi
#   /usr/share/grub/arm64-efi  (less common)
GRUB_PLATFORM_DIR=""
if [[ -d /usr/lib/grub/arm64-efi ]]; then
    GRUB_PLATFORM_DIR="/usr/lib/grub/arm64-efi"
elif [[ -d /usr/share/grub/arm64-efi ]]; then
    GRUB_PLATFORM_DIR="/usr/share/grub/arm64-efi"
fi

if [[ -z "${GRUB_PLATFORM_DIR}" ]]; then
    echo "[ERROR] GRUB arm64-efi modules directory not found."
    echo "        Expected /usr/lib/grub/arm64-efi (or /usr/share/grub/arm64-efi)."
    echo "        In Docker, ensure you install grub-efi-arm64-bin for the target arch."
    exit 1
fi
echo "[INFO] GRUB platform dir: ${GRUB_PLATFORM_DIR}"

# ==============================================================================
# Step 5  Build standalone BOOTAA64.EFI (self-contained + embedded bootstrap)
# ==============================================================================
BOOTSTRAP_CFG="$(mktemp -p "${WORKDIR}" efiesp.bootstrap.XXXXXX.cfg)"
cat > "${BOOTSTRAP_CFG}" <<EOF
# Embedded bootstrap grub.cfg (inside BOOTAA64.EFI)
set default=0
set timeout=0

# Prefer label-based discovery for portability
search --no-floppy --label ${ROOT_LABEL} --set=root

if [ -e (\$root)/boot/grub/grub.cfg ]; then
  set prefix=(\$root)/boot/grub
  configfile (\$root)/boot/grub/grub.cfg
else
  echo 'ERROR: Rootfs found but no GRUB config at /boot/grub/grub.cfg'
  echo 'Dropping to GRUB shell.'
fi
EOF

# A conservative module set for: GPT partitioning + FAT/ext + search + configfile + linux boot.
# Add more (usb, nvme) if your firmware doesn't provide access to storage early enough.
GRUB_MODULES="all_video boot btrfs cat chain configfile echo efi_gop efifwsetup ext2 fat font gettext gfxmenu gfxterm gfxterm_background gzio halt help hfsplus iso9660 jpeg keystatus loadenv linux lsefi lsefimmap lsefisystab lsmmap luks lvm mdraid09 mdraid1x memdisk minicmd normal part_gpt part_msdos png probe reboot regexp search search_fs_uuid search_label sleep test true video"

STANDALONE_EFI="$(mktemp -p "${WORKDIR}" efiesp.BOOTAA64.XXXXXX.EFI)"
echo "[INFO] Generating standalone BOOTAA64.EFI with embedded config..."
grub-mkstandalone \
    -O arm64-efi \
    -o "${STANDALONE_EFI}" \
    --modules="${GRUB_MODULES}" \
    "boot/grub/grub.cfg=${BOOTSTRAP_CFG}"

rm -f "${BOOTSTRAP_CFG}"

# ==============================================================================
# Step 6  Create and format ESP image
# ==============================================================================
echo "[INFO] Creating ${ESP_SIZE_MB} MB ESP image..."
dd if=/dev/zero of="${OUT_IMG}" bs=1M count="${ESP_SIZE_MB}" status=progress

LOOP_DEV="$(losetup --show -fP "${OUT_IMG}")"
echo "[INFO] Loop device attached: ${LOOP_DEV}"

echo "[INFO] Formatting as FAT32 with sector size ${SECTOR_SIZE}..."
mkfs.vfat -F 32 -S "${SECTOR_SIZE}" "${LOOP_DEV}" >/dev/null

mount "${LOOP_DEV}" "${MNT_DIR}"

# ==============================================================================
# Step 7  Populate ESP (UEFI removable path)
# ==============================================================================
mkdir -p "${MNT_DIR}/EFI/BOOT"
install -m 0644 "${STANDALONE_EFI}" "${MNT_DIR}/EFI/BOOT/BOOTAA64.EFI"
rm -f "${STANDALONE_EFI}"

sync
umount -l "${MNT_DIR}"
losetup -d "${LOOP_DEV}"
LOOP_DEV=""

echo "[SUCCESS] EFI System Partition image created: ${OUT_IMG}"
echo "[INFO] Contains: /EFI/BOOT/BOOTAA64.EFI (standalone GRUB + embedded bootstrap)."
echo "[INFO] Ensure rootfs filesystem label is '${ROOT_LABEL}' and it provides /boot/grub/grub.cfg."
