#!/bin/bash
# ==============================================================================
# Script: build-efi-esp.sh
# ------------------------------------------------------------------------------
# Description:
#   Creates a standalone EFI System Partition image (efiesp.bin) for ARM64
#   platforms (e.g. Snapdragon X Elite CRD).
#
#   Workflow:
#     1. **Auto‑elevate** – re‑executes itself with `sudo` if not already root.
#     2. **Install tooling** – `grub-efi-arm64-bin`, `grub2-common`, `dosfstools`.
#     3. **Allocate** a 200 MB blank file and format it FAT32.
#     4. **Loop‑attach** the image and install GRUB for the arm64‑efi target
#        in *removable* mode (no NVRAM writes).
#     5. **Seed** a minimal `grub.cfg` that chain‑loads the main GRUB on
#        the rootfs partition (assumed GPT 13).
#     6. **Cleanup** – unmount, detach loop device, and report success.
#
# Usage:
#   ./build-efi-esp.sh
#
# Output:
#   efiesp.bin  → flash to /dev/nvme0n1p12 (or appropriate ESP partition)
# ==============================================================================

set -euo pipefail

# ==============================================================================
# Step 0  Auto‑elevate if not run as root
# ==============================================================================
if [[ "$EUID" -ne 0 ]]; then
    echo "[INFO] Re‑running script as root using sudo…"
    exec sudo "$0" "$@"
fi

# ==============================================================================
# Step 1  Configuration
# ==============================================================================
ESP_IMG="efiesp.bin"
ESP_SIZE_MB=200
MNT_DIR="mnt"

# ==============================================================================
# Step 2  Install Required Packages
# ==============================================================================
echo "[INFO] Installing required packages…"
apt-get update -y
apt-get install -y grub2-common grub-efi-arm64-bin dosfstools

# ==============================================================================
# Step 3  Create and Format ESP Image
# ==============================================================================
echo "[INFO] Creating ${ESP_SIZE_MB} MB EFI System Partition image: ${ESP_IMG}"
dd if=/dev/zero of="${ESP_IMG}" bs=1M count="${ESP_SIZE_MB}" status=progress

LOOP_DEV=$(losetup --show -fP "${ESP_IMG}")
echo "[INFO] Loop device attached: ${LOOP_DEV}"

echo "[INFO] Formatting as FAT32…"
mkfs.vfat -F 32 "${LOOP_DEV}"

# ==============================================================================
# Step 4  Install GRUB to ESP Image
# ==============================================================================
mkdir -p "${MNT_DIR}"
mount "${LOOP_DEV}" "${MNT_DIR}"
mkdir -p "${MNT_DIR}/boot"

echo "[INFO] Installing GRUB bootloader (arm64‑efi)…"
grub-install \
    --target=arm64-efi \
    --efi-directory="${MNT_DIR}" \
    --boot-directory="${MNT_DIR}/boot" \
    --removable \
    --no-nvram

# ==============================================================================
# Step 5  Write Bootstrap grub.cfg
# ==============================================================================
echo "[INFO] Writing bootstrap grub.cfg…"
cat > "${MNT_DIR}/boot/grub/grub.cfg" <<EOF
search --no-floppy --label system --set=root
set prefix=(\$root)/boot/grub
configfile /boot/grub.cfg
EOF

# ==============================================================================
# Step 6  Cleanup
# ==============================================================================
umount -l "${MNT_DIR}"
losetup -d "${LOOP_DEV}"
rm -rf "${MNT_DIR}"

echo "[SUCCESS] EFI System Partition image created: ${ESP_IMG}"

