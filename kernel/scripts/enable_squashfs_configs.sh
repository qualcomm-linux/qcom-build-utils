#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# ===================================================
# enable_squashfs_configs.sh
#
# Adds SQUASHFS compression-related options to arch/arm64/configs/defconfig
# and commits the change. Required for Ubuntu compatibility with rootfs images using SQUASHFS and multiple compression formats.
#
# Usage:
#   ./enable_squashfs_configs.sh /path/to/qcom-next
#
# Author: Bjordis Collaku <bcollaku@qti.qualcomm.com>
# ===================================================

set -euo pipefail

# Check for required argument
if [ $# -ne 1 ]; then
  echo "Usage: $0 /path/to/qcom-next"
  exit 1
fi

KERNEL_SRC=$(realpath "$1")
DEFCONFIG_REL="arch/arm64/configs/defconfig"
DEFCONFIG_PATH="$KERNEL_SRC/$DEFCONFIG_REL"

# Verify path
if [ ! -f "$DEFCONFIG_PATH" ]; then
  echo "Error: defconfig not found at $DEFCONFIG_PATH"
  exit 1
fi

echo "[INFO] Kernel source: $KERNEL_SRC"
echo "[INFO] Updating defconfig: $DEFCONFIG_REL"

# Required SQUASHFS-related configs
REQUIRED_CONFIGS=(
  CONFIG_SQUASHFS
  CONFIG_SQUASHFS_XZ
  CONFIG_SQUASHFS_LZO
  CONFIG_SQUASHFS_XATTR
  CONFIG_SQUASHFS_ZLIB
  CONFIG_SQUASHFS_LZ4
)

MODIFIED=0

# Append comment block once
if ! grep -q "Added for Ubuntu SQUASHFS compatibility" "$DEFCONFIG_PATH"; then
  echo -e "\n# Added for Ubuntu SQUASHFS compatibility" >> "$DEFCONFIG_PATH"
  MODIFIED=1
fi

# Append missing configs
for cfg in "${REQUIRED_CONFIGS[@]}"; do
  if ! grep -qE "^($cfg=|# $cfg is not set)" "$DEFCONFIG_PATH"; then
    echo "$cfg=y" >> "$DEFCONFIG_PATH"
    echo "  -> Added $cfg=y"
    MODIFIED=1
  else
    echo "  -> $cfg already present"
  fi
done

# Commit if any changes were made
if [ "$MODIFIED" -eq 1 ]; then
  echo "[INFO] Changes detected — committing..."
  git -C "$KERNEL_SRC" add "$DEFCONFIG_REL"
  git -C "$KERNEL_SRC" commit -m "arm64: defconfig: Enable SQUASHFS compression options for Ubuntu compatibility

Adds support for multiple SQUASHFS compression algorithms required by
Ubuntu-based root filesystem images.

Enabled:
- CONFIG_SQUASHFS
- CONFIG_SQUASHFS_XZ
- CONFIG_SQUASHFS_LZO
- CONFIG_SQUASHFS_XATTR
- CONFIG_SQUASHFS_ZLIB
- CONFIG_SQUASHFS_LZ4"
  echo "[INFO] Commit completed."
else
  echo "[INFO] No changes needed — nothing to commit."
fi
