#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# ==============================================================================
# Script: patch-volatile-vars.sh
# ------------------------------------------------------------------------------
# Description:
#   Writes VolatileVars.bin (see gen-volatile-vars.py) into the root of an
#   EXISTING FAT32 ESP image, in place, using mtools (mcopy). Unlike
#   build-efi-esp.sh, this does not format the image or install GRUB, and it
#   does not require loop devices/mounting or root — mtools operates directly
#   on the image file. Intended for flows where a single efi.bin is built
#   once and shared across boards (see flash/gen-flash-dirs.sh), so only the
#   board(s) that need VolatileVars.bin get it patched into their own copy.
#
# Usage:
#   ./patch-volatile-vars.sh --efi <efi.bin> [--config <json>]
#
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EFI_IMG=""
VOLATILE_VARS_CONFIG=""

print_usage() {
    cat <<EOF
Usage:
  $0 --efi <efi.bin> [--config <json>] [-h|--help]

Notes:
  - <efi.bin> must already be a formatted FAT32 filesystem image; it is
    modified in place via mtools (no mount/loop device/root required).
  - --config forwards a JSON config to gen-volatile-vars.py to add/override
    entries on top of its built-in defaults (see gen-volatile-vars.py).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --efi)
            EFI_IMG="${2-}"; shift 2 ;;
        --config)
            VOLATILE_VARS_CONFIG="${2-}"; shift 2 ;;
        -h|--help)
            print_usage; exit 0 ;;
        *)
            echo "[ERROR] Unknown argument: $1"
            print_usage
            exit 1 ;;
    esac
done

if [[ -z "${EFI_IMG}" ]]; then
    echo "[ERROR] --efi is required"
    print_usage
    exit 1
fi
if [[ ! -f "${EFI_IMG}" ]]; then
    echo "[ERROR] EFI image not found: ${EFI_IMG}"
    exit 1
fi

command -v python3 >/dev/null 2>&1 || { echo "[ERROR] python3 is required"; exit 1; }

if ! command -v mcopy >/dev/null 2>&1; then
    echo "[INFO] mcopy (mtools) not found — attempting to install..."
    if [[ "${EUID}" -eq 0 ]]; then
        APT_GET=(apt-get)
    elif command -v sudo >/dev/null 2>&1; then
        APT_GET=(sudo apt-get)
    else
        echo "[ERROR] mcopy (mtools) is required and not installable without root/sudo"
        exit 1
    fi
    DEBIAN_FRONTEND=noninteractive "${APT_GET[@]}" update -y
    DEBIAN_FRONTEND=noninteractive "${APT_GET[@]}" install -y mtools
    command -v mcopy >/dev/null 2>&1 || { echo "[ERROR] mcopy still not found after install attempt"; exit 1; }
fi

TMP_VV="$(mktemp -p "$(dirname "${EFI_IMG}")" patchvv.XXXXXX.bin)"
cleanup() { rm -f "${TMP_VV}"; }
trap cleanup EXIT

GEN_VOLATILE_VARS_ARGS=(--out "${TMP_VV}")
if [[ -n "${VOLATILE_VARS_CONFIG}" ]]; then
    GEN_VOLATILE_VARS_ARGS+=(--config "${VOLATILE_VARS_CONFIG}")
fi
python3 "${SCRIPT_DIR}/gen-volatile-vars.py" "${GEN_VOLATILE_VARS_ARGS[@]}"

echo "[INFO] Writing VolatileVars.bin into ${EFI_IMG}..."
mcopy -o -i "${EFI_IMG}" "${TMP_VV}" "::VolatileVars.bin"

echo "[SUCCESS] Patched VolatileVars.bin into: ${EFI_IMG}"
