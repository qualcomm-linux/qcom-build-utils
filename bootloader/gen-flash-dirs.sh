#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# ==============================================================================
# Script: gen-flash-dirs.sh
# ------------------------------------------------------------------------------
# Description:
#   Generates per-board flash directories from a boards JSON array.
#   Each board entry specifies its own boot binary archive, CDT archive,
#   and qcom-ptool platform. All boards share the same system image
#   (rootfs.img, efi.bin, dtb.bin).
#
# Usage:
#   gen-flash-dirs.sh \
#     --boards-json    '<json-array>'   \
#     --ptool-dir      <path/to/qcom-ptool>  \
#     --boot-bins-dir  <path/to/boot_bins>   \
#     --system-images  <path/to/images-dir>  \
#     --output-dir     <path/to/output>      \
#     [--contents-xml-in <path/to/contents.xml.in>]
#
# boards-json format (array of objects):
#   [
#     {
#       "name":               "qcs6490-rb3gen2-vision-kit",
#       "boot_binaries_url":  "https://...",
#       "qcom_ptool_platform":"qcs6490-rb3gen2",
#       "cdt_binaries_url":   "https://...",   (optional)
#       "cdt_filename":       "cdt_vision_kit.bin"  (optional)
#     },
#     ...
#   ]
#
# Outputs (inside --output-dir):
#   flash_<board-name>_<storage>/
#     rawprogram*.xml, patch*.xml, gpt_*.bin, zeros_*.bin  (from ptool)
#     *.elf, *.mbn, *.melf, *.fv, *.bin, prog_*, boot.img  (from boot bins)
#     cdt.bin                                               (from CDT zip, if set)
#     efi.bin, rootfs.img, dtb.bin, *.manifest              (shared system images)
#   contents.xml                                            (top-level, from gen_contents.py)
#
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Defaults
# ------------------------------------------------------------------------------
BOARDS_JSON=""
PTOOL_DIR=""
BOOT_BINS_DIR=""
SYSTEM_IMAGES_DIR=""
OUTPUT_DIR=""
CONTENTS_XML_IN=""

print_usage() {
    cat <<EOF
Usage:
  $0 --boards-json '<json>' --ptool-dir <dir> --boot-bins-dir <dir> \
     --system-images <dir> --output-dir <dir> [--contents-xml-in <file>]
EOF
}

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --boards-json)      BOARDS_JSON="$2";      shift 2 ;;
        --ptool-dir)        PTOOL_DIR="$2";         shift 2 ;;
        --boot-bins-dir)    BOOT_BINS_DIR="$2";     shift 2 ;;
        --system-images)    SYSTEM_IMAGES_DIR="$2"; shift 2 ;;
        --output-dir)       OUTPUT_DIR="$2";        shift 2 ;;
        --contents-xml-in)  CONTENTS_XML_IN="$2";   shift 2 ;;
        -h|--help)          print_usage; exit 0 ;;
        *) echo "[ERROR] Unknown argument: $1"; print_usage; exit 1 ;;
    esac
done

# ------------------------------------------------------------------------------
# Validate required args
# ------------------------------------------------------------------------------
for var in BOARDS_JSON PTOOL_DIR BOOT_BINS_DIR SYSTEM_IMAGES_DIR OUTPUT_DIR; do
    if [[ -z "${!var}" ]]; then
        echo "[ERROR] --$(echo "$var" | tr '[:upper:]_' '[:lower:]-') is required"
        print_usage
        exit 1
    fi
done

if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 is required"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "[ERROR] jq is required"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# ------------------------------------------------------------------------------
# Helper: remove dangerous ptool-generated wipe files from a flash dir
# ------------------------------------------------------------------------------
cleanup_flash_dir() {
    local dir="$1"
    rm -vf "${dir}"/rawprogram*_BLANK_GPT.xml
    rm -vf "${dir}"/rawprogram*_WIPE_PARTITIONS.xml
    rm -vf "${dir}"/wipe_rawprogram*.xml
}

# ------------------------------------------------------------------------------
# Helper: copy boot binary files (allowlist) from a source dir into a flash dir
# Excludes partition/GPT/wipe files that come from ptool instead.
# ------------------------------------------------------------------------------
copy_boot_bins() {
    local src="$1"
    local dst="$2"
    find "$src" -maxdepth 1 \( \
        -name 'LICENSE' \
        -o -name 'Qualcomm-Technologies-Inc.-Proprietary' \
        -o -name 'prog_*' \
        -o -name 'boot.img' \
        -o -name '*.bin' \
        -o -name '*.elf' \
        -o -name '*.melf' \
        -o -name '*.fv' \
        -o -name '*.mbn' \
        -o -name '*.lzma' \
        -o -name '*.xz' \
    \) \
    ! -name 'gpt_*' \
    ! -name 'zeros_*' \
    -exec cp --preserve=mode,timestamps -v '{}' "$dst/" \;
}

# ------------------------------------------------------------------------------
# Helper: copy shared system images into a flash dir
# ------------------------------------------------------------------------------
copy_system_images() {
    local dst="$1"
    for f in rootfs.img efi.bin dtb.bin; do
        if [[ -f "${SYSTEM_IMAGES_DIR}/${f}" ]]; then
            cp --preserve=mode,timestamps -v "${SYSTEM_IMAGES_DIR}/${f}" "$dst/"
        else
            echo "[WARN] System image not found: ${SYSTEM_IMAGES_DIR}/${f}"
        fi
    done
    # copy all manifest files
    for f in "${SYSTEM_IMAGES_DIR}"/*.manifest; do
        [[ -f "$f" ]] && cp --preserve=mode,timestamps -v "$f" "$dst/"
    done
}

# ------------------------------------------------------------------------------
# Track which ptool platforms have already had partition tables generated
# so boards sharing the same platform reuse the output.
# ------------------------------------------------------------------------------
declare -A GENERATED_PLATFORMS

# Track the last spinor partition.xml path for contents.xml generation
LAST_SPINOR_PARTITION_XML=""
LAST_SPINOR_PLATFORM_DIR=""

# ------------------------------------------------------------------------------
# Main loop: iterate over boards
# ------------------------------------------------------------------------------
BOARD_COUNT=$(echo "$BOARDS_JSON" | jq 'length')
echo "[INFO] Processing ${BOARD_COUNT} board(s)"

for i in $(seq 0 $((BOARD_COUNT - 1))); do
    BOARD_NAME=$(echo "$BOARDS_JSON"        | jq -r ".[$i].name")
    PTOOL_PLATFORM=$(echo "$BOARDS_JSON"    | jq -r ".[$i].qcom_ptool_platform")
    CDT_FILENAME=$(echo "$BOARDS_JSON"      | jq -r ".[$i].cdt_filename // empty")

    echo ""
    echo "========================================================"
    echo "[INFO] Board ${i}: ${BOARD_NAME}  (ptool: ${PTOOL_PLATFORM})"
    echo "========================================================"

    PLATFORM_DIR="${PTOOL_DIR}/platforms/${PTOOL_PLATFORM}"
    if [[ ! -d "$PLATFORM_DIR" ]]; then
        echo "[ERROR] qcom-ptool platform directory not found: ${PLATFORM_DIR}"
        exit 1
    fi

    # ------------------------------------------------------------------
    # Generate ptool partition tables for this platform (once per platform)
    # ------------------------------------------------------------------
    PTOOL_WORK="${BOOT_BINS_DIR}/ptool_${PTOOL_PLATFORM}"

    if [[ -z "${GENERATED_PLATFORMS[$PTOOL_PLATFORM]+x}" ]]; then
        echo "[INFO] Generating partition tables for platform: ${PTOOL_PLATFORM}"
        mkdir -p "$PTOOL_WORK"
        pushd "$PTOOL_WORK" > /dev/null

        for storage in nvme ufs spinor emmc; do
            CONF="${PLATFORM_DIR}/${storage}/partitions.conf"
            if [[ -f "$CONF" ]]; then
                echo "[INFO]   Generating ${storage} partition table"
                python3 "${PTOOL_DIR}/qcom_ptool/gen_partition.py" \
                    -i "$CONF" -o "partition_${storage}.xml"
                python3 "${PTOOL_DIR}/qcom_ptool/ptool.py" \
                    -x "partition_${storage}.xml" \
                    -t "./partition_${storage}"
                cleanup_flash_dir "./partition_${storage}"

                if [[ "$storage" == "spinor" ]]; then
                    LAST_SPINOR_PARTITION_XML="${PTOOL_WORK}/partition_spinor.xml"
                    LAST_SPINOR_PLATFORM_DIR="$PLATFORM_DIR"
                fi
            fi
        done

        popd > /dev/null
        GENERATED_PLATFORMS[$PTOOL_PLATFORM]=1
    else
        echo "[INFO] Reusing cached partition tables for platform: ${PTOOL_PLATFORM}"
    fi

    # ------------------------------------------------------------------
    # Locate CDT file for this board (if configured)
    # ------------------------------------------------------------------
    CDT_SRC=""
    if [[ -n "$CDT_FILENAME" ]]; then
        CDT_SRC=$(find "${BOOT_BINS_DIR}/cdt_${BOARD_NAME}" -name "$CDT_FILENAME" 2>/dev/null | head -1 || true)
        if [[ -z "$CDT_SRC" ]]; then
            # fallback: search anywhere under the board's cdt dir
            CDT_SRC=$(find "${BOOT_BINS_DIR}/cdt_${BOARD_NAME}" -name '*.bin' 2>/dev/null | head -1 || true)
        fi
        if [[ -z "$CDT_SRC" ]]; then
            echo "[WARN] CDT file '${CDT_FILENAME}' not found for board ${BOARD_NAME}"
        else
            echo "[INFO] CDT file: ${CDT_SRC}"
        fi
    fi

    # ------------------------------------------------------------------
    # Build one flash dir per storage type supported by this platform
    # ------------------------------------------------------------------
    for storage in nvme ufs spinor emmc; do
        PARTITION_DIR="${PTOOL_WORK}/partition_${storage}"
        if [[ ! -d "$PARTITION_DIR" ]]; then
            continue
        fi

        FLASH_DIR="${OUTPUT_DIR}/flash_${BOARD_NAME}_${storage}"
        echo "[INFO] Creating flash dir: ${FLASH_DIR}"
        mkdir -p "$FLASH_DIR"

        # 1. Copy ptool-generated partition files
        cp --preserve=mode,timestamps -av "${PARTITION_DIR}/." "${FLASH_DIR}/"

        # 2. Copy boot binaries (allowlist, no partition files)
        BOARD_BOOT_DIR="${BOOT_BINS_DIR}/bins_${BOARD_NAME}"
        if [[ -d "$BOARD_BOOT_DIR" ]]; then
            copy_boot_bins "$BOARD_BOOT_DIR" "$FLASH_DIR"
        else
            echo "[WARN] Boot bins directory not found: ${BOARD_BOOT_DIR}"
        fi

        # 3. Copy CDT
        if [[ -n "$CDT_SRC" ]]; then
            cp --preserve=mode,timestamps -v "$CDT_SRC" "${FLASH_DIR}/cdt.bin"
        fi

        # 4. Copy shared system images
        copy_system_images "$FLASH_DIR"
    done
done

# ------------------------------------------------------------------------------
# Generate combined contents.xml at output root
# ------------------------------------------------------------------------------
echo ""
echo "[INFO] Generating combined contents.xml"

CONTENTS_TEMPLATE=""
if [[ -n "$CONTENTS_XML_IN" && -f "$CONTENTS_XML_IN" ]]; then
    CONTENTS_TEMPLATE="$CONTENTS_XML_IN"
elif [[ -n "$LAST_SPINOR_PLATFORM_DIR" && -f "${LAST_SPINOR_PLATFORM_DIR}/spinor/contents.xml.in" ]]; then
    CONTENTS_TEMPLATE="${LAST_SPINOR_PLATFORM_DIR}/spinor/contents.xml.in"
fi

if [[ -n "$CONTENTS_TEMPLATE" && -n "$LAST_SPINOR_PARTITION_XML" ]]; then
    python3 "${PTOOL_DIR}/qcom_ptool/gen_contents.py" \
        -t "$CONTENTS_TEMPLATE" \
        -p "$LAST_SPINOR_PARTITION_XML" \
        -o "${OUTPUT_DIR}/contents.xml"
    echo "[INFO] contents.xml written to: ${OUTPUT_DIR}/contents.xml"
else
    echo "[WARN] Skipping contents.xml generation (no spinor template or partition.xml found)"
fi

echo ""
echo "[INFO] gen-flash-dirs.sh complete. Output: ${OUTPUT_DIR}"
