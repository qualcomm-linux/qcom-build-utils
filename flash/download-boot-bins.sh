#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# ==============================================================================
# Script: download-boot-bins.sh
# ------------------------------------------------------------------------------
# Description:
#   Downloads and extracts boot binary archives and CDT archives for each board
#   in a boards JSON array. Deduplicates downloads: if two boards share the same
#   boot_binaries_url, the ZIP is downloaded only once and the extracted contents
#   are reused via a symlink/copy.
#
# Usage:
#   download-boot-bins.sh --boards-json '<json-array>' --output-dir <dir>
#
# Output layout (inside --output-dir):
#   bins_<board-name>/     extracted boot binary files for that board
#   cdt_<board-name>/      extracted CDT files for that board (if cdt_binaries_url set)
#
# ==============================================================================

set -euo pipefail

BOARDS_JSON=""
OUTPUT_DIR=""

print_usage() {
    echo "Usage: $0 --boards-json '<json>' --output-dir <dir>"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --boards-json)  BOARDS_JSON="$2"; shift 2 ;;
        --output-dir)   OUTPUT_DIR="$2";  shift 2 ;;
        -h|--help)      print_usage; exit 0 ;;
        *) echo "[ERROR] Unknown argument: $1"; print_usage; exit 1 ;;
    esac
done

if [[ -z "$BOARDS_JSON" || -z "$OUTPUT_DIR" ]]; then
    echo "[ERROR] --boards-json and --output-dir are required"
    print_usage
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "[ERROR] jq is required"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Cache: map URL -> local extracted directory (to deduplicate downloads)
declare -A URL_TO_EXTRACTED_DIR

BOARD_COUNT=$(echo "$BOARDS_JSON" | jq 'length')

for i in $(seq 0 $((BOARD_COUNT - 1))); do
    BOARD_NAME=$(echo "$BOARDS_JSON"     | jq -r ".[$i].name")
    BOOT_URL=$(echo "$BOARDS_JSON"       | jq -r ".[$i].boot_bin_url")
    CDT_URL=$(echo "$BOARDS_JSON"        | jq -r ".[$i].cdt_url // empty")

    echo ""
    echo "[INFO] Board: ${BOARD_NAME}"

    # ------------------------------------------------------------------
    # Boot binaries — deduplicate by URL
    # ------------------------------------------------------------------
    BINS_DST="${OUTPUT_DIR}/bins_${BOARD_NAME}"

    if [[ -n "${URL_TO_EXTRACTED_DIR[$BOOT_URL]+x}" ]]; then
        CACHED="${URL_TO_EXTRACTED_DIR[$BOOT_URL]}"
        echo "[INFO]   Boot bins already downloaded (${BOOT_URL}), reusing: ${CACHED}"
        if [[ ! -d "$BINS_DST" ]]; then
            cp -a "$CACHED" "$BINS_DST"
        fi
    else
        echo "[INFO]   Downloading boot bins: ${BOOT_URL}"
        ARCHIVE_NAME=$(basename "$BOOT_URL")
        ARCHIVE_PATH="${OUTPUT_DIR}/${ARCHIVE_NAME}"

        wget -q --show-progress -O "$ARCHIVE_PATH" "$BOOT_URL"

        EXTRACT_DIR="${OUTPUT_DIR}/_extract_$(echo "$BOOT_URL" | md5sum | cut -c1-8)"
        mkdir -p "$EXTRACT_DIR"

        if [[ "$ARCHIVE_NAME" == *.zip ]]; then
            unzip -q "$ARCHIVE_PATH" -d "$EXTRACT_DIR"
        else
            tar -xf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"
        fi

        # Strip a single top-level directory if the archive has one
        TOP_DIRS=("$EXTRACT_DIR"/*/)
        if [[ ${#TOP_DIRS[@]} -eq 1 && -d "${TOP_DIRS[0]}" ]]; then
            FLAT_DIR="${EXTRACT_DIR}_flat"
            mv "${TOP_DIRS[0]}" "$FLAT_DIR"
            rm -rf "$EXTRACT_DIR"
            EXTRACT_DIR="$FLAT_DIR"
        fi

        rm -f "$ARCHIVE_PATH"
        URL_TO_EXTRACTED_DIR[$BOOT_URL]="$EXTRACT_DIR"
        cp -a "$EXTRACT_DIR" "$BINS_DST"
        echo "[INFO]   Boot bins extracted to: ${BINS_DST}"
    fi

    # ------------------------------------------------------------------
    # CDT archive — always board-specific
    # ------------------------------------------------------------------
    if [[ -n "$CDT_URL" ]]; then
        CDT_DST="${OUTPUT_DIR}/cdt_${BOARD_NAME}"
        echo "[INFO]   Downloading CDT: ${CDT_URL}"
        CDT_ARCHIVE_NAME=$(basename "$CDT_URL")
        CDT_ARCHIVE_PATH="${OUTPUT_DIR}/${CDT_ARCHIVE_NAME}"

        wget -q --show-progress -O "$CDT_ARCHIVE_PATH" "$CDT_URL"
        mkdir -p "$CDT_DST"
        unzip -q "$CDT_ARCHIVE_PATH" -d "$CDT_DST"
        rm -f "$CDT_ARCHIVE_PATH"
        echo "[INFO]   CDT extracted to: ${CDT_DST}"
    fi
done

echo ""
echo "[INFO] download-boot-bins.sh complete."
