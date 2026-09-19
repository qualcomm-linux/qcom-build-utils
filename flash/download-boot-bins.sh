#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# ==============================================================================
# Script: download-boot-bins.sh
# ------------------------------------------------------------------------------
# Description:
#   Downloads and extracts boot binary archives and CDT archives for each target
#   in a boards JSON array. Deduplicates downloads: if two targets share the same
#   boot_bin_url, the ZIP is downloaded only once and the extracted contents
#   are reused.
#
#   When a target also has boot_bin_immutable_url set, that second archive is
#   downloaded and its contents are merged (cp -a) into the same bins_<board>/
#   directory, mirroring the Yocto firmware-qcom-boot-common.inc behaviour where
#   both BOOTBINARIES and BOOTBINARIES_IMMUTABLE are deployed to the same
#   DEPLOYDIR.
#
# Usage:
#   download-boot-bins.sh --boards-json '<json-array>' --output-dir <dir>
#
# Output layout (inside --output-dir):
#   bins_<board-name>/     extracted boot binary files for that board
#                          (main + immutable archives merged into one directory)
#   cdt_<board-name>/      extracted CDT files for that board (if cdt_url set)
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

# ------------------------------------------------------------------------------
# Helper: download_and_extract <url> -> sets EXTRACTED_DIR
#   Downloads <url> into OUTPUT_DIR, extracts it, strips a single top-level
#   directory if present, caches the result in URL_TO_EXTRACTED_DIR, and
#   sets the global EXTRACTED_DIR variable to the resulting path.
# ------------------------------------------------------------------------------
download_and_extract() {
    local url="$1"

    if [[ -n "${URL_TO_EXTRACTED_DIR[$url]+x}" ]]; then
        EXTRACTED_DIR="${URL_TO_EXTRACTED_DIR[$url]}"
        echo "[INFO]   Already downloaded (${url}), reusing: ${EXTRACTED_DIR}"
        return
    fi

    local archive_name
    archive_name=$(basename "$url")
    local archive_path="${OUTPUT_DIR}/${archive_name}"

    echo "[INFO]   Downloading: ${url}"
    wget -q --show-progress -O "$archive_path" "$url" || \
        { echo "[ERROR] Failed to download: $url"; exit 1; }

    local extract_dir="${OUTPUT_DIR}/_extract_$(echo "$url" | sha256sum | cut -c1-8)"
    mkdir -p "$extract_dir"

    if [[ "$archive_name" == *.zip ]]; then
        unzip -q "$archive_path" -d "$extract_dir"
    else
        tar -xf "$archive_path" -C "$extract_dir"
    fi

    # Strip a single top-level directory if the archive has one.
    # Use find -type d to count only real subdirectories, ignoring any
    # top-level files that would cause the glob approach to miscount.
    local top_dirs=()
    while IFS= read -r -d '' d; do
        top_dirs+=("$d")
    done < <(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d -print0)
    if [[ ${#top_dirs[@]} -eq 1 ]]; then
        local flat_dir="${extract_dir}_flat"
        mv "${top_dirs[0]}" "$flat_dir"
        rm -rf "$extract_dir"
        extract_dir="$flat_dir"
    fi

    rm -f "$archive_path"
    URL_TO_EXTRACTED_DIR[$url]="$extract_dir"
    EXTRACTED_DIR="$extract_dir"
}

BOARD_COUNT=$(echo "$BOARDS_JSON" | jq 'length')

for i in $(seq 0 $((BOARD_COUNT - 1))); do
    BOARD_NAME=$(echo "$BOARDS_JSON"     | jq -r ".[$i].name")
    BOOT_URL=$(echo "$BOARDS_JSON"       | jq -r ".[$i].boot_bin_url")
    BOOT_IMMUTABLE_URL=$(echo "$BOARDS_JSON" | jq -r ".[$i].boot_bin_immutable_url // empty")
    CDT_URL=$(echo "$BOARDS_JSON"        | jq -r ".[$i].cdt_url // empty")

    echo ""
    echo "[INFO] Board: ${BOARD_NAME}"

    # ------------------------------------------------------------------
    # Boot binaries (main archive) — deduplicate by URL
    # ------------------------------------------------------------------
    BINS_DST="${OUTPUT_DIR}/bins_${BOARD_NAME}"

    echo "[INFO]   Boot bins (main):"
    download_and_extract "$BOOT_URL"
    if [[ ! -d "$BINS_DST" ]]; then
        cp -a "$EXTRACTED_DIR" "$BINS_DST"
    fi
    echo "[INFO]   Boot bins extracted to: ${BINS_DST}"

    # ------------------------------------------------------------------
    # Boot binaries (immutable archive) — optional, merged into BINS_DST
    # Mirrors Yocto firmware-qcom-boot-common.inc: both BOOTBINARIES and
    # BOOTBINARIES_IMMUTABLE are deployed into the same DEPLOYDIR.
    # ------------------------------------------------------------------
    if [[ -n "$BOOT_IMMUTABLE_URL" ]]; then
        echo "[INFO]   Boot bins (immutable):"
        download_and_extract "$BOOT_IMMUTABLE_URL"
        cp -a "${EXTRACTED_DIR}/." "${BINS_DST}/"
        echo "[INFO]   Immutable boot bins merged into: ${BINS_DST}"
    fi

    # ------------------------------------------------------------------
    # CDT archive — always board-specific
    # ------------------------------------------------------------------
    if [[ -n "$CDT_URL" ]]; then
        CDT_DST="${OUTPUT_DIR}/cdt_${BOARD_NAME}"
        echo "[INFO]   Downloading CDT: ${CDT_URL}"
        CDT_ARCHIVE_NAME=$(basename "$CDT_URL")
        CDT_ARCHIVE_PATH="${OUTPUT_DIR}/${CDT_ARCHIVE_NAME}"

        wget -q --show-progress -O "$CDT_ARCHIVE_PATH" "$CDT_URL" || \
            { echo "[ERROR] Failed to download CDT: $CDT_URL"; exit 1; }
        mkdir -p "$CDT_DST"
        unzip -q "$CDT_ARCHIVE_PATH" -d "$CDT_DST"
        rm -f "$CDT_ARCHIVE_PATH"
        echo "[INFO]   CDT extracted to: ${CDT_DST}"
    fi
done

echo ""
echo "[INFO] download-boot-bins.sh complete."

# ------------------------------------------------------------------------------
# Cleanup: remove all _extract_* / _flat temporary directories now that every
# bins_<board>/ folder has been created.
# ------------------------------------------------------------------------------
echo "[INFO] Cleaning up temporary extract directories..."
for tmp_dir in "${URL_TO_EXTRACTED_DIR[@]}"; do
    rm -rf "$tmp_dir"
done
echo "[INFO] Cleanup complete."
