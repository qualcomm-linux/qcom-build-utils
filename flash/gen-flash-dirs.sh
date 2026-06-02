#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# ==============================================================================
# Script: gen-flash-dirs.sh
# ------------------------------------------------------------------------------
# Description:
#   Generates per-target, per-storage flash directories from a boards JSON
#   array. All targets share the same rootfs.img (placed at the output root).
#   efi.bin and dtb.bin placement follows these rules:
#
#   Storage layout rules (Table 1):
#     nvme, ufs, emmc:
#       - always: efi.bin (sector-size matched)
#       - rootfs.img: referenced via ../../rootfs.img in rawprogram XMLs (not copied)
#       - dtb.bin: only if the target has NO spinor storage
#     spinor:
#       - always: dtb.bin
#       - never:  efi.bin, rootfs.img  (firmware-only storage)
#
#   Sector sizes (Table 2):
#     ufs  -> 4096 bytes
#     nvme -> 4096 bytes
#     emmc -> 512  bytes
#
# Output layout:
#   <output-dir>/
#     rootfs.img                        (shared, at root)
#     <target-name>/
#       <storage>/                      (one dir per storage type)
#         rawprogram*.xml, patch*.xml   (from ptool)
#         gpt_*.bin, zeros_*.bin        (from ptool)
#         <boot-bins>                   (*.elf, *.mbn, *.melf, *.fv, *.bin …)
#         cdt.bin                       (if cdt configured)
#         efi.bin                       (nvme/ufs/emmc only, sector-size matched)
#         rawprogram*.xml               (rootfs.img ref rewritten to ../../rootfs.img)
#         dtb.bin                       (spinor always; nvme/ufs/emmc if no spinor)
#     contents.xml                      (top-level, from gen_contents.py if spinor present)
#
# Usage:
#   gen-flash-dirs.sh \
#     --boards-json    '<json-array>'        \
#     --ptool-dir      <path/to/qcom-ptool>  \
#     --boot-bins-dir  <path/to/boot_bins>   \
#     --system-images  <path/to/images-dir>  \
#     --output-dir     <path/to/output>      \
#     [--contents-xml-in <path/to/contents.xml.in>]
#
# boards-json format (array of objects):
#   [
#     {
#       "name":                "iq-x7181-evk",
#       "boot_bin_url":   "https://...",
#       "ptool_platform": "iq-x7181-evk",
#       "cdt_url":    "",
#       "cdt_filename":        ""
#     },
#     ...
#   ]
#
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Sector size map (Table 2)
# ------------------------------------------------------------------------------
sector_size_for() {
    case "$1" in
        ufs)  echo 4096 ;;
        nvme) echo 4096 ;;
        emmc) echo 512  ;;
        *)    echo 512  ;;   # spinor/other: not used for efi, default safe value
    esac
}

# ------------------------------------------------------------------------------
# Argument parsing
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

for var in BOARDS_JSON PTOOL_DIR BOOT_BINS_DIR SYSTEM_IMAGES_DIR OUTPUT_DIR; do
    if [[ -z "${!var}" ]]; then
        echo "[ERROR] --$(echo "$var" | tr '[:upper:]_' '[:lower:]-') is required"
        print_usage; exit 1
    fi
done

# Resolve all path arguments to absolute paths so they remain valid after pushd/popd
PTOOL_DIR=$(realpath "$PTOOL_DIR")
BOOT_BINS_DIR=$(realpath "$BOOT_BINS_DIR")
SYSTEM_IMAGES_DIR=$(realpath "$SYSTEM_IMAGES_DIR")
OUTPUT_DIR=$(realpath -m "$OUTPUT_DIR")
[[ -n "$CONTENTS_XML_IN" ]] && CONTENTS_XML_IN=$(realpath "$CONTENTS_XML_IN")

command -v python3 &>/dev/null || { echo "[ERROR] python3 is required"; exit 1; }
command -v jq     &>/dev/null || { echo "[ERROR] jq is required";     exit 1; }

mkdir -p "$OUTPUT_DIR"

# ------------------------------------------------------------------------------
# Place rootfs.img at the output root (shared by all targets)
# ------------------------------------------------------------------------------
if [[ -f "${SYSTEM_IMAGES_DIR}/rootfs.img" ]]; then
    cp --preserve=mode,timestamps -v \
        "${SYSTEM_IMAGES_DIR}/rootfs.img" "${OUTPUT_DIR}/rootfs.img"
else
    echo "[WARN] rootfs.img not found in ${SYSTEM_IMAGES_DIR}"
fi

# ------------------------------------------------------------------------------
# Helper: remove dangerous ptool wipe files
# ------------------------------------------------------------------------------
cleanup_flash_dir() {
    local dir="$1"
    rm -vf "${dir}"/rawprogram*_BLANK_GPT.xml
    rm -vf "${dir}"/rawprogram*_WIPE_PARTITIONS.xml
    rm -vf "${dir}"/wipe_rawprogram*.xml
}

# ------------------------------------------------------------------------------
# Helper: copy boot binary files (allowlist) — no partition/GPT/wipe files
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
# Cache: ptool platform -> work dir (avoid regenerating for shared platforms)
# ------------------------------------------------------------------------------
declare -A GENERATED_PLATFORMS

# For contents.xml generation — track last spinor partition.xml seen
LAST_SPINOR_PARTITION_XML=""
LAST_SPINOR_PLATFORM_DIR=""

# ------------------------------------------------------------------------------
# Main loop: iterate over boards/targets
# ------------------------------------------------------------------------------
BOARD_COUNT=$(echo "$BOARDS_JSON" | jq 'length')
echo "[INFO] Processing ${BOARD_COUNT} target(s)"

for i in $(seq 0 $((BOARD_COUNT - 1))); do
    BOARD_NAME=$(echo "$BOARDS_JSON"     | jq -r ".[$i].name")
    PTOOL_PLATFORM=$(echo "$BOARDS_JSON" | jq -r ".[$i].ptool_platform")
    CDT_FILENAME=$(echo "$BOARDS_JSON"   | jq -r ".[$i].cdt_filename // empty")

    echo ""
    echo "========================================================"
    echo "[INFO] Target ${i}: ${BOARD_NAME}  (ptool: ${PTOOL_PLATFORM})"
    echo "========================================================"

    PLATFORM_DIR="${PTOOL_DIR}/platforms/${PTOOL_PLATFORM}"
    if [[ ! -d "$PLATFORM_DIR" ]]; then
        echo "[ERROR] qcom-ptool platform directory not found: ${PLATFORM_DIR}"
        exit 1
    fi

    PRE_PARTITIONED=$(echo "$BOARDS_JSON" | jq -r ".[$i].pre_partitioned // \"false\"")

    # ------------------------------------------------------------------
    # Determine which storage types this target supports
    # ------------------------------------------------------------------
    HAS_SPINOR=false
    SUPPORTED_STORAGES=()

    if [[ "$PRE_PARTITIONED" == "true" ]]; then
        # Archive already contains partition_<storage>/ subdirs — discover from bins dir
        BOARD_BOOT_DIR="${BOOT_BINS_DIR}/bins_${BOARD_NAME}"
        for storage in nvme ufs emmc spinor; do
            if [[ -d "${BOARD_BOOT_DIR}/partition_${storage}" ]]; then
                SUPPORTED_STORAGES+=("$storage")
                [[ "$storage" == "spinor" ]] && HAS_SPINOR=true
            fi
        done
        echo "[INFO] Pre-partitioned archive — storages discovered: ${SUPPORTED_STORAGES[*]}"
    else
        for storage in nvme ufs emmc spinor; do
            if [[ -f "${PLATFORM_DIR}/${storage}/partitions.conf" ]]; then
                SUPPORTED_STORAGES+=("$storage")
                [[ "$storage" == "spinor" ]] && HAS_SPINOR=true
            fi
        done
        echo "[INFO] Supported storages: ${SUPPORTED_STORAGES[*]}"
    fi
    echo "[INFO] Has spinor: ${HAS_SPINOR}"

    # ------------------------------------------------------------------
    # Generate ptool partition tables
    # ------------------------------------------------------------------
    PTOOL_WORK="${BOOT_BINS_DIR}/ptool_${PTOOL_PLATFORM}"

    if [[ "$PRE_PARTITIONED" == "true" ]]; then
        # Pre-partitioned: archive already has partition files + boot bins combined.
        # We still need partition_spinor.xml as input to gen_contents.py.
        # Run gen_partition.py only (not ptool.py) to produce it.
        if [[ "$HAS_SPINOR" == "true" && -f "${PLATFORM_DIR}/spinor/partitions.conf" ]]; then
            mkdir -p "$PTOOL_WORK"
            echo "[INFO] Generating spinor partition XML for contents.xml (pre-partitioned)"
            python3 "${PTOOL_DIR}/gen_partition.py" \
                -i "${PLATFORM_DIR}/spinor/partitions.conf" \
                -o "${PTOOL_WORK}/partition_spinor.xml"
            LAST_SPINOR_PARTITION_XML="${PTOOL_WORK}/partition_spinor.xml"
            LAST_SPINOR_PLATFORM_DIR="$PLATFORM_DIR"
        fi
    elif [[ -z "${GENERATED_PLATFORMS[$PTOOL_PLATFORM]+x}" ]]; then
        echo "[INFO] Generating partition tables for platform: ${PTOOL_PLATFORM}"
        mkdir -p "$PTOOL_WORK"
        pushd "$PTOOL_WORK" > /dev/null

        for storage in "${SUPPORTED_STORAGES[@]}"; do
            CONF="${PLATFORM_DIR}/${storage}/partitions.conf"
            echo "[INFO]   Generating ${storage} partition table"
            python3 "${PTOOL_DIR}/gen_partition.py" \
                -i "$CONF" -o "partition_${storage}.xml"
            python3 "${PTOOL_DIR}/ptool.py" \
                -x "partition_${storage}.xml" \
                -t "./partition_${storage}"
            cleanup_flash_dir "./partition_${storage}"

            if [[ "$storage" == "spinor" ]]; then
                LAST_SPINOR_PARTITION_XML="${PTOOL_WORK}/partition_spinor.xml"
                LAST_SPINOR_PLATFORM_DIR="$PLATFORM_DIR"
            fi
        done

        popd > /dev/null
        GENERATED_PLATFORMS[$PTOOL_PLATFORM]=1
    else
        echo "[INFO] Reusing cached partition tables for platform: ${PTOOL_PLATFORM}"
    fi

    # ------------------------------------------------------------------
    # Locate CDT file for this board
    # ------------------------------------------------------------------
    CDT_SRC=""
    if [[ -n "$CDT_FILENAME" ]]; then
        CDT_SRC=$(find "${BOOT_BINS_DIR}/cdt_${BOARD_NAME}" \
            -name "$CDT_FILENAME" 2>/dev/null | head -1 || true)
        if [[ -z "$CDT_SRC" ]]; then
            CDT_SRC=$(find "${BOOT_BINS_DIR}/cdt_${BOARD_NAME}" \
                -name '*.bin' 2>/dev/null | head -1 || true)
        fi
        if [[ -z "$CDT_SRC" ]]; then
            echo "[WARN] CDT file '${CDT_FILENAME}' not found for board ${BOARD_NAME}"
        else
            echo "[INFO] CDT file: ${CDT_SRC}"
        fi
    fi

    # ------------------------------------------------------------------
    # Build one directory per storage type: <output>/<target>/<storage>/
    # ------------------------------------------------------------------
    TARGET_DIR="${OUTPUT_DIR}/${BOARD_NAME}"
    BOARD_BOOT_DIR="${BOOT_BINS_DIR}/bins_${BOARD_NAME}"

    for storage in "${SUPPORTED_STORAGES[@]}"; do
        STORAGE_DIR="${TARGET_DIR}/${storage}"

        echo ""
        echo "[INFO] Building ${BOARD_NAME}/${storage}/"
        mkdir -p "$STORAGE_DIR"

        if [[ "$PRE_PARTITIONED" == "true" ]]; then
            # Pre-partitioned: extract partition_<storage>/ directly from bins dir.
            # This contains both partition files AND boot binaries already combined.
            PRE_PART_DIR="${BOARD_BOOT_DIR}/partition_${storage}"
            cp --preserve=mode,timestamps -av "${PRE_PART_DIR}/." "${STORAGE_DIR}/"
            cleanup_flash_dir "$STORAGE_DIR"
        else
            PARTITION_DIR="${PTOOL_WORK}/partition_${storage}"

            # 1. ptool-generated partition files
            cp --preserve=mode,timestamps -av "${PARTITION_DIR}/." "${STORAGE_DIR}/"

            # 2. Boot binaries (allowlist, no partition files)
            if [[ -d "$BOARD_BOOT_DIR" ]]; then
                copy_boot_bins "$BOARD_BOOT_DIR" "$STORAGE_DIR"
            else
                echo "[WARN] Boot bins directory not found: ${BOARD_BOOT_DIR}"
            fi
        fi

        # 3. CDT (both paths)
        if [[ -n "$CDT_SRC" ]]; then
            cp --preserve=mode,timestamps -v "$CDT_SRC" "${STORAGE_DIR}/cdt.bin"
        fi

        # 4. Post-process rawprogram XMLs to wire OS image filenames.
        #    Pre-partitioned archives ship with filename="" for OS partitions.
        #    Rules (Table 1):
        #      nvme/ufs/emmc: efi label -> efi.bin, rootfs label -> ../../rootfs.img
        #      spinor:        dtb_a/dtb_b labels -> dtb.bin
        case "$storage" in
            nvme|ufs|emmc)
                for xml in "${STORAGE_DIR}"/rawprogram*.xml; do
                    [[ -f "$xml" ]] || continue
                    # Wire efi: filename="" ... label="efi" -> efi.bin
                    sed -i -E 's/filename=""([^>]*label="efi")/filename="efi.bin"\1/g' "$xml"
                    # Wire rootfs: filename="" ... label="rootfs" -> ../../rootfs.img
                    sed -i -E 's|filename=""([^>]*label="rootfs")|filename="../../rootfs.img"\1|g' "$xml"
                    # Normalise any already-set bare rootfs.img -> relative path
                    sed -i 's|filename="rootfs\.img"|filename="../../rootfs.img"|g' "$xml"
                    echo "[INFO] Patched efi/rootfs filenames in $(basename "$xml")"
                done
                ;;
            spinor)
                for xml in "${STORAGE_DIR}"/rawprogram*.xml; do
                    [[ -f "$xml" ]] || continue
                    # Wire dtb_a/dtb_b: filename="" -> dtb.bin
                    sed -i -E 's/filename=""([^>]*label="dtb_a")/filename="dtb.bin"\1/g' "$xml"
                    sed -i -E 's/filename=""([^>]*label="dtb_b")/filename="dtb.bin"\1/g' "$xml"
                    echo "[INFO] Patched dtb_a/dtb_b filenames in $(basename "$xml")"
                done
                ;;
        esac

        # 5. System images — apply Table 1 rules (same for both paths)
        case "$storage" in
            spinor)
                # spinor: dtb.bin only — no efi, no rootfs
                if [[ -f "${SYSTEM_IMAGES_DIR}/dtb.bin" ]]; then
                    cp --preserve=mode,timestamps -v \
                        "${SYSTEM_IMAGES_DIR}/dtb.bin" "${STORAGE_DIR}/dtb.bin"
                else
                    echo "[WARN] dtb.bin not found for spinor"
                fi
                ;;
            nvme|ufs|emmc)
                # efi.bin: sector-size matched
                SECTOR_SIZE=$(sector_size_for "$storage")
                EFI_SRC="${SYSTEM_IMAGES_DIR}/efi_${SECTOR_SIZE}.bin"
                if [[ ! -f "$EFI_SRC" ]]; then
                    EFI_SRC="${SYSTEM_IMAGES_DIR}/efi.bin"
                fi
                if [[ -f "$EFI_SRC" ]]; then
                    cp --preserve=mode,timestamps -v "$EFI_SRC" "${STORAGE_DIR}/efi.bin"
                else
                    echo "[WARN] efi.bin not found for ${storage} (sector size ${SECTOR_SIZE})"
                fi

                # dtb.bin: only if this target has NO spinor
                if [[ "$HAS_SPINOR" == "false" ]]; then
                    if [[ -f "${SYSTEM_IMAGES_DIR}/dtb.bin" ]]; then
                        cp --preserve=mode,timestamps -v \
                            "${SYSTEM_IMAGES_DIR}/dtb.bin" "${STORAGE_DIR}/dtb.bin"
                    else
                        echo "[WARN] dtb.bin not found for ${storage} (no spinor fallback)"
                    fi
                fi
                ;;
        esac
    done
done

# ------------------------------------------------------------------------------
# Generate combined contents.xml at output root (if spinor present)
# ------------------------------------------------------------------------------
echo ""
echo "[INFO] Generating combined contents.xml"

CONTENTS_TEMPLATE=""
if [[ -n "$CONTENTS_XML_IN" && -f "$CONTENTS_XML_IN" ]]; then
    CONTENTS_TEMPLATE="$CONTENTS_XML_IN"
elif [[ -n "$LAST_SPINOR_PLATFORM_DIR" && \
        -f "${LAST_SPINOR_PLATFORM_DIR}/spinor/contents.xml.in" ]]; then
    CONTENTS_TEMPLATE="${LAST_SPINOR_PLATFORM_DIR}/spinor/contents.xml.in"
fi

if [[ -n "$CONTENTS_TEMPLATE" && -n "$LAST_SPINOR_PARTITION_XML" ]]; then
    python3 "${PTOOL_DIR}/gen_contents.py" \
        -t "$CONTENTS_TEMPLATE" \
        -p "$LAST_SPINOR_PARTITION_XML" \
        -o "${OUTPUT_DIR}/contents.xml"
    echo "[INFO] contents.xml written to: ${OUTPUT_DIR}/contents.xml"

    # Patch OS storage file_path values in contents.xml to match actual output layout.
    # The template uses generic NVME/ and UFS/ paths; rewrite them to
    # <board-name>/nvme/ and <board-name>/ufs/ for each board that has those storages.
    BOARD_COUNT_INNER=$(echo "$BOARDS_JSON" | jq 'length')
    for j in $(seq 0 $((BOARD_COUNT_INNER - 1))); do
        PATCH_BOARD=$(echo "$BOARDS_JSON" | jq -r ".[$j].name")
        PATCH_PTOOL=$(echo "$BOARDS_JSON" | jq -r ".[$j].ptool_platform")
        PATCH_PRE=$(echo "$BOARDS_JSON"   | jq -r ".[$j].pre_partitioned // \"false\"")
        PATCH_PLATFORM_DIR="${PTOOL_DIR}/platforms/${PATCH_PTOOL}"

        # Determine which OS storages this board has
        HAS_NVME=false; HAS_UFS=false; HAS_EMMC=false
        if [[ "$PATCH_PRE" == "true" ]]; then
            PATCH_BINS="${BOOT_BINS_DIR}/bins_${PATCH_BOARD}"
            [[ -d "${PATCH_BINS}/partition_nvme"  ]] && HAS_NVME=true
            [[ -d "${PATCH_BINS}/partition_ufs"   ]] && HAS_UFS=true
            [[ -d "${PATCH_BINS}/partition_emmc"  ]] && HAS_EMMC=true
        else
            [[ -f "${PATCH_PLATFORM_DIR}/nvme/partitions.conf"  ]] && HAS_NVME=true
            [[ -f "${PATCH_PLATFORM_DIR}/ufs/partitions.conf"   ]] && HAS_UFS=true
            [[ -f "${PATCH_PLATFORM_DIR}/emmc/partitions.conf"  ]] && HAS_EMMC=true
        fi

        if [[ "$HAS_NVME" == "true" ]]; then
            sed -i "s|>NVME/<|>${PATCH_BOARD}/nvme/<|g" "${OUTPUT_DIR}/contents.xml"
            echo "[INFO] Patched NVME/ -> ${PATCH_BOARD}/nvme/ in contents.xml"
        fi
        if [[ "$HAS_UFS" == "true" ]]; then
            sed -i "s|>UFS/<|>${PATCH_BOARD}/ufs/<|g" "${OUTPUT_DIR}/contents.xml"
            echo "[INFO] Patched UFS/ -> ${PATCH_BOARD}/ufs/ in contents.xml"
        fi
        if [[ "$HAS_EMMC" == "true" ]]; then
            sed -i "s|>EMMC/<|>${PATCH_BOARD}/emmc/<|g" "${OUTPUT_DIR}/contents.xml"
            echo "[INFO] Patched EMMC/ -> ${PATCH_BOARD}/emmc/ in contents.xml"
        fi
    done
else
    echo "[INFO] No spinor platform found; skipping contents.xml generation"
fi

echo ""
echo "[INFO] gen-flash-dirs.sh complete. Output: ${OUTPUT_DIR}"
