#!/usr/bin/env bash
#
# =============================================================================
# build-dtb-image.sh
#
# Description:
#   Build a FAT-formatted image containing a single *combined* Device Tree
#   Blob (DTB) file for Qualcomm-based ARM64 platforms.
#
#   This script supports two DTB source modes:
#
#     (A) Kernel .deb mode (recommended / upstream-friendly)
#         - Provide a Debian kernel package (.deb) as input.
#         - The script extracts the .deb via `dpkg-deb -R` into a temp directory.
#         - DTBs are expected to be present under:
#             $DEB_DIR/lib/firmware/$BASE_KERNEL_VERSION/device-tree
#           where $BASE_KERNEL_VERSION can be anything.
#         - The script assumes there is exactly ONE:
#             $DEB_DIR/lib/firmware/*/device-tree
#
#     (B) DTB source directory mode (dev/kernel-tree mode)
#         - Provide the DTB source directory directly (e.g. a kernel build tree):
#             arch/arm64/boot/dts/qcom
#
#   In both modes, the script:
#     1. Reads a manifest file listing DTB filenames (one per line).
#     2. Normalizes entries to absolute paths under the resolved DTB source
#        directory (unless already absolute).
#     3. Validates that all DTB files exist.
#     4. Concatenates all DTBs (in manifest order) into a single combined
#        DTB file: <DTB_SRC>/combined-dtb.dtb
#     5. Creates a FAT image of configurable size.
#     6. Mounts the FAT image via a loop device and copies the combined DTB
#        into the image root.
#
# Usage:
#   ./build-dtb-image.sh \
#       (--kernel-deb <path/to/kernel.deb> | --dtb-src <path/to/dtb/dir>) \
#       --manifest <file> \
#       [--size <MB>] [--out <file>]
#
# Arguments:
#   --kernel-deb / -kernel-deb
#              Path to a Debian kernel package (.deb). DTBs are taken from the
#              extracted payload under lib/firmware/*/device-tree.
#
#   --dtb-src / -dtb-src
#              Path to DTB source directory
#              e.g., arch/arm64/boot/dts/qcom
#
#   --manifest / -manifest
#              Path to manifest file listing DTBs (one per line). Each line:
#                - may be relative to the resolved DTB source directory, OR
#                - an absolute path to a .dtb file.
#              Blank lines and lines starting with '#' are ignored.
#
#   --size / -size
#              FAT image size in MB (integer > 0, default: 4)
#
#   --out / -out
#              Output image filename (default: dtb.bin)
#
# Requirements / Assumptions:
#   - Linux host with:
#       * bash
#       * mkfs.vfat
#       * losetup
#       * mount / umount
#       * dd (status=progress support is nice but not required)
#       * mountpoint
#       * dpkg-deb (only required for --kernel-deb mode)
#   - This script must be run as root (no internal sudo calls).
#
# Notes:
#   - The combined DTB is written to: <DTB_SRC>/combined-dtb.dtb
#     * In --kernel-deb mode, <DTB_SRC> is inside a temporary extraction dir,
#       so the combined DTB is not persisted after cleanup.
#     * In --dtb-src mode, <DTB_SRC> is your provided directory, so the
#       combined DTB will be written there (same behavior as before).
#   - The resulting FAT image contains exactly one file: combined-dtb.dtb
#     in the root directory of the filesystem.
#   - The script installs a cleanup trap to:
#       * unmount the image,
#       * detach the loop device,
#       * delete temporary files and directories.
#
# =============================================================================

set -euo pipefail

# Require running as root (needed for losetup, mkfs, mount, etc.)
if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (no internal sudo calls)." >&2
    exit 1
fi

# ----------------------------- Defaults --------------------------------------

DTB_BIN_SIZE=4         # Default FAT image size (MB)
DTB_BIN="dtb.bin"      # Default output image filename

DTB_SRC=""             # DTB source directory (resolved; required via one mode)
DTB_LIST=""            # Manifest file (required)

KERNEL_DEB=""          # Optional: kernel .deb input (preferred mode)
DEB_DIR=""             # Temporary extraction directory when using --kernel-deb

SANLIST=""             # Will hold the path to the sanitized DTB list
MNT_DIR=""             # Temporary mount directory
LOOP_DEV=""            # Loop device used for the FAT image

# ---------------------------- Helper Functions -------------------------------

usage() {
    cat <<EOF
Usage: $0 (--kernel-deb <kernel.deb> | --dtb-src <path>) --manifest <file> [--size <MB>] [--out <file>]

  --kernel-deb, -kernel-deb  Path to Debian kernel package (.deb). DTBs read from:
                             <extract>/lib/firmware/*/device-tree  (must be exactly one)

  --dtb-src,   -dtb-src      Path to DTB source directory
                             (e.g. arch/arm64/boot/dts/qcom)

  --manifest,  -manifest     Path to manifest file listing DTBs (one per line)

  --size,      -size         FAT image size in MB (default: 4)

  --out,       -out          Output image filename (default: dtb.bin)

Notes:
  - Exactly one of --kernel-deb or --dtb-src must be provided.
  - Blank manifest lines and lines beginning with '#' are ignored.
EOF
    exit 1
}

require_cmd() {
    local c="$1"
    if ! command -v "$c" >/dev/null 2>&1; then
        echo "[ERROR] Required command not found: $c" >&2
        exit 1
    fi
}

cleanup() {
    # Preserve the original exit status so we can exit with the right code
    local status=$?

    # Ensure any buffered writes are flushed (best-effort)
    sync || true

    # Unmount the mountpoint if it exists and is currently mounted
    if [[ -n "${MNT_DIR:-}" && -d "$MNT_DIR" ]]; then
        if mountpoint -q "$MNT_DIR"; then
            umount "$MNT_DIR" || true
        fi
        # Try to remove the temporary directory (ignore failures)
        rmdir "$MNT_DIR" 2>/dev/null || true
    fi

    # Detach loop device if it was created
    if [[ -n "${LOOP_DEV:-}" ]]; then
        losetup -d "$LOOP_DEV" || true
    fi

    # Remove temporary sanitized list
    if [[ -n "${SANLIST:-}" && -f "$SANLIST" ]]; then
        rm -f "$SANLIST"
    fi

    # Remove extracted deb directory (kernel-deb mode)
    if [[ -n "${DEB_DIR:-}" && -d "$DEB_DIR" ]]; then
        rm -rf "$DEB_DIR" || true
    fi

    exit "$status"
}

# Install trap early to handle failures after we start creating resources.
trap cleanup EXIT

# ------------------------------ Arg Parsing ----------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        -dtb-src|--dtb-src)
            DTB_SRC="${2:-}"
            shift 2
            ;;
        -kernel-deb|--kernel-deb)
            KERNEL_DEB="${2:-}"
            shift 2
            ;;
        -manifest|--manifest)
            DTB_LIST="${2:-}"
            shift 2
            ;;
        -size|--size)
            DTB_BIN_SIZE="${2:-}"
            shift 2
            ;;
        -out|--out)
            DTB_BIN="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

# ----------------------------- Validation ------------------------------------

# Require mandatory manifest argument
if [[ -z "${DTB_LIST}" ]]; then
    echo "[ERROR] --manifest is required." >&2
    usage
fi

# Exactly one source mode must be selected
if [[ -n "${KERNEL_DEB}" && -n "${DTB_SRC}" ]]; then
    echo "[ERROR] Provide only one of --kernel-deb or --dtb-src (not both)." >&2
    usage
fi
if [[ -z "${KERNEL_DEB}" && -z "${DTB_SRC}" ]]; then
    echo "[ERROR] Provide one of --kernel-deb or --dtb-src." >&2
    usage
fi

# Validate manifest exists
if [[ ! -f "${DTB_LIST}" ]]; then
    echo "[ERROR] Manifest file '${DTB_LIST}' not found." >&2
    exit 1
fi

# Validate image size is a positive integer
if ! [[ "${DTB_BIN_SIZE}" =~ ^[0-9]+$ ]] || (( DTB_BIN_SIZE <= 0 )); then
    echo "[ERROR] --size must be a positive integer (MB), got '${DTB_BIN_SIZE}'." >&2
    exit 1
fi

# Basic command requirements
require_cmd awk
require_cmd dd
require_cmd losetup
require_cmd mkfs.vfat
require_cmd mount
require_cmd umount
require_cmd mountpoint
require_cmd mktemp
require_cmd ls
require_cmd cat
require_cmd cp

# Resolve DTB_SRC based on mode
if [[ -n "${KERNEL_DEB}" ]]; then
    # Validate kernel deb exists
    if [[ ! -f "${KERNEL_DEB}" ]]; then
        echo "[ERROR] Kernel .deb '${KERNEL_DEB}' not found." >&2
        exit 1
    fi

    require_cmd dpkg-deb

    # Extract the .deb into a temporary directory
    DEB_DIR="$(mktemp -d -t kernel-deb-XXXXXX)"
    echo "[INFO] Extracting kernel .deb to: ${DEB_DIR}"
    dpkg-deb -R "${KERNEL_DEB}" "${DEB_DIR}"

    # Locate exactly one device-tree directory under lib/firmware/*/device-tree
    shopt -s nullglob
    dt_dirs=( "${DEB_DIR}/lib/firmware"/*/device-tree )
    shopt -u nullglob

    if (( ${#dt_dirs[@]} == 0 )); then
        echo "[ERROR] No DTB directory found at '${DEB_DIR}/lib/firmware/*/device-tree'." >&2
        exit 1
    fi
    if (( ${#dt_dirs[@]} > 1 )); then
        echo "[ERROR] Multiple DTB directories found; expected exactly one:" >&2
        for d in "${dt_dirs[@]}"; do
            echo "        - $d" >&2
        done
        exit 1
    fi

    DTB_SRC="${dt_dirs[0]}"
    echo "[INFO] Using DTB source directory from .deb payload: ${DTB_SRC}"
else
    # DTB source directory mode
    if [[ ! -d "${DTB_SRC}" ]]; then
        echo "[ERROR] DTB source directory '${DTB_SRC}' not found." >&2
        exit 1
    fi
    echo "[INFO] Using DTB source directory: ${DTB_SRC}"
fi

# --------------------------- Sanitize Manifest -------------------------------

# Temporary file to hold the fully-qualified DTB paths
SANLIST="$(mktemp -t dtb-list-XXXXXX)"

# Normalize manifest lines:
#   - Skip blank lines
#   - Skip comment lines starting with '#'
#   - If the entry is absolute, keep as-is
#   - Otherwise, prefix with DTB_SRC
#   - Strip a trailing CR (helps with Windows CRLF manifests)
awk -v src="${DTB_SRC}" '
  {
    sub(/\r$/, "", $0)
  }
  /^[[:space:]]*$/ {next}    # skip blank lines
  /^[[:space:]]*#/ {next}    # skip comments
  {
    if ($0 ~ /^\//) print $0;
    else            print src "/" $0;
  }
' "${DTB_LIST}" > "${SANLIST}"

# Ensure that the manifest produced at least one valid entry
if [[ ! -s "${SANLIST}" ]]; then
    echo "[ERROR] Manifest '${DTB_LIST}' has no valid DTB entries (non-comment, non-empty)." >&2
    exit 1
fi

# Validate each DTB exists
while IFS= read -r f; do
    if [[ ! -f "$f" ]]; then
        echo "[ERROR] Missing DTB: $f" >&2
        exit 1
    fi
done < "${SANLIST}"

# -------------------------- Combine DTBs -------------------------------------

OUT="${DTB_SRC}/combined-dtb.dtb"
rm -f "${OUT}"

# Concatenate in the order specified by the sanitized manifest.
# Use a read-loop to preserve filenames safely (including whitespace).
: > "${OUT}"
while IFS= read -r f; do
    cat "$f" >> "${OUT}"
done < "${SANLIST}"

echo "[INFO] Combined DTBs into: ${OUT}"
ls -lh "${OUT}"

# -------------------------- Create FAT Image ---------------------------------

echo "[INFO] Creating FAT image '${DTB_BIN}' (${DTB_BIN_SIZE} MB)..."
dd if=/dev/zero of="${DTB_BIN}" bs=1M count="${DTB_BIN_SIZE}" status=progress

# Attach a loop device to the image
LOOP_DEV="$(losetup --show -fP "${DTB_BIN}")"
echo "[INFO] Using loop device: ${LOOP_DEV}"

# Create a temporary mount directory for this run
MNT_DIR="$(mktemp -d -t dtb-mnt-XXXXXX)"

# Format the loop device with FAT (4 KiB logical sector size)
echo "[INFO] Formatting ${LOOP_DEV} as FAT with 4 KiB sector size..."
mkfs.vfat -S 4096 "${LOOP_DEV}" >/dev/null

# Mount the loop device
echo "[INFO] Mounting ${LOOP_DEV} at ${MNT_DIR}..."
mount "${LOOP_DEV}" "${MNT_DIR}"

# ----------------------- Deploy Combined DTB ---------------------------------

cp "${OUT}" "${MNT_DIR}/"
echo "[INFO] Deployed combined DTB into FAT image."
echo "[INFO] Files in image:"
ls -lh "${MNT_DIR}"

# Normal exit (cleanup will still run, but now everything should succeed).
exit 0
