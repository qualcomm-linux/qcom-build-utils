#!/usr/bin/env bash
#
# =============================================================================
# build-dtb-image.sh
#
# Description:
#   Build a FAT-formatted image containing a single *combined* Device Tree
#   Blob (DTB) file for Qualcomm-based ARM64 platforms.
#
#   This script:
#     1. Reads a manifest file listing DTB filenames (one per line).
#     2. Normalizes entries to absolute paths under the specified DTB source
#        directory (unless already absolute).
#     3. Validates that all DTB files exist.
#     4. Concatenates all DTBs (in manifest order) into a single combined
#        DTB file: <DTB_SRC>/combined-dtb.dtb
#     5. Creates a FAT image of configurable size.
#     6. Mounts the FAT image via a loop device and copies the combined DTB
#        into the image.
#
# Usage:
#   ./build-dtb-image.sh -dtb-src <path> -manifest <file> [-size <MB>] [-out <file>]
#
# Arguments:
#   -dtb-src   Path to DTB source directory
#              e.g., arch/arm64/boot/dts/qcom
#
#   -manifest  Path to manifest file listing DTBs (one per line). Each line:
#                - may be relative to -dtb-src, OR
#                - an absolute path to a .dtb file.
#              Blank lines and lines starting with '#' are ignored.
#
#   -size      FAT image size in MB (integer > 0, default: 4)
#
#   -out       Output image filename (default: dtb.bin)
#
# Requirements / Assumptions:
#   - Linux host with:
#       * bash
#       * mkfs.vfat
#       * losetup
#       * mount / umount
#       * dd (with status=progress support is nice but not required)
#   - This script must be run as root (no internal sudo calls).
#
# Notes:
#   - The combined DTB is written to: <DTB_SRC>/combined-dtb.dtb
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
if [[ "$EUID" -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (no internal sudo calls)." >&2
    exit 1
fi

# ----------------------------- Defaults --------------------------------------

DTB_BIN_SIZE=4         # Default FAT image size (MB)
DTB_BIN="dtb.bin"      # Default output image filename

DTB_SRC=""             # DTB source directory (required)
DTB_LIST=""            # Manifest file (required)

SANLIST=""             # Will hold the path to the sanitized DTB list
MNT_DIR=""             # Temporary mount directory
LOOP_DEV=""            # Loop device used for the FAT image

# ---------------------------- Helper Functions -------------------------------

usage() {
    cat <<EOF
Usage: $0 -dtb-src <path> -manifest <file> [-size <MB>] [-out <file>]

  -dtb-src   Path to DTB source directory (e.g. arch/arm64/boot/dts/qcom)
  -manifest  Path to manifest file listing DTBs (one per line)
  -size      FAT image size in MB (default: 4)
  -out       Output image filename (default: dtb.bin)
EOF
    exit 1
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

    exit "$status"
}

# Install trap early to handle failures after we start creating resources.
trap cleanup EXIT

# ------------------------------ Arg Parsing ----------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        -dtb-src)
            DTB_SRC="${2:-}"
            shift 2
            ;;
        -manifest)
            DTB_LIST="${2:-}"
            shift 2
            ;;
        -size)
            DTB_BIN_SIZE="${2:-}"
            shift 2
            ;;
        -out)
            DTB_BIN="${2:-}"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

# ----------------------------- Validation ------------------------------------

# Require mandatory arguments
if [[ -z "$DTB_SRC" || -z "$DTB_LIST" ]]; then
    echo "ERROR: -dtb-src and -manifest are required." >&2
    usage
fi

# Validate manifest exists
if [[ ! -f "$DTB_LIST" ]]; then
    echo "ERROR: Manifest file '$DTB_LIST' not found." >&2
    exit 1
fi

# Validate DTB source directory
if [[ ! -d "$DTB_SRC" ]]; then
    echo "ERROR: DTB source directory '$DTB_SRC' not found." >&2
    exit 1
fi

# Validate image size is a positive integer
if ! [[ "$DTB_BIN_SIZE" =~ ^[0-9]+$ ]] || (( DTB_BIN_SIZE <= 0 )); then
    echo "ERROR: -size must be a positive integer (MB), got '$DTB_BIN_SIZE'." >&2
    exit 1
fi

# --------------------------- Sanitize Manifest -------------------------------

# Temporary file to hold the fully-qualified DTB paths
SANLIST="$(mktemp -t dtb-list-XXXXXX)"

# Normalize manifest lines:
#   - Skip blank lines
#   - Skip comment lines starting with '#'
#   - If the entry is absolute, keep as-is
#   - Otherwise, prefix with DTB_SRC
awk -v src="$DTB_SRC" '
  /^[[:space:]]*$/ {next}    # skip blank lines
  /^[[:space:]]*#/ {next}    # skip comments
  {
    if ($0 ~ /^\//) print $0;
    else            print src "/" $0;
  }
' "$DTB_LIST" > "$SANLIST"

# Ensure that the manifest produced at least one valid entry
if [[ ! -s "$SANLIST" ]]; then
    echo "ERROR: Manifest '$DTB_LIST' has no valid DTB entries (non-comment, non-empty)." >&2
    exit 1
fi

# Validate each DTB exists
while IFS= read -r f; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: Missing DTB: $f" >&2
        exit 1
    fi
done < "$SANLIST"

# -------------------------- Combine DTBs -------------------------------------

OUT="${DTB_SRC}/combined-dtb.dtb"
rm -f "$OUT"

# Concatenate in the order specified by the sanitized manifest.
xargs -a "$SANLIST" -r cat > "$OUT"
echo "[INFO] Combined DTBs into: $OUT"
ls -lh "$OUT"

# -------------------------- Create FAT Image ---------------------------------

echo "[INFO] Creating FAT image '$DTB_BIN' (${DTB_BIN_SIZE} MB)..."
dd if=/dev/zero of="$DTB_BIN" bs=1M count="$DTB_BIN_SIZE" status=progress

# Attach a loop device to the image
LOOP_DEV="$(losetup --show -fP "$DTB_BIN")"
echo "[INFO] Using loop device: $LOOP_DEV"

# Create a temporary mount directory for this run
MNT_DIR="$(mktemp -d -t dtb-mnt-XXXXXX)"

# Format the loop device with FAT (4 KiB logical sector size)
echo "[INFO] Formatting $LOOP_DEV as FAT with 4 KiB sector size..."
mkfs.vfat -S 4096 "$LOOP_DEV" >/dev/null

# Mount the loop device
echo "[INFO] Mounting $LOOP_DEV at $MNT_DIR..."
mount "$LOOP_DEV" "$MNT_DIR"

# ----------------------- Deploy Combined DTB ---------------------------------

cp "$OUT" "$MNT_DIR/"
echo "[INFO] Deployed combined DTB into FAT image."
echo "[INFO] Files in image:"
ls -lh "$MNT_DIR"

# Normal exit (cleanup will still run, but now everything should succeed).
exit 0
