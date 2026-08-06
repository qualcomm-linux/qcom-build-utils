#!/bin/sh
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# rootfs-resize.sh - grow the root filesystem to fill its partition.
#
# The image ships a fixed 8G ext4 filesystem, but the partition it is flashed
# into is larger, so the filesystem is grown to match on boot. Only the
# filesystem is resized; the partition table is never touched.
#
# Do NOT "simplify" the size check to df or stat -f. ext4_statfs() reports
# f_blocks minus filesystem overhead, so a fully grown filesystem always looks
# smaller than its block device and the script would resize on every boot
# forever. Compare block counts from the superblock instead.

set -eu

log() { echo "rootfs-resize: $*"; }
die() { log "$*"; exit 1; }

# Resolve the device from what is mounted on /, never from a filesystem label.
# LABEL=system is not unique: every image this repo builds carries it, so a
# second flashed medium would make a label lookup ambiguous.
#
# Each capture clears its status explicitly. Under set -e a failing command
# substitution aborts the script, which would make the guards below unreachable.
ROOT_DEV=$(findmnt -n -o SOURCE --nofsroot /) || ROOT_DEV=''
[ -n "$ROOT_DEV" ] && [ -b "$ROOT_DEV" ] || die "no block device for / (got '${ROOT_DEV}')"

DUMP=$(dumpe2fs -h "$ROOT_DEV" 2>/dev/null) || die "cannot read ext superblock on ${ROOT_DEV}"
FS_BLOCKS=$(printf '%s\n' "$DUMP" | awk -F': *' '/^Block count:/ {print $2}')
FS_BSIZE=$( printf '%s\n' "$DUMP" | awk -F': *' '/^Block size:/  {print $2}')
[ -n "$FS_BLOCKS" ] && [ -n "$FS_BSIZE" ] || die "could not parse superblock on ${ROOT_DEV}"

DEV_BYTES=$(blockdev --getsize64 "$ROOT_DEV") || die "blockdev failed on ${ROOT_DEV}"
DEV_BLOCKS=$((DEV_BYTES / FS_BSIZE))

# Compare in filesystem blocks, not bytes. FS_BLOCKS * FS_BSIZE is always a
# multiple of the block size while blockdev returns sectors * 512, so a byte
# comparison stays false after a full grow and the resize would repeat on every
# boot. This block comparison is what makes the unit idempotent.
if [ "$FS_BLOCKS" -ge "$DEV_BLOCKS" ]; then
    log "already fills ${ROOT_DEV} (${FS_BLOCKS} of ${DEV_BLOCKS} blocks of ${FS_BSIZE}B)"
    exit 0
fi

log "growing ${ROOT_DEV} from ${FS_BLOCKS} to ${DEV_BLOCKS} blocks of ${FS_BSIZE}B"
resize2fs "$ROOT_DEV"

NEW_BLOCKS=$(dumpe2fs -h "$ROOT_DEV" 2>/dev/null | awk -F': *' '/^Block count:/ {print $2}') \
    || NEW_BLOCKS=''
log "grew ${ROOT_DEV} to ${NEW_BLOCKS:-unknown} blocks of ${FS_BSIZE}B"
