# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

import os

LINUX_IMAGE_DBGSYM_DEB = "oss/linux-qcom-tools*/linux-qcom-tools*_arm64.deb"
LINUX_MODULES_DEB = "linux-modules-*-qcom/linux-modules-*_arm64.deb"
<<<<<<< HEAD
SNAP_SHOT_DATE = "2025-09-23"  #update date for snapshot date from https://ports-ubuntu.qualcomm.com/ports.ubuntu.com/
=======
SNAP_SHOT_DATE = "2025-09-12"  #update date for snapshot date from https://ports-ubuntu.qualcomm.com/ports.ubuntu.com/
>>>>>>> 965bfda (Debian package:use a Qualcomm-specific Ubuntu mirror with a snapshot date.)

KERNEL_DEBS = [
    "linux-modules",
    "linux-tools",
    "linux-buildinfo",
    "linux-qcom-tools",
    "linux-headers",
    "linux-image-unsigned",
    "linux-libc-dev-qcom",
    "linux-source",
    "linux-qcom-headers",
    "linux-qcom-tools"
]

COMBINED_DTB_FILE  = "combined-dtb.dtb"
VMLINUX_QCOM_FILE  = "vmlinux"
IMAGE_NAME         = "system.img"

IMAGE_SIZE_IN_G     = 8

TERMINAL = "/bin/bash"

HOST_FS_MOUNT = ["dev", "proc"]
