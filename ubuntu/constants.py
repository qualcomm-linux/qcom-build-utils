# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

import os

LINUX_MODULES_DEB = "linux-modules-*-qcom/linux-modules-*_arm64.deb"
SNAP_SHOT_DATE = "2025-09-12"  #update date for snapshot date from https://ports-ubuntu.qualcomm.com/ports.ubuntu.com/

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
IMAGE_NAME         = "system.img"

IMAGE_SIZE_IN_G     = 8

TERMINAL = "/bin/bash"

HOST_FS_MOUNT = ["dev", "proc"]
