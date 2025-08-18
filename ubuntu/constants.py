import os

LINUX_MODULES_DEB = "linux-modules-*-qcom/linux-modules-*_arm64.deb"

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
