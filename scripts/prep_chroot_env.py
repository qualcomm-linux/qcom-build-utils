#!/usr/bin/env python3

# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
prep_chroot_env.py

Checks that the resulting chroot is present. Prepares it otherwise.

Running as root is necessary to create the chroot.
"""

import os
import sys
import argparse
import subprocess

from color_logger import logger

def parse_arguments():
    parser = argparse.ArgumentParser(description="Prepares a chroot environment")
    parser.add_argument("--arch",
                        required=False,
                        default="arm64",
                        help="The architecture of the chroot environment. (default: arm64)")

    parser.add_argument("--os-codename",
                        required=True,
                        help="The codename of the OS, e.g. noble, bionic, focal, etc.")

    parser.add_argument("--suffix",
                        required=False,
                        default="ubuntu",
                        help="The suffix for the chroot name. (default: ubuntu)")

    args = parser.parse_args()

    return args

def main():

    args = parse_arguments()

    logger.debug(f"args: {args}")

    OS_CODENAME    = args.os_codename
    ARCH           = args.arch
    SUFFIX         = args.suffix
    CHROOT_NAME    = OS_CODENAME + "-" + ARCH + "-" + SUFFIX

    CHROOT_DIR     = "/srv/chroot"
    DEBIAN_MIRROR  = "http://ports.ubuntu.com"

    logger.debug(f"Checking if chroot container '{CHROOT_NAME}' is already registered")

    cmd = f"schroot -l | grep chroot:{CHROOT_NAME}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        logger.info(f"Schroot container {CHROOT_NAME} already exists. Skipping creation.")
        sys.exit(0)

    logger.warning(f"Schroot container '{CHROOT_NAME}' does not exist, creating it for the first time.")

    if os.geteuid() != 0:
        logger.critical("Creating a schroot environment requires root privileges")
        logger.critical("Please use sudo. Aborting.")
        sys.exit(1)

    logger.warning(f"The chroot will be created in {CHROOT_DIR}/{CHROOT_NAME}")
    logger.warning(f"Its config will be stored as /etc/schroot/chroot.d/{CHROOT_NAME}-xxxx")

    # this command creates a chroot environment that will be named "{DIST}-{ARCH}-{SUFFIX}" (note the explicit '-' in  --chroot-suffix)
    # We supply our own suffix, otherwise sbuild will use 'sbuild'
    cmd = f"sbuild-createchroot --arch={ARCH}" \
                             f" --chroot-suffix=-{SUFFIX}" \
                             f" --components=main,universe" \
                             f" {OS_CODENAME}" \
                             f" {CHROOT_DIR}/{CHROOT_NAME}" \
                             f" {DEBIAN_MIRROR}"

    logger.debug(f"Creating schroot environment with command: {cmd}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        logger.critical("Error creating schroot environment!")
        logger.critical(f"stderr: {result.stderr}")
        logger.critical(f"stdout: {result.stdout}")
        sys.exit(1)


    logger.info(f"Schroot environment {CHROOT_NAME} created successfully.")

    sys.exit(0)

if __name__ == "__main__":
    main()
