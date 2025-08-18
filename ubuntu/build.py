#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
build.py

This script automates the process of building a Debian-based system image. It handles the following tasks:
- Parses command-line arguments to configure the build process.
- Checks for root privileges and creates necessary directories.
- Optionally builds the kernel and organizes kernel-related Debian packages.
- Generates Debian binary packages if specified.
- Packs the system image with the generated Debian packages.
- Cleans up temporary files and directories after the build process.

Usage:
------
- Run this script as a root user with the required command-line arguments to build the system image.

"""

import os
import random
import shutil
import argparse
import traceback
import glob

from build_kernel import build_kernel, reorganize_kernel_debs
from build_dtb import build_dtb
from build_deb import PackageBuilder, PackageNotFoundError, PackageBuildError
from constants import *
from datetime import date
from helpers import create_new_directory, umount_dir, check_if_root, check_and_append_line_in_file, cleanup_file, cleanup_directory, change_folder_perm_read_write, print_build_logs, start_local_apt_server, build_deb_package_gz, pull_debs_wget
from deb_organize import generate_manifest_map
from pack_deb import PackagePacker
from flat_meta import create_flat_meta
from deb_abi_checker import multiple_repo_deb_abi_checker
from color_logger import logger

# Check for root privileges
if not check_if_root():
    logger.critical('Please run this script as root user.')
    #exit(1)

DIST           = "noble"
ARCH           = "arm64"
CHROOT_SUFFIX  = "ubuntu"
CHROOT_NAME    = DIST + "-" + ARCH + "-" + CHROOT_SUFFIX
CHROOT_DIR     = "/srv/chroot"


def parse_arguments():
    """
    Parses command-line arguments for the build process.

    Returns:
    --------
    argparse.Namespace: The parsed command-line arguments.

    Raises:
    -------
    SystemExit: If any of the specified paths are not absolute.
    """
    parser = argparse.ArgumentParser(description="Process command line arguments.")

    parser.add_argument('--apt-server-config', type=str, required=False,
                        default="deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main",
                        help='APT Server configuration to use')
    parser.add_argument('--mount_dir', type=str, required=False,
                        help='Mount directory for builds (default: <workspace>/build/mount)',
                        default="build/mount")
    parser.add_argument('--workspace', type=str, required=False,
                        default=".",
                        help='Workspace directory, defaults to pwd')
    parser.add_argument('--build-kernel', action='store_true', default=False,
                        help='Build kernel')
    parser.add_argument('--kernel-src-dir', type=str, required=False,
                        help='Kernel directory (default: <workspace>/kernel)',
                        default="kernel")
    parser.add_argument('--kernel-dest-dir', type=str, required=False,
                        help='Kernel out directory (default: <workspace>/debian_packages/oss)')
    parser.add_argument('--kernel-deb-path', type=str, required=False,
                        help='directory with built kernel debians (default: <workspace>/debian_packages/oss)')
    parser.add_argument('--kernel-deb-url', type=str, required=False,
                        help='directory with built kernel debians',
                        default="https://pkg.qualcomm.com/pool/stable/main")
    parser.add_argument('--flavor', type=str, choices=['server', 'desktop'], default='server',
                        help='Image flavor (only server or desktop, default: server)')
    parser.add_argument('--debians-path', type=str, required=False,
                        help='Directory with debians to install')
    parser.add_argument('--gen-debians', action='store_true', default=False,
                        help='Generate Debian binary (default: False)')
    parser.add_argument('--pack-image', action='store_true', default=False,
                        help='Pack system.img with generated debians (default: False)')
    parser.add_argument('--pack-variant', type=str, choices=['base', 'qcom'], default='qcom',
                        help='Pack variant (only base or qcom, default: qcom)')
    parser.add_argument('--packages-manifest-path', type=str, required=False,
                        help='Absolute path to the package manifest file')
    parser.add_argument('--output-image-file', type=str, required=False,
                        help='Output file name in <workspace>/out/system.img',
                        default="out/system.img")
    parser.add_argument('--package', type=str, required=False,
                        help='Package to build')
    parser.add_argument("--nocleanup", action="store_true",
                        help="Cleanup workspace after build", default=False)
    parser.add_argument("--prepare-sources", action="store_true",
                        help="Prepares sources, does not build", default=False)
    parser.add_argument("--no-abi-check", action="store_true",
                        help="Skip ABI compatibility check", default=False)
    parser.add_argument("--force-abi-check", action="store_true",
                        help="Skip ABI compatibility check", default=False)

    # Deprecated
    parser.add_argument('--chroot-name', type=str, required=False,
                        help='chroot name to use')
    parser.add_argument('--skip-starter-image', action='store_true', default=False,
                        help='Build starter image (deprecated)')
    parser.add_argument('--input-image-file', type=str, required=False,
                        help='Path for input system.img (deprecated)')
    parser.add_argument('--flat-meta', type=str, required=False,help='Flat meta')

    args = parser.parse_args()

    # Make workspace absolute path. If no value was passed, resolve the '.' default value to the current pwd
    if not os.path.isabs(args.workspace):
        args.workspace = os.path.abspath(args.workspace)

    # If not overriden with an absolute path, resolve the relative path to the workspace : <workspace>/out/system.img
    if not os.path.isabs(args.output_image_file):
        args.output_image_file = os.path.join(args.workspace, args.output_image_file)

    # If not overriden with an absolute path, resolve the repative path to the workspace : <workspace>/build/mount
    if not os.path.isabs(args.mount_dir):
        args.mount_dir = os.path.join(args.workspace, args.mount_dir)

    # If not overriden with an absolute path, resolve the repative path to the workspace : <workspace>/kernel
    if not os.path.isabs(args.kernel_src_dir):
        args.kernel_src_dir = os.path.join(args.workspace, args.kernel_src_dir)

    if 'lnxbuild' in args.workspace:
        logger.disable_color()
        logger.info("the string 'lnxbuild' was detected in the workspace path, which indicates a CI build. Turning off the color encoding for the logging to avoid polluting the log with special characters")

    # Absolute path checks
    for path_arg, path_value in {
        '--kernel-dest-dir': args.kernel_dest_dir,
        '--kernel-deb-path' : args.kernel_deb_path ,
        '--debians-path': args.debians_path,
        '--packages-manifest-path': args.packages_manifest_path,
    }.items():
        if path_value and not os.path.isabs(path_value):
            logger.critical(f"Error: {path_arg} must be an absolute path.")
            exit(1)

    # Check for conflicting arguments
    if args.kernel_deb_path and IF_BUILD_KERNEL:
        logger.critical('Error: --kernel-deb-path and --build-kernel cannot be used together.')
        exit(1)

    if args.chroot_name:
        logger.warning("The argument --chroot-name is not used anymore. Take it out to silence this warning.")

    return args

# Parse command-line arguments
args = parse_arguments()

# Set up workspace and image parameters
WORKSPACE_DIR = args.workspace
IMAGE_TYPE = args.flavor
PACKAGES_MANIFEST_PATH = args.packages_manifest_path

BUILD_PACKAGE_NAME = args.package
DEBIAN_INSTALL_DIR = args.debians_path

# Process Flags
IF_BUILD_KERNEL = args.build_kernel
IF_GEN_DEBIANS = args.gen_debians
IF_PACK_IMAGE = args.pack_image
IF_FLAT_META = args.flat_meta
IS_CLEANUP_ENABLED = not args.nocleanup
IS_PREPARE_SOURCE = args.prepare_sources

PACK_VARIANT = args.pack_variant

TARGET_HW = args.flat_meta
NO_ABI_CHECK = args.no_abi_check
FORCE_ABI_CHECK = args.force_abi_check

# Define kernel and output directories
KERNEL_DIR = args.kernel_src_dir
KERNEL_DEB_URL = args.kernel_deb_url
SOURCES_DIR = os.path.join(WORKSPACE_DIR, "sources")
OUT_DIR = os.path.join(WORKSPACE_DIR, "out")
DEB_OUT_DIR = os.path.join(WORKSPACE_DIR, "debian_packages")

OSS_DEB_OUT_DIR = os.path.join(DEB_OUT_DIR, "oss")

KERNEL_DEB_OUT_DIR = (
    args.kernel_dest_dir if args.kernel_dest_dir
    else args.kernel_deb_path if args.kernel_deb_path
    else OSS_DEB_OUT_DIR
)
PROP_DEB_OUT_DIR = os.path.join(DEB_OUT_DIR, "prop")
DEB_OUT_TEMP_DIR = os.path.join(DEB_OUT_DIR, "temp")

# Set up APT server configuration and generate manifest map
APT_SERVER_CONFIG = [config.strip() for config in args.apt_server_config.split(',')] if args.apt_server_config else None
APT_SERVER_CONFIG = list(set(APT_SERVER_CONFIG)) if APT_SERVER_CONFIG else None

# Create necessary directories for the build process
create_new_directory(KERNEL_DIR, delete_if_exists=False)
create_new_directory(KERNEL_DEB_OUT_DIR, delete_if_exists=False)
create_new_directory(SOURCES_DIR, delete_if_exists=False)
create_new_directory(OUT_DIR, delete_if_exists=False)
create_new_directory(DEB_OUT_DIR, delete_if_exists=False)
create_new_directory(OSS_DEB_OUT_DIR, delete_if_exists=False)
create_new_directory(PROP_DEB_OUT_DIR, delete_if_exists=False)
create_new_directory(DEB_OUT_TEMP_DIR, delete_if_exists=False) # Don't clear all the temp folders

try:
    MANIFEST_MAP = generate_manifest_map(WORKSPACE_DIR)
except Exception as e:
    logger.error(f"Failed to generate manifest map: {e}")
    MANIFEST_MAP = {}

# Build the kernel if specified
if IF_BUILD_KERNEL:
    error_during_kernel_build = False

    logger.info("Running the kernel build phase")

    try:
        os.chdir(WORKSPACE_DIR)
        build_kernel(KERNEL_DIR)
        reorganize_kernel_debs(WORKSPACE_DIR, KERNEL_DEB_OUT_DIR)

        build_dtb(KERNEL_DEB_OUT_DIR, LINUX_MODULES_DEB, COMBINED_DTB_FILE, OUT_DIR)

    except Exception as e:
        logger.critical(f"Exception during kernel build : {e}")
        traceback.print_exc()
        error_during_kernel_build = True

    finally:
        if error_during_kernel_build:
            logger.critical("Kernel build failed. Exiting.")
            exit(1)

if IF_GEN_DEBIANS or IS_PREPARE_SOURCE :
    error_during_packages_build = False

    logger.info("Running the debian packages generation phase")

    try:
        DEB_OUT_DIR_APT = None
        DEBIAN_INSTALL_DIR_APT = None

        if DEB_OUT_DIR and os.path.exists(DEB_OUT_DIR):
            DEB_OUT_DIR_APT = build_deb_package_gz(DEB_OUT_DIR, start_server=True)
        if DEBIAN_INSTALL_DIR and os.path.exists(DEBIAN_INSTALL_DIR):
            DEBIAN_INSTALL_DIR_APT = build_deb_package_gz(DEBIAN_INSTALL_DIR, start_server=True)

        # Initialize the PackageBuilder to load packages
        builder = PackageBuilder(CHROOT_NAME, CHROOT_DIR, SOURCES_DIR, APT_SERVER_CONFIG, MANIFEST_MAP, DEB_OUT_TEMP_DIR, DEB_OUT_DIR, DEB_OUT_DIR_APT, DEBIAN_INSTALL_DIR_APT, IS_CLEANUP_ENABLED, IS_PREPARE_SOURCE)
        builder.load_packages()

        # Build a specific package if provided, otherwise build all packages
        if BUILD_PACKAGE_NAME:
            logger.debug(f"Building specific package: {BUILD_PACKAGE_NAME}")
            builder.build_specific_package(BUILD_PACKAGE_NAME)
        else:
            logger.debug("Building all packages")
            builder.build_all_packages()

    except Exception as e:
        error_during_packages_build = True

        logger.critical(f"Exception during debian package(s) generation : {e}")

        if not isinstance(e, PackageBuildError):
            # Dont clog the output with the stack trace if it just a package build exception, the full build log is
            # already printed in build function if build fails.=
            traceback.print_exc()

    finally:
        if error_during_packages_build:
            logger.critical("Debian package generation error. Exiting.")
            exit(1)


if NO_ABI_CHECK:
    logger.warning("ABI check is explicitely disabled. Skipping ABI check.")
elif (not IF_GEN_DEBIANS and not IS_PREPARE_SOURCE) and not FORCE_ABI_CHECK:
    logger.debug("Skipping ABI check since no debian packages generated")
else:
    if FORCE_ABI_CHECK and (not IF_GEN_DEBIANS and not IS_PREPARE_SOURCE):
        logger.info("Forcing ABI check even if no debian package were built")

    error_during_abi_check = False

    logger.info("Running the ABI checking phase")

    try:
        if not APT_SERVER_CONFIG:
            raise Exception("No apt server config provided")

        if len(APT_SERVER_CONFIG) > 1:
            logger.warning("Multiple apt server configs are not supported yet, picking the first one in the list")

        logger.debug("Running the package ABI checker over the temp folder containing all the repo outputs")
        check_passed = multiple_repo_deb_abi_checker(DEB_OUT_TEMP_DIR, APT_SERVER_CONFIG[0])

        if check_passed:
            logger.info("ABI check passed.")
        else:
            logger.critical("ABI check failed.")

    except Exception as e:
        logger.critical(f"Exception during the ABI checking : {e}")
        traceback.print_exc()
        error_during_abi_check = True

    finally:
        if error_during_abi_check:
            logger.critical("ABI check failed. Exiting.")
            exit(1)

# Pack the image if specified
if IF_PACK_IMAGE:
    error_during_image_packing = False
    packer = None

    logger.info("Running the image packing phase")

    # Define mount directory
    MOUNT_DIR = args.mount_dir
    OUT_SYSTEM_IMG = args.output_image_file

    logger.debug(f"mount dir {MOUNT_DIR}")
    logger.debug(f"out system img {OUT_SYSTEM_IMG}")

    try:
        if os.path.isfile(OUT_SYSTEM_IMG):
            cleanup_file(OUT_SYSTEM_IMG)

        if os.path.exists(MOUNT_DIR):
            # Make sure no leftovers from a previous run are present, especially in terms of mouted directories.
            umount_dir(MOUNT_DIR, UMOUNT_HOST_FS=True)
            cleanup_directory(MOUNT_DIR)

        create_new_directory(MOUNT_DIR)

        files_check = glob.glob(os.path.join(KERNEL_DEB_OUT_DIR, LINUX_MODULES_DEB))
        if len(files_check) == 0:
            logger.warning(f"No files matching {LINUX_MODULES_DEB} exist in {KERNEL_DEB_OUT_DIR}. Pulling it from pkg.qualcomm.com")
            cur_file = os.path.dirname(os.path.realpath(__file__))
            manifest_file_path = os.path.join(cur_file, "packages", "base", f"{IMAGE_TYPE}.manifest")
            pull_debs_wget(manifest_file_path, KERNEL_DEB_OUT_DIR,KERNEL_DEBS,KERNEL_DEB_URL)
        else:
            logger.info("Linux modules found locally. Skipping pull from pkg.qualcomm.com")

        build_dtb(KERNEL_DEB_OUT_DIR, LINUX_MODULES_DEB, COMBINED_DTB_FILE, OUT_DIR)

        packer = PackagePacker(MOUNT_DIR, IMAGE_TYPE, PACK_VARIANT, OUT_DIR, OUT_SYSTEM_IMG, APT_SERVER_CONFIG, DEB_OUT_TEMP_DIR, DEB_OUT_DIR, DEBIAN_INSTALL_DIR, IS_CLEANUP_ENABLED, PACKAGES_MANIFEST_PATH)
        packer.build_image()

    except Exception as e:
        error_during_image_packing = True

        logger.critical(f"Exception during packaging : {e}")
        traceback.print_exc()

        print_build_logs(DEB_OUT_TEMP_DIR)

    finally:
        umount_dir(MOUNT_DIR, UMOUNT_HOST_FS=True)

        if IS_CLEANUP_ENABLED:
            cleanup_directory(MOUNT_DIR)
        if error_during_image_packing:
            logger.critical("Image packing failed. Exiting.")
            exit(1)

if IF_FLAT_META:
    try:
        create_flat_meta(PACK_VARIANT, IMAGE_TYPE, TARGET_HW, WORKSPACE_DIR)
    except Exception as e:
        logger.error(e)
        ERROR_EXIT_BUILD = True

# Change permissions for output directories if cleanup is enabled
if IS_CLEANUP_ENABLED:
    error_during_cleanup = False

    try:
        change_folder_perm_read_write(OSS_DEB_OUT_DIR)
        change_folder_perm_read_write(PROP_DEB_OUT_DIR)
        change_folder_perm_read_write(DEB_OUT_DIR)
        change_folder_perm_read_write(OUT_DIR)
    except Exception:
        error_during_cleanup = True

    finally:
        if error_during_cleanup:
            logger.critical("Cleanup failed. Exiting.")
            exit(1)

logger.info("Script execution sucessful")
exit(0)