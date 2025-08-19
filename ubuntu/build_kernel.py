# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
build_kernel.py

This script is designed to build a kernel from a specified source directory for the ARM64 architecture.
It requires root privileges to execute and utilizes various helper functions for environment setup,
logging, and file management.
"""

from helpers import check_if_root, check_and_append_line_in_file, set_env, create_new_directory
from color_logger import logger
import os
import shutil
import subprocess

def build_kernel(source_dir: str):
    """
    Builds the kernel for ARM64 architecture from the specified source directory.

    Args:
    _____
    - source_dir (str): Path to the kernel source directory

    Raises:
    _______
    - SystemExit: If not run as root or if any build step fails

    Note:
    _____
    - This function must be executed with root privileges
    """
    if not check_if_root():
        logger.error('Please run this script as root user.')
        exit(1)

    set_env('ARCH', 'arm64')
    set_env('CROSS_COMPILE', 'aarch64-linux-gnu-')

    try:
        result = subprocess.run(["dpkg-architecture", '-aarm64'], capture_output=True, text=True, check=True)

        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                set_env(key, value)
    except:
        logger.error('Issue in setting environment variables.')
        exit(1)

    os.chdir(source_dir)

    try:
        os.symlink('/usr/bin/aarch64-linux-gnu-gcc-13', '/usr/bin/aarch64-linux-gnu-gcc-11')
    except:
        pass

    try:
        subprocess.run(["fakeroot", 'debian/rules', 'clean'], check=True)
        result = subprocess.run(['pwd'], capture_output=True, text=True, check=True)
        existing_env = os.environ.copy()
        existing_env['do_skip_checks'] = 'true'
        subprocess.run(["fakeroot", 'debian/rules', 'binary'], env=existing_env, check=True)

    except Exception as e:
        logger.error(f'Issue in running fakeroot: {e}')
        exit(1)

def reorganize_kernel_debs(WORKSPACE_DIR, DEB_OUT_DIR):
    """
    Reorganizes generated Debian packages (.deb files) into package-specific directories.

    Scans the workspace directory for .deb files and moves each package to its own
    subdirectory within the output directory. The subdirectory name is derived from
    the package name (first part before '_' in the filename).

    Args:
    _____
    - WORKSPACE_DIR (str): Directory containing the generated .deb files
    - DEB_OUT_DIR (str): Target directory where package-specific subdirectories will be created

    Note:
    -----
    - Creates new directories as needed but won't delete existing ones
    """
    for root, dirs, files in os.walk(WORKSPACE_DIR):
        for file in files:
            if file.endswith('.deb'):
                pkg_name = file.split('_')[0]
                pkg_dir = os.path.join(DEB_OUT_DIR, pkg_name)
                create_new_directory(pkg_dir, delete_if_exists=False)
                shutil.move(os.path.join(root, file), os.path.join(pkg_dir, file))
