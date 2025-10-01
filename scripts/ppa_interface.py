#!/usr/bin/env python3

# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
ppa_interface.py

Helper script to interface a PPA.
All operations are performed without messing with the host configurations.
This is done by creating a temp folder to store a apt cache

This script can query or download a package for a latest version or a specific one.
"""

import os
import sys
import argparse
import subprocess
import traceback

from color_logger import logger
from helpers import create_new_directory

# Arguments
APT_CONFIG=None
TEMP_DIR=None
PACKAGE_NAME=None
PACKAGE_VERSION=None

SOURCE_LIST_FILE = None
APT_CACHE_DIR = None
OPT = None

def parse_arguments():
    parser = argparse.ArgumentParser(description="List or download a package from a PPA")

    parser.add_argument("--operation",
                        required=True,
                        type=str,
                        choices=['download', 'list-versions', 'contains-version'],
                        help="Operation to perform. Options are [download, ...]")

    parser.add_argument("--apt-config",
                        required=False,
                        default="deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main",
                        help="APT server configuration")

    parser.add_argument("--package-name",
                        required=True,
                        help="Package name to download or query")

    parser.add_argument("--version",
                        required=False,
                        help="Specific version to download. If not set, use the latest available")

    parser.add_argument("--temp-dir",
                        required=False,
                        default="./apt_temp",
                        help="Temporary directory to store the apt cache")

    args = parser.parse_args()

    return args

def setup():
    global OPT
    global APT_CACHE_DIR
    global SOURCE_LIST_FILE

    create_new_directory(TEMP_DIR, delete_if_exists=False)

    SOURCE_LIST_FILE = os.path.join(TEMP_DIR, "sources.list")

    with open(SOURCE_LIST_FILE, "w") as f:
        f.write(APT_CONFIG)

    APT_CACHE_DIR = os.path.join(TEMP_DIR, "cache")
    create_new_directory(APT_CACHE_DIR)

    OPT =  f" -o Dir::Etc::sourcelist={SOURCE_LIST_FILE}"
    OPT += f" -o Dir::Etc::sourceparts=/dev/null"
    OPT += f" -o Dir::State={APT_CACHE_DIR}"
    OPT += f" -o Dir::Cache={APT_CACHE_DIR}"

def run_apt_update() -> bool :

    command = "apt-get update" + OPT

    logger.debug(f"[PPA_INTERFACE]/{PACKAGE_NAME}: Running: {command}")

    apt_ret = subprocess.run(command, cwd=TEMP_DIR, shell=True, capture_output=True)

    if apt_ret.returncode != 0:
        logger.critical(f"[PPA_INTERFACE]/{PACKAGE_NAME}: Failed to update package list: {apt_ret.stderr}")
        return False

    logger.info("[PPA_INTERFACE]/{PACKAGE_NAME}: Successfuly ran apt-get update")

    return True

def download_package() -> bool :
    global PACKAGE_NAME
    global PACKAGE_VERSION
    global OPT
    global TEMP_DIR

    logger.debug(f"[PPA_INTERFACE]/[DOWNLOAD]/{PACKAGE_NAME}: Downloading version = {PACKAGE_VERSION} ")

    package = PACKAGE_NAME + ("" if PACKAGE_VERSION == None else ("=" + PACKAGE_VERSION))

    command = f"apt-get download {package}" + OPT

    logger.debug(f"[PPA_INTERFACE]/[DOWNLOAD]/{PACKAGE_NAME}: Running: {command}")


    apt_ret = subprocess.run(command, cwd=TEMP_DIR, shell=True, capture_output=True)

    if apt_ret.returncode != 0:
        logger.error(f"[PPA_INTERFACE]/[DOWNLOAD]/{PACKAGE_NAME}: Failed to download {package}: {apt_ret.stderr}")
        return False

    logger.info(f"[PPA_INTERFACE]/[DOWNLOAD]/{PACKAGE_NAME}: Downloaded {package}:\n{apt_ret.stdout}")

    return True

def list_versions() :
    logger.debug(f"[PPA_INTERFACE]/[LIST_VERSIONS]/{PACKAGE_NAME}: Listing versions available to download")

    command = f"apt-cache policy {PACKAGE_NAME} {OPT}"

    apt_ret = subprocess.run(command, cwd=TEMP_DIR, shell=True, capture_output=True)

    if apt_ret.returncode != 0:
        logger.debug("command failed")
        logger.info(f"stdout :\n{apt_ret.stdout}")
        logger.info(f"stderr :\n{apt_ret.stderr}")
        sys.exit(1)

    logger.info(f"stdout :\n{apt_ret.stdout.decode()}")


def contains_version(version : str) -> bool :
    logger.debug(f"[PPA_INTERFACE]/[CONTAINS_VERSION]/{PACKAGE_NAME}: Checking if PPA contains version : {version}")

    command = f"apt-cache policy {PACKAGE_NAME} {OPT}"

    apt_ret = subprocess.run(command, cwd=TEMP_DIR, shell=True, capture_output=True)

    if apt_ret.returncode != 0:
        logger.debug("command failed")
        logger.info(f"stdout :\n{apt_ret.stdout}")
        logger.info(f"stderr :\n{apt_ret.stderr}")
        sys.exit(1)

    logger.debug(f"apt-cache stdout:\n{apt_ret.stdout}")

    for line in apt_ret.stdout.decode().splitlines():
        if line.startswith("  Candidate:"):
            versions = line.split("Candidate: ")[1]
            if version in versions.split(" "):
                logger.info(f"Found version : {version}")
                sys.exit(0)

    logger.warning(f"Did not find version : {version}")
    sys.exit(1)

def main():

    global APT_CONFIG
    global TEMP_DIR
    global PACKAGE_NAME
    global PACKAGE_VERSION

    args = parse_arguments()

    logger.debug(f"args: {args}")

    APT_CONFIG = args.apt_config
    PACKAGE_NAME = args.package_name
    PACKAGE_VERSION = args.version

    if not os.path.isabs(args.temp_dir):
        args.temp_dir = os.path.abspath(args.temp_dir)

    TEMP_DIR = args.temp_dir

    setup()

    run_apt_update()

    match args.operation:
        case "download":
            download_package()

        case "list-versions":
            list_versions()

        case "contains-version":
            if not args.version:
                logger.critical("Need to supply --version")
                sys.exit(1)
            contains_version(args.version)

        case _:
            sys.exit(1)


    ret = 0

    sys.exit(ret)

if __name__ == "__main__":

    try:
        main()
    except Exception as e:
        logger.critical(f"Uncaught exception : {e}")

        traceback.print_exc()

        sys.exit(1)