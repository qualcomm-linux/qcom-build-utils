#!/usr/bin/env python3

# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
deb_abi_checker.py: ABI Comparison Tool

This script compares two Debian binary packages (.deb) to detect ABI (Application Binary Interface) changes.
It usses the abipkgdiff tool (Package-level ABI comparison)
   --------------------------------------------------
   - Compares the entire old .deb and new .deb packages directly.
   - Internally extracts and analyzes binary symbols and type information using libabigail.
   - Reports any changes in ABI that may cause incompatibility (e.g., removed or modified symbols).

   Advantages:
     - Simple interface: only requires two .deb files as input.
     - Ideal for high-level package comparison.

   Limitations:
     - Depends on symbol/debug info availability.
     - Does not show per-library granularity.

Usage:


Options:
    --report-dir     Directory to save logs (default: ./reports)
    --keep-temp      Preserve extracted .deb directories for inspection
"""

import os
import sys
import subprocess
import shutil
import argparse
import glob
import re
import traceback
from helpers import create_new_directory
from color_logger import logger

RETURN_ABI_NO_DIFF           = 0b00000
RETURN_ABI_COMPATIBLE_DIFF   = 0b00001
RETURN_ABI_INCOMPATIBLE_DIFF = 0b00010
RETURN_ABI_STRIPPED_PACKAGE  = 0b00100
RETURN_PPA_PACKAGE_NOT_FOUND = 0b01000
RETURN_PPA_ERROR             = 0b10000

class ABI_DIFF_Result:
    def __init__(self, package_name):
        self.package_name = package_name
        self.repo_name = None

        self.new_deb_name=None
        self.new_dev_name=None
        self.new_ddeb_name=None
        self.new_deb_version=None

        self.old_deb_name=None
        self.old_dev_name=None
        self.old_ddeb_name=None
        self.old_deb_version=None

        self.abi_pkg_diff_result = None
        self.abi_pkg_diff_remark = None
        self.abi_pkg_diff_version_check = None
        self.abi_pkg_diff_output = None

# package_name - result
global_checker_results: dict[str, ABI_DIFF_Result] = {}

def produce_report(log_file=None):

    log = "ABI Check results\n\n"

    log += ("-" * 100 + "\n")

    for package_name, result in global_checker_results.items():
        log += f"Package Name:     {package_name}\n"
        log += f"Repository Name:  {result.repo_name}\n"
        log += f"New Package:\n"
        log += f"  - DEB Name:     {result.new_deb_name}\n"
        log += f"  - DEV Name:     {result.new_dev_name}\n"
        log += f"  - DDEB Name:    {result.new_ddeb_name}\n"
        log += f"  - Version:      {result.new_deb_version}\n"
        log += f"Old Package:\n"
        log += f"  - DEB Name:     {result.old_deb_name}\n"
        log += f"  - DEV Name:     {result.old_dev_name}\n"
        log += f"  - DDEB Name:    {result.old_ddeb_name}\n"
        log += f"  - Version:      {result.old_deb_version}\n"
        log += f"ABI Package Diff:\n"
        log += f"  - Result:       {result.abi_pkg_diff_result}\n"
        log += f"  - Version:      {result.abi_pkg_diff_version_check}\n"
        log += f"  - Remark:       {result.abi_pkg_diff_remark}\n"
        log += f"  - Output:       {"" if result.abi_pkg_diff_output is not None else result.abi_pkg_diff_output}\n"
        if result.abi_pkg_diff_output is not None:
            cmd = f"echo \"{result.abi_pkg_diff_output}\" | sed 's/^/       /'"
            output = subprocess.run(cmd, capture_output=True, text=True, shell=True)

            log += f"{output.stdout}\n"

        log += ("-" * 100 + "\n")

    if log_file is not None:
        with open(log_file, 'w') as f:
            f.write(log)

    logger.debug(log)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Compare two .deb packages using abipkgdiff or abidiff.")
    parser.add_argument("--apt-server-config",
                        default="deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main",
                        help="APT server configuration to download the old package to compare against")

    parser.add_argument("--new-package-dir",
                        required=True,
                        help="Path to the folder containing the new package to compare. (.deb,  optional -dev.deb, optional -dbgsym.ddeb)")

    parser.add_argument("--delete-temp",
                        action="store_true",
                        help="Keep temp extracted folders for debugging.")

    parser.add_argument("--old-version",
                        required=False,
                        help="Specific version of the old package to compare against. (optional)")

    parser.add_argument("--result-file",
                        required=False,
                        help="Path for the result file")

    args = parser.parse_args()

    return args

def main():
    args = parse_arguments()

    logger.debug(f"args: {args}")

    if not os.path.isabs(args.new_package_dir):
        args.new_package_dir = os.path.abspath(args.new_package_dir)

    print_debug_tree = True



    ret = single_repo_deb_abi_checker(args.new_package_dir,
                                         args.apt_server_config,
                                         True if args.delete_temp is False else False,
                                         None if not args.old_version else args.old_version,
                                         print_debug_tree=print_debug_tree)

    if args.result_file is not None:
        if not os.path.isabs(args.result_file):
            args.result_file = os.path.abspath(args.result_file)

    produce_report(args.result_file)

    sys.exit(ret)

def multiple_repo_deb_abi_checker(package_dir, apt_server_config, keep_temp=True, specific_apt_version=None) -> int:
    """
    Runs the ABI check in a folder containing multiple package folders.

    Note: For a single package, use the function single_repo_deb_abi_checker()

    Args:
        package_dir (str): Path to the temporary directory containing the packages.
            Must have a structure like the following, where the core deb package is placed alongside
            its development and debug package:
            .
            └── my_package
                ├── my_package_1.0.0_arm64.deb
                ├── my_package-dbgsym_1.0.0_arm64.ddeb
                └── my_package-dev_1.0.0_arm64.deb

        apt_server_config (str): APT server configuration to download the old package to compare against.
            Must be in the format "deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main".

        keep_temp (bool): Whether to keep the temporary directory after the comparison.

        specific_apt_version (str): Specific version of the old package to compare against. (optional)


    Returns:
    --------
        - bool: Aglomeration of bitwise return value of every repo
    """

    final_ret = 0

    for folder in os.listdir(package_dir):
        folder_path = os.path.join(package_dir, folder)
        if os.path.isdir(folder_path):

            try:
                final_ret |= single_repo_deb_abi_checker(folder_path, apt_server_config, keep_temp, specific_apt_version)
            except Exception as e:
                logger.critical(f"Function single_repo_deb_abi_checker threw an exception: {e}")

                traceback.print_exc()
                sys.exit(-1)

    log_file = os.path.join(package_dir, "abi_checker.log")

    produce_report(log_file)

    return final_ret

def single_repo_deb_abi_checker(repo_package_dir, apt_server_config, keep_temp=True, specific_apt_version=None, print_debug_tree=False) -> int:
    """
    Runs the ABI check for all the packages in a single repo output directory

    Note: For running the ABI check accross multiple repo folders, use the function multiple_repo_deb_abi_checker(), which
    will run the ABI check for all the packages in all the repo folders.

    Args:
        repo_package_dir (str): Path to the directory where a repo has build its packages. This directory
            would typically be named after the repo name. For example, if the repo is named "my_package",
            then the directory would be named "my_package".

            Must have a structure like the following, where the core deb package is placed alongside
            its development and debug package:
            .
            └── repo_package_dir
                ├── my_package_1.0.0_arm64.deb
                ├── my_package-dbgsym_1.0.0_arm64.ddeb
                └── my_package-dev_1.0.0_arm64.deb

            Note: It is possible for a repo to produce multiple core packages, in which case the directory
            would contain multiple core packages. For example:
            .
            └── repo_package_dir
                ├── my_package_1.0.0_arm64.deb
                ├── my_package_2.0.0_arm64.deb
                ├── my_package-dbgsym_1.0.0_arm64.ddeb
                ├── my_package-dbgsym_2.0.0_arm64.ddeb
                └── my_package-dev_1.0.0_arm64.deb
                └── my_package-dev_2.0.0_arm64.deb

            If this is the case, this function will handle all the core packages in the directory.

        apt_server_config (str): APT server configuration to download the old package to compare against.
            Must be in the format "deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main".

        keep_temp (bool): Whether to keep the temporary directory after the comparison.

        specific_apt_version (str): Specific version of the old package to compare against. (optional)

    Returns:
    --------
        - bool: True if the package ABI diff was performed sucessfully, False otherwise.
            Note that this does not mean that the ABI diff passed, only that it was performed successfully.
    """

    logger.debug(f"[ABI_CHECKER]/[SINGLE_REPO]: Checking {repo_package_dir}")

    basedir = os.path.basename(repo_package_dir)

    logger.debug(f"[ABI_CHECKER]/[SINGLE_REPO]: performing abi checking for repo '{basedir}'")

    if print_debug_tree:
        tree_cmd = f"tree -a {repo_package_dir} | sed 's/^/       /'"
        tree_output = subprocess.run(tree_cmd, capture_output=True, text=True, shell=True)
        if tree_output.returncode == 0:
            logger.debug(f"[ABI_CHECKER]/[SINGLE_REPO]: Content :\n{tree_output.stdout}")
        else:
            logger.error(f"[ABI_CHECKER]/[SINGLE_REPO]: Failed to run 'tree' command: {tree_output.stderr}")

    abi_check_temp_dir = os.path.join(repo_package_dir, "abi_check_tmp")

    create_new_directory(abi_check_temp_dir, delete_if_exists=True) # <-- !delete the directory if it already exists

    # Find the .deb file(s) in the abi_check_temp_dir that represents the core packages
    # We filter out the -dev and -dbgsym packages as we are interested in building the list of core packages
    # that are built from the repo.
    deb_files = [f for f in os.listdir(repo_package_dir) if f.endswith('.deb') and '-dev' not in f and '-dbgsym' not in f]

    if not deb_files:
        logger.warning(f"[ABI_CHECKER]/[SINGLE_REPO]: No .deb file found, nothing to compare, returning success")
        return RETURN_ABI_NO_DIFF

    logger.debug(f"[ABI_CHECKER]/[SINGLE_REPO]: Found {len(deb_files)} package{"s" if len(deb_files) > 1 else ""}")

    final_ret = 0

    for deb_file in deb_files:
        logger.debug(f"[ABI_CHECKER]/[SINGLE_REPO]: core deb file detected: {deb_file}")
        package_name = os.path.splitext(os.path.basename(deb_file))[0].split('_')[0]
        logger.debug(f"[ABI_CHECKER]/[SINGLE_REPO]: package name: {package_name}")

        package_abi_check_temp_dir = os.path.join(abi_check_temp_dir, package_name)
        create_new_directory(package_abi_check_temp_dir)

        global_checker_results[package_name] = ABI_DIFF_Result(package_name)
        global_checker_results[package_name].repo_name = basedir

        # Run the single_package_abi_checker function for the package
        ret = single_package_abi_checker(repo_package_dir=repo_package_dir,
                                         package_abi_check_temp_dir=package_abi_check_temp_dir,
                                         package_name=package_name,
                                         package_file=deb_file,
                                         apt_server_config=apt_server_config,
                                         keep_temp=keep_temp,
                                         specific_apt_version=specific_apt_version,
                                         print_debug_tree=print_debug_tree)

        final_ret = final_ret | ret

    return final_ret

def single_package_abi_checker(repo_package_dir,
                               package_abi_check_temp_dir,
                               package_name,
                               package_file,
                               apt_server_config,
                               keep_temp=True,
                               specific_apt_version=None,
                               print_debug_tree=False) -> int:
    """
    Runs the ABI check in a folder containing a single package.
    """

    result = global_checker_results[package_name]

    logger.debug(f"[ABI_CHECKER]/{package_name}: running single_package_abi_checker")

    old_extract_dir = os.path.join(package_abi_check_temp_dir, "old")
    new_extract_dir = os.path.join(package_abi_check_temp_dir, "new")

    create_new_directory(old_extract_dir)
    create_new_directory(new_extract_dir)

    new_version = os.path.splitext(package_file)[0].split('_')[1]
    logger.info(f"[ABI_CHECKER]/{package_name}: New package version: {new_version}")

    new_deb_path = os.path.join(repo_package_dir, package_file)

    result.new_deb_name = package_file
    result.new_deb_version = new_version

    # -dev.deb package is optional, but if it exists, we need to extract it too
    # The package name may contain the major version number at the end, but by canonical convention, dev packages shall not contain that
    # major version, so deal with this to make sure the dev package not containing it is found
    package_name_without_major = (package_name[:-1] if package_name[-1].isdigit() else package_name)


    deb_dev_files = [f for f in os.listdir(repo_package_dir) if f.endswith('.deb') and package_name_without_major in f and "-dev" in f]

    if not deb_dev_files:
        logger.warning(f"[ABI_CHECKER]/{package_name}: No -dev.deb package found")
        new_dev_path = None
    elif len(deb_dev_files) == 1:
        logger.info(f"[ABI_CHECKER]/{package_name}: -dev.deb package found: {deb_dev_files[0]}")
        new_dev_path = os.path.join(repo_package_dir, deb_dev_files[0])
        result.new_dev_name = deb_dev_files[0]
    else:
        deb_dev_file = [f for f in deb_dev_files if f"{package_name_without_major}-dev" in f]
        if len(deb_dev_file) > 1:
            logger.critical(f"[ABI_CHECKER]/{package_name}: Multiple -dev.deb files found")
            result.new_dev_name = "ERROR : multiple detected"
            return -1
        new_dev_path = os.path.join(repo_package_dir, deb_dev_file[0])
        result.new_dev_name = deb_dev_file[0]

    # -dbgsym.ddeb package is optional, but if it exists, we need to extract it too

    deb_ddeb_files = [f for f in os.listdir(repo_package_dir) if f.endswith('.ddeb') and f"{package_name}-dbgsym" in f]

    if not deb_ddeb_files:
        logger.warning(f"[ABI_CHECKER]/{package_name}: No -dbgsym.ddeb package found")
        new_ddeb_path = None
    elif len(deb_ddeb_files) == 1:
        logger.info(f"[ABI_CHECKER]/{package_name}: -dbgsym.ddeb debug package found: {deb_ddeb_files[0]}")
        new_ddeb_path = os.path.join(repo_package_dir, deb_ddeb_files[0])
        result.new_ddeb_name = deb_ddeb_files[0]
    else:
        logger.critical(f"[ABI_CHECKER]/{package_name}: Multiple -dev-dbgsym.ddeb files found")
        result.new_ddeb_name = "ERROR : multiple detected"
        return False

    # Extract all the packages in the 'new' directory
    extract_deb(new_deb_path, new_dev_path, new_ddeb_path, new_extract_dir)

    if print_debug_tree:
        # Run the 'tree' command to list files in a tree structure
        tree_cmd = f"tree -a {new_extract_dir} | sed 's/^/       /'"
        tree_output = subprocess.run(tree_cmd, capture_output=True, text=True, shell=True)
        if tree_output.returncode == 0:
            logger.debug(f"[ABI_CHECKER]/{package_name}: Tree structure of new_extract_dir:\n{tree_output.stdout}")
        else:
            logger.error(f"[ABI_CHECKER]/{package_name}: Failed to run 'tree' command: {tree_output.stderr}")

    # ******* OLD DEB PACKAGE fetching *********************************************************

    logger.debug(f"[ABI_CHECKER]/{package_name}: Fetching old deb package from APT server")
    logger.debug(f"[ABI_CHECKER]/{package_name}: APT Server Config: {apt_server_config}")

    old_download_dir = os.path.join(package_abi_check_temp_dir, "old_download")

    create_new_directory(old_download_dir)

    apt_dir = os.path.join(old_download_dir, "apt")
    create_new_directory(apt_dir)

    # Use apt-get to download the latest version of the package
    if specific_apt_version is None:
        logger.debug(f"[ABI_CHECKER]/{package_name}: Using apt-get to download the *latest* version of {package_name}")
    else:
        logger.warning(f"[ABI_CHECKER]/{package_name}: Using apt-get to download the *specific* version {specific_apt_version} of {package_name}")

    # Create a temporary sources.list file
    temp_sources_list = os.path.join(apt_dir, "sources.list")
    with open(temp_sources_list, "w") as f:
        f.write(apt_server_config)

    cache_dir = os.path.join(apt_dir, "cache")
    create_new_directory(cache_dir)

    opt  = f" -o Dir::Etc::sourcelist={temp_sources_list}"
    opt += f" -o Dir::Etc::sourceparts=/dev/null"
    opt += f" -o Dir::State={cache_dir}"
    opt += f" -o Dir::Cache={cache_dir}"

    # Update the package list
    cmd = "apt-get update" + opt

    logger.debug(f"[ABI_CHECKER]/{package_name}: Running: {cmd}")
    apt_ret = subprocess.run(cmd, cwd=old_download_dir, shell=True, capture_output=True)
    if apt_ret.returncode != 0:
        logger.critical(f"[ABI_CHECKER]/{package_name}: Failed to update package list: {apt_ret.stderr}")
        return RETURN_PPA_ERROR

    # download the .deb package
    pkg = package_name + (("=" + specific_apt_version) if specific_apt_version else "")
    cmd = f"apt-get download {pkg}" + opt
    apt_ret = subprocess.run(cmd, cwd=old_download_dir, shell=True, capture_output=True)
    if apt_ret.returncode != 0:
        logger.error(f"[ABI_CHECKER]/{package_name}: Failed to download {pkg}: {apt_ret.stderr}")
        return RETURN_PPA_PACKAGE_NOT_FOUND
    else:
        logger.info(f"[ABI_CHECKER]/{package_name}: Downloaded {pkg}")

    # download the -dev.deb package
    pkg = package_name_without_major + "-dev"  + (("=" + specific_apt_version) if specific_apt_version else "")
    cmd = f"apt-get download {pkg}" + opt
    apt_ret = subprocess.run(cmd, cwd=old_download_dir, shell=True, capture_output=True)
    if apt_ret.returncode != 0:
        logger.warning(f"[ABI_CHECKER]/{package_name}: Failed to download {pkg}: {apt_ret.stderr}")
    else:
        logger.info(f"[ABI_CHECKER]/{package_name}: Downloaded {pkg}")

    # download the -dbgsym.deb package
    pkg = package_name + "-dbgsym"  + (("=" + specific_apt_version) if specific_apt_version else "")
    cmd = f"apt-get download {pkg}" + opt
    apt_ret = subprocess.run(cmd, cwd=old_download_dir, shell=True, capture_output=True)
    if apt_ret.returncode != 0:
        logger.warning(f"[ABI_CHECKER]/{package_name}: Failed to download {pkg}: {apt_ret.stderr}")
    else:
        logger.info(f"[ABI_CHECKER]/{package_name}: Downloaded {pkg}")


    # Configure the old packages paths
    old_deb_file = next((f for f in os.listdir(old_download_dir) if f.endswith('.deb') and '-dev' not in f), None)
    if old_deb_file is None:
        logger.critical(f"[ABI_CHECKER]/{package_name}: No .deb file found in '{old_download_dir}' that does not contain '-dev' in the name")
        result.old_deb_name = "ERROR : None found"
        raise Exception("No .deb file found in '{old_download_dir}' that does not contain '-dev' in the name")

    old_deb_path = os.path.join(old_download_dir, old_deb_file)
    result.old_deb_name = old_deb_file
    result.old_deb_version = os.path.splitext(old_deb_file)[0].split('_')[1]


    old_version = os.path.splitext(os.path.basename(old_deb_path))[0].split('_')[1]
    logger.info(f"[ABI_CHECKER]/{package_name}: Old package version: {old_version}")
    result.old_version = old_version

    old_dev_file = next((f for f in os.listdir(old_download_dir) if f.endswith('.deb') and '-dev' in f), None)
    if old_dev_file is None:
        old_dev_path = None
        logger.warning(f"[ABI_CHECKER]/{package_name}: No -dev.deb file that does contains '-dev' in the name")
    else:
        old_dev_path = os.path.join(old_download_dir, old_dev_file)
        result.old_dev_name = old_dev_file

    old_ddeb_file =  next((f for f in os.listdir(old_download_dir) if f.endswith('.ddeb') and '-dbgsym' in f), None)
    if old_ddeb_file is None:
        old_ddeb_path = None
        logger.warning(f"[ABI_CHECKER]/{package_name}: No -dbgsym.ddeb file found that does contains '-dbgsym' in the name")
    else:
        old_ddeb_path = os.path.join(old_download_dir, old_ddeb_file)
        result.old_ddeb_name = old_ddeb_file

    extract_deb(old_deb_path, old_dev_path, old_ddeb_path, old_extract_dir)

    if print_debug_tree:
        # Run the 'tree' command to list files in a tree structure
        tree_cmd = f"tree -a {old_extract_dir} | sed 's/^/       /'"
        tree_output = subprocess.run(tree_cmd, capture_output=True, text=True, shell=True)
        if tree_output.returncode == 0:
            logger.debug(f"[ABI_CHECKER]: Tree structure of old_extract_dir:\n{tree_output.stdout}")
        else:
            logger.error(f"[ABI_CHECKER]: Failed to run 'tree' command: {tree_output.stderr}")

    # ******* ABI CHECKING **********************************************************************

    report_dir = os.path.join(package_abi_check_temp_dir,"report")

    abidiff_result = compare_with_abipkgdiff(old_deb_path, old_dev_path, old_ddeb_path,
                                             new_deb_path, new_dev_path, new_ddeb_path,
                                             report_dir, include_non_reachable_types=True)

    return_value = 0

    # The return value between abidiff and abipkgdiff has the same meaning, so we can use the same analysis
    if abidiff_result != 0:

        cmd =f"cat {report_dir}/abipkgdiff_output.txt"

        log = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        result.abi_pkg_diff_output = log.stdout


        # Analyze the first 4 bits of the return value
        bit1 = (abidiff_result & 0b0001)
        bit2 = (abidiff_result & 0b0010) >> 1
        bit3 = (abidiff_result & 0b0100) >> 2
        bit4 = (abidiff_result & 0b1000) >> 3

        # Determine the overall result based on the bit analysis
        if bit1:
            logger.critical(f"[ABI_CHECKER]: abipkgdiff encountered an error")
            result.abi_pkg_diff_result = "ERROR"
            raise Exception("abipkgdiff encountered an error")
        if bit2:
            logger.error(f"[ABI_CHECKER]: abipkgdiff usage error. This has shown to be true for stripped packages")
            result.abi_pkg_diff_result = "STRIPPED-PACKAGE"
            return RETURN_ABI_STRIPPED_PACKAGE
        if bit3:
            result.abi_pkg_diff_result = "COMPATIBLE-DIFF"
            logger.warning(f"[ABI_CHECKER]: abipkgdiff detected ABI changes")

            return_value = RETURN_ABI_COMPATIBLE_DIFF

            match = re.search(r"Functions changes summary:\s+(\d+)\s+Removed,\s+(\d+)\s+Changed,", result.abi_pkg_diff_output)
            if match:
                changed_count = int(match.group(2))
                if changed_count > 0:
                    abidiff_result |= 0b1000
                    return_value = RETURN_ABI_INCOMPATIBLE_DIFF
                    result.abi_pkg_diff_result = "INCOMPATIBLE-DIFF"
                    logger.warning(f"[ABI_CHECKER]: Overriding to INCOMPATIBLE CHANGE since there are changed functions")

        if bit4:
            # if bit 4 is set, bit 3 must be too, so this fallthrough is ok
            result.abi_pkg_diff_result = "INCOMPATIBLE-DIFF"
            logger.warning(f"[ABI_CHECKER]: abipkgdiff detected ABI ***INCOMPATIBLE*** changes.")
            return_value = RETURN_ABI_INCOMPATIBLE_DIFF

        # Print the content of all the files in 'report_dir'
        for filename in os.listdir(report_dir):
            file_path = os.path.join(report_dir, filename)
            if os.path.isfile(file_path):
                with open(file_path, 'r') as file:
                    logger.debug(f"Content of {filename}:")
                    logger.warning(file.read())


    else:
        result.abi_pkg_diff_result = "NO-DIFF"
        logger.info(f"[ABI_CHECKER]/{package_name}: abipkgdiff did not find any differences between old and new packages")
        return_value = RETURN_ABI_NO_DIFF

    msg = "[ABI_CHECKER]/{package_name}: Although, no {pkg} was found for the {version} package, interpret the results with caution"

    if old_dev_path is None:
        logger.warning(msg.format(package_name=package_name, pkg="-dev.deb", version="old"))
    if new_dev_path is None:
        logger.warning(msg.format(package_name=package_name, pkg="-dev.deb", version="new"))
    if old_dev_path is None or new_dev_path is None:
        result.abi_pkg_diff_remark = "NO-DEV-PACKAGE"

    if old_ddeb_path is None:
        logger.warning(msg.format(package_name=package_name, pkg="-dbgsym.ddeb", version="old"))
    if new_ddeb_path is None:
        logger.warning(msg.format(package_name=package_name, pkg="-dbgsym.ddeb", version="new"))
    if old_ddeb_path is None or new_ddeb_path is None:
        if result.abi_pkg_diff_remark is not None:
            result.abi_pkg_diff_remark += ", NO-DBG-PACKAGE"
        else:
            result.abi_pkg_diff_remark = "NO-DBG-PACKAGE"


    if not keep_temp:
        logger.debug(f"[ABI_CHECKER]: Removing temporary directory {abi_check_temp_dir}")
        shutil.rmtree(abi_check_temp_dir)

    result.abi_pkg_diff_version_check = analyze_abi_diff_result(old_version, new_version, abidiff_result)

    return return_value

def extract_deb(deb_path, dev_path, ddeb_path, extract_dir):
    """Extract the content of a .deb package and its .ddeb to a specified directory."""

    if deb_path is None:
        raise ValueError("deb_path cannot be None")
    if not deb_path.endswith(".deb") or not os.path.isfile(deb_path):
        raise ValueError(f"Invalid deb_path: {deb_path}. Expected a file with .deb extension")

    cmd = ["dpkg", "-x", deb_path, extract_dir]
    subprocess.run(cmd, check=True)

    if dev_path is not None:
        cmd = ["dpkg", "-x", dev_path, extract_dir]
        subprocess.run(cmd, check=True)

    if ddeb_path is not None:
        cmd = ["dpkg", "-x", ddeb_path, extract_dir]
        subprocess.run(cmd, check=True)

def compare_with_abipkgdiff(old_deb_path, old_dev_path, old_ddeb_path,
                            new_deb_path, new_dev_path, new_ddeb_path,
                            report_dir, include_non_reachable_types=False):
    """Run abipkgdiff on two .deb packages and log the result."""

    logger.debug("[ABI_CHECKER]/[ABI_PKG_DIFF] : Comparing with abipkgdiff tool")

    os.makedirs(report_dir, exist_ok=True)
    log_path = os.path.join(report_dir, "abipkgdiff_output.txt")

    cmd = "abipkgdiff"

    if include_non_reachable_types:
        logger.debug("[ABI_CHECKER]/[ABI_PKG_DIFF] : Using --non-reachable-types option")
        cmd += " --non-reachable-types"

    if old_dev_path is not None and new_dev_path is not None:
        cmd += f" --devel-pkg1 {old_dev_path} --devel-pkg2 {new_dev_path}"
    else:
        logger.warning("[ABI_CHECKER]/[ABI_PKG_DIFF]: One or both of the -dev packages are missing. Potentially missing on information")

    if old_ddeb_path is not None and new_ddeb_path is not None:
        cmd += f" --debug-info-pkg1 {old_ddeb_path} --debug-info-pkg2 {new_ddeb_path}"
    else:
        logger.warning("[ABI_CHECKER]/[ABI_PKG_DIFF]: One or both of the -dbgsym.ddeb packages are missing. Potentially missing on information")

    cmd += f" {old_deb_path} {new_deb_path}"


    logger.debug(f"[ABI_CHECKER]/[ABI_PKG_DIFF]: command: {cmd}")

    abidiff_output = subprocess.run(cmd, capture_output=True, text=True, shell=True)

    with open(log_path, "w") as f:
        f.write(abidiff_output.stdout)

    rc = abidiff_output.returncode

    return rc

def version_bumped(old_version, new_version, index):
    """
    Checks if the major version has been increased.

    Args:
        old_version (str): The old version string (e.g., "1.0.0").
        new_version (str): The new version string (e.g., "2.0.0").

    Returns:
        bool: True if the major version has been increased, False otherwise.
    """
    if index not in ["major", "minor", "patch"]:
        raise ValueError("Index must be one of 'major', 'minor', or 'patch'")

    # Remove the build number from the version strings, if present
    old_version = old_version.split('-')[0]
    new_version = new_version.split('-')[0]

    # Split the version strings into their components
    old_version_parts = list(map(int, old_version.split('.')))
    new_version_parts = list(map(int, new_version.split('.')))

    # Determine the index of the version part to check
    if index == "major":
        index = 0
    elif index == "minor":
        index = 1
    elif index == "patch":
        index = 2

    # Check if the version part at the specified index has increased
    if new_version_parts[index] > old_version_parts[index]:
        return True
    else:
        return False


def extract_upstream_version(version):
    match = re.match(r'^(\d+\.\d+\.\d+)', version)
    return match.group(1) if match else version


def analyze_abi_diff_result(old_version, new_version, abidiff_result) -> str:
    import re

    logger.debug(f"old_version: {old_version}")
    logger.debug(f"new_version: {new_version}")

    # Keep the first part of the version, before the first '-', '+' or '~'

    old_version = extract_upstream_version(old_version)
    new_version = extract_upstream_version(new_version)


    logger.debug(f"old_version: {old_version}")
    logger.debug(f"new_version: {new_version}")

    # Define a regular expression pattern for a major-minor-patch version
    version_pattern = r"^\d+\.\d+\.\d+(-\d+)?$"

    # Check if old_version and new_version match the pattern
    if not re.match(version_pattern, old_version):
        raise ValueError(f"Invalid old version: {old_version}. Expected a string in the format 'major.minor.patch'")

    if not re.match(version_pattern, new_version):
        raise ValueError(f"Invalid new version: {new_version}. Expected a string in the format 'major.minor.patch'")

    logger.debug("[ABI_CHECKER]/[RESULT]: Performing version analysis of the ABI diff result versus the versions")

    # If both versions are valid, proceed with the analysis
    # For now, just print the versions and the result
    logger.debug(f"[ABI_CHECKER]/[RESULT]: Old version: {old_version}")
    logger.debug(f"[ABI_CHECKER]/[RESULT]: New version: {new_version}")

    if (abidiff_result & 0b0011):
        raise ValueError("[ABI_CHECKER]/[RESULT]: ASSERT : this scenario should have already been dealt with")

    abi_change = True if (abidiff_result & 0b0100) else False
    incompatible_abi_change = True if (abidiff_result & 0b1000) else False


    if incompatible_abi_change and not abi_change:
        raise ValueError("[ABI_CHECKER]/[RESULT]: ASSERT : impossible scenario, if incompatible is set, change has to be set too")

    major_bumped = version_bumped(old_version, new_version, "major")
    minor_bumped = version_bumped(old_version, new_version, "minor")
    patch_bumped = version_bumped(old_version, new_version, "patch")

    if incompatible_abi_change: # Incompatible change
        logger.error(f"[ABI_CHECKER]/[RESULT]: INCOMPATIBLE change detected")

        if major_bumped:
            result = "PASS : Major version increased"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.debug("[ABI_CHECKER]/[RESULT]: Increasing the major version for an incompatible ABI is what is required")

        elif minor_bumped:
            result = "FAIL : Minor version increased, needed major increase"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.debug(f"[ABI_CHECKER]/[RESULT]: Increasing only the minor version for an incompatible ABI change is not enough")

        elif patch_bumped:
            result = "FAIL : Patch version increased, needed major increase"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.debug(f"[ABI_CHECKER]/[RESULT]: Increasing only the patch version for an incompatible ABI change is not enough")

        else:
            result = "FAIL : No version increase"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.debug(f"[ABI_CHECKER]/[RESULT]: Increasing the version number is required for an ABI change")

    elif abi_change: # Compatible change
        logger.warning(f"[ABI_CHECKER]/[RESULT]: COMPATIBLE change detected")

        if major_bumped:
            result = "PASS : Major version increased"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.warning(f"[ABI_CHECKER]/[RESULT]: Increasing the major version for a compatible ABI change was probably overkill, but at least it respects version increase")

        elif minor_bumped:
            result = "PASS : Minor version increased"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.debug(f"[ABI_CHECKER]/[RESULT]: Increasing the minor version for a compatible ABI change is what is required")

        elif patch_bumped:
            result = "FAIL : Patch version increased, needed minor increase"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.debug(f"[ABI_CHECKER]/[RESULT]: Increasing only the patch number while there is an ABI change, albeit compatible, is not enough")

        else:
            result = "FAIL : No version increase"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.debug(f"[ABI_CHECKER]/[RESULT]: Increasing at least the minor version number is required for a compatible ABI change")

    else: # No change
        logger.info(f"[ABI_CHECKER]/[RESULT]: No ABI change detected")

        if major_bumped:
            result = "PASS : Major version increased"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.warning("[ABI_CHECKER]/[RESULT]: Increasing the major version when there is no ABI change is probably overkill, but at least it respects version increase")

        elif minor_bumped:
            result = "PASS : Minor version increased"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.warning(f"[ABI_CHECKER]/[RESULT]: Increasing the minor version for a compatible ABI change is probably overkill, but at least it respects version increase")

        elif patch_bumped:
            result = "PASS : Patch version increased"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")
            logger.debug(f"[ABI_CHECKER]/[RESULT]: Increasing only the patch number while there is no ABI change seems reasonable")

        else:
            result = "PASS : No version increase"
            logger.debug(f"[ABI_CHECKER]/[RESULT]: {result}")

    return result

if __name__ == "__main__":
    main()
