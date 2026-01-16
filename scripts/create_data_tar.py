#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
"""
create_data_tar.py

Standalone utility to:
- Parse a .changes file (provided via --changes-file, or auto-detected)
- Extract each referenced .deb into data/<pkg>/<arch>/
- Pack the data/ directory as <changes_basename>.tar.gz in the same directory as the .changes file
"""

import os
import sys
import argparse
import glob
import re
import tarfile
import subprocess
import traceback

from color_logger import logger


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Generate data.tar.gz by extracting deb contents to data/<pkg>/<arch>/ from a .changes file."
    )
    parser.add_argument(
        "--changes-file",
        required=False,
        default="",
        help="Path to the .changes file. If not provided, the newest .changes in --output-dir will be used."
    )
    parser.add_argument(
        "--output-dir",
        required=False,
        default=".",
        help="Directory to search for the newest .changes when --changes-file is not provided. Also used as default working dir."
    )
    parser.add_argument(
        "--arch",
        required=False,
        default="arm64",
        help="Architecture subfolder under each package directory (default: arm64)."
    )
    return parser.parse_args()


def find_changes_file(changes_file: str, output_dir: str) -> str:
    """
    Return the path to the .changes file to use.
    Priority:
      1) If changes_file is provided and exists, use it.
      2) Else, find newest *.changes in output_dir.
    """
    if changes_file:
        if os.path.exists(changes_file):
            return os.path.abspath(changes_file)
        else:
            raise FileNotFoundError(f"Specified --changes-file not found: {changes_file}")

    # Search for newest .changes in output_dir
    candidates = glob.glob(os.path.join(output_dir or '.', '*.changes'))
    if not candidates:
        raise FileNotFoundError(f"No .changes files found in directory: {output_dir}")

    newest = max(candidates, key=lambda p: os.path.getmtime(p))
    return os.path.abspath(newest)


def collect_debs_from_changes(changes_path: str):
    """
    Read the .changes file and collect referenced .deb filenames.
    Returns a list of basenames (or relative names) as they appear in the changes file.
    """
    try:
        with open(changes_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except Exception as e:
        raise RuntimeError(f"Failed to read .changes file {changes_path}: {e}")

    # Regex to capture *.deb tokens
    debs = [fn for _, fn in re.findall(r'(^|\\s)([^\\s]+\\.deb)\\b', text)]
    if not debs:
        # Fallback: simple tokenization
        for line in text.splitlines():
            if '.deb' in line:
                for tok in line.split():
                    if tok.endswith('.deb'):
                        debs.append(tok)

    # De-duplicate, keep order
    uniq = list(dict.fromkeys(debs))
    if not uniq:
        raise RuntimeError(f"No .deb files referenced in .changes file: {changes_path}")
    return uniq


def extract_debs_to_data(deb_names, work_dir, arch) -> bool:
    """
    For each deb in deb_names (relative to work_dir), extract with dpkg-deb -x
    into work_dir/data/<pkg>/<arch>/
    Returns True if at least one deb was extracted successfully.
    """
    data_root = os.path.join(work_dir, 'data')
    os.makedirs(data_root, exist_ok=True)

    extracted_any = False
    for deb_name in deb_names:
        deb_path = deb_name if os.path.isabs(deb_name) else os.path.join(work_dir, deb_name)
        if not os.path.exists(deb_path):
            logger.warning(f"Referenced .deb not found: {deb_path} (skipping)")
            continue

        base = os.path.basename(deb_path)
        # Expected: <pkg>_<version>_<arch>.deb, fall back to stem if no underscores
        pkg = base.split('_')[0] if '_' in base else os.path.splitext(base)[0]
        dest_dir = os.path.join(data_root, pkg, arch)
        os.makedirs(dest_dir, exist_ok=True)

        logger.debug(f"Extracting {deb_path} -> {dest_dir}")
        try:
            subprocess.run(['dpkg-deb', '-x', deb_path, dest_dir], check=True)
            extracted_any = True
        except FileNotFoundError:
            logger.error("dpkg-deb not found on host. Install dpkg tools to enable extraction.")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"dpkg-deb failed extracting {deb_path}: {e}")

    if not extracted_any:
        logger.error("No .deb files were successfully extracted.")
        return False
    return True


def create_tar_of_data(work_dir: str, tar_name: str) -> str:
    """
    Create work_dir/<tar_name> containing the data/ directory.
    Returns the path to the tarball on success.
    """
    data_root = os.path.join(work_dir, 'data')
    if not os.path.isdir(data_root):
        raise RuntimeError(f"Missing data directory to archive: {data_root}")

    tar_path = os.path.join(work_dir, tar_name)
    logger.debug(f"Creating tarball: {tar_path}")
    with tarfile.open(tar_path, 'w:gz') as tar:
        tar.add(data_root, arcname='data')
    return tar_path


def main():
    args = parse_arguments()

    # Determine the .changes file
    try:
        changes_path = find_changes_file(args.changes_file, args.output_dir)
    except Exception as e:
        logger.critical(str(e))
        sys.exit(1)

    # The working directory is where the .changes was generated (and where the debs are expected)
    work_dir = os.path.dirname(changes_path)
    logger.debug(f"Using .changes file: {changes_path}")
    logger.debug(f"Working directory: {work_dir}")

    # Collect debs from the changes file
    try:
        deb_names = collect_debs_from_changes(changes_path)
    except Exception as e:
        logger.critical(str(e))
        sys.exit(1)

    # Extract each deb into data/<pkg>/<arch>/
    ok = extract_debs_to_data(deb_names, work_dir, args.arch)
    if not ok:
        sys.exit(1)

    # Create tarball named after the .changes file (e.g., pkg_1.0_arm64.tar.gz)
    try:
        base = os.path.basename(changes_path)
        tar_name = re.sub(r'\.changes$', '.tar.gz', base)
        if tar_name == base:
            tar_name = base + '.tar.gz'
        tar_path = create_tar_of_data(work_dir, tar_name)
        logger.info(f"Created tarball: {tar_path}")
    except Exception as e:
        logger.critical(f"Failed to create tarball: {e}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Uncaught exception: {e}")
        traceback.print_exc()
        sys.exit(1)
