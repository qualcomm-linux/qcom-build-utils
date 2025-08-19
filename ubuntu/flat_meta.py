# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

import os
import shutil
import subprocess
import tarfile
from helpers import logger

def create_flat_meta(pack_variant, flavor, target_hw, workspace):
    board_specific_path = os.path.join(workspace, "sources/modem-apis/qclinux/Ubuntu_NHLOS/")
    inc_file = os.path.join(board_specific_path, f"firmware-{target_hw}.inc")
    if not os.path.isfile(inc_file):
        raise FileNotFoundError(f"INC file not found: {inc_file}")

    output_files = ["system.img", "efi.bin", "dtb.bin"]
    output_dir = os.path.join(workspace, "out")
    # Check for missing files
    missing_files = [f for f in output_files if not os.path.isfile(os.path.join(output_dir, f))]

    # Raise an exception if any files are missing
    if missing_files:
        logger.info("Files missed required for Flatmeta creation, Ensure build.py --pack-image done.")
        raise FileNotFoundError(f"The following required files are missing from {output_dir}: {', '.join(missing_files)}")
    logger.info(f"Creating Flat meta for {target_hw}")
    # ExtractBUILD_ID BUILD_ID and BIN_PATH
    build_id = None
    bin_path = None
    with open(inc_file, 'r') as f:
        for line in f:
            if 'BUILD_ID' in line:
                build_id = line.split('=')[1].strip().strip('"')
            elif 'BIN_PATH' in line:
                bin_path = line.split('=')[1].strip().strip('"')

    if not build_id or not bin_path:
        raise ValueError("BUILD_ID or BIN_PATH not found in the .inc file")

    print(f"Meta SP : {bin_path}")
    print(f"Meta ID : {build_id}")

    # Download the tar.gz file
    tarball_url = f"https://artifactory-las.qualcomm.com/artifactory/lint-lv-local/ubun_nhlos/{bin_path}/{build_id}.tar.gz"
    tarball_name = f"{build_id}.tar.gz"
    subprocess.run(["wget", "--no-check-certificate", tarball_url], check=True)

    # Extract the tarball
    extract_path = os.path.join(f"{workspace}", f"ub_{pack_variant}_image", flavor, target_hw)
    os.makedirs(extract_path, exist_ok=True)
    with tarfile.open(tarball_name, "r:gz") as tar:
        tar.extractall(path=extract_path)

    # Copy output files
    for file in output_files:
        src = os.path.join(output_dir, file)
        if os.path.exists(src):
            shutil.copy(src, extract_path)
    # Copy vmlinu* files
    for file in os.listdir(output_dir):
        if file.startswith("vmlinu"):
            shutil.copy(os.path.join(output_dir, file), extract_path)

    # Remove the tarball
    os.remove(tarball_name)
    print(f"✅ Flat meta created successfully under : {extract_path}.")
