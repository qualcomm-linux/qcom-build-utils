# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
helper.py

This module provides utilities for managing Debian package builds and related operations.
It includes functions for executing shell commands, managing files and directories,
logging, and setting up a local APT server.
"""

import os
import stat
import shlex
import random
import shutil
import logging
import subprocess
import glob
from pathlib import Path
from git import Repo
from apt_server import AptServer
from constants import TERMINAL, HOST_FS_MOUNT
from color_logger import logger

def check_if_root() -> bool:
    """
    Checks if the script is being run with root privileges.

    Returns:
    --------
    - bool: True if the script is run as root, False otherwise.
    """
    return os.geteuid() == 0

def check_and_append_line_in_file(file_path, line_to_check, append_if_missing=False):
    """
    Checks if a specific line exists in a file and appends it if it is missing.

    Args:
    -----
    - file_path (str): The path to the file to check.
    - line_to_check (str): The line to check for in the file.
    - append_if_missing (bool): If True, appends the line to the file if it is missing.

    Returns:
    --------
    - bool: True if the line exists or was appended, False if the line does not exist and append_if_missing is False.
    """
    if not os.path.exists(file_path):
        logger.error(f"{file_path} does not exist.")
        exit(1)

    with open(file_path, "r") as file:
        lines = file.readlines()

    for line in lines:
        if line.strip() == line_to_check.strip():
            return True

    if append_if_missing:
        with open(file_path, "a") as file:
            file.write(f"\n{line_to_check}\n")
        return True

    return False

def parse_debs_manifest(manifest_path):
    """
    Parses a manifest file and returns a dictionary of module names and their corresponding versions.
    """
    DEBS = []
    user_manifest = Path(manifest_path)
    if not user_manifest.is_file() or not user_manifest.name.endswith('.manifest'):
        raise ValueError(f"Provided manifest path '{user_manifest}' is not a valid '.manifest' file.")
    if os.path.isfile(manifest_path):
        with open(manifest_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = list(line.split('\t'))
                    DEBS.append({
                        'package': parts[0],
                        'version': parts[1] if len(parts) > 1 else None,
                    })
            return DEBS
    else:
        print(f"Manifest file {manifest_path} not found.")
        return None

def run_command(command, check=True, get_object=False, cwd=None):
    """
    Executes a shell command and returns the output, logging any errors.

    Args:
    -----
    - command (str): The shell command to execute.
    - check (bool): If True, raises an exception on a non-zero exit code.
    - get_object (bool): If True, returns the result object instead of the output string.
    - cwd (str): The working directory to execute the command in.

    Returns:
    --------
    - str: The standard output of the command.

    Raises:
    -------
    - Exception: If the command fails and check is True.
    """

    logger.debug(f'Running command: {command}')

    try:
        result = subprocess.run(command, shell=True, check=check, capture_output=True, text=True, cwd=cwd)

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with return value: {e.returncode}")
        logger.error(f"stderr: {e.stderr.strip() if e.stderr else str(e)}")
        logger.error(f"stdout: {e.stdout.strip()}")
        raise Exception(e)

    stderr = result.stderr.strip()
    if stderr:
        if result.returncode == 0:
            logger.debug(f"Successful return value, yet there is content in stderr: {stderr}")
        else:
            logger.error(f"Error: {stderr}")

    return result.stdout.strip()

def run_command_for_result(command):
    """
    Executes a shell command and returns the output and return code in a dictionary.

    Args:
    -----
    - command (str): The shell command to execute.

    Returns:
    --------
    - dict: A dictionary containing:
        - "output" (str): The standard output of the command.
        - "returncode" (int): The return code of the command.
    """
    command = command.strip()
    logger.debug(f'Running for result: {command}')
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.sys.stdout)
        return {"output": result.decode("utf-8").strip(), "returncode": 0}
    except subprocess.CalledProcessError as e:
        return {"output": e.output.decode("utf-8", errors="ignore").strip(), "returncode": e.returncode}

def set_env(key, value):
    """
    Sets an environment variable.

    Args:
    -----
    - key (str): The name of the environment variable.
    - value (str): The value to set for the environment variable.
    """
    os.environ[str(key)] = str(value)

def cleanup_directory(dirname):
    """
    Removes a directory and its contents.

    Args:
    -----
    - dirname (str): The path to the directory to clean up.

    Raises:
    -------
    - Exception: If an error occurs while trying to remove the directory.
    """
    try:
        if os.path.exists(dirname):
            shutil.rmtree(dirname)
    except Exception as e:
        logger.error(f"Error cleaning directory {dirname}: {e}")
        raise Exception(e)

def cleanup_file(file_path):
    """
    Deletes a specified file.

    Args:
    -----
    - file_path (str): The path to the file to delete.

    Raises:
    -------
    - Exception: If an error occurs while trying to delete the file.
    """

    logger.debug(f"Cleaning file {file_path}")

    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        logger.error(f"Error cleaning file {file_path}: {e}")
        raise Exception(e)

def create_new_directory(dirname, delete_if_exists=True):
    """
    Creates a new directory, optionally deleting it if it already exists.

    Args:
    -----
    - dirname (str): The path to the directory to create.
    - delete_if_exists (bool): If True, deletes the directory if it already exists.

    Raises:
    -------
    - SystemExit: If an error occurs while creating the directory.
    """
    try:
        if os.path.exists(dirname):
            # Check if the directory exists, if so delete it
            if delete_if_exists:
                cleanup_directory(dirname)
        # Create the destination directory
        os.makedirs(dirname, exist_ok=not delete_if_exists)
    except Exception as e:
        logger.error(f"Error creating directory {dirname}: {e}")
        exit(1)

def create_new_file(filepath, delete_if_exists=True) -> str:
    """
    Creates a new file, optionally deleting it if it already exists.

    Args:
    -----
    - filepath (str): The path to the file to create.
    - delete_if_exists (bool): If True, deletes the file if it already exists.

    Returns:
    --------
    - str: The path to the created file.

    Raises:
    -------
    - SystemExit: If an error occurs while creating the file.
    """
    try:
        if os.path.exists(filepath):
            # Check if the file exists, if so don't do anything
            return filepath
        # Create the destination directory
        with open(filepath, 'w') as f: pass
        return filepath
    except Exception as e:
        logger.error(f"Error creating file {filepath}: {e}")
        exit(1)

def mount_img(IMG_PATH, MOUNT_DIR, MOUNT_HOST_FS=False, MOUNT_IMG=True):
    """
    Mounts an image file to a specified directory, with optional host filesystem mounts.

    Args:
    -----
    - IMG_PATH (str): The path to the image file to mount.
    - MOUNT_DIR (str): The directory to mount the image to.
    - MOUNT_HOST_FS (bool): If True, mounts the host filesystem directories.
    - MOUNT_IMG (bool): If True, mounts the image file.
    """
    if MOUNT_IMG:
        create_new_directory(MOUNT_DIR)
        run_command(f"mount {IMG_PATH} {MOUNT_DIR}")
    if MOUNT_HOST_FS:
        for direc in HOST_FS_MOUNT:
            run_command(f"mount --bind /{direc} {MOUNT_DIR}/{direc}")

def umount_dir(MOUNT_DIR, UMOUNT_HOST_FS=False):
    """
    Unmounts a specified directory and optionally unmounts host filesystem mounts.

    If the directory is not mounted, (ie, return code 32 from umount) then it is
    silently ignored.

    Args:
    -----
    - MOUNT_DIR (str): The directory to unmount.
    - UMOUNT_HOST_FS (bool): If True, unmounts the host filesystem directories.
    """

    logger.debug(f"umount dir {MOUNT_DIR}")

    if UMOUNT_HOST_FS:
        for direc in HOST_FS_MOUNT:
            result = subprocess.run(f"umount -l {MOUNT_DIR}/{direc}",
                                    shell=True, capture_output=True, text=True)

            if result.returncode != 0 and result.returncode != 32:
                logger.error(f"Failed to unmount {MOUNT_DIR}/{direc}: {result.stderr}")

    result = subprocess.run(f"umount -l {MOUNT_DIR}",
                            shell=True, capture_output=True, text=True)
    if result.returncode != 0 and result.returncode != 32:
        logger.error(f"Failed to unmount {MOUNT_DIR}: {result.stderr}")

def change_folder_perm_read_write(DIR):
    """
    Changes permissions of a directory and its contents to allow read and write access.

    Args:
    -----
    - DIR (str): The path to the directory whose permissions are to be changed.

    Raises:
    -------
    - Exception: If an error occurs while changing permissions.
    """
    try:
        # Change permissions for the root folder itself
        current_permissions = os.stat(DIR).st_mode
        new_permissions = current_permissions

        if current_permissions & stat.S_IWUSR:
            new_permissions |= stat.S_IWOTH

        if current_permissions & stat.S_IXUSR:
            new_permissions |= stat.S_IXOTH

        os.chmod(DIR, new_permissions)

        for root, dirs, files in os.walk(DIR):
            for dir_ in dirs:
                dir_path = os.path.join(root, dir_)
                current_permissions = os.stat(dir_path).st_mode
                new_permissions = current_permissions

                if current_permissions & stat.S_IWUSR:
                    new_permissions |= stat.S_IWOTH
                if current_permissions & stat.S_IXUSR:
                    new_permissions |= stat.S_IXOTH

                os.chmod(dir_path, new_permissions)

            for file in files:
                file_path = os.path.join(root, file)
                current_permissions = os.stat(file_path).st_mode
                new_permissions = current_permissions

                if current_permissions & stat.S_IWUSR:
                    new_permissions |= stat.S_IWOTH
                if current_permissions & stat.S_IXUSR:
                    new_permissions |= stat.S_IXOTH

                os.chmod(file_path, new_permissions)

        logger.info(f"Permissions updated conditionally for all folders and files in {DIR}.")
    except Exception as e:
        logger.error(f"Error while changing permissions: {e}")

def print_build_logs(directory):
    """
    Prints the contents of build log files in a specified directory.

    Args:
    -----
    - directory (str): The path to the directory containing build logs.
    """
    logger.info("===== Build Logs Start ======")
    build_logs = []
    for entry in os.listdir(directory):
        full_path = os.path.join(directory, entry)
        if (os.path.islink(full_path) and entry.endswith(".build")) or entry.endswith(".mmdebstrap.build"):
            build_logs.append(entry)
    for entry in build_logs:
        full_path = os.path.join(directory, entry)
        logger.info(f"===== {full_path} =====")
        content = None
        with open(full_path, 'r') as log_file:
            content = log_file.read()
        logger.error(content)
    logger.info("=====  Build Logs End  ======")

def start_local_apt_server(dir):
    """
    Starts a local APT server in the specified directory and returns the APT repository line.

    Args:
    -----
    - dir (str): The directory to serve as the APT repository.

    Returns:
    --------
    - str: The APT repository line to add to sources.list.
    """

    server = AptServer(directory=dir, port=random.randint(7500, 8500))
    server.start()

    return f"deb [trusted=yes arch=arm64] http://localhost:{server.port} stable main"

def build_deb_package_gz(dir, start_server=True) -> str:
    """
    Builds a Debian package and creates a compressed Packages file, optionally starting a local APT server.

    Args:
    -----
    - dir (str): The directory where the package is built.
    - start_server (bool): If True, starts a local APT server after building the package.

    Returns:
    --------
    - str: The APT repository line if a server is started, None otherwise.

    Raises:
    -------
    - Exception: If an error occurs while creating the Packages file.
    """

    packages_dir = os.path.join(dir, 'dists', 'stable', 'main', 'binary-arm64')
    packages_path = os.path.join(packages_dir, "Packages")

    try:
        os.makedirs(packages_dir, exist_ok=True)

        cmd = f'dpkg-scanpackages -m . > {packages_path}'

        result = subprocess.run(cmd, shell=True, cwd=dir, check=False, capture_output=True, text=True)

        if result.returncode != 0:
            logger.error(f"Error running : {cmd}")
            logger.error(f"stdout : {result.stdout}")
            logger.error(f"stderr : {result.stderr}")

            raise Exception(result.stderr)

        # Even with a successful exit code, dpkg-scanpackages still outputs the number of entries written to stderr        logger.debug(result.stderr.strip())


        cmd = f"gzip -k -f {packages_path}"
        result = subprocess.run(cmd, shell=True, cwd=dir, check=False, capture_output=True, text=True)

        if result.returncode != 0:
            logger.error(f"Error running : {cmd}")
            logger.error(f"stdout : {result.stdout}")
            logger.error(f"stderr : {result.stderr}")

            raise Exception(result.stderr)

        logger.debug(f"Packages file created at {packages_path}.gz")

    except Exception as e:
        logger.error(f"Error creating Packages file in {dir} : {e}")
        raise Exception(e)

    if start_server:
        return start_local_apt_server(dir)
    return None


def pull_debs_wget(manifest_file_path, out_dir,DEBS_to_download_list,base_url):
    """
    Downloads Debian packages from a remote repository using wget.

    Args:
    -----
    - manifest_file_path (str): Path to the manifest file containing package versions.
    - out_dir (str): Directory where downloaded packages will be saved.
    - DEBS_to_download_list (list): List of package name prefixes to download.
    - base_url (str): Base URL of the repository to download packages from.

    Returns:
    --------
    - int: Number of packages successfully downloaded.

    Raises:
    -------
    - Exception: If an error occurs while downloading packages.
    """
    # Read manifest file
    # Parse manifest into a dictionary
    with open(manifest_file_path, 'r') as f:
        manifest_text = f.read()

    # Parse manifest into a dictionary
    version_map = {}
    for line in manifest_text.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2:
            name, version = parts[0], parts[1]
            version_map[name] = version


    # Generate wget links and download
    os.makedirs(out_dir, exist_ok=True)
    for module in DEBS_to_download_list:
        for name, version in version_map.items():
            if name.startswith(module):
                first_letter = name[0]
                deb_name = f"{name}_{version}_arm64.deb"
                url = f"{base_url}/{first_letter}/{name}/{deb_name}"
                output_path = os.path.join(out_dir,name,deb_name)
                create_new_directory(os.path.join(out_dir,name))
                # Construct wget command
                wget_cmd = ["wget", "--no-check-certificate", url, "-O", output_path]
                try:
                    logger.info(f"Downloading {url}...")
                    subprocess.run(wget_cmd, check=True)
                    logger.info(f"Saved to {output_path}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"error: Failed to download {url}: {e}")
                break  # Stop after first match
