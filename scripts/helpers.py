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
import subprocess
import glob
from pathlib import Path

from color_logger import logger

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

