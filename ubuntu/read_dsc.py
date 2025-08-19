# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
read_dsc.py

This script provides a function to extract MD5 checksums, sizes, and filenames from a Debian source control (DSC) file.
It allows for filtering of the extracted files based on an optional filename pattern, making it useful for
analyzing package files in Debian packaging workflows.
"""

import fnmatch

def extract_md5sum_from_files(dsc_path, filename_pattern=None):
    """
    Extracts MD5 checksums, sizes, and filenames from a Debian source control (DSC) file.

    Args:
    -----
    - dsc_path (str): The path to the DSC file from which to extract information.
    - filename_pattern (str, optional): A filename pattern to filter the results.
                                        Only files matching this pattern will be included in the output.

    Returns:
    --------
    - list: A list of dictionaries, each containing the following keys:
        - 'md5sum' (str): The MD5 checksum of the file.
        - 'size' (str): The size of the file in bytes.
        - 'filename' (str): The name of the file.

    Example:
    --------
        extract_md5sum_from_files('path/to/file.dsc', '*.deb')
        [{'md5sum': 'abc123...', 'size': '12345', 'filename': 'package.deb'}, ...]

    Notes:
    ------
    - The function reads the DSC file line by line, looking for the 'Files:' section.
    - It extracts the MD5 checksum, size, and filename for each file listed in that section.
    - If a filename pattern is provided, only files matching that pattern will be included in the output.
    """
    entries = []
    in_files_section = False

    with open(dsc_path, 'r') as dsc_file:
        for line in dsc_file:
            if line.startswith('Files:'):
                in_files_section = True
                continue

            if in_files_section and not line.startswith(' '):
                break

            if in_files_section and line.startswith(' '):
                parts = line.strip().split(maxsplit=2)
                if len(parts) == 3:
                    md5sum, size, filename = parts
                    if not filename_pattern or fnmatch.fnmatch(filename, filename_pattern):
                        entries.append({
                            'md5sum': md5sum,
                            'size': size,
                            'filename': filename
                        })

    return entries
