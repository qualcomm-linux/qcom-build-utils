#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
ppa_organizer.py

Organizes the output packages from a build into an organized PPA structure

A PPA will contain a dists folder for the Packages.gz files, and a pool folder for the actual content.

Consider this example tree for an example package build folder with sbuild:

build/
├── libqcom-example_1.1.0_arm64-2025-08-27T23:32:19Z.build
├── libqcom-example_1.1.0_arm64.build -> libqcom-example_1.1.0_arm64-2025-08-27T23:32:19Z.build
├── libqcom-example_1.1.0_arm64.buildinfo
├── libqcom-example_1.1.0_arm64.changes
├── libqcom-example_1.1.0.dsc
├── libqcom-example1_1.1.0_arm64.deb
├── libqcom-example1-dbgsym_1.1.0_arm64.ddeb
└── libqcom-example-dev_1.1.0_arm64.deb

Note that here there is only one 'libqcom-example' package built, but when sbuild builds a package,
the debian/control file can list more packages.

The goal of the operation is to copy over the .dsc, .deb and .ddeb files :
├── libqcom-example_1.1.0.dsc
├── libqcom-example1_1.1.0_arm64.deb
├── libqcom-example1-dbgsym_1.1.0_arm64.ddeb
└── libqcom-example-dev_1.1.0_arm64.deb

Into the PPA structure, like this example tree :
└── pool
    └── noble
       └── stable
            └── main
                └── libqcom-example
                    ├── libqcom-example_1.1.0.dsc
                    ├── libqcom-example1_1.1.0_arm64.deb
                    ├── libqcom-example1-dbgsym_1.1.0_arm64.ddeb
                    └── libqcom-example-dev_1.1.0_arm64.deb

This script will extract the 'canonical' package name (ie, without the major number in it, in this case its 1)
and create a folder in the PPA structure for this package name, and copy over all the .deb/ddeb that correspondt to it.
 
This operation will be done for all the 'canonical' package names because again, there can be multiple of this example package
alongside one another

"""

import os
import sys
import shutil
import argparse
import subprocess

from color_logger import logger
from helpers import create_new_directory

def parse_arguments():
    parser = argparse.ArgumentParser(description="Organizes the output packages from a folder into a PPA repo structure")
    parser.add_argument("--build-dir",
                        required=True,
                        help="The build directory where the packages have been built (.deb/.ddeb)")

    parser.add_argument("--output-dir",
                        required=True,
                        help="The output directory where the packages will be organized. In the example from the doc, it would be [...]/pool/noble/stable/main folder")

    args = parser.parse_args()

    return args



def reorganize(build_dir : str, output_dir : str):

    logger.debug(f"Organize files from build dir : {build_dir} into : {output_dir}")

    # Create a list of all the packages (.deb, -dev.deb, -dbgsym.ddeb)
    files = os.listdir(build_dir)
    
    dsc_files = [f for f in files if f.endswith('.dsc')                     ]
    deb_files = [f for f in files if f.endswith('.deb')  and "-dev" not in f]
    dev_files = [f for f in files if f.endswith('.deb')  and "-dev"     in f]
    dbg_files = [f for f in files if f.endswith('.ddeb') and "-dbgsym"  in f]


    # Isolate all the canonical package names (i.e. remove the version and architecture from the filenames)
    dsc_pkg_names = [f.split('_')[0]                         for f in dsc_files]
    deb_pkg_names = [f.split('_')[0]                         for f in deb_files]
    dev_pkg_names = [f.split('_')[0].removesuffix("-dev")    for f in dev_files]
    dbg_pkg_names = [f.split('_')[0].removesuffix("-dbgsym") for f in dbg_files]

    # Second pass to remove all the major version that often suffix the package names
    # The norm is that packages that include the major in the deb name DO NOT include it in the dev
    # this ensures we deal with root package name and not doubles when we combine the lists below
    dsc_pkg_names = [(f[:-1] if f[-1].isdigit() else f) for f in dsc_pkg_names]
    deb_pkg_names = [(f[:-1] if f[-1].isdigit() else f) for f in deb_pkg_names]
    dev_pkg_names = [(f[:-1] if f[-1].isdigit() else f) for f in dev_pkg_names]
    dbg_pkg_names = [(f[:-1] if f[-1].isdigit() else f) for f in dbg_pkg_names]

    package_names = list(set(dsc_pkg_names) | set(deb_pkg_names) | set(dev_pkg_names) | set(dbg_pkg_names))

    # Important that the list be sorted from the longest package name to the shortest
    # Starting with the longest and removing it from the _files lists ensures we deal
    # properly specificaly with the edge case or qcom-adreno/qcom-adreno-cl where one
    # package name is a substring of the other
    package_names.sort(reverse=True, key=lambda x: len(x))

    for package_name in package_names:

        output_dir_pkg = os.path.join(output_dir, package_name)
        
        # Do not delete if the directory exists, it may very well contain the same package, but with older versions
        # We want to copy the newly built packages alongside the other versions
        create_new_directory(output_dir_pkg, delete_if_exists=False)

        logger.debug(f"Re-organizing outputs of package: {package_name}")

        dsc_package = next((file for file in dsc_files if package_name in file), None)
        deb_package = next((file for file in deb_files if package_name in file), None)
        dev_package = next((file for file in dev_files if package_name in file), None)
        dbg_package = next((file for file in dbg_files if package_name in file), None)

        if dsc_package is not None:
            shutil.copy(os.path.join(build_dir, dsc_package), os.path.join(output_dir_pkg, dsc_package))
            logger.info(f'Copied {dsc_package} to {output_dir_pkg}')
            dsc_files.remove(deb_package)
        else:
            logger.debug(f"No .dsc package found for {package_name}")


        if deb_package is not None:
            shutil.copy(os.path.join(build_dir, deb_package), os.path.join(output_dir_pkg, deb_package))
            logger.info(f'Copied {deb_package} to {output_dir_pkg}')
            deb_files.remove(deb_package)
        else:
            logger.debug(f"No .deb package found for {package_name}")

        if dev_package is not None:
            shutil.copy(os.path.join(build_dir, dev_package), os.path.join(output_dir_pkg, dev_package))
            logger.info(f'Copied {dev_package} to {output_dir_pkg}')
            dev_files.remove(dev_package)
        else:
            logger.debug(f"No -dev.deb package found for {package_name}")

        if dbg_package is not None:
            shutil.copy(os.path.join(build_dir, dbg_package), os.path.join(output_dir_pkg, dbg_package))
            logger.info(f'Copied {dbg_package} to {output_dir_pkg}')
            dbg_files.remove(dbg_package)
        else:
            logger.debug(f"No -dbgsym.ddeb package found for {package_name}")

def main():

    args = parse_arguments()

    logger.debug(f"args: {args}")

    # Make sure to resolve relative paths to absolute
    if not os.path.isabs(args.build_dir):
        args.build_dir = os.path.abspath(args.build_dir)

    if not os.path.isabs(args.output_dir):
        args.output_dir = os.path.abspath(args.output_dir)

    reorganize(args.build_dir, args.output_dir)

if __name__ == "__main__":
    main()
