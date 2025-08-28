qcom-build-utils
--------

Overview
--------
build.py is a Python-based build orchestration script designed for end-to-end management of kernel building,
packaging, and system image creation in an embedded Linux or Debian-based environment.
It supports kernel compilation, Debian package generation, and packing custom system images using multiple
configurable options via command-line arguments.

Branches
--------
main: Primary development branch. Contributors should develop submissions based on this branch, and submit pull requests to this branch.

Features
--------
- Build Linux kernel with custom sources.
- Generate Debian binary packages.
- Install and organize Debian packages for the root file system.
- Pack a system.img (system image) including the generated packages.
- Image and build flavor configuration (server/desktop, base/qcom).
- Automated workspace cleanup.

Requirements
------------
- Operating System: Linux
- Python: 3.6+
- Root privileges: Required for some operations
- Dependencies: Additional modules required:
- build_kernel, build_dtb, build_deb, constants, helpers, deb_organize, pack_deb
- Ensure all required helper scripts and dependencies are accessible.

Usage
-----
Run the script with the desired set of command-line arguments:

Source the setup environment script first:
- #source qcom-build-utils/ubuntu/setup-environment.
- #sudo python3 build.py --workspace /absolute/path/to/workspace [Mandatory]

Example:
--------
- #sudo python3 qcom-build-utils/ubuntu/build.py --workspace /home/user/workspace --build-kernel --gen-debians --pack-image

Arguments
---------

| Argument              | Type    | Default                                                                 | Description |
|-----------------------|---------|-------------------------------------------------------------------------|-------------|
| `--workspace`         | string  | **required**                                                            | Absolute path to the workspace directory. |
| `--build-kernel`      | flag    | `False`                                                                 | Build the kernel. |
| `--kernel-src-dir`    | string  | `<workspace>/kernel`                                                    | Directory containing kernel sources. |
| `--kernel-dest-dir`   | string  | `<workspace>/debian_packages/oss`                                       | Output directory for built kernel `.deb` files. |
| `--flavor`            | string  | `server`                                                                | Image flavor: `server` or `desktop`. |
| `--debians-path`      | string  | -                                                                       | Directory with additional Debian packages to install. |
| `--gen-debians`       | flag    | `False`                                                                 | Generate Debian binary packages. |
| `--pack-image`        | flag    | `False`                                                                 | Pack a `system.img` with generated Debian packages. |
| `--pack-variant`      | string  | `qcom`                                                                  | Pack variant: `base` or `qcom`. |
| `--output-image-file` | string  | `<workspace>/out/system.img`                                            | Path for output system image. |
| `--chroot-name`       | string  | auto-generated                                                          | Name of the chroot environment. |
| `--package`           | string  | -                                                                       | Name of a specific package to build. |
| `--nocleanup`         | flag    | `False`                                                                 | Skip workspace cleanup after build. |
| `--prepare-sources`   | flag    | `False`                                                                 | Prepare sources but do not build. |
| `--apt-server-config` | string  | `deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main` | APT server configuration(s). |

Deprecated:
-----------
Argument		Description
--skip-starter-image	Build starter image (deprecated)
--input-image-file	Input system image (deprecated)

Common Workflows
------ ---------
Build Only the Kernel:
- #sudo python3 build.py --workspace /path/to/workspace --build-kernel

Generate Debian Packages:
- #sudo python3 build.py --workspace /path/to/workspace --gen-debians

Build and Pack System Image:
-# sudo python3 build.py --workspace /path/to/workspace --build-kernel --gen-debians --pack-image

Directory Structure
--------- ---------
Directory				Purpose
<workspace>/kernel			Kernel sources
<workspace>/sources			Source code for Debian packages
<workspace>/debian_packages		Output directory for Debian packages
<workspace>/debian_packages/oss		Open-source Debian package output
<workspace>/debian_packages/prop	Proprietary Debian package output
<workspace>/debian_packages/temp	Temporary files for build process
<workspace>/out				Output directory (e.g., system.img)

Notes:-
-------
- Absolute Paths: Paths for all major directories are required to be absolute.
- Root Privileges: The script must be run as root.
- Workspace Cleanup: Controlled by --nocleanup flag.

License
-------
qcom-build-utils is licensed under the BSD-3-clause-clear License. See LICENSE for the full license text.
