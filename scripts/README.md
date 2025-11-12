# qcom-build-utils Scripts

## Overview

This directory contains utility scripts for building, organizing, and managing Debian packages for Qualcomm Linux platforms. These tools provide a streamlined workflow for package development, testing, and distribution.

## Available Tools

### 1. docker_deb_build.py

The primary tool for building Debian packages in a containerized environment. It works on both ARM64 and x86_64 hosts, building natively on ARM64 and cross-compiling on x86_64.

**Key Features:**
- Builds Debian packages inside Docker containers
- Supports multiple distributions (noble, questing)
- Automatic Docker image creation on first run
- Optional lintian checks for package quality
- Custom APT repository support

**Usage:**
```bash
./scripts/docker_deb_build.py --source-dir <source-dir> --output-dir <output-dir>
```

**Options:**
- `--source-dir`: Path to the source directory containing debian package source (default: current directory)
- `--output-dir`: Path to the output directory for built packages (default: parent directory)
- `--distro`: Target distribution - `noble` or `questing` (default: noble)
- `--run-lintian`: Run lintian quality checks on the built package
- `--extra-repo`: Additional APT repository configuration
  - Example: `'deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main'`
- `--rebuild`: Rebuild the Docker image before building the package

**Examples:**
```bash
# Basic package build
./scripts/docker_deb_build.py --source-dir ./my-package --output-dir ./build

# Build with lintian checks
./scripts/docker_deb_build.py --source-dir ./my-package --run-lintian

# Build with custom repository
./scripts/docker_deb_build.py --source-dir ./my-package \
  --extra-repo 'deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main'

# Rebuild Docker image and build package
./scripts/docker_deb_build.py --source-dir ./my-package --rebuild
```

**Pro Tip:** Create a shell alias for easier use:
```bash
# Add to ~/.bashrc
alias debb="<path-to-repo>/scripts/docker_deb_build.py"

# Then use it simply as:
debb --source-dir ./my-package
```

### 2. deb_abi_checker.py

ABI (Application Binary Interface) compatibility checker for Debian packages.

**Key Features:**
- Compares two versions of a package for ABI changes
- Uses `abipkgdiff` from libabigail
- Detects incompatible changes
- Downloads old versions from PPA for comparison
- Generates detailed comparison reports

**Usage:**
```bash
./scripts/deb_abi_checker.py --new-package-dir <package-dir>
```

**Options:**
- `--new-package-dir`: Directory containing new package (.deb, optional -dev.deb, optional -dbgsym.ddeb)
- `--apt-server-config`: APT server to download old package from
  - Default: `'deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main'`
- `--old-version`: Specific old version to compare against (optional, defaults to latest)
- `--delete-temp`: Delete temporary extracted folders after comparison
- `--result-file`: Path to save the comparison result file

**Examples:**
```bash
# Compare against latest version from PPA
./scripts/deb_abi_checker.py --new-package-dir ./build/new-package

# Compare against specific version
./scripts/deb_abi_checker.py \
  --new-package-dir ./build/new-package \
  --old-version 1.0-1

# Save results to file
./scripts/deb_abi_checker.py \
  --new-package-dir ./build/new-package \
  --result-file ./abi-report.txt
```

**Return Codes:**
- `0b00000` (0): No ABI differences detected
- `0b00001` (1): Compatible ABI changes detected
- `0b00010` (2): Incompatible ABI changes detected
- `0b00100` (4): Package is stripped (no debug symbols)
- `0b01000` (8): Old package not found in PPA
- `0b10000` (16): PPA error

### 3. merge_debian_packaging_upstream

Shell script for merging upstream changes into Debian packaging branch.

**Key Features:**
- Merges upstream changes while preserving debian/ directory
- Also preserves .github/ directory
- Similar to `gbp-import-ref --merge-mode=replace` but with .github/ support

**Prerequisites:**
- Debian packaging branch must be checked out
- Working tree must be clean
- Not in detached HEAD state

**Usage:**
```bash
./scripts/merge_debian_packaging_upstream <upstream-commitish>
```

**Example:**
```bash
# Merge upstream tag
./scripts/merge_debian_packaging_upstream v1.2.3

# Merge upstream branch
./scripts/merge_debian_packaging_upstream upstream/main
```

## Common Workflows

### Building a Single Package

```bash
# 1. Build the package
./scripts/docker_deb_build.py --source-dir ./my-package --output-dir ./build

# 2. Check ABI compatibility (optional)
./scripts/deb_abi_checker.py --new-package-dir ./build
```

### Setting Up a Development Environment

```bash
# Create alias for quick access
echo 'alias debb="$(pwd)/scripts/docker_deb_build.py"' >> ~/.bashrc
source ~/.bashrc

# Build Docker image once
debb --rebuild --source-dir ./some-package

# Now you can quickly build packages
debb --source-dir ./package1
debb --source-dir ./package2 --run-lintian
```

## Requirements

### System Requirements
- **Operating System**: Linux (Ubuntu recommended)
- **Python**: 3.6 or later
- **Docker**: Required for docker_deb_build.py
  - Docker daemon must be running
  - User must have Docker permissions (member of `docker` group) or run with sudo

### Python Dependencies
The scripts use these Python modules (all included in scripts/):
- `color_logger`: Colored logging output
- `helpers`: Helper functions for directory operations

### External Tools
- **Docker**: For containerized builds (docker_deb_build.py)
- **libabigail** (`abipkgdiff`): For ABI checking (deb_abi_checker.py)

## Docker Setup

The first time you run `docker_deb_build.py`, it will automatically build the required Docker image from the Dockerfile in the `docker/` directory. The Dockerfiles are architecture and distribution specific:

- `docker/Dockerfile.arm64.noble` - ARM64 build for Ubuntu Noble
- `docker/Dockerfile.arm64.questing` - ARM64 build for Ubuntu Questing
- `docker/Dockerfile.amd64.noble` - x86_64 build for Ubuntu Noble
- `docker/Dockerfile.amd64.questing` - x86_64 build for Ubuntu Questing

To rebuild the Docker image:
```bash
./scripts/docker_deb_build.py --rebuild
```

## Troubleshooting

### Docker Permission Issues

If you get permission errors when running docker_deb_build.py:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Start a new shell with updated group membership
newgrp docker

# Or logout and login again
```

### Missing Dependencies

If a script fails due to missing dependencies, ensure all required tools are installed:

```bash
# Install Docker (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install docker.io

# Install libabigail for ABI checking
sudo apt-get install abigail-tools
```

## License

qcom-build-utils is licensed under the [BSD-3-clause License](https://spdx.org/licenses/BSD-3-Clause.html). See [LICENSE.txt](LICENSE.txt) for the full license text.
