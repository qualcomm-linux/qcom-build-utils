# qcom-build-utils

Centralized build tooling, reusable GitHub workflows, and composite actions for the [Qualcomm Linux](https://github.com/qualcomm-linux) Debian package ecosystem. This repository standardizes how `pkg-*` package repositories build, validate, promote, and release Debian packages for Qualcomm ARM64 platforms.

## Architecture Overview

The Qualcomm Linux packaging system is composed of four main components:

```
┌─────────────────────────┐     ┌──────────────────────────────┐
│  Upstream Repositories  │     │  Package Repositories (pkg-*)│
│  (source code)          │────▶│  (Debian packaging + source) │
└─────────────────────────┘     └──────────┬───────────────────┘
                                           │
                         calls reusable    │
                         workflows from    │
                                           ▼
                                ┌──────────────────────┐
                                │   qcom-build-utils   │
                                │  (this repository)   │
                                └──────────┬───────────┘
                                           │
                                           ▼
                                ┌──────────────────────┐
                                │  Build Infrastructure │
                                │  GHCR · Staging Repo  │
                                │  ARM64 Runners · S3   │
                                └───────────────────────┘
```

**Upstream Repositories** contain the project source code (e.g., [qcom-example-package-source](https://github.com/qualcomm-linux/qcom-example-package-source)).
**Package Repositories** (prefixed `pkg-`) hold Debian packaging metadata, track upstream versions, and invoke the reusable workflows defined here. New package repos are created from the [pkg-template](https://github.com/qualcomm-linux/pkg-template).
A complete working example is available at [pkg-example](https://github.com/qualcomm-linux/pkg-example).

## Repository Structure

```
qcom-build-utils/
├── .github/
│   ├── actions/                  # Composite GitHub Actions
│   │   ├── abi_checker/          # ABI compatibility checks
│   │   ├── build_package/        # Debian package build (gbp + sbuild)
│   │   └── push_to_repo/         # Publish packages to staging APT repo
│   └── workflows/                # Reusable workflow definitions
│       ├── qcom-build-pkg-reusable-workflow.yml
│       ├── qcom-promote-upstream-reusable-workflow.yml
│       ├── qcom-upstream-pr-pkg-build-reusable-workflow.yml
│       ├── qcom-release-reusable-workflow.yml
│       └── qcom-preflight-checks.yml
├── scripts/                      # Python & shell build utilities
│   ├── deb_abi_checker.py        # ABI comparison tool (libabigail)
│   ├── ppa_interface.py          # APT repository interface
│   ├── ppa_organizer.py          # Build output organizer
│   ├── create_promotion_pr.py    # PR generation for promotions
│   ├── merge_debian_packaging_upstream  # Upstream merge script
│   └── helpers.py                # Shared utility functions
├── kernel/scripts/               # Kernel build scripts
│   ├── build_kernel.sh           # ARM64 kernel build
│   ├── build-kernel-deb.sh       # Kernel .deb packaging
│   └── build-dtb-image.sh        # Device Tree Blob image builder
├── bootloader/
│   └── build-efi-esp.sh          # EFI System Partition builder
├── rootfs/scripts/
│   └── build-rootfs.sh           # Root filesystem image builder
└── docs/                         # Detailed documentation
```

## Reusable Workflows

Package repositories call these workflows from their own `.github/workflows/` directory. Each workflow is invoked with `uses: qualcomm-linux/qcom-build-utils/.github/workflows/<workflow>@main`.

| Workflow | Purpose |
|----------|---------|
| **qcom-build-pkg-reusable-workflow** | Main Debian package build — used for both pre-merge (PR) and post-merge builds. Orchestrates build, ABI check, and repository push. |
| **qcom-promote-upstream-reusable-workflow** | Promotes a new upstream release into a package repo — merges upstream code, updates changelog, and creates a PR. |
| **qcom-upstream-pr-pkg-build-reusable-workflow** | Validates that PRs in an upstream repo won't break the Debian package build. Called from the upstream repo. |
| **qcom-release-reusable-workflow** | Triggers a formal release — finalizes the changelog, builds packages, uploads to S3, and notifies downstream consumers. |
| **qcom-preflight-checks** | Security and quality gates — runs repolinter, semgrep, license checks, and dependency review. |

## Composite Actions

| Action | Description |
|--------|-------------|
| **build_package** | Builds Debian packages using `git-buildpackage` and `sbuild`. Supports native ARM64 builds and cross-compilation. |
| **abi_checker** | Compares ABI compatibility against the previously published version using `libabigail`. Returns a bitmask indicating compatibility status. |
| **push_to_repo** | Uploads built `.deb` / `.ddeb` packages to the [pkg-oss-staging-repo](https://github.com/qualcomm-linux/pkg-oss-staging-repo) APT repository with deduplication. |

## Getting Started

### Creating a New Package Repository

1. Use the [pkg-template](https://github.com/qualcomm-linux/pkg-template) — click **"Use this template"** and name your repo with the `pkg-` prefix (e.g., `pkg-mypackage`). Enable **"Include all branches"**.
2. Customize the `debian/` directory on the `debian/qcom-next` branch for your package.
3. Set repository variables:
   - **`UPSTREAM_REPO_GITHUB_NAME`** — in the **package repo**, points to the upstream source repo (e.g., `qualcomm-linux/qcom-example-package-source`).
   - **`PKG_REPO_GITHUB_NAME`** — in the **upstream repo**, points to the package repo (e.g., `qualcomm-linux/pkg-example`).
4. Configure branch protection for `debian/qcom-next` with `build / build-debian-package` as a required status check.
5. Copy `.github/TO_PASTE_IN_UPSTREAM_REPO/pkg-build-pr-check.yml` into the upstream repo's `.github/workflows/` on its default branch.

See [pkg-example](https://github.com/qualcomm-linux/pkg-example) for a complete working reference.

### Package Repo Branch Structure

| Branch | Purpose |
|--------|---------|
| `main` | Workflows, docs, and boilerplate files |
| `debian/qcom-next` | Active Debian packaging branch (build target) |
| `debian/<version>` | Version-specific tags/branches (e.g., `debian/1.1.0-1`) |
| `upstream/latest` | Latest upstream source (non-native packages) |
| `upstream/<version>` | Tagged upstream versions |

### Typical Workflow Lifecycle

```
 Developer opens PR ──▶ pre-merge build ──▶ ABI check
        │                                       │
        ▼                                       ▼
  PR merged into        build passes ──▶ package pushed
  debian/qcom-next      and tagged         to staging repo
        │
        ▼
  Release triggered ──▶ changelog finalized ──▶ upload to S3
```

1. **Pre-merge**: A PR against `debian/qcom-next` triggers a build and ABI compatibility check.
2. **Post-merge**: On merge, the package is built, pushed to the staging APT repo, and tagged `debian/<version>`.
3. **Upstream promotion**: When the upstream project tags a new release, the promote workflow merges it into the packaging branch and opens a PR.
4. **Upstream PR validation**: PRs in the upstream repo are validated against the package build to catch breakages early.
5. **Release**: A manual dispatch finalizes the changelog, builds the package, uploads artifacts to S3, and notifies [qcom-distro-images](https://github.com/qualcomm-linux/qcom-distro-images).

## Build Infrastructure

| Component | Details |
|-----------|---------|
| **Container images** | `ghcr.io/qualcomm-linux/pkg-builder:{arch}-{distro}` — pre-built for `arm64`/`amd64` across `noble`, `questing`, `resolute`, `trixie`, `sid` |
| **Staging APT repo** | [pkg-oss-staging-repo](https://github.com/qualcomm-linux/pkg-oss-staging-repo) served via GitHub Pages |
| **Runners** | Self-hosted ARM64 runners (`lecore-prd-u2404-arm64-xlrg-od-ephem`) |
| **Artifact storage** | S3 for release builds |

## Build & Utility Scripts

### Package Build Scripts (`scripts/`)

| Script | Description |
|--------|-------------|
| `deb_abi_checker.py` | Compares ABI between package versions using `libabigail`. Return codes: `0` no diff, `1` compatible, `2` incompatible, `4` stripped, `8` not found, `16` PPA error. |
| `merge_debian_packaging_upstream` | Merges an upstream commitish into the `debian/` branch, preserving `debian/` and `.github/` directories. |
| `ppa_interface.py` | Interfaces with APT repositories — download, list, and query package versions. |
| `ppa_organizer.py` | Organizes build output into APT pool structure. |
| `create_promotion_pr.py` | Generates PR title and body for upstream promotions. |
| `helpers.py` | Shared utilities for directory management, logging, and APT server setup. |

### Platform Build Scripts

| Script | Description |
|--------|-------------|
| `kernel/scripts/build_kernel.sh` | Builds the Linux kernel for ARM64 with Qualcomm defconfig. |
| `kernel/scripts/build-kernel-deb.sh` | Packages kernel artifacts into an Ubuntu-compliant `.deb`. |
| `kernel/scripts/build-dtb-image.sh` | Builds a FAT-formatted Device Tree Blob image for Qualcomm platforms. |
| `bootloader/build-efi-esp.sh` | Creates a deterministic EFI System Partition (`efi.bin`) for ARM64. |
| `rootfs/scripts/build-rootfs.sh` | Generates a bootable ext4 root filesystem image using `debootstrap`. |

## Local Package Building

For building packages locally outside of GitHub Actions, see the [docker-pkg-build](https://github.com/qualcomm-linux/docker-pkg-build) repository which provides containerized Debian package builds.

## Documentation

Detailed documentation is available in the [`docs/`](docs/) directory:

- [Workflow Architecture](docs/workflow-architecture.md) — system overview and component interactions
- [Reusable Workflows](docs/reusable-workflows.md) — detailed reference for each workflow
- [GitHub Actions](docs/github-actions.md) — composite action reference and patterns
- [Package Repository Integration](docs/package-repo-integration.md) — step-by-step setup guide

## Related Repositories

| Repository | Description |
|------------|-------------|
| [pkg-template](https://github.com/qualcomm-linux/pkg-template) | Template for creating new `pkg-*` package repositories |
| [pkg-example](https://github.com/qualcomm-linux/pkg-example) | Complete working example of a package repository |
| [qcom-example-package-source](https://github.com/qualcomm-linux/qcom-example-package-source) | Example upstream source repo with package build integration |
| [docker-pkg-build](https://github.com/qualcomm-linux/docker-pkg-build) | Containerized local Debian package builder |
| [pkg-oss-staging-repo](https://github.com/qualcomm-linux/pkg-oss-staging-repo) | Staging APT repository for built packages |
| [qcom-distro-images](https://github.com/qualcomm-linux/qcom-distro-images) | Distribution image configuration consuming released packages |

## Branches

**main**: Primary development branch. Contributors should develop submissions based on this branch and submit pull requests to this branch.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on the branching strategy, pull request process, and DCO sign-off requirements.

## Getting in Contact

* [Report an Issue on GitHub](../../issues)
* [Open a Discussion on GitHub](../../discussions)

## License

qcom-build-utils is licensed under the [BSD-3-Clause License](https://spdx.org/licenses/BSD-3-Clause.html). See [LICENSE.txt](LICENSE.txt) for the full license text.
