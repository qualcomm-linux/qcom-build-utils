# Reusable Workflows

This document provides detailed information about each reusable workflow in qcom-build-utils.

## Overview

Reusable workflows are defined in `.github/workflows/` and are designed to be called from package repositories. They orchestrate the build, test, and deployment process for Debian packages.

## Available Workflows

1. [qcom-build-pkg-reusable-workflow](#qcom-build-pkg-reusable-workflow)
2. [qcom-release-reusable-workflow](#qcom-release-reusable-workflow)
3. [qcom-promote-upstream-reusable-workflow](#qcom-promote-upstream-reusable-workflow)
4. [qcom-upstream-pr-pkg-build-reusable-workflow](#qcom-upstream-pr-pkg-build-reusable-workflow)
5. [qcom-preflight-checks](#qcom-preflight-checks)

---

## qcom-build-pkg-reusable-workflow

**File**: `.github/workflows/qcom-build-pkg-reusable-workflow.yml`

**Purpose**: Build a package through a hybrid flow: Debian suites are built and tested through Debusine, while Ubuntu codenames keep using the local `pkg-builder` + composite-action path.

### Workflow Diagram

```mermaid
flowchart TD
    A[Workflow Called] --> B[Resolve suite family]
    B -->|Debian| C[Checkout debusine-action helpers]
    C --> D[Generate source package + build in Debusine]
    D --> E[Test installability from Debusine workspace]
    B -->|Ubuntu| F[Run local pkg-builder build]
    F --> G[Optional ABI check]
    E --> H[Expose outputs]
    G --> H
```

### Inputs

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `qcom-build-utils-ref` | string | Yes | - | The ref (branch/tag) of qcom-build-utils to use |
| `debian-ref` | string | Yes | `debian/qcom-next` | The package-repository ref to check out and build |
| `suite` | string | No | `unstable` | Distribution codename or Debian suite |
| `run-lintian` | boolean | No | `true` | Used by the Ubuntu/pkg-builder path |
| `run-abi-checker` | boolean | No | `false` | Used by the Ubuntu/pkg-builder path |
| `is-prebuilt` | string | No | `""` | Passed through to the Ubuntu/pkg-builder `build_package` action |
| `job-index` | string | No | `"0"` | Optional matrix index used to keep Debusine child workspace names unique |
| `release` | boolean | No | `false` | Whether to prepare the release bundle before generating the Debian release source package |

### Secrets

| Secret | Required | Description |
|--------|----------|-------------|
| `DEBUSINE_USER` | Debian only | Debusine user used by the Debian test gate |
| `DEBUSINE_TOKEN` | Debian only | Debusine token used to create the child workspace and submit the Debian source package |

### Outputs

| Output | Description |
|--------|-------------|
| `target_suite` | The resolved suite/codename actually used by the workflow |
| `workspace` | Debusine child workspace name |
| `workspace_url` | Debusine web URL for that child workspace |
| `srcpkg_name` | Source package name |
| `srcpkg_version` | Source package version |

### Workflow Steps

1. **Resolve suite family**: Normalize the caller input and decide whether the run is Debian or Ubuntu
2. **Debian path**: Check out `debusine-action/lib`, optionally prepare a release bundle, generate a source package, submit it to Debusine, and run installability checks from the Debusine CI workspace
3. **Ubuntu path**: Run the old local `pkg-builder` flow with `build_package` and optional `abi_checker`
4. **Publish Outputs**: Expose consistent source-package metadata; Debusine workspace outputs are populated only for Debian runs

### Usage Examples

#### Manual build from a packaging ref

```yaml
jobs:
  build:
    uses: qualcomm-linux/qcom-build-utils/.github/workflows/qcom-build-pkg-reusable-workflow.yml@development
    with:
      qcom-build-utils-ref: development
      debian-ref: debian/qcom-next
      suite: trixie
```

#### Matrix-safe caller

```yaml
jobs:
  build-matrix:
    uses: qualcomm-linux/qcom-build-utils/.github/workflows/qcom-build-pkg-reusable-workflow.yml@development
    with:
      qcom-build-utils-ref: development
      debian-ref: refs/heads/${{ matrix.target_branch }}
      suite: ${{ matrix.suite }}
      job-index: ${{ strategy.job-index }}
```

This workflow is the low-level build/test primitive used directly by package
repositories.

---

## qcom-release-reusable-workflow

**File**: `.github/workflows/qcom-release-reusable-workflow.yml`

**Purpose**: Release through a hybrid flow: Debian suites use Debusine build/test/publish, while Ubuntu codenames keep the older local `pkg-builder` + S3 release process.

### Workflow Diagram

```mermaid
flowchart TD
    A[Workflow Called] --> B[Resolve suite family]
    B -->|Debian| C[Prepare release bundle + build/test in Debusine]
    C --> D{test-run?}
    D -->|true| E[Stop after validation]
    D -->|false| F[Publish CI workspace to Debusine prod]
    F --> G[Push release tag and reopen development]
    B -->|Ubuntu| H[Run local release/tag/provenance flow]
    H --> I[Build in pkg-builder]
    I --> J[Upload artifacts to S3]
```

### Inputs

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `qcom-build-utils-ref` | string | Yes | - | The ref (branch/tag) of qcom-build-utils to invoke |
| `debian-branch` | string | No | `debian/qcom-next` | The packaging branch to release from |
| `suite` | string | No | `noble` | Distribution codename or Debian suite to build/test/release |
| `test-run` | boolean | No | `true` | Debian: stop after Debusine build/test. Ubuntu: keep the older release flow and upload to the test S3 location |

### Secrets

| Secret | Required | Description |
|--------|----------|-------------|
| `PAT` | Yes | GitHub token used to check out and push the packaging repository |
| `DEBUSINE_USER` | Debian only | Debusine user used for CI workspace apt access during the Debian test gate |
| `DEBUSINE_TOKEN` | Debian only | Debusine CI token used for the Debian build workspace and test gate |
| `DEBUSINE_RELEASE_TOKEN` | Debian publish only | Separate Debusine production token used only for the Debian publish step |

### Outputs

| Output | Description |
|--------|-------------|
| `workspace` | Debusine child workspace name for Debian releases; empty for Ubuntu |
| `workspace_url` | Debusine web URL for that child workspace for Debian releases; empty for Ubuntu |
| `srcpkg_name` | Source package name prepared for release |
| `srcpkg_version` | Source package version prepared for release |
| `complete_version` | Alias for `srcpkg_version` |

### Workflow Steps

1. **Resolve suite family**: Decide whether the release follows the Debian or Ubuntu branch
2. **Debian branch**: Reuse `qcom-build-pkg-reusable-workflow` with `release=true`, then optionally publish to Debusine prod and push git state
3. **Ubuntu branch**: Restore the earlier local release flow with changelog/tag handling, provenance generation, local `pkg-builder` build, and S3 upload

### Caller Requirements

- Debian callers should pass `DEBUSINE_RELEASE_TOKEN` when they want the reusable workflow to publish to Debusine prod
- Ubuntu callers do not use the Debusine secrets, but still need `PAT` for the release git/S3/dispatch flow

### Usage Example

```yaml
jobs:
  release:
    uses: qualcomm-linux/qcom-build-utils/.github/workflows/qcom-release-reusable-workflow.yml@development
    with:
      qcom-build-utils-ref: development
      suite: trixie
      debian-branch: debian/qcom-next
      test-run: false
    secrets:
      PAT: ${{ secrets.DEB_PKG_BOT_CI_TOKEN }}
      DEBUSINE_USER: ${{ secrets.DEBUSINE_USER }}
      DEBUSINE_TOKEN: ${{ secrets.DEBUSINE_TOKEN }}
      DEBUSINE_RELEASE_TOKEN: ${{ secrets.DEBUSINE_RELEASE_TOKEN }}
```

---

## qcom-promote-upstream-reusable-workflow

**File**: `.github/workflows/qcom-promote-upstream-reusable-workflow.yml`

**Purpose**: Automates the promotion of a new upstream version into the package repository. This workflow imports an upstream tag, merges it into the packaging branch, and creates a PR for review.

### Workflow Diagram

```mermaid
flowchart TD
    A[Workflow Called with upstream-tag] --> B[Normalize Tag Version<br/>v1.0.0 → 1.0.0]
    B --> C[Checkout qcom-build-utils]
    C --> D[Checkout Package Repository]
    D --> E[Checkout debian/qcom-next and upstream/latest]
    E --> F{Tag already exists?}
    F -->|Yes| G[Fail: Tag already integrated]
    F -->|No| H[Add Upstream Repository as Remote]
    H --> I[Fetch Upstream Tags]
    I --> J{upstream/latest exists?}
    J -->|No| K[Create upstream/latest from tag]
    J -->|Yes| L[Fast-forward merge to tag]
    K --> M[Checkout debian/qcom-next]
    L --> M
    M --> N[Create debian/pr/version-1 branch]
    N --> O[Merge upstream tag into debian branch]
    O --> P[Promote Changelog with gbp dch]
    P --> Q[Push upstream/latest branch]
    Q --> R[Push upstream/version tag]
    R --> S[Push debian/pr/version-1 branch]
    S --> T[Create Pull Request]
    T --> U[End]
```

### Inputs

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `qcom-build-utils-ref` | string | Yes | - | The ref of qcom-build-utils to use |
| `upstream-tag` | string | Yes | - | The tag in upstream repo to promote (e.g., `v1.0.0`) |
| `upstream-repo` | string | Yes | - | The upstream git repository address (e.g., `org/repo`) |
| `promote-changelog` | boolean | No | `false` | Whether to run gbp dch to update changelog |

### Secrets

| Secret | Required | Description |
|--------|----------|-------------|
| `PAT` | No | GitHub Personal Access Token for authenticating against **private** upstream repositories. Not required when the upstream repository is public. |

### Environment Variables

- `NORMALIZED_VERSION`: Version with 'v' prefix removed

### Workflow Steps

1. **Normalize Tag Version**: Remove 'v' prefix from version tag
2. **Checkout Repositories**: Clone qcom-build-utils and package repository
3. **Validate Tag**: Ensure tag doesn't already exist in the package repo
4. **Add Upstream Remote**: Configure upstream repository as git remote
5. **Fetch Upstream Tags**: Get all tags from upstream
6. **Pre-populate upstream/latest**: Create or fast-forward upstream/latest branch
7. **Merge Upstream**: Create PR branch and merge upstream tag
8. **Promote Changelog**: Update debian/changelog with new version
9. **Push Branches and Tags**: Push upstream/latest and PR branch
10. **Create PR**: Open pull request for manual review

### Usage Example

```yaml
jobs:
  promote:
    uses: qualcomm-linux/qcom-build-utils/.github/workflows/qcom-promote-upstream-reusable-workflow.yml@development
    with:
      qcom-build-utils-ref: development
      upstream-tag: v2.1.0
      upstream-repo: qualcomm-linux/my-upstream-project
      promote-changelog: true
```

### Notes

- Creates a PR branch: `debian/pr/{version}-1`
- Creates an upstream tag: `upstream/{version}`
- Automatically updates the changelog
- PR must be reviewed and merged manually
- Uses git-buildpackage (gbp) tools for Debian packaging operations

---

## qcom-upstream-pr-pkg-build-reusable-workflow

**File**: `.github/workflows/qcom-upstream-pr-pkg-build-reusable-workflow.yml`

**Purpose**: Validates that upstream repository pull requests don't break the Debian package build. This workflow is called from the upstream repository's PR workflow.

### Workflow Diagram

```mermaid
flowchart TD
    A[PR in Upstream Repo] --> B[Checkout qcom-build-utils]
    B --> C[Checkout Package Repository]
    C --> D[Checkout Upstream PR Branch]
    D --> E[Tag PR as upstream/pr]
    E --> F[Add Upstream as Remote to Package Repo]
    F --> G[Checkout debian/qcom-next]
    G --> H[Create debian/upstream-pr branch]
    H --> I[Parse Current Version]
    I --> J[Import PR with gbp<br/>Version: upstream~prNNN]
    J --> K[Merge upstream/latest into debian/upstream-pr]
    K --> L[Update Changelog with PR version]
    L --> M[Build Debian Package]
    M --> N[Run ABI Checker]
    N --> O[Report Results to PR]
```

### Inputs

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `qcom-build-utils-ref` | string | Yes | - | The ref of qcom-build-utils to use |
| `upstream-repo` | string | Yes | - | The upstream repository triggering the workflow |
| `upstream-repo-ref` | string | Yes | - | The ref (PR branch) in upstream repo |
| `pkg-repo` | string | Yes | - | The package repository to test against |
| `pr-number` | number | Yes | - | The PR number in upstream repo |
| `run-lintian` | boolean | No | `false` | Whether to run lintian |
| `suite` | string | No | `noble` | Distribution codename or Debian suite |
| `runner` | string | No | `ubuntu-latest` | Runner to use |

### Environment Variables

- `REPO_URL`: APT repository URL for ABI checking
- `upstream_version`: Extracted upstream version from changelog
- `distro_revision`: Extracted distribution revision from changelog

### Workflow Steps

1. **Checkout Repositories**: Clone qcom-build-utils, package repo, and upstream PR
2. **Tag Upstream PR**: Create `upstream/pr` tag on the PR branch
3. **Add Remote**: Add upstream repo as remote to package repo
4. **Merge PR Changes**: Create test branch and merge PR into debian/qcom-next
5. **Version Manipulation**: Create special version with `~pr{number}` suffix
6. **Import with gbp**: Use git-buildpackage to import the PR
7. **Promote Changelog**: Update changelog for test build
8. **Build Package**: Build the package with PR changes
9. **Run ABI Check**: Verify ABI compatibility
10. **Report Status**: Return success/failure to the upstream PR

### Usage Example

Called from upstream repository's workflow (e.g., `.github/workflows/pkg-build-pr-check.yml`):

```yaml
name: Package Build PR Check

on:
  pull_request:
    branches: [ main ]

jobs:
  package-build-pr-check:
    uses: qualcomm-linux/qcom-build-utils/.github/workflows/qcom-upstream-pr-pkg-build-reusable-workflow.yml@development
    with:
      qcom-build-utils-ref: development
      upstream-repo: ${{github.repository}}
      upstream-repo-ref: ${{github.head_ref}}
      pkg-repo: ${{vars.PKG_REPO_GITHUB_NAME}}
      pr-number: ${{github.event.pull_request.number}}
```

**Setup Requirements**:

The `PKG_REPO_GITHUB_NAME` variable is the key to linking upstream and package repositories:

1. **Configure in upstream repository**: Go to Settings → Secrets and variables → Actions → Variables
2. **Create variable**:
   - **Name**: `PKG_REPO_GITHUB_NAME`
   - **Value**: Package repository in format `organization/repo-name` (e.g., `qualcomm-linux/pkg-example`)
3. **Use in workflow**: Reference as `${{vars.PKG_REPO_GITHUB_NAME}}` in the `pkg-repo` parameter

```mermaid
graph LR
    A[Upstream Repo<br/>Variable Set] -->|PKG_REPO_GITHUB_NAME| B[Workflow reads<br/>vars.PKG_REPO_GITHUB_NAME]
    B -->|Passes to| C[qcom-upstream-pr-pkg-build<br/>reusable workflow]
    C -->|Clones and tests| D[Package Repository<br/>e.g., pkg-example]
    
    style A fill:#e1f5ff
    style D fill:#ffe6e6
```

**Example**: See [qcom-example-package-source](https://github.com/qualcomm-linux/qcom-example-package-source) for a complete example

### Notes

- Creates special version with `~pr{number}` to indicate test build
- The `~` character ensures version sorts lower than release versions
- Filters out `.git`, `.github`, and `debian` folders from upstream
- Does not push built packages to repository
- Only validates that the build succeeds

---

## qcom-container-build-and-upload

**File**: `.github/workflows/qcom-container-build-and-upload.yml`

**Purpose**: Builds and publishes the Docker container images used for building Debian packages. These containers include all necessary tools and dependencies.

### Workflow Diagram

```mermaid
flowchart TD
    A[Trigger: PR/Push/Schedule/Manual] --> B{Check if Build Needed}
    B -->|docker/ changed| C[Build Needed]
    B -->|Schedule/Manual| C
    B -->|No changes| D[Skip Build]
    C --> E[Build amd64 Image on ubuntu-latest]
    C --> F[Build arm64 Image on self-hosted ARM runner]
    E --> G[Test Build: pkg-example noble]
    E --> H[Test Build: pkg-example questing]
    F --> I[Test Build: pkg-example noble]
    F --> J[Test Build: pkg-example questing]
    G --> K{Event Type}
    H --> K
    I --> K
    J --> K
    K -->|push to main| L[Push to GHCR]
    K -->|PR or other| M[Don't Push]
    L --> N[End]
    M --> N
    D --> N
```

### Triggers

- **Schedule**: Monday at 00:00 UTC (weekly rebuild)
- **Pull Request**: On PRs to `main` or `development` branches
- **Push**: On push to `main` branch
- **Manual**: Via `workflow_dispatch`

### Environment Variables

- `QCOM_ORG_NAME`: `qualcomm-linux`
- `IMAGE_NAME`: `pkg-builder`

### Jobs

#### check-if-build-needed

Determines whether container rebuild is necessary:

- **For PRs**: Check if `docker/` folder changed
- **For Pushes**: Check if `.github/docker/` folder changed
- **For Schedule/Manual**: Always build

#### build-image-amd64

- Runs on: `ubuntu-latest` (x86_64)
- Builds: `amd64` container images natively
- Tests: Builds `pkg-example` for noble and questing
- Pushes: Only on non-PR events

#### build-image-arm64

- Runs on: `["self-hosted", "lecore-prd-u2404-arm64-xlrg-od-ephem"]`
- Builds: `arm64` container images natively
- Tests: Builds `pkg-example` for noble and questing
- Pushes: Only on non-PR events

### Container Images

Built images are tagged as:
- `ghcr.io/qualcomm-linux/pkg-builder:amd64-noble`
- `ghcr.io/qualcomm-linux/pkg-builder:amd64-questing`
- `ghcr.io/qualcomm-linux/pkg-builder:arm64-noble`
- `ghcr.io/qualcomm-linux/pkg-builder:arm64-questing`

### Notes

- Cross-compilation using QEMU was attempted but had reliability issues
- Native builds on appropriate architecture runners are used instead
- Images include all tools for Debian package building (sbuild, gbp, etc.)
- Test builds with `pkg-example` ensure container functionality before publishing

---

## qcom-preflight-checks

**File**: `.github/workflows/qcom-preflight-checks.yml`

**Purpose**: Runs security and quality checks on the qcom-build-utils repository itself. This workflow uses Qualcomm's centralized preflight checks.

### Workflow Diagram

```mermaid
flowchart TD
    A[PR or Push to main/latest] --> B[qcom-preflight-checks-reusable-workflow]
    B --> C[Repolinter]
    B --> D[Semgrep]
    B --> E[Copyright License Detector]
    B --> F[PR Email Check]
    B --> G[Dependency Review]
    C --> H[Report Results]
    D --> H
    E --> H
    F --> H
    G --> H
```

### Triggers

- **Pull Request**: On PRs to `main` or `latest` branches
- **Push**: On push to `main` or `latest` branches
- **Manual**: Via `workflow_dispatch`

### Checks Enabled

| Check | Purpose |
|-------|---------|
| `repolinter` | Validates repository structure and required files |
| `semgrep` | Static analysis for security vulnerabilities |
| `copyright-license-detector` | Verifies license headers and compliance |
| `pr-check-emails` | Validates commit author emails |
| `dependency-review` | Checks for vulnerable dependencies in PRs |

### Secrets

| Secret | Description |
|--------|-------------|
| `SEMGREP_APP_TOKEN` | Token for Semgrep security scanning |

### Notes

- Uses external reusable workflow from `qualcomm/qcom-reusable-workflows`
- Version pinned to `v1.1.4` for stability
- All checks are enabled by default
- Security scanning results are written to security events

---

## Common Patterns

### Calling Reusable Workflows

All reusable workflows are called using the same pattern:

```yaml
jobs:
  job-name:
    uses: qualcomm-linux/qcom-build-utils/.github/workflows/{workflow-name}.yml@{ref}
    with:
      # Input parameters
      qcom-build-utils-ref: development
      # ... other inputs
```

### Required Organization Secrets

Package repositories need these organization secrets configured:

- `SEMGREP_APP_TOKEN` - For security scanning (used by qcom-preflight-checks)

### Required Organization Variables

- `DEB_PKG_BOT_CI_USERNAME` - Username for container registry
- `DEB_PKG_BOT_CI_NAME` - Name for git commits
- `DEB_PKG_BOT_CI_EMAIL` - Email for git commits

## Best Practices

1. **Pin workflow versions**: Use specific refs (tags or commit SHAs) for production
2. **Use development ref for testing**: Test changes with `@development` ref
3. **Enable ABI checking**: Always run ABI checker in pre-merge and post-merge
4. **Test before pushing**: Use `push-to-repo: false` for pre-merge builds
5. **Review automation**: Even automated PRs should be reviewed before merging
