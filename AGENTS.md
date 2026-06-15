# qcom-build-utils — Agent Guidelines

## Purpose

`qcom-build-utils` is the shared workflow repository for Qualcomm Linux package repos.
It owns the reusable GitHub workflows that package repositories call, plus the package-policy
orchestration around build, test, promotion, and release flows.

## Current Build/Release Architecture

- Package repos call `pkg-build-reusable-workflow.yml` and `pkg-release-reusable-workflow.yml`.
- Those workflows are now **hybrid**:
  - Debian suites (`trixie`, `sid`, `unstable`, `bookworm`, `forky`) use
    `qualcomm-linux/debusine-action` and Debusine builder images
  - Ubuntu codenames (`noble`, `questing`, `resolute`, and similar Ubuntu targets) use the
    older local `pkg-builder` path with qcom-build-utils composite actions
- Ubuntu release path now prepares release changelog/tag state as an artifact,
  builds once via `pkg-build-reusable-workflow.yml`, then gates on environment
  `pkg-release-approval` before pushing git state, publishing provenance, and
  uploading the already-built artifacts directly to apt artifactory.
- Debian-path helper entrypoints come from checked-out `debusine-action/lib/`:
  - `prepare-release`
  - `generate-source-package`
  - `build`
  - `generate-apt-config`
  - `release`
  - `push-release`
- The Debian Debusine builder images (`ghcr.io/qualcomm-linux/debusine-pkg-builder:<suite>`) are
  published from `qualcomm-linux/debusine-action`, while the Ubuntu-capable `pkg-builder` images
  are still consumed from GHCR by the local path.

## Package Repo Extra Repositories

- The `build_package` composite action supports an optional
  `debian/extra-repositories.txt` file in package repositories.
- Active entries are passed to `sbuild` as `--extra-repository`.
- Supported entry styles:
  - global entries (apply to all suites)
  - suite-filtered entries (for example `[noble,questing] deb ...`)
- Suite filters are exact matches against the build suite.
- `unstable` and `sid` are treated as equivalent for suite-filter matching.

## Workflow Naming Convention

- `pkg-*` workflow names are for package lifecycle flows (`build`, `promote`, `release`, and
  package PR hooks).
- `qcom-*` workflow names are reserved for qcom-wide infrastructure and preflight flows that are
  installed broadly (for example `qcom-preflight-checks.yml`).
- Keep this split so package-specific automation remains easy to identify in `pkg-*` repositories.

## Build Branch Convention (Caller Contract)

For `pkg-build-reusable-workflow.yml`, callers should pass a `debian-ref` branch
name where the last two `/`-delimited fields are:

- `<family>/<suite>`

Expected values:

- `family`: `debian` or `ubuntu`
- `suite`: distro codename/suite such as `sid`, `bookworm`, `noble`, `resolute`

Examples:

- `qcom/debian/latest` (normalized to suite `sid`)
- `qcom/debian/bookworm`
- `qcom/ubuntu/resolute`
- `test/qcom/ubuntu/resolute`
- `ubuntu/resolute`
- `dev/whatever/yo/debian/trixie`

Invalid examples:

- `resolute`
- `ubuntu`
- `ubuntu-resolute`

`pkg-build-reusable-workflow.yml` no longer takes a separate `suite` input for
routing; it resolves family/suite from `debian-ref`.
For PR validation where `debian-ref` is a transient branch (for example
`debian/pr/*`), routing falls back to `github.base_ref`.

## Important Workflows

- `.github/workflows/pkg-build-reusable-workflow.yml`
  - main hybrid package build/test entrypoint for package repos
- `.github/workflows/pkg-release-reusable-workflow.yml`
  - hybrid release entrypoint: Debian via Debusine, Ubuntu via pkg-builder + direct apt upload
- `.github/workflows/pkg-promote-reusable-workflow.yml`
  - upstream-to-packaging promotion flow
- `.github/workflows/pkg-upstream-pr-build-reusable-workflow.yml`
  - validate upstream PRs against the Debian packaging build

## Important Debian/Debusine Helper Entrypoints

The Debian branch of the reusable workflows depends on the checked-out `debusine-action/lib/`
scripts. If you change those interfaces, update both the `debusine-action` repo and the workflow
call sites here.

## Do Not Reintroduce

These older Debusine-era artifacts were intentionally removed and should stay gone unless there is a
clear design change:

- local Debusine wrapper workflows such as `qcom-debusine-reusable-workflow.yml`
- local Debusine image publishing workflows and `Dockerfiles/debusine-builder/`
- the copied `scripts/ci/` Debusine helper tree
- stale `*.old` workflow snapshots

## Editing Guidance

- Prefer keeping package-repo callers thin; put shared behavior in the reusable workflows here.
- Keep Debusine-specific implementation inside `debusine-action` unless `qcom-build-utils` truly
  needs local orchestration around it, but preserve the local `pkg-builder` flow for Ubuntu suites.
- When changing workflow contracts, check the synced package-repo templates and `pkg-example`.
- Preserve the current split of responsibilities:
  - `qcom-build-utils` orchestrates package-repo behavior
  - `debusine-action` owns Debusine helper scripts, action logic, and builder-image publication

## Validation Expectations

For changes that touch the active hybrid build/release path:

1. validate the edited scripts and workflow YAML locally
2. push the relevant branch if needed
3. confirm the Debian path with an end-to-end `pkg-example` run
4. confirm the Ubuntu path with a representative pkg-builder-based run
