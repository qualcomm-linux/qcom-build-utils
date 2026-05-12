# qcom-build-utils — Agent Guidelines

## Purpose

`qcom-build-utils` is the shared workflow repository for Qualcomm Linux package repos.
It owns the reusable GitHub workflows that package repositories call, plus the package-policy
orchestration around build, test, promotion, and release flows.

## Current Build/Release Architecture

- Package repos call `qcom-build-pkg-reusable-workflow.yml` and `qcom-release-reusable-workflow.yml`.
- Those workflows are now **hybrid**:
  - Debian suites (`trixie`, `sid`, `unstable`, `bookworm`, `forky`) use
    `qualcomm-linux/debusine-action` and Debusine builder images
  - Ubuntu codenames (`noble`, `questing`, `resolute`, and similar Ubuntu targets) use the
    older local `pkg-builder` path with qcom-build-utils composite actions
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

## Important Workflows

- `.github/workflows/qcom-build-pkg-reusable-workflow.yml`
  - main hybrid package build/test entrypoint for package repos
- `.github/workflows/qcom-release-reusable-workflow.yml`
  - hybrid release entrypoint: Debian via Debusine, Ubuntu via pkg-builder + S3 flow
- `.github/workflows/qcom-promote-upstream-reusable-workflow.yml`
  - upstream-to-packaging promotion flow
- `.github/workflows/qcom-upstream-pr-pkg-build-reusable-workflow.yml`
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
