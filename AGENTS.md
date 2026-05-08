# qcom-build-utils — Agent Guidelines

## Purpose

`qcom-build-utils` is the shared workflow and helper repository for Qualcomm Linux package repos.
It owns the reusable GitHub workflows that package repositories call, plus the local helper scripts
those workflows need for source-package preparation, installability testing, release git handling,
and other packaging automation.

## Current Debusine Architecture

- Package repos call `qcom-build-pkg-reusable-workflow.yml` and `qcom-release-reusable-workflow.yml`.
- Those workflows now use `qualcomm-linux/debusine-action` for Debusine-specific operations such as:
  - importing the `.dsc` artifact
  - starting Debusine workflows
- `qcom-build-utils` still owns the local orchestration around that:
  - generating the source package
  - preparing the Debusine child workspace and pipeline inputs
  - polling Debusine work requests with richer diagnostics
  - validating installability from the Debusine CI workspace
  - preparing/pushing release git state
- The Debusine builder images (`ghcr.io/qualcomm-linux/debusine-pkg-builder:<suite>`) are consumed
  here, but are published from `qualcomm-linux/debusine-action`, not from this repository.

## Important Workflows

- `.github/workflows/qcom-build-pkg-reusable-workflow.yml`
  - main package build/test entrypoint for package repos
- `.github/workflows/qcom-release-reusable-workflow.yml`
  - release entrypoint built on top of the Debusine build/test path
- `.github/workflows/qcom-promote-upstream-reusable-workflow.yml`
  - upstream-to-packaging promotion flow
- `.github/workflows/qcom-upstream-pr-pkg-build-reusable-workflow.yml`
  - validate upstream PRs against the Debian packaging build

## Important Helper Scripts

The `scripts/ci/` directory is still active. Do not remove or bypass these without checking call
sites in the reusable workflows:

- `generate-source-package`
- `prepare-release`
- `prepare-debusine-build`
- `poll-debusine-workflow`
- `prepare-test`
- `prepare-debusine-release`
- `push-release`
- `generate-apt-config`
- `next_qcom_version`, `next_qcom_version.py`, `next_qcom_version_test.py`
- `poll_workflow.py`

## Do Not Reintroduce

These older Debusine-era artifacts were intentionally removed and should stay gone unless there is a
clear design change:

- local Debusine wrapper workflows such as `qcom-debusine-reusable-workflow.yml`
- local Debusine image publishing workflows and `Dockerfiles/debusine-builder/`
- stale `*.old` workflow snapshots
- unused Incus-era helpers such as `scripts/ci/build`, `scripts/ci/prepare-debusine`, and
  `scripts/ci/release`

## Editing Guidance

- Prefer keeping package-repo callers thin; put shared behavior in the reusable workflows here.
- Keep Debusine-specific implementation inside `debusine-action` unless `qcom-build-utils` truly
  needs local orchestration around it.
- Before deleting anything under `scripts/ci/`, search for live references from workflows first.
- When changing workflow contracts, check the synced package-repo templates and `pkg-example`.
- Preserve the current split of responsibilities:
  - `qcom-build-utils` orchestrates package-repo behavior
  - `debusine-action` owns Debusine action logic and builder-image publication

## Validation Expectations

For changes that touch the active Debusine build/release path:

1. validate the edited scripts and workflow YAML locally
2. push the relevant branch if needed
3. confirm behavior with an end-to-end `pkg-example` run
