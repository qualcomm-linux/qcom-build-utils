# qcom-build-utils - Agent Guidelines

## Purpose

`qcom-build-utils` no longer owns package lifecycle CI assets.

The following were migrated to `qualcomm-linux/qli-ci`:

- reusable package workflows
- composite package actions
- shared package promotion/build scripts

Use this repository for platform build helpers only.

## Current Scope

Primary maintained paths:

- `kernel/`
- `bootloader/`
- `rootfs/`
- `flash/`
- repository metadata and issue templates under `.github/`

## Source of Truth for Package CI

For package lifecycle workflow behavior, use:

- `qualcomm-linux/qli-ci` for reusable workflows and package helper scripts
- `qualcomm-linux/debusine-action` for Debusine implementation details

## Do Not Reintroduce

Unless there is an explicit design decision, do not add back:

- `.github/workflows/pkg-*.yml` reusable workflow definitions
- `.github/actions/` package composite actions
- `scripts/` package CI helper scripts

## Editing Guidance

When the request is about package promotion/build/release CI wiring, work in
`qli-ci` (and `debusine-action` when Debian Debusine internals are involved),
not here.

For this repo, keep changes focused on platform build helpers.

## Validation Expectations

For platform-helper changes:

1. run script-level checks locally where applicable
2. verify updated docs/reference paths are consistent
3. validate in the consuming repository before merge when possible
