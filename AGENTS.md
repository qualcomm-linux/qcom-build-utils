# qcom-build-utils — Agent Guidelines

## Purpose

`qcom-build-utils` hosts shared build utilities and composite actions for the
Qualcomm Linux ecosystem.

Package lifecycle reusable workflows were moved to
`qualcomm-linux/pkg-infra/qli-ci`.

## Current Scope

- Composite GitHub actions under `.github/actions/`
- Build/helper scripts under `scripts/`
- Platform build helpers under `kernel/`, `bootloader/`, `rootfs/`, and `flash/`
- Utility documentation under `docs/`

## Out of Scope

Do not reintroduce package lifecycle reusable workflows in this repository.
Those belong in `qli-ci`, including:

- pkg build/release/promote/upstream-pr reusable workflows
- package workflow templates (`.github/pkg-workflows/*`)
- package workflow sync automation

## Workflow Ownership Model

- `qli-ci` is the package workflow source of truth for `pkg-*` repositories.
- `debusine-action` owns Debusine-specific implementation details.
- `qcom-build-utils` provides lower-level reusable tools and scripts.

## Editing Guidance

- Prefer small, explicit changes focused on utilities/actions here.
- If a change affects package workflow orchestration, implement it in `qli-ci`.
- Keep references and examples aligned with the new ownership model.

## Validation Expectations

For utility/action changes in this repo:

1. validate touched scripts/actions locally where possible
2. check docs/examples for stale references
3. validate downstream caller impact only if action interfaces changed
