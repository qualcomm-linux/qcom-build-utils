# GitHub Actions

This document describes the composite GitHub Actions in `qcom-build-utils`.

## Overview

Composite actions live under `.github/actions/` and provide reusable utility
steps that can be consumed by workflows in this repository or externally.

## Available Actions

1. [build_package](./actions/build_package.md)
2. [abi_checker](./actions/abi_checker.md)
3. [push_to_repo](./actions/push_to_repo.md)
4. [build_container](./actions/build_container.md)

## Quick Reference

| Action | Purpose |
|--------|---------|
| `build_package` | Build Debian packages with gbp/sbuild flows |
| `abi_checker` | Validate ABI compatibility against prior versions |
| `push_to_repo` | Publish built artifacts to APT staging repositories |
| `build_container` | Build and validate package-builder container images |

## Common Patterns

### Action Location

Actions are referenced relative to a checkout of this repository:

```yaml
uses: ./qcom-build-utils/.github/actions/{action_name}
```

### Error Handling

Actions use strict shell modes and explicit return-code checks.

### Output Indicators

Status output conventions:

- ✅ Success
- ❌ Fatal error
- ⚠️ Warning
- ℹ️ Information

## Notes

Package lifecycle reusable workflows are no longer hosted in
`qcom-build-utils`; they now live in `qualcomm-linux/qli-ci`.
