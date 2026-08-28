# qcom-build-utils

Shared build utilities and composite actions for Qualcomm Linux infrastructure.

## Scope

`qcom-build-utils` now focuses on reusable tooling and scripts for build systems.
Package lifecycle reusable workflows (`pkg-build`, `pkg-promote`,
`pkg-release`, `pkg-upstream-pr-build`) were moved to
[`qualcomm-linux/qli-ci`](https://github.com/qualcomm-linux/qli-ci).

## Repository Structure

```text
qcom-build-utils/
├── .github/
│   └── actions/
│       ├── abi_checker/
│       ├── build_package/
│       └── push_to_repo/
├── scripts/
├── kernel/
├── bootloader/
├── rootfs/
├── flash/
└── docs/
```

## Composite Actions

- `abi_checker`: ABI compatibility checks against prior published packages.
- `build_package`: Debian package build helpers based on gbp/sbuild flows.
- `push_to_repo`: Publish built packages and metadata to APT staging repos.

## Scripts and Build Helpers

The repository also carries utilities used by Qualcomm Linux build pipelines,
including kernel, bootloader, and rootfs build helpers.

## Migration Note

If your package repository still references workflows under:

- `qualcomm-linux/qcom-build-utils/.github/workflows/*`

retarget it to:

- `qualcomm-linux/qli-ci/.github/workflows/*`

and use `qli-ci` workflow inputs (for example `qli-ci-ref`).

## Documentation

See [`docs/`](docs/) for action and scripting documentation.

## Related Repositories

- [`qualcomm-linux/qli-ci`](https://github.com/qualcomm-linux/qli-ci)
  package reusable workflows and templates.
- [`qualcomm-linux/debusine-action`](https://github.com/qualcomm-linux/debusine-action)
  Debusine implementation details.
- [`qualcomm-linux/docker-pkg-build`](https://github.com/qualcomm-linux/docker-pkg-build)
  local/containerized package build reference.

## Branches

`main` is the primary development branch.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

qcom-build-utils is licensed under [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html).
See [LICENSE.txt](LICENSE.txt).
