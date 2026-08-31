# qcom-build-utils

This repository now hosts Qualcomm Linux platform build helpers only.

## Migration Status

Package CI assets were migrated out of `qcom-build-utils` to
[`qualcomm-linux/qli-ci`](https://github.com/qualcomm-linux/qli-ci).

Migrated paths:

- `scripts/`
- `.github/actions/`
- `.github/workflows/`

## Current Repository Scope

The maintained build helper content in this repository is:

- `kernel/`
- `bootloader/`
- `rootfs/`
- `flash/`

## Package CI Source of Truth

For package build, promote, release, and upstream PR validation workflows, use:

- [`qualcomm-linux/qli-ci`](https://github.com/qualcomm-linux/qli-ci)
- [`qualcomm-linux/debusine-action`](https://github.com/qualcomm-linux/debusine-action)

## Repository Layout

```text
qcom-build-utils/
|- .github/
|  |- ISSUE_TEMPLATE/
|  |- PULL_REQUEST_TEMPLATE/
|- bootloader/
|- docs/
|- flash/
|- kernel/
|- rootfs/
|- AGENTS.md
|- CONTRIBUTING.md
|- LICENSE.txt
`- README.md
```

## Related Repositories

- [`qualcomm-linux/qli-ci`](https://github.com/qualcomm-linux/qli-ci)
- [`qualcomm-linux/debusine-action`](https://github.com/qualcomm-linux/debusine-action)
- [`qualcomm-linux/pkg-example`](https://github.com/qualcomm-linux/pkg-example)
- [`qualcomm-linux/docker-pkg-build`](https://github.com/qualcomm-linux/docker-pkg-build)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements.

## License

Licensed under the [BSD-3-Clause License](https://spdx.org/licenses/BSD-3-Clause.html).
See [LICENSE.txt](LICENSE.txt).
