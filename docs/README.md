# qcom-build-utils Workflow Documentation

This directory contains documentation for the GitHub workflows and actions used in the qcom-build-utils repository.

## Overview

The qcom-build-utils repository provides a set of **reusable GitHub workflows** and **composite actions** designed to standardize the Debian package build process for Qualcomm Linux projects. These workflows are primarily consumed by Debian packaging repositories (conventionally prefixed with `pkg-`).

## Documentation Index

1. **[Workflow Architecture](./workflow-architecture.md)** - High-level overview of the workflow ecosystem and how it integrates with package repositories
2. **[Reusable Workflows](./reusable-workflows.md)** - Detailed documentation of each reusable workflow
3. **[GitHub Actions](./github-actions.md)** - Documentation of composite actions used by the workflows
4. **[Package Repository Integration](./package-repo-integration.md)** - Guide for integrating these workflows into package repositories

## Quick Start

For package repository maintainers looking to use these workflows:

1. **Start with the template**: Use [pkg-template](https://github.com/qualcomm-linux/pkg-template) to quickly create a new package repository
2. Review the [Workflow Architecture](./workflow-architecture.md) to understand the overall system
3. Follow the [Package Repository Integration](./package-repo-integration.md) guide to customize your repository
4. Refer to the [pkg-example](https://github.com/qualcomm-linux/pkg-example) repository for a complete working example

## Key Concepts

- **Upstream Repository**: The source code repository for a project (e.g., [qcom-example-package-source](https://github.com/qualcomm-linux/qcom-example-package-source))
- **Package Repository (pkg-*)**: A Debian packaging repository following the git-buildpackage structure, containing debian control files and workflows
- **Reusable Workflows**: Centralized workflow definitions in qcom-build-utils that are called from package repositories
- **Composite Actions**: Modular steps that perform specific tasks like building packages or checking ABI compatibility
- **Debian Branches**: Git branches following the `debian/` prefix convention (e.g., `debian/latest`, `debian/1.0.0-1`)
- **Upstream Branches**: Git branches following the `upstream/` prefix convention for tracking upstream source code

## Support

For questions or issues:
- Review the documentation in this directory
- Use the [pkg-template](https://github.com/qualcomm-linux/pkg-template) to start a new package repository
- Check the [pkg-example](https://github.com/qualcomm-linux/pkg-example) repository for a complete packaging example
- See the [qcom-example-package-source](https://github.com/qualcomm-linux/qcom-example-package-source) repository for an example upstream project with package integration
- Consult the main [README.md](../README.md) for general build instructions
