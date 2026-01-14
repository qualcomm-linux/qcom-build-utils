#!/bin/bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# ===================================================
# build_kernel.sh
#
# Tool to build and deploy linux kernel artifacts for iot & compute platforms
#
# Author: Bjordis Collaku <bcollaku@qti.qualcomm.com>
# ===================================================

kpath=$BUILD_TOP/qcom-next/arch/arm64/boot

# Clean previous build
rm -rf $BUILD_TOP/out/*;

# Make config
cd $BUILD_TOP/qcom-next/
make ARCH=arm64 defconfig qcom.config
# Deploy boot config to out/
cp $BUILD_TOP/qcom-next/.config $BUILD_TOP/out/

# Make kernel
make ARCH=arm64 -j32;
# Deploy kernel Image to out/
cp $kpath/Image $BUILD_TOP/out/

# Make modules
mkdir -p $BUILD_TOP/out/modules/
make ARCH=arm64 modules
# Deploy kernel modules to out/
make ARCH=arm64 modules_install INSTALL_MOD_PATH=$BUILD_TOP/out/modules INSTALL_MOD_STRIP=1

# Deploy ALL device tree blobs (*.dtb) to out/ (recursively)
find "$kpath/dts" -type f -name '*.dtb' -print0 | xargs -0 -I{} cp "{}" "$BUILD_TOP/out/"
