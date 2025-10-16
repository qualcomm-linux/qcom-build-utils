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
CRD_DTB=$kpath/dts/qcom/x1e80100-crd.dtb
EVK_DTB=$kpath/dts/qcom/hamoa-iot-evk.dtb
QCS6490_DTB=$kpath/dts/qcom/qcs6490-rb3gen2.dtb
QCS8300_DTB=$kpath/dts/qcom/qcs8300-ride.dtb 
QCS9100_DTB=$kpath/dts/qcom/qcs9100-ride-r3.dtb

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

# Deploy device tree blobs to out/
[ -f "$CRD_DTB" ] && cp "$CRD_DTB" "$BUILD_TOP/out/"
[ -f "$EVK_DTB" ] && cp "$EVK_DTB" "$BUILD_TOP/out/"
[ -f "$QCS6490_DTB" ] && cp "$QCS6490_DTB" "$BUILD_TOP/out/"
[ -f "$QCS8300_DTB" ] && cp "$QCS8300_DTB" "$BUILD_TOP/out/"
[ -f "$QCS9100_DTB" ] && cp "$QCS9100_DTB" "$BUILD_TOP/out/"
