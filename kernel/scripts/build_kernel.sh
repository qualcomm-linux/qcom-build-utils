#!/bin/bash

# Script by Bjordis C. to build and deploy linux kernel for iot & compute platforms

# ===================================================
kpath=$BUILD_TOP/qcom-next/arch/arm64/boot
CRD_DTB=$kpath/dts/qcom/x1e80100-crd.dtb
QCS6490_DTB=$kpath/dts/qcom/qcs6490-rb3gen2.dtb
 
# Clean previous build
rm -rf $BUILD_TOP/out/*;

# Make config
cd $BUILD_TOP/qcom-next/
make ARCH=arm64 defconfig
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
cp $CRD_DTB $BUILD_TOP/out/
cp $QCS6490_DTB $BUILD_TOP/out/
