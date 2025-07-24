# Clone qcom-build-utils
```
 git clone git@github.com:qualcomm-linux/qcom-build-utils.git -b latest
```
```
cd qcom-build-utils
```

# Sync and build qcom-next
```
cd kernel && export BUILD_TOP=`pwd`
```
```
git clone https://github.com/qualcomm-linux/kernel.git --single-branch -b qcom-next --depth=1 $BUILD_TOP/qcom-next
```

### Add Kernel SQUASHFS configs required for Ubuntu
```
./scripts/enable_squashfs_configs.sh $BUILD_TOP/qcom-next/
```

### Run build_kernel.sh
```
./scripts/build_kernel.sh
```
At the end of kernel build, below products will be deployed in ```kernel/out/```

# Generate Linux Kernel Debian Package
Run ```build-kernel-deb.sh``` and pass as argument the directory where kernel build artifacts were deployed (```out/```):
```
./scripts/build-kernel-deb.sh out/
```
```linux-kernel-<kversion>-arm64.deb``` will be generated in ```kernel/```

# Build EFI System Partition Image
```
cd ../  # Moves you into the qcom-build-utils/ directory
```
```
./bootloader/build-efi-esp.sh
```
```efiesp.bin``` will be generated and deployed in ```qcom-build-utils/```

# Download firmware debian package for X Elite CRD
```
wget "https://qli-stg-kernel-gh-artifacts.s3.amazonaws.com/kernel/ubuntu-firmware/linux-firmware-xelite_1.0-1%2Bnoble_arm64.deb?AWSAccessKeyId=AKIAXYMT55OHLXWGCTOU&Signature=TiG%2FZrnzJwhZoWK91y4qEf%2BczzA%3D&Expires=1788577277" -O "linux-firmware-xelite_1.0-1+noble_arm64.deb"
```
```linux-firmware-xelite_1.0-1+noble_arm64.deb``` will be downloaded in ```qcom-build-utils/linux-firmware-xelite_1.0-1+noble_arm64.deb```

# Build Ubuntu Rootfs
```
./rootfs/scripts/build-ubuntu-rootfs.sh kernel/linux-kernel-<kversion>-arm64.deb linux-firmware-xelite_1.0-1+noble_arm64.deb
```
```ubuntu.img``` root filesystem image will be generated in ```qcom-build-utils/ubuntu.img```

# Final Products
Kernel Debian Package:
```qcom-build-utils/kernel/```
```
  -linux-kernel-<kversion>-arm64.deb
```
Bootable images: 
```qcom-build-utils/```
```
    - efiesp.bin
    - ubuntu.img
```

