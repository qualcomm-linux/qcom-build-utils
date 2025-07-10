# Clone kmake-image
```
git clone git@github.com:qualcomm-linux-stg/kmake-image.git -b ubuntu-noble-arm64
```
```
cd kmake-image
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
vim qcom-next/arch/arm64/configs/defconfig
```
Enable below:
```
CONFIG_SQUASHFS_XZ=y
CONFIG_SQUASHFS_LZO=y
CONFIG_SQUASHFS_XATTR=y
CONFIG_SQUASHFS_ZLIB=y
CONFIG_SQUASHFS_LZ4=y
```
Exit + save + commit defconfig change

### Run build_kernel.sh
```
./scripts/build_kernel.sh
```
At the end of kernel build, below products will be deployed in ```kernel/out/```

```
.config
Image
modules/lib/modules/<kernel_version>
x1e80100-crd.dtb
qcs6490-rb3gen2.dtb
```

# Generate Linux Kernel Debian Package
```
cd kmake-image/kernel/
```
Run build-kernel-deb.sh and pass as argument the directory where kernel build artifacts were deployed (```out/```):
```
./scripts/build-kernel-deb.sh out/
```
```linux-kernel-<kversion>-arm64.deb``` will be generated in ```kernel/```


