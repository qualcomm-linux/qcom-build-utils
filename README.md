# Build debian package locally
```
./scripts/docker_deb_build.py --source-dir ./some-pkg-repo --output-dir ./some-pkg-build-dir
```

The script docker_deb_build.py is a unified solution to build a debian package.
It works both on a arm64 or x86_64 build host; it builds natively for arm64 on arm64, and cross compiles on x86

The docker image from docker/Dockerfile.{arch}.noble/questing is used for building. The first time the script is ran, the image will be built.

pro-tip : Clone this repo somewhere and add the script as some short (debb == debian build) alias in ~/.bashrc :

```
alias debb="<loc>/scripts/docker_deb_build.py"
```

To rebuild the image :
```
debb --rebuild
```

# License

qcom-build-utils is licensed under the [BSD-3-clause License](https://spdx.org/licenses/BSD-3-Clause.html). See [LICENSE.txt](LICENSE.txt) for the full license text.
