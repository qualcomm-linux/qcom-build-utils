#!/usr/bin/env bash
# create-provenance.sh — Generate provenance.json for a Debian package release.
#
# Writes build/provenance.json (relative to the caller's working directory).
# Supports both source packages and prebuilt binary packages (upstream.conf).
#
# Required environment variables:
#   DISTRO_CODENAME   — suite name, e.g. resolute, noble, trixie
#   DEBIAN_BRANCH     — packaging branch, e.g. qcom/ubuntu/resolute
#   PKG_VERSION       — debian version string from changelog
#   PKG_REPO          — GitHub repository slug, e.g. qualcomm-linux/pkg-kgsl
#   UPSTREAM_REPO     — upstream GitHub repo slug (source packages only)

set -euo pipefail

: "${DISTRO_CODENAME:?DISTRO_CODENAME is required}"
: "${DEBIAN_BRANCH:?DEBIAN_BRANCH is required}"
: "${PKG_VERSION:?PKG_VERSION is required}"
: "${PKG_REPO:?PKG_REPO is required}"

mkdir -p build

cd package-repo

SOURCE=$(grep-dctrl -n -s Source -r '' debian/control | head -n1)
ALL_PKGS=$(grep-dctrl -n -s Package -r '' debian/control | sort -u)
ALL_PKGS_JSON=$(printf '%s\n' "$ALL_PKGS" | jq -c -R -s 'split("\n") | map(select(length>0))')

PACKAGE_REPO_TAG=$(git describe --tags --match "${DISTRO_CODENAME}/*" --abbrev=0 "${DEBIAN_BRANCH}")

if [[ -f "upstream.conf" ]]; then
  echo "ℹ️ upstream.conf found — generating provenance for prebuilt binary package"
  # shellcheck source=/dev/null
  source upstream.conf

  cat > ../build/provenance.json << EOF
{
  "$SOURCE" : {
    "source_pkg_version": "${PKG_VERSION}",

    "upstream_type": "prebuilt_binary",
    "upstream_repo": "$ARTIFACTORY",
    "upstream_repo_tag": "$TAG",
    "src_distro": "$DISTRO",
    "src_package_name": "$PACKAGE_NAME",

    "pkg_repo": "${PKG_REPO}",
    "pkg_repo_tag": "$PACKAGE_REPO_TAG",
    "pkg_repo_commit": "$(git rev-parse HEAD)",

    "binary_pkgs": $ALL_PKGS_JSON
  }
}
EOF
else
  echo "ℹ️ No upstream.conf — generating provenance for source package"

  : "${UPSTREAM_REPO:?UPSTREAM_REPO is required for source packages}"

  NEAREST_UPSTREAM_BRANCH_TAG=$(git describe --tags --match 'upstream/*' --abbrev=0)
  NEAREST_UPSTREAM_COMMIT=$(git rev-list -n 1 "$NEAREST_UPSTREAM_BRANCH_TAG")
  NEAREST_UPSTREAM_TAG=$(git ls-remote --tags "https://github.com/${UPSTREAM_REPO}.git" | \
    awk -v commit="$NEAREST_UPSTREAM_COMMIT" '$1 == commit && $2 ~ /refs\/tags\// { sub("refs/tags/", "", $2); print $2 }' | head -n1)

  cat > ../build/provenance.json << EOF
{
  "$SOURCE" : {
    "source_pkg_version": "${PKG_VERSION}",

    "upstream_type": "source",
    "upstream_repo": "${UPSTREAM_REPO}",
    "upstream_repo_tag": "$NEAREST_UPSTREAM_TAG",
    "upstream_repo_commit": "$NEAREST_UPSTREAM_COMMIT",

    "pkg_repo": "${PKG_REPO}",
    "pkg_repo_tag": "$PACKAGE_REPO_TAG",
    "pkg_repo_commit": "$(git rev-parse HEAD)",
    "pkg_repo_upstream_tag": "$NEAREST_UPSTREAM_BRANCH_TAG",

    "binary_pkgs": $ALL_PKGS_JSON
  }
}
EOF
fi

echo "Content of the provenance file:"
cat ../build/provenance.json | sed 's/^/\x1b[34m/' | sed 's/$/\x1b[0m/'
