#!/usr/bin/env bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Generate the release provenance.json for a package repo checkout.
#
# The upstream source for a package is tracked by one of three mechanisms,
# checked in this order:
#   1. upstream.conf               - prebuilt binary fetched from Artifactory
#   2. debian/watch (qartifactory) - prebuilt binary fetched via uscan/Artifactory
#   3. upstream/* git tags         - source package built from a git-forge upstream
#
# Required env vars: DISTRO_CODENAME, PKG_VERSION, PKG_REPO, SRCPKG_NAME,
# PKG_REPO_BRANCH. UPSTREAM_REPO is required only for mechanism 3.

set -euo pipefail

usage() {
  echo "Usage: $0 <package-repo-dir> <output-json-path>" >&2
  exit 2
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "::error::$name is required" >&2
    exit 1
  fi
}

resolve_package_repo_tag() {
  if PACKAGE_REPO_TAG=$(git describe --tags --match "${DISTRO_CODENAME}/*" --abbrev=0 2>/dev/null); then
    echo "Using package repo tag from git history: ${PACKAGE_REPO_TAG}"
  else
    local transformed_pkg_version sanitized_pkg_version
    transformed_pkg_version="$(echo "$PKG_VERSION" | perl -pe 'y/:~/%_/; s/\.(?=\.|$|lock$)/.#/g')"
    sanitized_pkg_version="$(echo "$transformed_pkg_version" | sed 's/[^A-Za-z0-9.+/%_#()-]//g')"
    PACKAGE_REPO_TAG="${DISTRO_CODENAME}/${sanitized_pkg_version}"
    echo "No matching local tag found; using derived sanitized tag: ${PACKAGE_REPO_TAG}"
  fi
}

write_provenance_prebuilt_binary_conf() {
  local output_path="$1" pkg_source="$2" all_pkgs_json="$3"

  echo "ℹ️ upstream.conf found — generating provenance for prebuilt binary package"
  # shellcheck source=/dev/null
  source "upstream.conf"

  cat > "$output_path" << EOF2
{
  "$pkg_source" : {
    "source_pkg_version": "${PKG_VERSION}",

    "upstream_type": "prebuilt_binary",
    "upstream_repo": "$ARTIFACTORY",
    "upstream_repo_tag": "$TAG",
    "src_distro": "$DISTRO",
    "src_package_name": "$PACKAGE_NAME",

    "pkg_repo": "${PKG_REPO}",
    "pkg_repo_tag": "$PACKAGE_REPO_TAG",
    "pkg_repo_commit": "$PACKAGE_REPO_COMMIT",
    "pkg_repo_branch": "${PKG_REPO_BRANCH}",

    "binary_pkgs": $all_pkgs_json
  }
}
EOF2
}

write_provenance_prebuilt_binary_watch() {
  local output_path="$1" pkg_source="$2" all_pkgs_json="$3"

  echo "ℹ️ debian/watch (Artifactory) found — generating provenance for uscan-fetched prebuilt binary package"

  # Same derivation build_package/action.yml uses to name/report the orig
  # tarball: strip the debian revision suffix from the source package version.
  local upstream_ver watch_url
  upstream_ver="$(echo "$PKG_VERSION" | sed 's/-[^-]*$//')"

  # Traceability only: capture the Artifactory URL pattern from debian/watch
  # itself, since there's no upstream.conf/ARTIFACTORY var for this mechanism.
  watch_url="$(grep -E '^\s*https://' debian/watch | head -1 | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]\\]*$//')"

  cat > "$output_path" << EOF2
{
  "$pkg_source" : {
    "source_pkg_version": "${PKG_VERSION}",

    "upstream_type": "prebuilt_binary_watch",
    "upstream_repo": "$watch_url",
    "upstream_repo_tag": "$upstream_ver",

    "pkg_repo": "${PKG_REPO}",
    "pkg_repo_tag": "$PACKAGE_REPO_TAG",
    "pkg_repo_commit": "$PACKAGE_REPO_COMMIT",
    "pkg_repo_branch": "${PKG_REPO_BRANCH}",

    "binary_pkgs": $all_pkgs_json
  }
}
EOF2
}

write_provenance_source() {
  local output_path="$1" pkg_source="$2" all_pkgs_json="$3"

  echo "ℹ️ No upstream.conf — generating provenance for source package"
  require_env UPSTREAM_REPO

  local nearest_upstream_branch_tag nearest_upstream_commit nearest_upstream_tag
  nearest_upstream_branch_tag=$(git describe --tags --match 'upstream/*' --abbrev=0)
  nearest_upstream_commit=$(git rev-list -n 1 "$nearest_upstream_branch_tag")
  nearest_upstream_tag="${nearest_upstream_branch_tag#upstream/}"

  if [[ "$nearest_upstream_tag" == "$nearest_upstream_branch_tag" ]]; then
    echo "::warning::Unexpected upstream tag format '${nearest_upstream_branch_tag}'; using it as-is"
  else
    echo "::notice::Using upstream tag '${nearest_upstream_tag}' derived from '${nearest_upstream_branch_tag}'"
  fi

  cat > "$output_path" << EOF2
{
  "$pkg_source" : {
    "source_pkg_version": "${PKG_VERSION}",

    "upstream_type": "source",
    "upstream_repo": "${UPSTREAM_REPO}",
    "upstream_repo_tag": "$nearest_upstream_tag",
    "upstream_repo_commit": "$nearest_upstream_commit",

    "pkg_repo": "${PKG_REPO}",
    "pkg_repo_tag": "$PACKAGE_REPO_TAG",
    "pkg_repo_commit": "$PACKAGE_REPO_COMMIT",
    "pkg_repo_branch": "${PKG_REPO_BRANCH}",
    "pkg_repo_upstream_tag": "$nearest_upstream_branch_tag",

    "binary_pkgs": $all_pkgs_json
  }
}
EOF2
}

main() {
  if (( $# != 2 )); then
    usage
  fi

  local package_repo_dir="$1" output_path="$2"

  require_env DISTRO_CODENAME
  require_env PKG_VERSION
  require_env PKG_REPO
  require_env SRCPKG_NAME
  require_env PKG_REPO_BRANCH

  local output_dir
  output_dir="$(dirname "$output_path")"
  mkdir -p "$output_dir"
  output_path="$(cd "$output_dir" && pwd)/$(basename "$output_path")"

  cd "$package_repo_dir"

  local pkg_source all_pkgs all_pkgs_json
  pkg_source="${SRCPKG_NAME}"
  all_pkgs=$(awk '/^Package:/{print $2}' debian/control | sort -u)
  all_pkgs_json=$(printf '%s\n' "$all_pkgs" | jq -c -R -s 'split("\n") | map(select(length>0))')

  resolve_package_repo_tag
  PACKAGE_REPO_COMMIT="$(git rev-parse HEAD)"

  if [[ -f "upstream.conf" ]]; then
    write_provenance_prebuilt_binary_conf "$output_path" "$pkg_source" "$all_pkgs_json"
  elif [[ -f "debian/watch" ]] && grep -q "qartifactory" "debian/watch"; then
    write_provenance_prebuilt_binary_watch "$output_path" "$pkg_source" "$all_pkgs_json"
  else
    write_provenance_source "$output_path" "$pkg_source" "$all_pkgs_json"
  fi

  echo "Content of the provenance file:"
  sed -e 's/^/\x1b[34m/' -e 's/$/\x1b[0m/' "$output_path"
}

main "$@"
