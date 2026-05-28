#!/usr/bin/env bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear
# push-provenance.sh — Push provenance.json to qcom-distro-artifacts.
#
# Clones qcom-distro-artifacts, merges the new provenance entry into the
# suite-level provenance.json, and pushes with up to 3 rebase retries.
#
# Required environment variables:
#   GH_PAT     — GitHub PAT with write access to qcom-distro-artifacts
#   SUITE      — suite name, e.g. resolute, noble
#   BOT_NAME   — git commit author name
#   BOT_EMAIL  — git commit author email
#
# Expected input file:
#   build/provenance.json  — written by create-provenance.sh

set -euo pipefail

: "${GH_PAT:?GH_PAT is required}"
: "${SUITE:?SUITE is required}"
: "${BOT_NAME:?BOT_NAME is required}"
: "${BOT_EMAIL:?BOT_EMAIL is required}"

git clone "https://x-access-token:${GH_PAT}@github.com/qualcomm-linux/qcom-distro-artifacts.git" ./qcom-distro-artifacts

cd qcom-distro-artifacts

git config user.name "${BOT_NAME}"
git config user.email "${BOT_EMAIL}"

mkdir -p "${SUITE}"

SUITE_PROVENANCE="${SUITE}/provenance.json"
NEW_PROVENANCE="../build/provenance.json"

if [[ -f "${SUITE_PROVENANCE}" ]]; then
  jq -s --indent 2 '.[0] * .[1]' "${SUITE_PROVENANCE}" "${NEW_PROVENANCE}" > /tmp/merged_provenance.json
  mv /tmp/merged_provenance.json "${SUITE_PROVENANCE}"
else
  cp "${NEW_PROVENANCE}" "${SUITE_PROVENANCE}"
fi

git add "${SUITE_PROVENANCE}"

if git diff --cached --quiet; then
  echo "Provenance unchanged, nothing to commit"
else
  SOURCE_PKG=$(jq -r 'keys[0]' "${NEW_PROVENANCE}")
  VERSION=$(jq -r '.[keys[0]].source_pkg_version' "${NEW_PROVENANCE}")
  git commit -m "provenance: update ${SOURCE_PKG} ${VERSION} for ${SUITE}"

  for attempt in 1 2 3; do
    git push origin main && break
    echo "Push attempt ${attempt} failed, rebasing and retrying..."
    git pull --rebase origin main
  done
fi
