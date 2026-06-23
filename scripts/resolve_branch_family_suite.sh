#!/usr/bin/env bash
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Resolve distro family/suite from a branch-like ref.
# The last two '/'-delimited fields are interpreted as "<family>/<suite>".

set -euo pipefail

normalize_ref() {
  local ref="$1"

  if [[ "$ref" == refs/heads/* ]]; then
    ref="${ref#refs/heads/}"
  fi
  if [[ "$ref" == refs/remotes/* ]]; then
    ref="${ref#refs/remotes/}"
  fi
  if [[ "$ref" == origin/* ]]; then
    ref="${ref#origin/}"
  fi

  printf '%s\n' "$ref"
}

resolve_from_ref() {
  local ref="$1"
  local -n out_family="$2"
  local -n out_suite="$3"
  local -a ref_parts

  IFS='/' read -r -a ref_parts <<< "$ref"
  if (( ${#ref_parts[@]} < 2 )); then
    return 1
  fi

  out_family="${ref_parts[$((${#ref_parts[@]} - 2))]}"
  out_suite="${ref_parts[$((${#ref_parts[@]} - 1))]}"

  case "$out_family" in
    debian|ubuntu)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

main() {
  if (( $# != 1 )); then
    echo "Usage: $0 <ref>" >&2
    exit 2
  fi

  local input_ref="$1"
  local normalized_ref family suite

  normalized_ref="$(normalize_ref "$input_ref")"
  if ! resolve_from_ref "$normalized_ref" family suite; then
    exit 1
  fi

  printf 'normalized_ref=%s\n' "$normalized_ref"
  printf 'family=%s\n' "$family"
  printf 'suite=%s\n' "$suite"
}

main "$@"
