#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# Parse a targets.json file and emit a validated JSON array to stdout.
#
# targets.json format:
#   [
#     {
#       "name":             "iq-x7181-evk",       (required)
#       "boot_bin_url":     "https://...",         (required)
#       "ptool_platform":   "iq-x7181-evk",       (required)
#       "cdt_url":          "https://...",         (optional, default "")
#       "cdt_filename":     "cdt_foo.bin",         (optional, default "")
#       "contents_xml_in":  "platform/foo/..."     (optional, default "")
#     },
#     ...
#   ]
#
# If targets.json does not exist, emits [] and exits 0 (non-flat-meta config).
# Exits 1 on parse or validation errors.
#
# Usage:
#   python3 parse-boards-config.py <targets.json>

import json
import os
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <targets.json>", file=sys.stderr)
        return 1

    path = sys.argv[1]

    if not os.path.isfile(path):
        print("[]")
        return 0

    try:
        with open(path) as f:
            targets = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] Cannot parse {path}: {e}", file=sys.stderr)
        return 1

    if not isinstance(targets, list):
        print(f"[ERROR] {path} must contain a JSON array", file=sys.stderr)
        return 1

    for i, t in enumerate(targets):
        for key in ("name", "boot_bin_url", "ptool_platform"):
            if not t.get(key):
                print(f"[ERROR] targets[{i}] missing '{key}'", file=sys.stderr)
                return 1
        t.setdefault("cdt_url", "")
        t.setdefault("cdt_filename", "")
        t.setdefault("contents_xml_in", "")

    print(json.dumps(targets, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
