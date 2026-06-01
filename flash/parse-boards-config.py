#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# Parse a qcom-product.conf file and emit a JSON array of board entries
# to stdout. Supports two forms:
#
# Form 1 — legacy single-board flat keys:
#   boot_binaries_url: https://...
#   qcom_ptool_platform: iq-x7181-evk
#   cdt_binaries_url: https://...      (optional)
#   cdt_filename: cdt_foo.bin          (optional)
#
# Form 2 — multi-board list:
#   boards:
#     - name: board-a
#       boot_binaries_url: https://...
#       qcom_ptool_platform: platform-a
#       cdt_binaries_url: https://...  (optional)
#       cdt_filename: cdt_a.bin        (optional)
#     - name: board-b
#       ...
#
# Output (JSON array, one object per board):
#   [
#     {
#       "name": "board-a",
#       "boot_binaries_url": "https://...",
#       "qcom_ptool_platform": "platform-a",
#       "cdt_binaries_url": "",
#       "cdt_filename": ""
#     },
#     ...
#   ]
#
# Exit 0 with empty array [] if neither form is present (non-flat-meta config).
# Exit 1 on parse errors.
#
# Usage:
#   python3 parse-boards-config.py <qcom-product.conf>

import json
import re
import sys


def parse_flat_key(lines: list[str], key: str) -> str:
    pattern = re.compile(r"^\s*" + re.escape(key) + r"\s*:\s*(.+)$")
    for line in lines:
        m = pattern.match(line)
        if m:
            return m.group(1).strip()
    return ""


def parse_boards_block(lines: list[str]) -> list[dict]:
    """Parse the boards: list block from qcom-product.conf lines."""
    boards: list[dict] = []
    in_boards = False
    current: dict | None = None

    for line in lines:
        stripped = line.rstrip()

        # Detect start of boards: block
        if re.match(r"^\s*boards\s*:\s*$", stripped):
            in_boards = True
            continue

        if not in_boards:
            continue

        # A top-level non-indented non-empty line ends the boards block
        if stripped and not stripped.startswith(" ") and not stripped.startswith("\t") and not stripped.startswith("#"):
            in_boards = False
            if current:
                boards.append(current)
                current = None
            continue

        # Skip blank lines and comments inside the block
        if not stripped or stripped.lstrip().startswith("#"):
            continue

        # New board entry starts with "  - name:"
        m_entry = re.match(r"^\s+-\s+name\s*:\s*(.+)$", stripped)
        if m_entry:
            if current:
                boards.append(current)
            current = {
                "name": m_entry.group(1).strip(),
                "boot_binaries_url": "",
                "qcom_ptool_platform": "",
                "cdt_binaries_url": "",
                "cdt_filename": "",
            }
            continue

        # Key-value inside a board entry (indented, no leading dash)
        m_kv = re.match(r"^\s+(\w+)\s*:\s*(.+)$", stripped)
        if m_kv and current is not None:
            key = m_kv.group(1).strip()
            val = m_kv.group(2).strip()
            if key in current:
                current[key] = val

    if current:
        boards.append(current)

    return boards


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <qcom-product.conf>", file=sys.stderr)
        return 1

    conf_path = sys.argv[1]
    try:
        with open(conf_path) as f:
            lines = f.readlines()
    except OSError as e:
        print(f"[ERROR] Cannot read {conf_path}: {e}", file=sys.stderr)
        return 1

    # Try multi-board form first
    boards = parse_boards_block(lines)
    if boards:
        # Validate required fields
        for i, b in enumerate(boards):
            if not b.get("name"):
                print(f"[ERROR] Board entry {i} missing 'name'", file=sys.stderr)
                return 1
            if not b.get("boot_binaries_url"):
                print(f"[ERROR] Board '{b['name']}' missing 'boot_binaries_url'", file=sys.stderr)
                return 1
            if not b.get("qcom_ptool_platform"):
                print(f"[ERROR] Board '{b['name']}' missing 'qcom_ptool_platform'", file=sys.stderr)
                return 1
        print(json.dumps(boards, indent=2))
        return 0

    # Fall back to legacy single-board flat keys
    boot_url = parse_flat_key(lines, "boot_binaries_url")
    ptool_platform = parse_flat_key(lines, "qcom_ptool_platform")

    if not boot_url or not ptool_platform:
        # No flat-meta config — emit empty array
        print("[]")
        return 0

    board: dict = {
        "name": ptool_platform,  # use platform name as board name for legacy configs
        "boot_binaries_url": boot_url,
        "qcom_ptool_platform": ptool_platform,
        "cdt_binaries_url": parse_flat_key(lines, "cdt_binaries_url"),
        "cdt_filename": parse_flat_key(lines, "cdt_filename"),
    }
    print(json.dumps([board], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
