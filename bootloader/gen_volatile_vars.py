#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Generate a VolatileVars.bin for EBBR-style UEFI variable persistence.

Usage:
    # write VolatileVars.bin with only the built-in default entries
    python3 gen_volatile_vars.py

    # write to a specific path
    python3 gen_volatile_vars.py --out /path/to/VolatileVars.bin

    # merge in extra entries from a JSON config (same guid+name as a
    # default entry overrides it; otherwise the entry is appended)
    python3 gen_volatile_vars.py --config extra.json --out VolatileVars.bin

Config file format:
    {
      "entries": [
        {
          "guid": "12345678-1234-1234-1234-123456789abc",
          "name": "ExampleVar",
          "attributes": "0x7",
          "data_hex": "01020304"
        }
      ]
    }
    Each entry needs exactly one of data_hex / data_b64 / data_utf8.

Format (all little-endian), matches the EFI_VARIABLE_FILE / EFI_VARIABLE_ENTRY
layout read by the firmware's UpdateVariableFromRTVolatileBin():

EFI_VARIABLE_FILE header (24 bytes):
    UINT64 Reserved      (0)
    UINT8  Magic[7]      "UbEfiVa"
    UINT8  Revision      1
    UINT32 Length        total file size
    UINT32 Crc32         zlib crc32 over everything after the header

EFI_VARIABLE_ENTRY, repeated, each 8-byte aligned (32-byte header + name + data):
    UINT32   DataSize
    UINT32   Attributes
    UINT64   Reserved     (0)
    EFI_GUID VendorGuid   (16 bytes)
    CHAR16   Name[]       UCS-2, NUL-terminated
    UINT8    Data[DataSize]
    <pad to 8-byte alignment>
"""
import argparse
import base64
import json
import struct
import uuid
import zlib

MAGIC = b"UbEfiVa"
REVISION = 1
ALIGNMENT = 8

EFI_VARIABLE_NON_VOLATILE = 0x00000001
EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002
EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004

UINT32_MAX = 0xFFFFFFFF

# Always included, even without --config. A --config entry with the same
# (guid, name) overrides the default below.
DEFAULT_ENTRIES = [
    {
        "guid": "882f8c2b-9646-435f-8de5-f208ff80c1bd",
        "name": "VendorDtbOverlays",
        "attributes": (
            EFI_VARIABLE_NON_VOLATILE
            | EFI_VARIABLE_BOOTSERVICE_ACCESS
            | EFI_VARIABLE_RUNTIME_ACCESS
        ),
        "data_utf8": "camx",
    },
]


def _parse_int(value):
    """Parse an int from either a real int/float or a string like '7', '0x7'.

    Avoids int(x, 0), which rejects legal decimal strings with a leading
    zero (e.g. "07") by misinterpreting them as octal.
    """
    if isinstance(value, bool):
        raise ValueError(f"expected an integer, got bool: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ValueError(f"expected an integer, got float: {value!r}")
    s = value.strip()
    if s[:2].lower() == "0x":
        return int(s, 16)
    return int(s, 10)


def _require_uint32(value, field_name):
    n = _parse_int(value)
    if not (0 <= n <= UINT32_MAX):
        raise ValueError(f"{field_name} must fit in UINT32 (0..{UINT32_MAX}), got {n}")
    return n


def _guid_to_bytes(guid_str):
    g = uuid.UUID(guid_str)
    b = g.bytes_le  # EFI_GUID is stored little-endian (matches Data1/Data2/Data3 as LE, Data4 as-is)
    return b


def build_entry(guid_str, name, data, attributes):
    guid_bytes = _guid_to_bytes(guid_str)
    name_bytes = name.encode("utf-16-le") + b"\x00\x00"
    data_size = _require_uint32(len(data), "DataSize")
    attributes = _require_uint32(attributes, "Attributes")
    header = struct.pack("<IIQ", data_size, attributes, 0) + guid_bytes
    entry = header + name_bytes + data
    pad = (-len(entry)) % ALIGNMENT
    return entry + b"\x00" * pad


def build_volatile_vars(entries):
    """entries: list of dicts with keys guid, name, data (bytes), attributes"""
    body = b"".join(
        build_entry(e["guid"], e["name"], e["data"], e["attributes"])
        for e in entries
    )
    length = 24 + len(body)
    crc32 = zlib.crc32(body) & 0xFFFFFFFF
    header = struct.pack("<Q7sBII", 0, MAGIC, REVISION, length, crc32)
    return header + body


def _decode_data(entry):
    """Accept data as one of: data_hex, data_b64, data_utf8. Exactly one must be set."""
    present = [k for k in ("data_hex", "data_b64", "data_utf8") if k in entry]
    if len(present) > 1:
        raise ValueError(
            f"entry {entry.get('name')!r} has multiple data fields set {present}; "
            "exactly one of data_hex/data_b64/data_utf8 is allowed"
        )
    if "data_hex" in entry:
        return bytes.fromhex(entry["data_hex"])
    if "data_b64" in entry:
        return base64.b64decode(entry["data_b64"])
    if "data_utf8" in entry:
        return entry["data_utf8"].encode("utf-8")
    raise ValueError(f"entry {entry.get('name')!r} missing data_hex/data_b64/data_utf8")


def _parse_raw_entries(raw_entries, source):
    entries = []
    for i, e in enumerate(raw_entries):
        label = e.get("name", f"<unnamed entry {i}>")
        try:
            entries.append(
                {
                    "guid": e["guid"],
                    "name": e["name"],
                    "data": _decode_data(e),
                    "attributes": _parse_int(e["attributes"]),
                }
            )
        except KeyError as ex:
            raise ValueError(f"{source} entry {i} ({label!r}) missing required field: {ex}") from ex
        except ValueError as ex:
            raise ValueError(f"{source} entry {i} ({label!r}): {ex}") from ex
    return entries


def load_entries_from_config(path):
    with open(path) as f:
        cfg = json.load(f)
    if "entries" not in cfg:
        raise ValueError(f"{path}: missing top-level 'entries' array")
    return _parse_raw_entries(cfg["entries"], path)


def merge_entries(default_entries, override_entries):
    """override_entries with the same (guid, name) as a default replace it;
    otherwise they're appended. Order of defaults is preserved."""
    overrides_by_key = {(e["guid"].lower(), e["name"]): e for e in override_entries}
    merged = []
    used_keys = set()
    for e in default_entries:
        key = (e["guid"].lower(), e["name"])
        merged.append(overrides_by_key.get(key, e))
        used_keys.add(key)
    for e in override_entries:
        key = (e["guid"].lower(), e["name"])
        if key not in used_keys:
            merged.append(e)
    return merged


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        help="JSON file describing additional/override variable entries "
        "(merged with the built-in defaults; an entry with the same "
        "guid+name as a default replaces it)",
    )
    parser.add_argument("--out", default="VolatileVars.bin", help="output file path")
    args = parser.parse_args()

    default_entries = _parse_raw_entries(DEFAULT_ENTRIES, "<default>")
    config_entries = load_entries_from_config(args.config) if args.config else []
    entries = merge_entries(default_entries, config_entries)

    data = build_volatile_vars(entries)
    with open(args.out, "wb") as f:
        f.write(data)
    print(f"wrote {len(data)} bytes to {args.out} ({len(entries)} entries)")
