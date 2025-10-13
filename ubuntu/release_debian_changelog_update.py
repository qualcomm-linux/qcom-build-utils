#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
release_debian_changelog_update.py

Single entry: --apt-source-line
- If it starts with "deb " -> hosted APT source line (APT mode).
- Else, if it is an existing directory path OR "file:///..." -> local filer dir (Local mode).
- Otherwise, error.

Rules per debian/ tree (ADD +rel WITHOUT NUMERIC BUMP):
1) If NO .deb found:
   - Ensure a +rel entry at the tip of the local changelog:
       version := <local_top_version> + "+rel" (only if not already ending with +rel).
   - --dry-run: write simulated result to debian/changed-changelog
   - default:   apply with dch in-place to debian/changelog

2) If a .deb IS found:
   - Extract its changelog and read deb_top_version.
   - Let base = strip_rel_suffix(deb_top_version)  # remove trailing +rel if present
   - If base == local_top_version:
       -> Replace debian/changelog with the .deb changelog.
     Else:
       -> If an exact local entry equals 'base': prepend all local entries ABOVE that entry to the .deb changelog.
       -> If no exact match: prepend ONLY local entries whose version is GREATER than 'base'
          per dpkg --compare-versions (stop at first non-greater).
   - After replace/merge, ensure a +rel entry at the tip (only suffix; no numeric bump).
   - --dry-run: write merged/replaced content to debian/changed-changelog
   - default:   write merged/replaced content in place to debian/changelog

Maintainer identity on +rel:
- Always taken from the signature line of the entry being extended (the current tip entry):
    " -- Full Name <email>  date"
- If it cannot be parsed, the script logs an error and marks that tree as failed
  (no fallback identity).

Message for +rel entries:
- "Automated patch bump: Version updated to <new_version_with_rel>"

Dependencies:
  - Always: dch, dpkg-deb, dpkg
  - APT mode: apt-get
"""

import os
import re
import sys
import gzip
import lzma
import html
import shutil
import tempfile
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from color_logger import logger  # logger.info / logger.warning / logger.error

# ========================= Debian Changelog Parsing =========================

class ChangelogEntry:
    __slots__ = ("version", "distribution", "start", "end", "text")

    def __init__(self, version: str, distribution: Optional[str], start: int, end: int, text: str):
        self.version = version
        self.distribution = distribution
        self.start = start
        self.end = end
        self.text = text


HEADER_RE = re.compile(r'^(\S+)\s+\(([^)]+)\)\s+([^\s;]+);\s*urgency=.*$', re.MULTILINE)

# Primary: strict Debian signature line with tolerance for spaces before date
SIGNER_RE_PRIMARY = re.compile(
    r'^\s*--\s*(.*?)\s*<([^>]+)>\s+.+$',
    re.MULTILINE
)

# Secondary: generic line containing <email>, take text before '<' as name
SIGNER_RE_FALLBACK = re.compile(
    r'^(?P<prefix>.*?)(?P<email><[^>]+>).*?$',
    re.MULTILINE
)


def parse_debian_changelog(text: str) -> List[ChangelogEntry]:
    entries: List[ChangelogEntry] = []
    matches = list(HEADER_RE.finditer(text))
    if not matches:
        return entries
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        version = m.group(2).strip()
        distribution = (m.group(3) or "").strip()
        entries.append(ChangelogEntry(version, distribution, start, end, block))
    return entries


def serialize_changelog(entries: List[ChangelogEntry]) -> str:
    return "".join(e.text for e in entries)


def ensure_trailing_newline(s: str) -> str:
    return s if s.endswith("\n") else s + "\n"


def add_rel_suffix(version: str) -> str:
    if re.search(r'\+rel(\d+)?$', version):
        return version
    return version + "+rel"


def strip_rel_suffix(version: str) -> str:
    return re.sub(r'\+rel(\d+)?$', "", version)


def index_of_version(entries: List[ChangelogEntry], version: str) -> Optional[int]:
    for idx, e in enumerate(entries):
        if e.version.strip() == version.strip():
            return idx
    return None


def distribution_hint_from_text(text: str) -> Optional[str]:
    m = HEADER_RE.search(text)
    if not m:
        return None
    return (m.group(3) or "").strip() or None


def extract_maint_from_entry_text(entry_text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse signature line from an entry block, robustly:
      1) Unescape HTML (&lt;&gt; -> <>)
      2) Try Debian signature format: '^ -- Name <email>  date'
      3) Fallback: last line containing '<...>' -> name is text before '<', email is the ... inside <>
    Return (name, email) or (None, None).
    """
    unescaped = html.unescape(entry_text)

    # Strategy 1: standard Debian signature line
    matches = list(SIGNER_RE_PRIMARY.finditer(unescaped))
    if matches:
        m = matches[-1]  # last signature in block
        name = (m.group(1) or "").strip()
        email = (m.group(2) or "").strip()
        if name and "@" in email:
            return name, email

    # Strategy 2: generic last line containing <...>
    lines = unescaped.splitlines()
    for line in reversed(lines):
        if "<" in line and ">" in line:
            m2 = SIGNER_RE_FALLBACK.match(line.strip())
            if not m2:
                continue
            prefix = (m2.group("prefix") or "").strip()
            # Pull name after leading '--' if present
            prefix = re.sub(r'^\s*--\s*', '', prefix).strip()
            # Extract email inside <>
            em = re.search(r'<([^>]+)>', line)
            email = em.group(1).strip() if em else ""
            name = prefix
            if name and "@" in email:
                return name, email

    return None, None

# ========================= Debian Version Compare (dpkg) =========================

def dpkg_compare(v1: str, op: str, v2: str) -> bool:
    """
    Debian-accurate version compare via dpkg --compare-versions.
    op ∈ {"lt","le","eq","ne","ge","gt"}.
    """
    try:
        res = subprocess.run(
            ["dpkg", "--compare-versions", v1, op, v2],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except FileNotFoundError:
        logger.error("dpkg is required for version comparisons but not found in PATH.")
        raise


def newer_local_prefix(entries: List[ChangelogEntry], base: str) -> List[ChangelogEntry]:
    """
    Contiguous prefix of entries whose version is strictly GREATER than 'base' (newest->oldest).
    """
    newer: List[ChangelogEntry] = []
    for e in entries:
        if dpkg_compare(e.version, "gt", base):
            newer.append(e)
        else:
            break
    return newer

# ========================= dch Helpers =========================

def run_dch_newversion_inplace(
    changelog_path: str,
    new_version: str,
    distribution: str,
    maint_name: str,
    maint_email: str
):
    """
    Add a new top entry via dch with standardized message and exact identity.
    NOTE: This only appends '+rel' to the version; it NEVER changes numeric parts.
    """
    dch = shutil.which("dch")
    if not dch:
        logger.error("dch is required but not found in PATH.")
        raise RuntimeError("dch is required but not found in PATH.")
    env = os.environ.copy()
    # Enforce identity; set all known env vars dch can read
    env["DEBFULLNAME"] = maint_name
    env["DEBEMAIL"] = maint_email
    env["EMAIL"] = maint_email
    message = f"Automated patch bump: Version updated to {new_version}"
    cmd = [
        dch,
        "--changelog", changelog_path,
        "--newversion", new_version,
        "--force-distribution",
        "--distribution", distribution,
        message,
    ]
    subprocess.run(cmd, check=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def add_new_changelog_entry_with_dch(
    changelog_path: str,
    new_version: str,
    distribution: str,
    maint_name: str,
    maint_email: str
) -> str:
    run_dch_newversion_inplace(
        changelog_path, new_version, distribution, maint_name, maint_email
    )
    return Path(changelog_path).read_text(encoding="utf-8", errors="replace")


def ensure_rel_at_tip_inplace(
    changelog_path: str,
    distribution_fallback: str = "unstable"
):
    """
    Ensure +rel (only suffix) at the top; maintainer MUST be parsed from tip entry.
    """
    text = Path(changelog_path).read_text(encoding="utf-8", errors="replace")
    entries = parse_debian_changelog(text)
    if not entries:
        raise RuntimeError(f"Unable to parse {changelog_path} to enforce +rel.")

    top_entry = entries[0]
    top_version = top_entry.version
    rel_version = add_rel_suffix(top_version)
    if rel_version == top_version:
        logger.info(f"Top already has +rel: {top_version}")
        return

    name, email = extract_maint_from_entry_text(top_entry.text)
    if not name or not email:
        raise RuntimeError("Cannot parse maintainer name/email from tip entry; refusing to add +rel.")

    dist = top_entry.distribution or distribution_fallback
    logger.info(f"Adding +rel via dch: {rel_version} (dist={dist}, maint={name} <{email}>)")
    run_dch_newversion_inplace(
        changelog_path, rel_version, dist, name, email
    )


def ensure_rel_at_tip_with_dch_on_temp(
    base_text: str,
    distribution: str,
) -> str:
    """
    Ensure +rel (only suffix) at the tip WITHOUT touching the original file.
    Maintainer MUST be parsed from the tip entry of 'base_text'.
    """
    entries = parse_debian_changelog(base_text)
    if not entries:
        raise RuntimeError("Cannot parse changelog text to enforce +rel (dry-run).")

    top_entry = entries[0]
    top_version = top_entry.version
    rel_version = add_rel_suffix(top_version)
    if rel_version == top_version:
        return base_text

    name, email = extract_maint_from_entry_text(top_entry.text)
    if not name or not email:
        raise RuntimeError("Cannot parse maintainer from tip entry (dry-run); refusing to add +rel.")

    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False, prefix="tmp-changelog-", suffix=".chlog") as tmpf:
        tmp_path = tmpf.name
        tmpf.write(base_text)
    try:
        updated = add_new_changelog_entry_with_dch(
            tmp_path,
            new_version=rel_version,
            distribution=distribution or "unstable",
            maint_name=name,
            maint_email=email,
        )
        return updated
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

# ========================= .deb Handling =========================

def extract_changelog_from_deb(
    deb_path: Path, package_name: str, *, prefer_debian_changelog: bool = True
) -> Tuple[str, str]:
    extract_dir = Path(tempfile.mkdtemp(prefix=f"deb-extract-{package_name}-"))
    try:
        subprocess.run(
            ["dpkg-deb", "-x", str(deb_path), str(extract_dir)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except subprocess.CalledProcessError as e:
        _cleanup_dir(extract_dir)
        logger.error(f"dpkg-deb extraction failed: {e.stderr or e.stdout}")
        raise RuntimeError(f"dpkg-deb extraction failed: {e.stderr or e.stdout}")

    doc_base = extract_dir / "usr" / "share" / "doc" / package_name
    candidates: List[Path] = []
    if doc_base.exists():
        if prefer_debian_changelog:
            candidates += sorted(doc_base.glob("changelog.Debian*"))
        candidates += sorted(doc_base.glob("changelog*"))

    if not candidates:
        for pattern in ("**/changelog.Debian*", "**/changelog*"):
            candidates += sorted(extract_dir.glob(pattern))

    if not candidates:
        _cleanup_dir(extract_dir)
        raise FileNotFoundError("No changelog found in the .deb payload.")

    chosen = candidates[0]
    text = read_maybe_compressed(chosen)
    try:
        internal_path = "/" + str(chosen.relative_to(extract_dir)).replace("\\", "/")
    except Exception:
        internal_path = str(chosen).replace("\\", "/")

    _cleanup_dir(extract_dir)
    return text, internal_path


def read_maybe_compressed(path: Path) -> str:
    data: bytes
    if path.suffix == ".gz":
        with gzip.open(path, "rb") as f:
            data = f.read()
    elif path.suffix in (".xz", ".lzma"):
        with lzma.open(path, "rb") as f:
            data = f.read()
    else:
        with open(path, "rb") as f:
            data = f.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")

# ========================= APT & Local Detection =========================

def _parse_arch_from_deb_line(line: str) -> Optional[str]:
    m = re.search(r'\[([^\]]+)\]', line)
    if not m:
        return None
    opts = m.group(1)
    for token in opts.replace(",", " ").split():
        if token.startswith("arch="):
            val = token.split("=", 1)[1].strip()
            return val.split(",")[0]
    return None


def classify_source(apt_source_line: str) -> Tuple[str, Optional[Path], Optional[str]]:
    s = apt_source_line.strip()
    if s.lower().startswith("deb "):
        return "apt", None, s
    if s.lower().startswith("file://"):
        local_path = s[7:] if s.startswith("file://") else s.split("://", 1)[-1]
        p = Path(local_path).resolve()
        if p.is_dir():
            return "local", p, str(p)
        raise ValueError(f"Provided file:// path does not exist or is not a directory: {local_path}")
    p = Path(s).resolve()
    if p.is_dir():
        return "local", p, str(p)
    if re.match(r"^[a-zA-Z]+://", s):
        raise ValueError("Provide a full APT source line starting with 'deb ...', or a local directory path.")
    raise ValueError("Provided --apt-source-line is neither a 'deb ...' APT line nor an existing directory path.")


def apt_prepare_env(apt_line: str) -> Tuple[Dict[str, str], List[str], Path, Path, str]:
    if shutil.which("apt-get") is None:
        logger.error("apt-get is required for APT mode but not found in PATH.")
        raise RuntimeError("apt-get is required for APT mode but not found in PATH.")

    tmp_root = Path(tempfile.mkdtemp(prefix="apt-temp-"))
    apt_state = tmp_root / "state"
    apt_cache = tmp_root / "cache"
    empty_dir = tmp_root / "empty"
    download_dir = tmp_root / "downloads"
    status_file = apt_state / "status"
    sources_list = tmp_root / "sources.list"

    apt_state.mkdir(parents=True, exist_ok=True)
    apt_cache.mkdir(parents=True, exist_ok=True)
    empty_dir.mkdir(parents=True, exist_ok=True)
    download_dir.mkdir(parents=True, exist_ok=True)
    status_file.write_text("")

    line = apt_line.strip()
    if not line.endswith("\n"):
        line += "\n"
    sources_list.write_text(line)
    logger.info(f"APT source line: {line.strip()}")

    arch = _parse_arch_from_deb_line(line) or "arm64"
    if "arch=" not in line:
        logger.warning(f"No arch=... in source line; defaulting to {arch}")

    apt_env = os.environ.copy()
    apt_env["DEBIAN_FRONTEND"] = "noninteractive"

    apt_opts = [
        "-o", f"Dir::State={str(apt_state)}",
        "-o", f"Dir::Cache={str(apt_cache)}",
        "-o", f"Dir::State::status={str(status_file)}",
        "-o", f"Dir::Etc::sourcelist={str(sources_list)}",
        "-o", f"Dir::Etc::sourceparts={str(empty_dir)}",
        "-o", "Debug::NoLocking=true",
        "-o", "Acquire::Retries=2",
        "-o", "Acquire::Languages=none",
        "-o", f"APT::Architecture={arch}",
        "-o", f"APT::Architectures={arch}",
    ]

    logger.info(f"Running apt-get update (arch={arch})")
    try:
        subprocess.run(
            ["apt-get", *apt_opts, "update"],
            env=apt_env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        logger.info("apt-get update completed.")
    except subprocess.CalledProcessError as e:
        _cleanup_dir(tmp_root)
        logger.error("Failed to apt-get update.\n"
                     f"STDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}")
        raise RuntimeError("Failed to apt-get update.") from e

    return apt_env, apt_opts, tmp_root, download_dir, arch


def apt_download_deb_for_any(pkg_names: List[str], apt_env: Dict[str, str], apt_opts: List[str],
                             download_dir: Path, arch: str) -> Tuple[Optional[Path], Optional[str]]:
    for pkg in pkg_names:
        pkg_arch_qualified = f"{pkg}:{arch}" if arch else pkg
        logger.info(f"Attempting apt-get download for {pkg_arch_qualified} ...")
        try:
            subprocess.run(
                ["apt-get", *apt_opts, "download", pkg_arch_qualified],
                cwd=str(download_dir), env=apt_env, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Download failed for {pkg_arch_qualified}: "
                           f"{(e.stderr or e.stdout).strip()}")
            continue
        candidates = sorted(download_dir.glob(f"{pkg}_*.deb"))
        if candidates:
            deb_path = max(candidates, key=lambda p: p.stat().st_mtime)
            logger.info(f"Using downloaded .deb: {deb_path.name}")
            return deb_path, pkg
    return None, None


def local_find_deb_for_any(pkg_names: List[str], deb_dir: Path) -> Tuple[Optional[Path], Optional[str]]:
    """
    Prefer arm64 .debs if present, otherwise latest .deb regardless of arch.
    """
    preferred_arch = "arm64"
    for pkg in pkg_names:
        arm64 = sorted(deb_dir.glob(f"{pkg}_*_{preferred_arch}.deb"))
        if arm64:
            deb_path = max(arm64, key=lambda p: p.stat().st_mtime)
            logger.info(f"Found local arm64 .deb for {pkg}: {deb_path.name}")
            return deb_path, pkg
        any_arch = sorted(deb_dir.glob(f"{pkg}_*.deb"))
        if any_arch:
            deb_path = max(any_arch, key=lambda p: p.stat().st_mtime)
            logger.info(f"Found local .deb for {pkg}: {deb_path.name}")
            return deb_path, pkg
    return None, None

# ========================= Main Orchestration =========================

def process_debian_trees(
    input_root: str,
    *,
    apt_source_line: str,                 # Either 'deb ...' APT line OR local directory path
    prefer_debian_changelog: bool = True,
    dry_run: bool = False,                # if True: write to changed-changelog instead of changelog
) -> Dict[str, Dict[str, str]]:
    # Tool checks
    for tool in ("dch", "dpkg-deb", "dpkg"):
        if shutil.which(tool) is None:
            logger.error(f"Required tool '{tool}' not found in PATH.")
            raise RuntimeError(f"Required tool '{tool}' not found in PATH.")

    mode, local_dir, normalized = classify_source(apt_source_line)
    if mode == "apt" and shutil.which("apt-get") is None:
        logger.error("APT mode selected but 'apt-get' not found in PATH.")
        raise RuntimeError("APT mode selected but 'apt-get' not found in PATH.")

    input_root = os.path.abspath(input_root)
    statuses: Dict[str, Dict[str, str]] = {}

    apt_env = None
    apt_opts: List[str] = []
    tmp_root = None
    download_dir = None
    arch = None

    try:
        if mode == "apt":
            logger.info("Mode: APT")
            apt_env, apt_opts, tmp_root, download_dir, arch = apt_prepare_env(normalized)
        else:
            logger.info(f"Mode: LOCAL (dir={local_dir})")

        # Walk the input tree
        for root, dirs, files in os.walk(input_root):
            if "debian" not in dirs:
                continue

            debian_dir = os.path.join(root, "debian")
            control_path = os.path.join(debian_dir, "control")
            changelog_path = os.path.join(debian_dir, "changelog")
            changed_changelog_path = os.path.join(debian_dir, "changed-changelog")

            if not (os.path.isfile(control_path) and os.path.isfile(changelog_path)):
                logger.warning(f"Skipping {debian_dir}: control/changelog not present.")
                continue

            logger.info("=" * 80)
            logger.info(f"Processing: {debian_dir}")

            status = {"debian_dir": debian_dir, "action": "", "details": ""}

            # Parse binary packages
            control_text = Path(control_path).read_text(encoding="utf-8", errors="replace")
            pkg_names = _parse_binary_packages(control_text)
            logger.info(f"Binary packages in control: {pkg_names if pkg_names else 'NONE'}")
            if not pkg_names:
                status["action"] = "skip"
                status["details"] = "No binary packages found in control."
                statuses[debian_dir] = status
                continue

            # Load local changelog
            local_text = Path(changelog_path).read_text(encoding="utf-8", errors="replace")
            local_entries = parse_debian_changelog(local_text)
            if not local_entries:
                logger.error(f"Local debian/changelog has no valid entries: {changelog_path}")
                status["action"] = "error"
                status["details"] = "Local debian/changelog has no valid entries."
                statuses[debian_dir] = status
                continue

            local_top_entry = local_entries[0]
            local_top_version = local_top_entry.version
            local_top_dist = local_top_entry.distribution or "unstable"
            logger.info(f"Local top version: {local_top_version} (dist={local_top_dist})")

            # Obtain .deb (APT or local)
            if mode == "apt":
                deb_path, chosen_pkg = apt_download_deb_for_any(pkg_names, apt_env, apt_opts, download_dir, arch)
            else:
                deb_path, chosen_pkg = local_find_deb_for_any(pkg_names, local_dir)

            # Writer per dry-run
            def write_output_text(text: str, context: str):
                if dry_run:
                    Path(changed_changelog_path).write_text(text, encoding="utf-8")
                    logger.info(f"(dry-run) wrote: {changed_changelog_path} [{context}]")
                else:
                    Path(changelog_path).write_text(text, encoding="utf-8")
                    if os.path.exists(changed_changelog_path):
                        try:
                            os.remove(changed_changelog_path)
                            logger.info(f"removed: {changed_changelog_path}")
                        except Exception:
                            pass
                    logger.info(f"wrote: {changelog_path} [{context}]")

            # Case 1: no .deb → ensure +rel using the tip maintainer of local changelog
            if deb_path is None:
                try:
                    if dry_run:
                        final_text = ensure_rel_at_tip_with_dch_on_temp(
                            local_text, local_top_dist
                        )
                        write_output_text(final_text, "no-deb +rel simulated")
                    else:
                        name, email = extract_maint_from_entry_text(local_top_entry.text)
                        if not name or not email:
                            raise RuntimeError("Cannot parse maintainer from tip entry to add +rel.")
                        new_version = add_rel_suffix(local_top_version)  # ONLY append +rel; never bump numerics
                        if new_version == local_top_version:
                            logger.info(f"Top already has +rel: {local_top_version}. Nothing to add.")
                        else:
                            logger.info(f"No .deb found. Adding +rel via dch: {new_version} (maint={name} <{email}>)")
                            run_dch_newversion_inplace(
                                changelog_path,
                                new_version=new_version,
                                distribution=local_top_dist,
                                maint_name=name,
                                maint_email=email,
                            )
                        if os.path.exists(changed_changelog_path):
                            try:
                                os.remove(changed_changelog_path)
                                logger.info(f"removed: {changed_changelog_path}")
                            except Exception:
                                pass
                    status["action"] = "no-deb-add-rel" + (" (dry-run)" if dry_run else "")
                    status["details"] = "Ensured +rel at tip (no numeric bump)."
                except Exception as ex:
                    logger.error(str(ex))
                    status["action"] = "error"
                    status["details"] = f"No .deb and could not add +rel: {ex}"
                statuses[debian_dir] = status
                continue

            # .deb present: extract its changelog
            try:
                deb_changelog_text, deb_internal_path = extract_changelog_from_deb(
                    deb_path, chosen_pkg or pkg_names[0], prefer_debian_changelog=prefer_debian_changelog
                )
                logger.info(f"Extracted .deb changelog path: {deb_internal_path}")
            except Exception as ex:
                logger.warning(f".deb changelog extraction failed: {ex}. Falling back to +rel on local.")
                try:
                    if dry_run:
                        final_text = ensure_rel_at_tip_with_dch_on_temp(
                            local_text, local_top_dist
                        )
                        write_output_text(final_text, "deb-no-changelog +rel simulated")
                    else:
                        name, email = extract_maint_from_entry_text(local_top_entry.text)
                        if not name or not email:
                            raise RuntimeError("Cannot parse maintainer from tip entry to add +rel.")
                        new_version = add_rel_suffix(local_top_version)
                        if new_version != local_top_version:
                            run_dch_newversion_inplace(
                                changelog_path,
                                new_version=new_version,
                                distribution=local_top_dist,
                                maint_name=name,
                                maint_email=email,
                            )
                        if os.path.exists(changed_changelog_path):
                            try:
                                os.remove(changed_changelog_path)
                            except Exception:
                                pass
                    status["action"] = "deb-no-changelog-add-rel" + (" (dry-run)" if dry_run else "")
                    status["details"] = "Ensured +rel at tip (no changelog found in .deb)."
                except Exception as inner_ex:
                    logger.error(str(inner_ex))
                    status["action"] = "error"
                    status["details"] = f".deb present but +rel addition failed: {inner_ex}"
                statuses[debian_dir] = status
                continue

            deb_entries = parse_debian_changelog(deb_changelog_text)
            if not deb_entries:
                logger.warning(".deb changelog parsed to zero entries; using +rel on local.")
                try:
                    if dry_run:
                        final_text = ensure_rel_at_tip_with_dch_on_temp(
                            local_text, local_top_dist
                        )
                        write_output_text(final_text, "deb-empty-changelog +rel simulated")
                    else:
                        name, email = extract_maint_from_entry_text(local_top_entry.text)
                        if not name or not email:
                            raise RuntimeError("Cannot parse maintainer from tip entry to add +rel.")
                        new_version = add_rel_suffix(local_top_version)
                        if new_version != local_top_version:
                            run_dch_newversion_inplace(
                                changelog_path,
                                new_version=new_version,
                                distribution=local_top_dist,
                                maint_name=name,
                                maint_email=email,
                            )
                        if os.path.exists(changed_changelog_path):
                            try:
                                os.remove(changed_changelog_path)
                            except Exception:
                                pass
                    status["action"] = "deb-empty-changelog-add-rel" + (" (dry-run)" if dry_run else "")
                    status["details"] = "Ensured +rel at tip (empty .deb changelog)."
                except Exception as inner_ex:
                    logger.error(str(inner_ex))
                    status["action"] = "error"
                    status["details"] = f"Empty .deb changelog and +rel addition failed: {inner_ex}"
                statuses[debian_dir] = status
                continue

            deb_top_version = deb_entries[0].version
            deb_top_base = strip_rel_suffix(deb_top_version)
            logger.info(f".deb top version: {deb_top_version} (base='{deb_top_base}')")

            # Build base text (replace/merge)
            if deb_top_base.strip() == local_top_version.strip():
                base_text = deb_changelog_text
                logger.info("strip_rel(deb_top) == local_top -> replace with .deb changelog.")
            else:
                idx = index_of_version(local_entries, deb_top_base)
                if idx is not None:
                    logger.info(f"Exact base match at local index {idx}; prepending {idx} newer local entries.")
                    prepend_text = serialize_changelog(local_entries[:idx])
                else:
                    newer = newer_local_prefix(local_entries, deb_top_base)
                    logger.info(f"No exact match. Prepending {len(newer)} local entries where local_ver > base (dpkg semantics).")
                    prepend_text = serialize_changelog(newer)
                base_text = prepend_text + ensure_trailing_newline(deb_changelog_text)

            # Ensure +rel and write merged/replaced content
            try:
                if dry_run:
                    dist_hint = distribution_hint_from_text(base_text) or local_top_dist
                    final_text = ensure_rel_at_tip_with_dch_on_temp(
                        base_text, dist_hint
                    )
                    write_output_text(final_text, "deb-merge/replace +rel simulated")
                else:
                    Path(changelog_path).write_text(base_text, encoding="utf-8")
                    dist_hint = distribution_hint_from_text(base_text) or local_top_dist
                    ensure_rel_at_tip_inplace(
                        changelog_path,
                        distribution_fallback=dist_hint
                    )
                    if os.path.exists(changed_changelog_path):
                        try:
                            os.remove(changed_changelog_path)
                            logger.info(f"removed: {changed_changelog_path}")
                        except Exception:
                            pass
                    logger.info("wrote: changelog [deb-merge/replace applied]")

                # Update status
                result_text = Path(changed_changelog_path if dry_run else changelog_path).read_text(encoding='utf-8', errors='replace')
                result_entries = parse_debian_changelog(result_text)
                result_top = result_entries[0].version if result_entries else "<unparsed>"
                status["action"] = "deb-merge-or-replace-with-rel" + (" (dry-run)" if dry_run else "")
                status["details"] = (
                    f"deb_top={deb_top_version}, deb_top_base={deb_top_base}, local_top={local_top_version}, result_top={result_top}"
                )
            except Exception as ex:
                logger.error(str(ex))
                status["action"] = "error"
                status["details"] = f"Merged/replaced but failed to add +rel: {ex}"

            statuses[debian_dir] = status

    finally:
        if tmp_root:
            _cleanup_dir(tmp_root)

    return statuses

# ========================= Utilities =========================

def _parse_binary_packages(control_text: str) -> List[str]:
    pkgs = []
    for m in re.finditer(r"(?m)^\s*Package:\s*(\S+)\s*$", control_text):
        pkgs.append(m.group(1))
    seen = set()
    out = []
    for p in pkgs:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


def _cleanup_dir(path: Path):
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass

# ========================= CLI =========================

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Merge/replace Debian changelogs with .deb changelogs and add +rel (no numeric bumps). "
                    "Provide either a full APT source line (starting with 'deb ') or a local directory path."
    )
    p.add_argument("--input-root", required=True, help="Root directory to search for 'debian/' folders.")
    p.add_argument("--apt-source-line", required=True,
                   help="Either a full apt source line (e.g., 'deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main') "
                        "OR a local directory path (e.g., /filer/pkgdrops/ubuntu/noble/stable/arm64/).")
    p.add_argument("--prefer-generic-changelog", action="store_true",
                   help="Prefer generic changelog.* over changelog.Debian.* inside .deb.")
    p.add_argument("--dry-run", action="store_true",
                   help="Write to debian/changed-changelog instead of modifying debian/changelog.")
    return p.parse_args(argv)

def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        statuses = process_debian_trees(
            input_root=args.input_root,
            apt_source_line=args.apt_source_line,
            prefer_debian_changelog=not args.prefer_generic_changelog,
            dry_run=args.dry_run,
        )
    except Exception as e:
        logger.error(str(e))
        return 1

    logger.info("\nSUMMARY")
    for debian_dir, st in statuses.items():
        logger.info("-" * 80)
        logger.info(f"debian dir: {debian_dir}")
        logger.info(f"action: {st.get('action')}")
        logger.info(f"details: {st.get('details')}")

    had_error = any(st.get("action") == "error" for st in statuses.values())
    return 2 if had_error else 0

if __name__ == "__main__":
    sys.exit(main())
