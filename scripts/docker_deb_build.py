#!/usr/bin/env python3

# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
docker_deb_build.py

Helper script to build a debian package using the container from the Dockerfile in the docker/ folder.
"""

import os
import sys
import argparse
import subprocess
import traceback
import platform
import shutil
import urllib.request
import glob
import grp
import pwd
import getpass

from color_logger import logger

def parse_arguments():
    parser = argparse.ArgumentParser(description="Build a debian package inside a docker container.")

    parser.add_argument("--source-dir",
                        required=False,
                        default=".",
                        help="Path to the source directory containing the debian package source.")

    parser.add_argument("--output-dir",
                        required=False,
                        default="..",
                        help="Path to the output directory for the built package.")

    parser.add_argument("--distro",
                        type=str,
                        choices=['noble', 'questing'],
                        default='noble',
                        help="The target distribution for the package build.")

    parser.add_argument("--run-lintian",
                        action='store_true',
                        help="Run lintian on the package.")

    parser.add_argument("--extra-repo",
                        type=str,
                        action='append',
                        default=[],
                        help="Additional APT repository to include. Can be specified multiple times. Example: 'deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com noble/stable main'")

    parser.add_argument("--rebuild",
                        action='store_true',
                        help="Rebuild the package if it already exists.")

    args = parser.parse_args()

    return args

def check_docker_dependencies(timeout=20):
    """
    Verify docker CLI presence, daemon accessibility, and user permission to talk to the daemon.
    """

    # 1) docker binary present
    if shutil.which("docker") is None:
        raise Exception("docker CLI not found. Install Docker: https://docs.docker.com/get-docker/")

    # 2) try contacting the daemon
    try:
        p = subprocess.run(["docker", "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           check=True, timeout=timeout)
        logger.info("Docker CLI and daemon reachable.")
        return True
        
    except subprocess.CalledProcessError as e:
        err = (e.stderr or b"").decode(errors="ignore") + (e.stdout or b"").decode(errors="ignore")
        err_l = err.lower()
        sock = "/var/run/docker.sock"

        # permission issue -> check group on the socket
        if "permission denied" in err_l or "access denied" in err_l or "cannot connect to the docker daemon" in err_l:
            if os.path.exists(sock):
                st = os.stat(sock)
                try:
                    sock_group = grp.getgrgid(st.st_gid).gr_name
                except KeyError:
                    sock_group = f"gid:{st.st_gid}"
                user = getpass.getuser()
                # gather groups for user
                user_groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
                primary_gid = pwd.getpwnam(user).pw_gid
                try:
                    primary_group = grp.getgrgid(primary_gid).gr_name
                    user_groups.append(primary_group)
                except KeyError:
                    pass

                if sock_group not in user_groups:
                    raise Exception(
                        f"Permission denied accessing Docker socket ({sock}). Current user '{user}' is not in the socket group '{sock_group}'.\n"
                        f"Add the user to the group: \"sudo usermod -aG {sock_group} $USER\"  (then re-login) or run the script with sudo.\n"
                        f"Also, to avoid having to do a complete logout/login, you can run: \"newgrp {sock_group}\" which will start a new shell with the new group applied."
                    )
                else:
                    # user is in group but still cannot connect -> daemon likely stopped
                    raise Exception(
                        "Docker socket exists and group membership OK, but 'docker info' failed. Is the Docker daemon running?\n"
                        "Try: sudo systemctl start docker  (or check your platform's docker service)."
                    )
            else:
                raise Exception(
                    "Cannot contact Docker daemon and /var/run/docker.sock does not exist. Is the Docker engine installed and running?\n"
                    "Try: sudo systemctl start docker"
                )
        else:
            # generic failure
            raise Exception(f"Failed to contact Docker daemon: {err.strip() or e}")

    except subprocess.TimeoutExpired:
        raise Exception("Timed out while trying to contact the Docker daemon. Is it running?")

def build_docker_image(image, arch, distro):
    this_script_dir = os.path.dirname(os.path.abspath(__file__))
    docker_dir = os.path.normpath(os.path.join(this_script_dir, '..', 'docker'))
    context_dir = docker_dir
    dockerfile_name = f"Dockerfile.{arch}.{distro}"
    dockerfile_path = os.path.join(docker_dir, dockerfile_name)

    logger.debug(f"Building docker image '{image}' for arch '{arch}' from Dockerfile: {dockerfile_path}")
    
    if not os.path.exists(dockerfile_path):
        logger.error(f"No local Dockerfile found for arch '{arch}' at expected path: {dockerfile_path}. Cannot build image '{image}'.")
        return False

    build_cmd = ["docker", "build", "-t", image, "-f", dockerfile_path, context_dir]

    logger.debug(f"Running: {' '.join(build_cmd)}")

    # Stream build output live so the user sees progress
    try:
        proc = subprocess.Popen(build_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
        try:
            for line in proc.stdout:
                # print to terminal immediately
                sys.stdout.write(line)
                sys.stdout.flush()
                # also log the line
                #logger.debug(line.rstrip())

            rc = proc.wait()

        except KeyboardInterrupt:
            proc.terminate()
            proc.wait()
            raise

        if rc != 0:
            raise Exception(f"Failed to build docker image from {dockerfile_path} (exit {rc}).")

        logger.info(f"Successfully built image '{image}'.")
        return True
    except subprocess.TimeoutExpired:
        proc.kill()
        raise Exception(f"Timed out while building docker image from {dockerfile_path}.")

def rebuild_docker_image(image_base, arch, distro):
    """
    Force rebuild of the given docker image from local Dockerfile.
    """
    image = f"{image_base}{distro}"

    logger.debug(f"Rebuilding docker image '{image}' from local Dockerfile...")

    # Delete/purge the current image if it exists

    try:
        subprocess.run(["docker", "image", "rm", "-f", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        logger.info(f"Deleted existing image '{image}'.")
    except subprocess.CalledProcessError:
        logger.debug(f"No existing image '{image}' to delete.")

    # Build the image
    build_docker_image(image, arch, distro)

def check_docker_image(image_base, arch, distro):
    """
    Ensure the given docker image is available locally. If not, look for a local Dockerfile
    in ../docker named `Dockerfile.{arch}`.
    Raises an Exception with actionable guidance on failure.
    """

    image = f"{image_base}{distro}"

    logger.debug(f"Checking for docker image: {image}")

    # 1) check if image exists locally
    try:
        subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True, timeout=10)
        logger.info(f"Docker image '{image}' is present locally.")
        return True
    except subprocess.CalledProcessError:
        logger.warning(f"Docker image '{image}' not found locally.")
    except subprocess.TimeoutExpired:
        raise Exception("Timed out while checking local docker images.")

    # Since the image is not present locally, try to build it from local Dockerfile
    build_docker_image(image, arch, distro)

def build_package_in_docker(image_base, source_dir, output_dir, build_arch, distro, run_lintian: bool, extra_repo: list[str]) -> bool:
    """
    Build the debian package inside the given docker image.
    source_dir: path to the debian package source (mounted into the container)
    output_dir: path to the output directory for the built package (mounted into the container)
    build_arch: architecture string for the build (e.g. 'arm64')
    distro: target distribution string (e.g. 'noble')
    run_lintian: whether to run lintian on the built package
    extra_repo: list of additional APT repositories to include
    Returns True on success, False on failure.
    """

    image = f"{image_base}{distro}"

    # Register the name of the newest build log in the output_dir in case there are leftovers from a previous build
    # So that we can identify if this run produced a newer build log. Sbuild produces .build files with timestamps,
    # and one of them is a symlink to the latest build log.
    build_log_files = glob.glob(os.path.join(output_dir or '.', '*.build'))
    prev_build_log = next((os.readlink(p) for p in build_log_files if os.path.islink(p)), None)
    logger.debug(f"Previous build log: {prev_build_log}")

    # Build the gbp command
    # The --git-builder value is a single string passed to gbp
    extra_repo_option = " ".join(f"--extra-repository='{repo}'" for repo in extra_repo) if extra_repo else ""
    lintian_option = '--no-run-lintian' if not run_lintian else ""
    sbuild_cmd = f"sbuild --build-dir=/workspace/output --host=arm64 --build={build_arch} --dist={distro} {lintian_option} {extra_repo_option}"

    # Ensure git inside the container treats the mounted checkout as safe
    git_safe_cmd = "git config --global --add safe.directory /workspace/src"
    gbp_cmd = f"{git_safe_cmd} && gbp buildpackage --git-ignore-branch --git-builder=\"{sbuild_cmd}\""

    # Decide which build command to run based on debian/source/format in the source tree.
    # Prefer 'native' -> run sbuild directly. If the source format uses 'quilt', use gbp.
    format_file = os.path.join(source_dir, 'debian', 'source', 'format')
    if not os.path.exists(format_file):
        raise Exception(f"Missing {format_file}: cannot determine source format (native/quilt). Is the source dir correctly pointing to a debian package source tree?")

    try:
        with open(format_file, 'r', errors='ignore') as f:
            fmt = f.read().lower()
    except Exception as e:
        raise Exception(f"Failed to read {format_file}: {e}")

    if 'native' in fmt:
        build_cmd = sbuild_cmd
    elif 'quilt' in fmt:
        build_cmd = gbp_cmd
    else:
        raise Exception(f"Unsupported debian/source/format in {format_file}. Expected to contain 'native' or 'quilt', got: {fmt!r}")

    docker_cmd = [
        'docker', 'run', '--rm', '--privileged', "-t",
        '-v', f"{source_dir}:/workspace/src:Z",
        '-v', f"{output_dir}:/workspace/output:Z",
        '-w', '/workspace/src',
        image, 'bash', '-c', build_cmd
    ]

    logger.debug(f"Running build inside container: {' '.join(docker_cmd[:])}")

    try:
        # Run and stream output live
        res = subprocess.run(docker_cmd, check=False)
    except KeyboardInterrupt:
        raise

    if res.returncode == 0:
        logger.info("✅ Successfully built package")
    else:
        logger.error("❌ Build failed")


    build_log_files = glob.glob(os.path.join(output_dir or '.', '*.build'))
    new_build_log = next((os.readlink(p) for p in build_log_files if os.path.islink(p)), None)

    if new_build_log == prev_build_log:
        logger.debug("ℹ️ No new sbuild log produced during this run.")
    else:
        logger.debug(f"ℹ️ New sbuild log available at: {os.path.join(output_dir, new_build_log)}")

    return res.returncode == 0

def main():
    args = parse_arguments()

    logger.debug(f"Print of the arguments: {args}")

    # In sbuild terms, the build architecture is the architecture of the machine doing the build,
    # aka the architecture of the machine running this script.
    build_arch = platform.machine()

    logger.debug(f"The builder arch is {build_arch}")

    # Normalize the arch string for use later
    if build_arch == "x86_64":
        build_arch = "amd64"
        logger.debug("The build will be a cross-compilation amd64 -> arm64")
    elif build_arch == "aarch64":
        build_arch = "arm64"
        logger.debug("The build will be a native build arm64 -> arm64")
    else:
        raise Exception("Invalid base arch")

    # Verify Docker is available and the current user can talk to the daemon
    check_docker_dependencies()

    image_base = f"ghcr.io/qualcomm-linux/pkg-builder:{build_arch}-"

    # If --rebuild is specified, force rebuild of the docker image and exit
    if args.rebuild:
        rebuild_docker_image(image_base, build_arch, 'noble')
        rebuild_docker_image(image_base, build_arch, 'questing')
        sys.exit(0)

    # Make sure source and output dirs are absolute paths
    if not os.path.isabs(args.source_dir):
        args.source_dir = os.path.abspath(args.source_dir)
    if not os.path.isabs(args.output_dir):
        args.output_dir = os.path.abspath(args.output_dir)
    
    logger.debug(f"The source dir is {args.source_dir}")
    logger.debug(f"The output dir is {args.output_dir}")

    # Ensure the docker image is available, building it from local Dockerfile if needed
    check_docker_image(image_base, build_arch, args.distro)

    ret = build_package_in_docker(image_base, args.source_dir, args.output_dir, build_arch, args.distro, args.run_lintian, args.extra_repo)

    if ret:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":

    try:
        main()

    except Exception as e:
        logger.critical(f"Uncaught exception : {e}")

        traceback.print_exc()

        sys.exit(1)