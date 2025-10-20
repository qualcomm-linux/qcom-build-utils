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
                        default=".",
                        help="Path to the output directory for the built package.")

    parser.add_argument("--distro",
                        type=str,
                        choices=['noble', 'questing'],
                        default='noble',
                        help="The target distribution for the package build.")

    parser.add_argument("--run-lintian",
                        action='store_true',
                        help="Run lintian on the package.")

    args = parser.parse_args()

    return args


def check_docker_dependencies(timeout=5):
    """
    Verify docker CLI presence, daemon accessibility, and user permission to talk to the daemon.
    Raises an Exception with an actionable message when a check fails.
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
                        f"Add the user to the group: sudo usermod -aG {sock_group} $USER  (then re-login) or run the script with sudo."
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

def check_docker_image(image, arch=None, timeout=120):
    """
    Ensure the given docker image is available locally. If not, look for a local Dockerfile
    in ../docker named `Dockerfile.{arch}` where {arch} is taken from the image tag.
    Raises an Exception with actionable guidance on failure.
    """
    logger.debug(f"Checking for docker image: {image}")

    # 1) check if image exists locally
    try:
        subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True, timeout=10)
        logger.info(f"Docker image '{image}' is present locally.")
        return True
    except subprocess.CalledProcessError:
        logger.info(f"Docker image '{image}' not found locally.")
    except subprocess.TimeoutExpired:
        raise Exception("Timed out while checking local docker images.")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    docker_dir = os.path.normpath(os.path.join(script_dir, '..', 'docker'))
    dockerfile_name = f"Dockerfile.{arch}"
    dockerfile_path = os.path.join(docker_dir, dockerfile_name) if dockerfile_name else None

    if dockerfile_path and os.path.exists(dockerfile_path):
        logger.info(f"Found local Dockerfile for arch '{arch}': {dockerfile_path}. Building image now...")

        build_cmd = ["docker", "build", "-t", image, "-f", dockerfile_path, docker_dir]
        logger.info(f"Running: {' '.join(build_cmd)}")

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

                rc = proc.wait(timeout=timeout)
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

def build_package_in_docker(image, source_dir, output_dir, build_arch, distro, run_lintian: bool):

    # Check if the remote repository Release file exists (HEAD request)
    extra_repo = ''
    url = f"http://pkg.qualcomm.com/dists/{distro}/Release"
    try:
        req = urllib.request.Request(url, method='HEAD')
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                extra_repo = f"--extra-repository='deb [arch=arm64 trusted=yes] http://pkg.qualcomm.com {distro}/stable main'"
    except Exception:
        extra_repo = ''

    # Build the gbp command
    # The --git-builder value is a single string passed to gbp
    git_builder = (
        f"sbuild --host=arm64 --build-dep-resolver=apt  --build-dir=/workspace/output --build={build_arch} --dist={distro} {'--run-lintian' if run_lintian else ''} {extra_repo}"
    )

    # Build inside the docker image: mount source_dir -> /workspace/src, output_dir -> /workspace/output
    # Set working dir to /workspace/src and run gbp there. Preserve host uid/gid so files created are owned correctly.
    os.makedirs(output_dir, exist_ok=True)

    # Ensure git inside the container treats the mounted checkout as safe
    git_safe_cmd = "git config --global --add safe.directory /workspace/src"
    inner_cmd = f"{git_safe_cmd} && gbp buildpackage --git-ignore-branch --git-builder=\"{git_builder}\""

    docker_cmd = [
        'docker', 'run', '--rm', '--privileged',
        '-u', f"{os.getuid()}:{os.getgid()}",
        '-v', f"{os.path.abspath(source_dir)}:/workspace/src:Z",
        '-v', f"{os.path.abspath(output_dir)}:/workspace/output:Z",
        '-w', '/workspace/src',
    ]

    # command to run inside the container
    docker_cmd += [image, 'bash', '-c', inner_cmd]

    logger.info(f"Running build inside container: {' '.join(docker_cmd[:])}")

    try:
        # Run and stream output live
        res = subprocess.run(docker_cmd, check=False)
    except KeyboardInterrupt:
        raise

    if res.returncode == 0:
        logger.info("✅ Successfully built package")
        return True
    else:
        # Look for build log files in the output_dir on the host
        build_logs = glob.glob(os.path.join(output_dir or '.', '*.build'))
        build_logs = [p for p in build_logs if not os.path.islink(p)]

        if build_logs:
            log_path = build_logs[0]
            try:
                with open(log_path, 'r', errors='ignore') as f:
                    lines = f.readlines()
                tail = ''.join(lines[-500:])
                sys.stdout.write(tail)
                logger.info("❌ Build failed, printed the last 500 lines of the build log file")
            except Exception as e:
                logger.error(f"Failed to read build log {log_path}: {e}")
                raise Exception("❌ Build failed, and reading build log failed")
        else:
            logger.error("❌ Build failed, but no .build log file was found to print")

        raise Exception("Build failed")

def main():
    args = parse_arguments()

    logger.debug(f"Print of the arguments: {args}")

    if not os.path.isabs(args.source_dir):
        args.source_dir = os.path.abspath(args.source_dir)
    if not os.path.isabs(args.output_dir):
        args.output_dir = os.path.abspath(args.output_dir)

    # Verify Docker is available and the current user can talk to the daemon
    check_docker_dependencies()

    build_arch = platform.machine()

    logger.debug(f"The arch is {build_arch}")

    # Normalize the arch string for use later
    if build_arch == "x86_64":
        build_arch = "amd64"
        logger.info("The build will be a cross-compilation amd64 -> arm64")
    elif build_arch == "aarch64":
        build_arch = "arm64"
        logger.info("The build will be a native build arm64 -> arm64")
    else:
        raise Exception("Invalid base arch")

    # Test for the presence of the docker image
    image = f"qualcomm-linux/pkg-build:{build_arch}-latest"
    
    check_docker_image(image, build_arch)

    output_dir = os.path.abspath(os.path.join(args.source_dir, "..", "deb_output"))
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    logger.debug(f"The source dir is {args.source_dir}")
    logger.debug(f"The output dir is {output_dir}")

    build_package_in_docker(image, args.source_dir, output_dir, build_arch, args.distro, args.run_lintian)


if __name__ == "__main__":

    try:
        main()
    except Exception as e:
        logger.critical(f"Uncaught exception : {e}")

        traceback.print_exc()

        sys.exit(1)