#!/usr/bin/env python3
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
create_promotion_pr.py

Helper script to build a debian package using the container from the Dockerfile in the docker/ folder.
"""
import subprocess
import argparse
from color_logger import logger

# This script is used to create the PR content of the promotion PR. Then, the actual PR is created using GitHub CLI
def parse_arguments():
    parser = argparse.ArgumentParser(description="Craft the content for a promotion PR and opoen it using GitHub CLI.")

    parser.add_argument("--base-branch",
                        required=False,
                        default="debian/qcom-next",
                        help="Base branch for the promotion PR.")

    parser.add_argument("--upstream-tag",
                        required=True,
                        help="Upstream tag corresponding to the version being promoted.")

    parser.add_argument("--normalized-version",
                        required=True,
                        help="Normalized version of the upstream project.")

    args = parser.parse_args()

    return args

def create_pr_title(normalized_version: str) -> str:
    return f"Promotion to {normalized_version}"

def create_pr_body(base_branch: str, upstream_tag: str, normalized_version: str) -> str:
    pr_body = f"""
# This is an automated PR to test the promotion of this package repo to the upstream project version {normalized_version}.

This PR merges the upstream changes from the upstream tag '{upstream_tag}' into the {base_branch} branch, and updated the debian/changelog version to reflect this new version. Whatever was the distro version before (the part after the '-' in a version x.y.z-a), it has been reset to -1. 
The upstream tag '{upstream_tag}' has already been merged into the upstream/latest branch, and this PR merges that branch into {base_branch}.
In other words, this repo already contains the upstream changes in the upstream/latest branch, but the debian packaging is not yet updated to reflect this new upstream version. This is what this PR is doing.

The *build-debian-package.yml* workflow is triggered automatically in this PR to test the promotion by building the Debian package with the updated upstream code and packaging.
If something breaks due to the promotion of the upstream sources to this new revision, this is the moment where you can checkout this branch locally, make changes and push additional commits to make the build pass.

For example: you may need to add patches to the debian/patches/ folder to fix issues that were introduced upstream since the last version we were using, such as a new binary created upstream that needs to be packaged, or a build system change that requires updating the debian/rules file, etc.
Once you are satisfied with the changes, click the 'Merge' button below to finalize the promotion.

*Note: Due to the nature of the graph that is attempted to be merged, only a merge (and therefore the creation of a merge commit) with the 'Merge' button will work.*
       Attempting second option 'Squash and Merge' or 'Rebase and Merge' will fail. This is because in both of these two cases, this head branch woule need to be cleanly rebasable onto the base branch, which is not the case here.


This generated diagram attemps to illustrate what happened and what will happen when you click the 'Merge' button below.:
  - The right most 'upstream-main' branch represents the upstream repo, where the {upstream_tag} was pulled from.
  - To its left, the 'upstream/latest' branch lives is this repo, and represents a copy of the upstream repo (and it has already happened during the promotion workflow run).
    The commit tagged 'upstream/{normalized_version}' is a merge from the upstream tag {upstream_tag} commit where in addition,
    special git wizardry happened to perform a special filtering of any potential upstream .github/ and debian/ folders have been filtered out,
    and only homonym folders from the debian/qcom-next branch have been kept.
  - To its left, this 'debian/pr/{normalized_version}-1' branch was created during the promotion workflow and is the head branch of this PR.
    It represents the merge of the upstream/latest branch into {base_branch}.
  - Note that an extra commit for updating the debian/changelog file to reflect the new version {normalized_version}-1 has been added on top of that merge.
"""

    mermaid_diagram = f"""
```mermaid
---
config:
  themeVariables:
    'gitInv2': '#ff0000'
gitGraph:
  parallelCommits: true
  rotateCommitLabel: true
---
gitGraph BT:
  branch {base_branch}   order: 1
  branch upstream-main   order: 4
  branch upstream/latest order: 3
  checkout main
  commit id: 'Unrelated history: workflows, doc'
  checkout upstream-main
  commit
  checkout upstream-main
  commit
  commit id: 'release' tag: '{upstream_tag}'
  checkout upstream/latest
  commit id: 'previous stuff'
  merge upstream-main id: 'Filtered .github/debian folders' tag: 'upstream/{normalized_version}'
  checkout {base_branch}
  commit
  commit
  commit
  branch debian/pr/{normalized_version}-1 order: 2
  merge upstream/latest id: 'Merged Upstream'
  commit id: 'Changelog version update' type: HIGHLIGHT
```
"""

    return pr_body + mermaid_diagram
    
def main():
    args = parse_arguments()

    logger.debug(f"Print of the arguments: {args}")

    pr_title = create_pr_title(args.normalized_version)
    pr_body = create_pr_body(args.base_branch, args.upstream_tag, args.normalized_version)
    
    # Printing the pr body in a .md file for manual review:
    with open("promotion_pr_body.md", "w") as pr_body_file:
        pr_body_file.write(pr_body)

    pr_creation_command = f"gh pr create --title '{pr_title}' --body-file promotion_pr_body.md --base {args.base_branch} --head debian/pr/{args.normalized_version}-1"
    
    # Executing the PR creation command using GitHub CLI 
    subprocess.run(pr_creation_command, shell=True, check=True)
        

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Uncaught exception : {e}")
        traceback.print_exc()
        sys.exit(1)
