qcom-build-utils
--------

Overview
--------
qcom-build-utils holds set of tools which to developers to build, test and debug platform and CI/CD utilities.

Features
--------
- scripts/ : Helper scripts to used in the reusable workflows
- reusable-workflows/ : Reusable workflows that other repo shall call

Branches
--------
main: Primary stable branch. Contributors should develop submissions based on this branch, and submit pull requests to this branch.
development : Development happens on this branch, and gets merged back to main when the features are deemed stable
internal : This branch is the mirror of the internal version of the build-utils repo. It is there to keep a mirror, but the content
           main and delvelopment has diverged substentially from it. It exists to that internal CI can use it, but should not be used
           as a base for development

License
-------
qcom-build-utils is licensed under the [BSD-3-clause-clear License](https://spdx.org/licenses/BSD-3-Clause-Clear.html). See [LICENSE](LICENSE.txt) for the full license text.
