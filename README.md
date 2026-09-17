# fork-pr-secret-poc (branch: poc/fork-pr-secrets-qli39)

This branch is a throwaway proof-of-concept for
[qli-ci#39](https://github.com/qualcomm-linux/qli-ci/issues/39): does a
`pull_request` / `workflow_run` split actually keep a secret out of reach of
PR-controlled code when the PR comes from a fork?

It has unrelated history from `main` (orphan branch) and is not meant to be
merged. It stands in `POC_FORK_PR_TEST_TOKEN` (a throwaway repo secret, not a
real credential) for `DEBUSINE_TOKEN` / `DEB_PKG_BOT_CI_TOKEN`, and asks the
same question three ways. All triggers are scoped to this branch only so
nothing here can interact with real PRs against `main` or any other branch.

## Workflows

- **`poc-broken.yml`** — today's pattern in `qli-ci`'s `pkg-pr-hook.yml`: a
  plain `on: pull_request` trigger that references
  `${{ secrets.POC_FORK_PR_TEST_TOKEN }}` directly. Expected on a fork PR: the
  secret is empty. "Before" evidence for
  [qli-ci#30](https://github.com/qualcomm-linux/qli-ci/issues/30).

- **`poc-hook.yml`** + **`poc-check.yml`** — the proposed fix, mirroring
  `debusine-pr-hook.yml` / `debusine-pr-check.yml`, corrected for two bugs
  found while testing the real thing against an actual fork PR (see
  qli-ci#39 for the writeup):
  - the hook does not attempt to write anything (a fork PR's `GITHUB_TOKEN`
    is forced read-only, so a write attempt there always 403s — this is
    `debusine-action#69`);
  - the check identifies the PR via the `workflow_run` payload's
    `head_sha`/`head_repository.full_name`, not `pull_requests[0]` (empirically
    empty for fork PRs).

  The check checks out the PR head commit and runs the PR's own script (if
  any) in a step that does **not** have the secret in its env, before a later
  step that does have the secret but only does a stand-in "upload". The PR
  branch used for testing plants an `attack.sh` that tries to read the secret
  directly and, separately, tries to hijack `PATH` so that the *later*,
  secret-bearing step's `curl` invocation gets intercepted instead.

- **`poc-check-positive-control.yml`** — manual-only (`workflow_dispatch`)
  sanity check: deliberately puts the secret in the "untrusted" step's env and
  runs the same capture logic against itself, to prove the capture/detection
  method actually would catch a real leak.

All "capture" steps write to local files uploaded as workflow artifacts
(`env-dump`, `curl-capture`) — nothing is sent to any external endpoint.
