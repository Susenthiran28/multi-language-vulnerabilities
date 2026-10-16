#!/usr/bin/env bash
# File:    make-history-fixture.sh
# Purpose: Build a throwaway git repository whose HISTORY contains secrets that
#          are absent from HEAD, so the history-scanning path can be exercised
#          without planting credential-shaped strings in this repository.
#          All values written are synthetic and non-functional.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
#
# Usage: bash make-history-fixture.sh /tmp/secret-history-fixture

set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "usage: $0 <target-directory>" >&2
  exit 2
fi

if [ -e "$TARGET" ]; then
  echo "refusing to write: $TARGET already exists" >&2
  exit 1
fi

mkdir -p "$TARGET"
cd "$TARGET"

git init -q
git config user.email "fixture@vigilnz.local"
git config user.name "Vigilnz Fixture"

# Commit 1 - secrets present in the working tree
cat > config.js <<'INNER'
module.exports = {
  awsAccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  githubToken: 'ghp_FIXTURE00000000000000000000000000000'
};
INNER
git add config.js
git commit -q -m "chore: add service configuration"

# Commit 2 - secrets removed from the working tree, still reachable in history
cat > config.js <<'INNER'
module.exports = {
  awsAccessKeyId: process.env.AWS_ACCESS_KEY_ID,
  awsSecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  githubToken: process.env.GITHUB_TOKEN
};
INNER
git add config.js
git commit -q -m "fix(config): read credentials from the environment"

# Commit 3 - a dotfile containing a secret
cat > .env <<'INNER'
STRIPE_SECRET_KEY=sk_live_FIXTURE0000000000000000000000
SESSION_SECRET=fixture-session-secret-value-0000000000
INNER
git add -f .env
git commit -q -m "chore: add local environment file"

# Commit 4 - dotfile deleted, still reachable in history
git rm -q .env
printf '.env\n' > .gitignore
git add .gitignore
git commit -q -m "chore: stop tracking the local environment file"

echo "History fixture created at: $TARGET"
echo "  working-tree scan  -> expect 0 findings"
echo "  history scan       -> expect 4 findings across commits 1, 3 and 4"
