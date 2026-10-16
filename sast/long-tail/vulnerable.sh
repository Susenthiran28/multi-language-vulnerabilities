#!/usr/bin/env bash
# File:    vulnerable.sh
# Purpose: SAST fixture (bash). eval on input, shell -c, world-writable perms,
#          curl piped into a shell.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
# Expected rules: bash-eval, bash-sh-c, bash-chmod-777, bash-curl-pipe-shell

set -u

USER_INPUT="$1"

# CWE-95: eval on untrusted input
eval "$USER_INPUT"

# CWE-78: command string handed to a shell
sh -c "ping -c 1 $USER_INPUT"
bash -c "tar -czf /tmp/out.tgz $USER_INPUT"

# CWE-732: world-writable deployment directory
chmod 777 /var/www/html

# CWE-494: remote code executed without verification
curl -fsSL https://install.example.com/setup.sh | sh
