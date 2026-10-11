#!/usr/bin/env bash
set -euo pipefail

# Validates a CIDR list before it's ever set live, using the Worker's own
# parser (check-allowlist), so a typo is caught here rather than rejecting
# the entire live allowlist, and denying every request, after upload.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ $# -ne 1 ]]; then
  echo "usage: npm run set-allowlist -- <cidr>[,<cidr>...]" >&2
  exit 1
fi

(cd "$REPO_ROOT" && cargo run --quiet --bin check-allowlist -- "$1")
(cd "$REPO_ROOT" && npx --no-install wrangler kv key put --binding=ALLOWED_CIDRS_KV --remote cidrs "$1")
