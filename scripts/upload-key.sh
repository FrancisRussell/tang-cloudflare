#!/usr/bin/env bash
set -euo pipefail

# Validates a Tang key-set JSON file before it's ever set live, using the
# Worker's own parsing/initialization (check-key), then uploads it.
# Defaults to tang-keys.json, the name `keygen` writes, but takes a
# different path too, for a rotation kept under its own name.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
file="${1:-tang-keys.json}"

(cd "$REPO_ROOT" && cargo run --quiet --bin check-key <"$file")
(cd "$REPO_ROOT" && npx --no-install wrangler secret put TANG_KEYS <"$file")
