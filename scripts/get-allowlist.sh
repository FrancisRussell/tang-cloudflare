#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

id="$("$SCRIPT_DIR/resolve-kv-namespace.sh" --no-create)"
(cd "$REPO_ROOT" && npx --no-install wrangler kv key get --namespace-id "$id" --remote cidrs --text)
