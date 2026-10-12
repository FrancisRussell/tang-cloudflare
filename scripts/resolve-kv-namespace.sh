#!/usr/bin/env bash
set -euo pipefail

# Resolves ALLOWED_CIDRS_KV's real namespace id by name, creating the
# namespace first if none with that name exists yet, unless called with
# --no-create (for a pure read like get-allowlist, which shouldn't have
# the side effect of provisioning a namespace that was never set up).
# Needs no wrangler config file: `wrangler kv namespace list`/`create`
# operate on the account directly. Prints just the resolved id on stdout;
# `create`'s own human-readable output goes to stderr, so a caller can
# always safely capture this script's stdout as the id.
#
# KV_NAMESPACE_NAME is read from DEPLOY_VARS_FILE (default:
# deploy.vars), falling back to ALLOWED_CIDRS_KV's conventional name if
# neither sets it. DEPLOY_VARS_FILE given but missing is an error (it was
# asked for specifically); the default file missing is not (nothing
# requires it to exist).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -n "${DEPLOY_VARS_FILE:-}" ]]; then
  source "$DEPLOY_VARS_FILE"
elif [[ -f "$REPO_ROOT/deploy.vars" ]]; then
  source "$REPO_ROOT/deploy.vars"
fi
KV_NAMESPACE_NAME="${KV_NAMESPACE_NAME:-tang-allowed-cidrs}"

# Shared by both lookups below. Cloudflare rejects creating a second
# namespace with a duplicate title in the same account (confirmed against
# its own API docs), so at most one match is ever expected; `.[0]` rather
# than a `head`/pipe avoids a pipefail/SIGPIPE risk for no real benefit.
find_namespace_id() {
  (cd "$REPO_ROOT" && npx --no-install wrangler kv namespace list) \
    | jq -r --arg title "$KV_NAMESPACE_NAME" '[.[] | select(.title == $title)] | .[0].id // empty'
}

id="$(find_namespace_id)"
if [[ -z "$id" ]]; then
  if [[ "${1:-}" == "--no-create" ]]; then
    echo "no KV namespace named \"$KV_NAMESPACE_NAME\" exists yet; run deploy or set-allowlist first" >&2
    exit 1
  fi
  (cd "$REPO_ROOT" && npx --no-install wrangler kv namespace create "$KV_NAMESPACE_NAME") >&2
  id="$(find_namespace_id)"
fi

id="${id:?wrangler kv namespace create did not produce a namespace named \"$KV_NAMESPACE_NAME\"}"
echo "$id"
