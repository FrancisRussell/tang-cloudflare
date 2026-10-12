#!/usr/bin/env bash
set -euo pipefail

# wrangler.toml's committed `id` is a placeholder (see its own comment):
# the real id is resolved by name and substituted into a generated copy
# here, so the real, account-specific id never has to be committed.
#
# WRANGLER_DISABLE_SUBDOMAIN_MIXED_STATE_CHECK avoids a warning wrangler
# would otherwise print on every deploy, since workers_dev=true and
# preview_urls=false are a deliberate mismatch here (see wrangler.toml).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

id="$("$SCRIPT_DIR/resolve-kv-namespace.sh")"

# Guards against wrangler.toml ever being hand-edited back to a real,
# committed id (exactly the mistake this scheme exists to avoid): if the
# placeholder isn't there, sed would otherwise silently match nothing and
# deploy with whatever id is in the file instead, with no error.
grep -q REPLACE_WITH_NAMESPACE_ID "$REPO_ROOT/wrangler.toml" || {
  echo "wrangler.toml's id placeholder (REPLACE_WITH_NAMESPACE_ID) is missing; refusing to deploy with whatever id is there instead" >&2
  exit 1
}
# $id is a Cloudflare-issued hex id (no sed metacharacters), so a plain
# substitution is safe without escaping it.
sed "s/REPLACE_WITH_NAMESPACE_ID/$id/" "$REPO_ROOT/wrangler.toml" > "$REPO_ROOT/wrangler.generated.toml"

(cd "$REPO_ROOT" && WRANGLER_DISABLE_SUBDOMAIN_MIXED_STATE_CHECK=true npx --no-install wrangler deploy --config wrangler.generated.toml)
