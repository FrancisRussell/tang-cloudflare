#!/usr/bin/env bash
set -euo pipefail

# wrangler.toml's committed `id` is a placeholder (see its own comment):
# the real id is resolved by name and substituted into a generated copy
# here, so the real, account-specific id never has to be committed.
#
# WRANGLER_DISABLE_SUBDOMAIN_MIXED_STATE_CHECK avoids a warning wrangler
# would otherwise print on every deploy, since workers_dev=true and
# preview_urls=false are a deliberate mismatch here (see wrangler.toml).

# Cloudflare's edge can take a moment to pick up a new deploy, so a single
# immediate check could fail on propagation lag rather than a real
# problem; these ride out that window without masking one.
HEALTH_CHECK_RETRIES=5
HEALTH_CHECK_RETRY_DELAY_SECONDS=3

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

# Captured for the URL grep below, but `tee`'d to fd 3 (the real stdout,
# saved before the pipeline redirects it) so deploy progress still
# streams live instead of only appearing once the command finishes.
exec 3>&1
deploy_output="$(
  (cd "$REPO_ROOT" && WRANGLER_DISABLE_SUBDOMAIN_MIXED_STATE_CHECK=true npx --no-install wrangler deploy --config wrangler.generated.toml) \
    | tee /dev/fd/3
)"

# wrangler prints the deployed *.workers.dev URL on its own line; relied
# on here rather than reconstructed from wrangler.toml's `name`, since the
# account subdomain isn't recorded anywhere in this repo. The trailing
# `|| true` keeps a non-matching grep (an empty $url, handled below) from
# being treated as this whole script failing, under `pipefail`.
url="$(grep -oE 'https://[A-Za-z0-9.-]+\.workers\.dev' <<<"$deploy_output" | head -n1 || true)"
if [[ -z "$url" ]]; then
  echo "could not find the deployed URL in wrangler's output; skipping the post-deploy health check" >&2
  exit 1
fi

for ((attempt = 1; attempt <= HEALTH_CHECK_RETRIES; attempt++)); do
  if curl -sf --max-time "$HEALTH_CHECK_RETRY_DELAY_SECONDS" -o /dev/null "$url/health"; then
    echo "health check passed: $url/health"
    exit 0
  fi
  if ((attempt < HEALTH_CHECK_RETRIES)); then
    sleep "$HEALTH_CHECK_RETRY_DELAY_SECONDS"
  fi
done

echo "deployed Worker's health check failed at $url/health after $HEALTH_CHECK_RETRIES attempts" >&2
exit 1
