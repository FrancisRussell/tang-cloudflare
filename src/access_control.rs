use ipnetwork::IpNetwork;
use worker::*;

mod header_names {
    use http::HeaderName;

    /// Client IP set by Cloudflare's edge; trusted over `X-Forwarded-For`,
    /// which a client can set to anything. Completing a TLS handshake as
    /// this IP requires real network control, not just knowledge of it.
    pub const CF_CONNECTING_IP: HeaderName = HeaderName::from_static("cf-connecting-ip");
}

/// KV namespace holding a comma-separated CIDR list (v4 and/or v6) of who's
/// allowed to reach `/adv` and `/rec`: the VPS(es) this Tang instance
/// actually serves, and the sole access control (Clevis, the client, sends
/// no header beyond Content-Type and has no config option to add one, so
/// there's no bearer credential to check alongside this). KV rather than a
/// var or secret, so it's set with `wrangler kv key put`, independent of
/// any code deploy, and never has to live in a local file or in
/// wrangler.toml. Keep it as tight as the real network topology allows (a
/// bare /32 or /128) unless there's a concrete reason to widen it.
const ALLOWED_CIDRS_KV_BINDING: &str = "ALLOWED_CIDRS_KV";
/// The single key `ALLOWED_CIDRS_KV` is read and written under.
const ALLOWED_CIDRS_KV_KEY: &str = "cidrs";

/// Per-IP request cap (see wrangler.toml), a backstop against one source
/// repeatedly paying for a KV read and whatever follows it.
const RATE_LIMIT_BINDING: &str = "RATE_LIMITER";

/// The request's `CF-Connecting-IP` header, if present.
fn get_client_ip(req: &Request) -> Option<String> {
    req.headers().get(header_names::CF_CONNECTING_IP.as_str()).ok().flatten()
}

/// Splits a comma-separated CIDR list into trimmed, non-empty entries.
fn cidr_entries(raw: &str) -> impl Iterator<Item = &str> { raw.split(',').map(str::trim).filter(|s| !s.is_empty()) }

/// Parses the comma-separated CIDR list read from `ALLOWED_CIDRS_KV`. An
/// entry that fails to parse is dropped rather than failing the whole
/// request, so one typo doesn't take the Worker down. An empty result
/// still fails every request closed, since `ip_allowed` treats "no ranges"
/// as "nothing matches".
fn parse_cidr_list(raw: &str) -> Vec<IpNetwork> { cidr_entries(raw).filter_map(|s| s.parse().ok()).collect() }

/// Checks that every entry in a comma-separated CIDR list parses, unlike
/// `parse_cidr_list`, which silently drops a bad one so a single typo
/// doesn't take the Worker down for every other entry. Used by
/// `check-allowlist` to catch that typo before it's ever set as
/// `ALLOWED_CIDRS_KV`'s value, where it would otherwise go unnoticed until
/// the VPS can't unlock.
pub fn check_cidr_list(raw: &str) -> std::result::Result<(), String> {
    let mut any = false;
    for entry in cidr_entries(raw) {
        any = true;
        entry.parse::<IpNetwork>().map_err(|e| format!("{entry:?} is not a valid CIDR: {e}"))?;
    }
    if any {
        Ok(())
    } else {
        Err("no CIDR entries found".to_string())
    }
}

/// True if `req`'s `CF-Connecting-IP` falls within one of `allowed`. Fails
/// closed: a missing or unparseable header is treated as not allowed.
fn ip_allowed(req: &Request, allowed: &[IpNetwork]) -> bool {
    let Some(ip) = get_client_ip(req).and_then(|s| s.parse().ok()) else {
        return false;
    };
    allowed.iter().any(|net| net.contains(ip))
}

/// True if `req`'s source IP is still within `RATE_LIMIT_BINDING`'s
/// per-IP cap. Checked before the KV read in `authorized`, so a source
/// hammering the Worker doesn't keep paying for it. Fails closed on a
/// missing IP, same as `ip_allowed`; fails open on the binding itself
/// being unreachable, since a rate-limiter hiccup shouldn't take down
/// the real access check that follows it.
async fn rate_limit_ok(req: &Request, env: &Env) -> bool {
    let Some(ip) = get_client_ip(req) else { return false };
    let Ok(limiter) = env.rate_limiter(RATE_LIMIT_BINDING) else { return true };
    limiter.limit(ip).await.map_or(true, |outcome| outcome.success)
}

/// True if `req` is allowed to reach `/adv` or `/rec`: within the per-IP
/// rate limit, and in the CIDR list in `ALLOWED_CIDRS_KV`.
pub(crate) async fn authorized(req: &Request, env: &Env) -> bool {
    if !rate_limit_ok(req, env).await {
        return false;
    }
    let Ok(kv) = env.kv(ALLOWED_CIDRS_KV_BINDING) else { return false };
    let Ok(Some(allowed_cidrs)) = kv.get(ALLOWED_CIDRS_KV_KEY).text().await else { return false };
    let allowed = parse_cidr_list(&allowed_cidrs);
    !allowed.is_empty() && ip_allowed(req, &allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_list_parses_each_valid_entry() {
        let allowed = parse_cidr_list("203.0.113.0/24, 198.51.100.0/24");
        for ip in ["203.0.113.5", "198.51.100.5"] {
            let addr = ip.parse().expect("test address literal must parse");
            assert!(allowed.iter().any(|net| net.contains(addr)), "ip: {ip}");
        }
    }

    #[test]
    fn test_parse_cidr_list_drops_unparseable_entries_but_keeps_the_rest() {
        let allowed = parse_cidr_list("not-a-cidr, 203.0.113.0/24");
        let addr = "203.0.113.1".parse().expect("test address literal must parse");
        assert_eq!(allowed.len(), 1);
        assert!(allowed[0].contains(addr));
    }

    #[test]
    fn test_parse_cidr_list_empty_input_yields_no_ranges() {
        assert!(parse_cidr_list("").is_empty());
    }

    #[test]
    fn test_parse_cidr_list_trims_surrounding_whitespace() {
        let allowed = parse_cidr_list("  203.0.113.0/24 ,198.51.100.0/24  ");
        assert_eq!(allowed.len(), 2);
    }

    #[test]
    fn test_check_cidr_list_accepts_every_valid_entry() {
        assert!(check_cidr_list("203.0.113.0/24, 198.51.100.0/24").is_ok());
    }

    #[test]
    fn test_check_cidr_list_rejects_a_single_bad_entry_even_among_good_ones() {
        assert!(check_cidr_list("203.0.113.0/24, not-a-cidr").is_err());
    }

    #[test]
    fn test_check_cidr_list_rejects_empty_input() {
        assert!(check_cidr_list("").is_err());
        assert!(check_cidr_list("   ").is_err());
    }
}
