//! `/adv` and `/rec`'s access control: an IP allowlist plus a per-IP rate
//! limit. The allowlist is the sole access control here, not a supplement
//! to some other credential: Clevis, the client, sends no header beyond
//! `Content-Type` and has no config option to add one. It's read from KV
//! rather than a var or secret, so it's set with `wrangler kv key put`,
//! independent of any code deploy, and never has to live in a local file
//! or in `wrangler.toml`.

use std::result::Result;

use ipnetwork::IpNetwork;
use worker::{Env, Request};

mod header_names {
    use http::HeaderName;

    /// Client IP set by Cloudflare's edge; trusted over `X-Forwarded-For`,
    /// which a client can set to anything. Completing a TLS handshake as
    /// this IP requires real network control, not just knowledge of it.
    pub const CF_CONNECTING_IP: HeaderName = HeaderName::from_static("cf-connecting-ip");
}

/// KV namespace holding the allowlist: a comma-separated CIDR list (v4
/// and/or v6) of who's allowed to reach `/adv` and `/rec`.
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

/// The CIDR ranges read from `ALLOWED_CIDRS_KV`: who's allowed to reach
/// `/adv` and `/rec`.
pub struct AllowList(Vec<IpNetwork>);

impl AllowList {
    /// True if `ip` falls within one of `self`'s ranges.
    fn allows(&self, ip: std::net::IpAddr) -> bool { self.0.iter().any(|net| net.contains(ip)) }
}

/// Parses a comma-separated CIDR list, rejecting the whole thing if any
/// entry fails to parse or none are given. Used both by `authorized`
/// (which denies every request on an `Err`, the same as a missing KV
/// value) and by `check-allowlist` before a list is ever written to
/// `ALLOWED_CIDRS_KV`. A lenient parse that dropped bad entries instead
/// would be worse for both: silently losing an intended entry from a live
/// allowlist is easy to miss, where the VPS failing to unlock from a
/// rejected list is not.
impl std::str::FromStr for AllowList {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let mut entries = Vec::new();
        for entry in cidr_entries(raw) {
            entries.push(entry.parse::<IpNetwork>().map_err(|e| format!("{entry:?} is not a valid CIDR: {e}"))?);
        }
        if entries.is_empty() {
            return Err("no CIDR entries found".to_string());
        }
        Ok(AllowList(entries))
    }
}

/// True if `req`'s `CF-Connecting-IP` is in `allowed`. Fails closed: a
/// missing or unparseable header is treated as not allowed.
fn ip_allowed(req: &Request, allowed: &AllowList) -> bool {
    let Some(ip) = get_client_ip(req).and_then(|s| s.parse().ok()) else {
        return false;
    };
    allowed.allows(ip)
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
    let Ok(Some(raw)) = kv.get(ALLOWED_CIDRS_KV_KEY).text().await else { return false };
    let Ok(allowed) = raw.parse::<AllowList>() else { return false };
    ip_allowed(req, &allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_list_parses_each_valid_entry() {
        let allowed: AllowList = "203.0.113.0/24, 198.51.100.0/24".parse().unwrap();
        for ip in ["203.0.113.5", "198.51.100.5"] {
            assert!(allowed.allows(ip.parse().expect("test address literal must parse")), "ip: {ip}");
        }
    }

    #[test]
    fn test_allow_list_trims_surrounding_whitespace() {
        let allowed: AllowList = "  203.0.113.0/24 ,198.51.100.0/24  ".parse().unwrap();
        for ip in ["203.0.113.5", "198.51.100.5"] {
            assert!(allowed.allows(ip.parse().expect("test address literal must parse")), "ip: {ip}");
        }
    }

    #[test]
    fn test_allow_list_rejects_a_single_bad_entry_even_among_good_ones() {
        assert!("203.0.113.0/24, not-a-cidr".parse::<AllowList>().is_err());
    }

    #[test]
    fn test_allow_list_rejects_empty_input() {
        assert!("".parse::<AllowList>().is_err());
        assert!("   ".parse::<AllowList>().is_err());
    }
}
