#![warn(clippy::pedantic)]
// `use worker::*` is the crate's own idiom; naming every re-export
// individually buys nothing. This isn't a published library, so a per-fn
// `# Errors` section would be noise.
#![allow(clippy::wildcard_imports, clippy::missing_errors_doc)]
//
// Tang (Network-Bound Disk Encryption) server, deployed as a Cloudflare
// Worker. Serves the two stateless Tang endpoints (`/adv`, `/rec/<kid>`),
// with the actual protocol implemented by `tangy-lib`. A normal Tang
// deployment answers any caller; this one is gated to a single consumer
// (one VPS) by source IP, since the whole point here is limiting who can
// complete a recovery, not serving the public. There's no bearer
// credential on top of the IP check: the client is Clevis, which sends no
// header beyond `Content-Type` and has no config option to add one.

use base64ct::Encoding;
use http::StatusCode;
use ipnetwork::IpNetwork;
use tangy_lib::{KeySource, MyJwkEcKey, TangyLib};
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

/// Secret holding every Tang key generation as one JSON object (see
/// `TangKeys`), so it's set with a single direct paste rather than
/// assembled by hand from separate values.
const TANG_KEYS_SECRET: &str = "TANG_KEYS";

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
async fn authorized(req: &Request, env: &Env) -> bool {
    if !rate_limit_ok(req, env).await {
        return false;
    }
    let Ok(kv) = env.kv(ALLOWED_CIDRS_KV_BINDING) else { return false };
    let Ok(Some(allowed_cidrs)) = kv.get(ALLOWED_CIDRS_KV_KEY).text().await else { return false };
    let allowed = parse_cidr_list(&allowed_cidrs);
    !allowed.is_empty() && ip_allowed(req, &allowed)
}

/// `Response::error` using `status`'s own canonical reason phrase (e.g.
/// "Forbidden" for 403) as the message, for error paths that carry no extra
/// diagnostic detail beyond the status itself.
fn error_response(status: StatusCode) -> Result<Response> {
    Response::error(status.canonical_reason().expect("standard status code has a canonical reason"), status.as_u16())
}

/// `/adv`'s content type in the Tang wire protocol, matching the reference
/// `tangy` server.
const JOSE_JSON: &str = "application/jose+json";
/// `/rec`'s content type in the Tang wire protocol, matching the reference
/// `tangy` server.
const JWK_JSON: &str = "application/jwk+json";
/// The route pattern's named parameter for the recovery key ID, and the key
/// `ctx.param` looks it up by, kept as one constant so the two can't drift
/// apart silently.
const KID_PARAM: &str = "kid";

/// The JWA (RFC 7518) algorithm identifier tangy-lib gives the ES512
/// signing key, used to tell it apart from the exchange key in a freshly
/// generated key set.
pub const SIGNING_KEY_ALG: &str = "ES512";
/// The JWA (RFC 7518) algorithm identifier tangy-lib gives the ECMR
/// exchange key, used to tell it apart from the signing key in a freshly
/// generated key set.
pub const EXCHANGE_KEY_ALG: &str = "ECMR";

/// A `Headers` with a single `content-type` entry set to `value`.
fn content_type_headers(value: &str) -> Headers {
    let headers = Headers::new();
    headers.set("content-type", value).expect("static header name and value are valid");
    headers
}

/// One generation of Tang keys, generated and retired as a unit since
/// `sig`+`exc` are always minted together in one `keygen`/`rotate` call.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct KeyGeneration {
    pub sig: MyJwkEcKey,
    pub exc: MyJwkEcKey,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Hand-written rather than derived so `sig`/`exc` (each holding a private
/// scalar in `MyJwkEcKey`'s own, unredacted `Debug`) never end up in a
/// panic message or log line, which `console_error_panic_hook` would
/// otherwise forward verbatim to Cloudflare's live logs.
impl std::fmt::Debug for KeyGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyGeneration")
            .field("sig", &"<redacted>")
            .field("exc", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("note", &self.note)
            .finish()
    }
}

/// The `TANG_KEYS` secret's JSON shape: exactly one advertised generation
/// (`current`), plus however many retired generations are kept only so an
/// already-bound disk can keep completing `/rec` after a rotation.
/// `retired` is newest-first, so pruning the oldest is a pop from the
/// back.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TangKeys {
    pub current: KeyGeneration,
    #[serde(default)]
    pub retired: Vec<KeyGeneration>,
}

impl TangKeys {
    /// Every generation, current first: the full set `/rec` must serve.
    pub fn generations(&self) -> impl Iterator<Item = &KeyGeneration> {
        std::iter::once(&self.current).chain(self.retired.iter())
    }
}

/// Parses the `TANG_KEYS` secret's JSON. Shared so there's one parsing
/// path for the Worker itself, `check-key`, and `keygen`'s subcommands.
pub fn parse_tang_keys(raw: &str) -> std::result::Result<TangKeys, String> {
    serde_json::from_str(raw).map_err(|e| format!("not valid JSON: {e}"))
}

/// Serializes each generation's two keys back to the raw JWK JSON strings
/// `TangyLib::init` takes.
fn key_strings<'a>(generations: impl Iterator<Item = &'a KeyGeneration>) -> std::result::Result<Vec<String>, String> {
    let mut out = Vec::new();
    for generation in generations {
        out.push(serde_json::to_string(&generation.sig).map_err(|e| format!("signing key: {e}"))?);
        out.push(serde_json::to_string(&generation.exc).map_err(|e| format!("exchange key: {e}"))?);
    }
    Ok(out)
}

/// Builds the `TangyLib` that serves `/adv`: only the current generation,
/// so retired generations are never advertised. A separate `TangyLib`
/// from `build_rec_tangy`'s, rather than one shared instance with a
/// visibility flag, since tangy-lib itself has no advertised-vs-hidden
/// concept: every key it's given is advertised unconditionally.
fn build_adv_tangy(keys: &TangKeys) -> std::result::Result<TangyLib, String> {
    let adv_keys = key_strings(std::iter::once(&keys.current))?;
    let adv_refs: Vec<&str> = adv_keys.iter().map(String::as_str).collect();
    TangyLib::init(KeySource::Vector(&adv_refs)).map_err(|e| e.to_string())
}

/// Builds the `TangyLib` that serves `/rec` from `generations`. `init`
/// signs a fresh advertisement per signing key given to it, so the live
/// Worker only ever passes the single generation a request's `kid`
/// actually matched (see `find_generation`), keeping that cost constant
/// regardless of how many retired generations exist; `check_tangy_keys`
/// passes every generation at once, to validate them all against one
/// shared instance.
fn build_rec_tangy<'a>(generations: impl Iterator<Item = &'a KeyGeneration>) -> std::result::Result<TangyLib, String> {
    let rec_keys = key_strings(generations)?;
    let rec_refs: Vec<&str> = rec_keys.iter().map(String::as_str).collect();
    TangyLib::init(KeySource::Vector(&rec_refs)).map_err(|e| e.to_string())
}

/// Finds the generation whose exchange key's thumbprint is `kid`, the
/// only identifier `/rec` is ever asked for. A thumbprint is just a
/// SHA-256 hash (see `tangy_lib`'s `MyJwkEcKey::thumbprint`), far cheaper
/// than the real ECDSA signature `TangyLib::init` performs per signing
/// key, so the live Worker checks this first and rejects an unknown `kid`
/// without ever building a `TangyLib` for it.
fn find_generation<'a>(keys: &'a TangKeys, kid: &str) -> Option<&'a KeyGeneration> {
    keys.generations().find(|generation| generation.exc.thumbprint() == kid)
}

/// The P-521 curve's generator point, in the same JWK coordinate encoding
/// as a request body. Used below purely as a throwaway but genuinely
/// on-curve point: its value doesn't matter, only that it's valid. Read
/// off `p521::ProjectivePoint::generator()` rather than transcribed from
/// a spec, avoiding a transcription error in a 521-bit literal.
const GENERATOR_X: &str = "AMaFjga3BATpzZ4-y2YjlbRCnGSBOQU_tSH4KK9ga009uqFLXnfv51ko_h3BJ6L_qN4zSLPBhWpCm_l-fjHC5b1m";
const GENERATOR_Y: &str = "ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT-tB2E1PHCGonLCQIi-lHaf0WZQ";

/// Checks that `retired` is strictly newest-first, the invariant
/// `TangKeys` documents and `prune`'s default/`--keep` removal relies on
/// to drop the right end of the list. Doesn't compare `current` against
/// `retired`: reverting to an older generation (restoring it as current
/// and retiring whatever was current instead) can legitimately leave
/// `current` older than some retired generations, so that's not itself
/// a sign of corruption.
fn check_retired_order(keys: &TangKeys) -> std::result::Result<(), String> {
    for (index, (newer, older)) in keys.retired.iter().zip(keys.retired.iter().skip(1)).enumerate() {
        if older.created_at >= newer.created_at {
            return Err(format!(
                "retired[{}] (created {}) is not older than retired[{index}] (created {})",
                index + 1,
                older.created_at,
                newer.created_at
            ));
        }
    }
    Ok(())
}

/// Checks that `key`'s public point (`x`, `y`) is actually on the P-521
/// curve and is the point its own private scalar `d` derives (i.e.
/// `(x, y) == d * G`). Neither `TangyLib::init` nor `rec` ever read a
/// key's public point at all (only `d` is used, to sign or to perform
/// the exchange), so a wrong or off-curve `(x, y)` would otherwise pass
/// every other check in this file and still be echoed verbatim into
/// `/adv`'s payload.
fn check_key_point_matches_scalar(key: &MyJwkEcKey) -> std::result::Result<(), String> {
    let x = base64ct::Base64UrlUnpadded::decode_vec(&key.x).map_err(|e| format!("x coordinate: {e}"))?;
    let y = base64ct::Base64UrlUnpadded::decode_vec(&key.y).map_err(|e| format!("y coordinate: {e}"))?;
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let claimed = p521::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| "public point is not a valid, on-curve P-521 point".to_string())?;

    let d = key.d.as_deref().ok_or("missing private scalar \"d\"")?;
    let d = base64ct::Base64UrlUnpadded::decode_vec(d).map_err(|e| format!("d: {e}"))?;
    let secret = p521::SecretKey::from_slice(&d).map_err(|_| "private scalar \"d\" is invalid".to_string())?;

    if secret.public_key() != claimed {
        return Err("public point does not match the private scalar".to_string());
    }
    Ok(())
}

/// Validates a `TANG_KEYS` JSON more thoroughly than `parse_tang_keys`
/// alone. Checks `retired`'s order (see `check_retired_order`), every
/// key's public point against its own private scalar (see
/// `check_key_point_matches_scalar`), then every generation's exchange
/// key: `parse_tang_keys` and `TangyLib::init` only ever exercise a
/// signing key's private scalar (via the precomputed advertisement); an
/// exchange key's private scalar is never converted until an actual
/// `/rec` request names it by its own `kid`, so this exercises that path
/// too, for every generation, with a throwaway on-curve point standing
/// in for the client's half of the exchange. Used by `check-key`; the
/// Worker itself has no reason to run any of these checks on every
/// request.
pub fn check_tangy_keys(raw: &str) -> std::result::Result<(), String> {
    let keys = parse_tang_keys(raw)?;
    check_retired_order(&keys)?;
    for generation in keys.generations() {
        check_key_point_matches_scalar(&generation.sig)
            .map_err(|e| format!("signing key rejected (created {}): {e}", generation.created_at))?;
        check_key_point_matches_scalar(&generation.exc)
            .map_err(|e| format!("exchange key rejected (created {}): {e}", generation.created_at))?;
    }
    let rec = build_rec_tangy(keys.generations())?;
    let dummy_request = format!(r#"{{"kty":"EC","crv":"P-521","x":"{GENERATOR_X}","y":"{GENERATOR_Y}"}}"#);
    for generation in keys.generations() {
        rec.rec(&generation.exc.thumbprint(), &dummy_request)
            .map(|_| ())
            .map_err(|e| format!("exchange key rejected (created {}): {e}", generation.created_at))?;
    }
    Ok(())
}

/// Parses every Tang key generation from the `TANG_KEYS` secret for this
/// request. Key loading is just JSON parsing, not real computation, so
/// there's no benefit to caching it across requests/isolates. Discards
/// the specific parse error, rather than exposing key-handling details
/// to the client. Building the actual `TangyLib` is left to the caller,
/// so each handler only pays for the one it needs (building either one
/// performs a real signature per signing key, via `TangyLib::init`'s own
/// precomputed advertisement).
fn load_tang_keys(env: &Env) -> std::result::Result<TangKeys, StatusCode> {
    let raw = env.secret(TANG_KEYS_SECRET).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.to_string();
    parse_tang_keys(&raw).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Handles `GET /adv`.
async fn handle_adv(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if !authorized(&req, &ctx.env).await {
        return error_response(StatusCode::FORBIDDEN);
    }
    let keys = match load_tang_keys(&ctx.env) {
        Ok(k) => k,
        Err(status) => return error_response(status),
    };
    let Ok(adv) = build_adv_tangy(&keys) else { return error_response(StatusCode::INTERNAL_SERVER_ERROR) };
    match adv.adv(None) {
        Ok(body) => Ok(Response::ok(body)?.with_headers(content_type_headers(JOSE_JSON))),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// A P-521 field element's encoded length: 521 bits, rounded up to whole
/// bytes.
const P521_COORDINATE_BYTE_LEN: usize = 66;

/// True if `field` is valid unpadded base64url that decodes to exactly a
/// P-521 coordinate's length.
fn is_p521_coordinate(field: &str) -> bool {
    base64ct::Base64UrlUnpadded::decode_vec(field).is_ok_and(|bytes| bytes.len() == P521_COORDINATE_BYTE_LEN)
}

/// True if `body` parses as the EC public JWK `tangy_lib::TangyLib::rec`
/// expects. `tangy-lib` parses its input with bare `.unwrap()`s rather than
/// returning an error, so anything malformed reaching it panics, and this
/// project's `panic = "abort"` profile turns that into a whole-instance
/// reinit rather than just a failed request. Deserializing into tangy-lib's
/// own `MyJwkEcKey`, instead of a hand-rolled subset of its fields, catches
/// every shape mismatch it would itself reject, including an unrelated
/// field present with the wrong JSON type. A syntactically valid but
/// off-curve point still reaches the unwrap, since detecting that needs the
/// curve arithmetic `tangy-lib` itself does.
fn looks_like_ec_point(body: &str) -> bool {
    let Ok(key) = serde_json::from_str::<MyJwkEcKey>(body) else { return false };
    key.kty == "EC" && key.crv == "P-521" && is_p521_coordinate(&key.x) && is_p521_coordinate(&key.y)
}

/// Handles `POST /rec/:kid`.
async fn handle_rec(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if !authorized(&req, &ctx.env).await {
        return error_response(StatusCode::FORBIDDEN);
    }
    let Some(kid) = ctx.param(KID_PARAM).cloned() else {
        return error_response(StatusCode::BAD_REQUEST);
    };
    let body = req.text().await?;
    if !looks_like_ec_point(&body) {
        return error_response(StatusCode::BAD_REQUEST);
    }
    let keys = match load_tang_keys(&ctx.env) {
        Ok(k) => k,
        Err(status) => return error_response(status),
    };
    let Some(generation) = find_generation(&keys, &kid) else { return error_response(StatusCode::NOT_FOUND) };
    let Ok(rec) = build_rec_tangy(std::iter::once(generation)) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    match rec.rec(&kid, &body) {
        Ok(body) => Ok(Response::ok(body)?.with_headers(content_type_headers(JWK_JSON))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => error_response(StatusCode::NOT_FOUND),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// The Worker's HTTP entry point, routing to `/adv` and `/rec/:kid`.
#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    let rec_pattern = format!("/rec/:{KID_PARAM}");
    Router::new().get_async("/adv", handle_adv).post_async(&rec_pattern, handle_rec).run(req, env).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid base64url-encoded coordinate of exactly `byte_len` bytes, for
    /// exercising `is_p521_coordinate`'s length check without a hardcoded
    /// magic string.
    fn b64_coordinate_of_len(byte_len: usize) -> String {
        base64ct::Base64UrlUnpadded::encode_string(&vec![0u8; byte_len])
    }

    fn valid_rec_body() -> String {
        let coord = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN);
        format!(r#"{{"kty":"EC","crv":"P-521","x":"{coord}","y":"{coord}"}}"#)
    }

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

    #[test]
    fn test_parse_tang_keys_rejects_malformed_json() {
        assert!(parse_tang_keys("not json").is_err());
    }

    #[test]
    fn test_parse_tang_keys_rejects_a_missing_current_generation() {
        assert!(parse_tang_keys("{}").is_err());
    }

    #[test]
    fn test_parse_tang_keys_rejects_a_generation_missing_sig_exc_or_created_at() {
        assert!(parse_tang_keys(r#"{"current":{"exc":{},"created_at":"2024-01-01T00:00:00Z"}}"#).is_err());
        assert!(parse_tang_keys(r#"{"current":{"sig":{},"created_at":"2024-01-01T00:00:00Z"}}"#).is_err());
        assert!(parse_tang_keys(r#"{"current":{"sig":{},"exc":{}}}"#).is_err());
    }

    /// A freshly generated, genuinely valid key generation with an
    /// explicit `created_at`, labelled by each key's own `alg` the same
    /// way `keygen` does.
    fn valid_key_generation_json_at(created_at: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
        let (mut sig, mut exc) = (None, None);
        for key in tangy_lib::create_new_key_set() {
            let parsed: serde_json::Value = serde_json::from_str(&key).expect("tangy-lib must produce valid JSON");
            match parsed.get("alg").and_then(serde_json::Value::as_str) {
                Some(SIGNING_KEY_ALG) => sig = Some(parsed),
                Some(EXCHANGE_KEY_ALG) => exc = Some(parsed),
                other => panic!("unexpected key algorithm: {other:?}"),
            }
        }
        serde_json::json!({
            "sig": sig.expect("a signing key"),
            "exc": exc.expect("an exchange key"),
            "created_at": created_at.to_rfc3339(),
        })
    }

    /// As `valid_key_generation_json_at`, stamped with the current time.
    fn valid_key_generation_json() -> serde_json::Value {
        valid_key_generation_json_at(chrono::Utc::now())
    }

    /// A genuinely valid `TANG_KEYS` JSON with one current generation and
    /// no retired ones.
    fn valid_tang_keys_json() -> serde_json::Value {
        serde_json::json!({ "current": valid_key_generation_json(), "retired": [] })
    }

    #[test]
    fn test_check_tangy_keys_accepts_a_genuinely_valid_key_set() {
        // Also the test that GENERATOR_X/GENERATOR_Y are themselves valid:
        // if they weren't, rec()'s own conversion of the dummy request
        // body would panic before ever reaching the exchange key's check.
        assert!(check_tangy_keys(&valid_tang_keys_json().to_string()).is_ok());
    }

    #[test]
    fn test_check_tangy_keys_rejects_a_point_off_curve() {
        let mut keys = valid_tang_keys_json();
        // Swapping x and y leaves well-formed, correct-length
        // coordinates that are (overwhelmingly likely to be) off the
        // curve.
        let x = keys["current"]["exc"]["x"].clone();
        let y = keys["current"]["exc"]["y"].clone();
        keys["current"]["exc"]["x"] = y;
        keys["current"]["exc"]["y"] = x;
        assert!(check_tangy_keys(&keys.to_string()).is_err());
    }

    #[test]
    fn test_check_tangy_keys_rejects_a_point_that_does_not_match_its_scalar() {
        let mut keys = valid_tang_keys_json();
        // Another genuinely valid key's point: on the curve, but not
        // the point this key's own `d` actually derives.
        let other = valid_key_generation_json();
        keys["current"]["exc"]["x"] = other["exc"]["x"].clone();
        keys["current"]["exc"]["y"] = other["exc"]["y"].clone();
        assert!(check_tangy_keys(&keys.to_string()).is_err());
    }

    #[test]
    fn test_check_tangy_keys_rejects_a_corrupted_current_exchange_key() {
        let mut keys = valid_tang_keys_json();
        // A zero scalar: the right length, but out of a private key's
        // valid range, so parse_tang_keys alone (which never exercises
        // the exchange key) would accept this.
        keys["current"]["exc"]["d"] = serde_json::Value::String(base64ct::Base64UrlUnpadded::encode_string(&[0u8; 66]));
        assert!(parse_tang_keys(&keys.to_string()).is_ok());
        // tangy-lib reaches a bare .unwrap() on this, same as check-key's
        // own binary sees, so this runs under catch_unwind too.
        let result = std::panic::catch_unwind(|| check_tangy_keys(&keys.to_string()));
        assert!(matches!(result, Ok(Err(_)) | Err(_)));
    }

    #[test]
    fn test_check_tangy_keys_rejects_a_corrupted_retired_exchange_key() {
        let mut keys = valid_tang_keys_json();
        let mut retired = valid_key_generation_json();
        retired["exc"]["d"] = serde_json::Value::String(base64ct::Base64UrlUnpadded::encode_string(&[0u8; 66]));
        keys["retired"] = serde_json::json!([retired]);
        let result = std::panic::catch_unwind(|| check_tangy_keys(&keys.to_string()));
        assert!(matches!(result, Ok(Err(_)) | Err(_)));
    }

    #[test]
    fn test_check_tangy_keys_accepts_correctly_ordered_retired_generations() {
        let now = chrono::Utc::now();
        let mut keys = valid_tang_keys_json();
        keys["retired"] = serde_json::json!([
            valid_key_generation_json_at(now - chrono::Duration::hours(1)),
            valid_key_generation_json_at(now - chrono::Duration::hours(2)),
        ]);
        assert!(check_tangy_keys(&keys.to_string()).is_ok());
    }

    #[test]
    fn test_check_tangy_keys_rejects_retired_generations_out_of_order() {
        let now = chrono::Utc::now();
        let mut keys = valid_tang_keys_json();
        // retired[1] is newer than retired[0], violating the
        // newest-first invariant prune's default/--keep removal relies
        // on.
        keys["retired"] = serde_json::json!([
            valid_key_generation_json_at(now - chrono::Duration::hours(2)),
            valid_key_generation_json_at(now - chrono::Duration::hours(1)),
        ]);
        assert!(check_tangy_keys(&keys.to_string()).is_err());
    }

    #[test]
    fn test_check_tangy_keys_accepts_a_current_older_than_a_retired_generation() {
        // A legitimate revert: restoring an older generation as current
        // and retiring whatever was current instead leaves `current`
        // older than some retired generations. That's not corruption,
        // so it must not be rejected.
        let now = chrono::Utc::now();
        let mut keys = valid_tang_keys_json();
        keys["current"] = valid_key_generation_json_at(now - chrono::Duration::days(1));
        keys["retired"] = serde_json::json!([valid_key_generation_json_at(now)]);
        assert!(check_tangy_keys(&keys.to_string()).is_ok());
    }

    #[test]
    fn test_build_tangy_advertises_only_the_current_generation() {
        let mut keys_json = valid_tang_keys_json();
        keys_json["retired"] = serde_json::json!([valid_key_generation_json()]);
        let keys = parse_tang_keys(&keys_json.to_string()).expect("a valid TangKeys");
        let adv = build_adv_tangy(&keys).expect("a valid key set must build");
        let adv_body: serde_json::Value =
            serde_json::from_str(&adv.adv(None).expect("adv must succeed")).expect("adv body must be JSON");
        let payload = base64ct::Base64Url::decode_vec(adv_body["payload"].as_str().expect("adv body has a payload"))
            .expect("adv payload must be valid base64url");
        let payload: serde_json::Value = serde_json::from_slice(&payload).expect("adv payload must be JSON");
        let advertised_keys = payload["keys"].as_array().expect("adv payload has a keys array");
        assert_eq!(advertised_keys.len(), 2, "only the current generation's 2 keys should be advertised");
    }

    #[test]
    fn test_find_generation_locates_current_and_retired_by_thumbprint_but_not_an_unknown_one() {
        let mut keys_json = valid_tang_keys_json();
        keys_json["retired"] = serde_json::json!([valid_key_generation_json()]);
        let keys = parse_tang_keys(&keys_json.to_string()).expect("a valid TangKeys");

        let current_kid = keys.current.exc.thumbprint();
        let retired_kid = keys.retired[0].exc.thumbprint();

        assert!(find_generation(&keys, &current_kid).is_some());
        assert!(find_generation(&keys, &retired_kid).is_some());
        assert!(find_generation(&keys, "unknown-kid").is_none());
    }

    #[test]
    fn test_build_tangy_rec_can_still_resolve_a_retired_generation() {
        let mut keys_json = valid_tang_keys_json();
        let retired = valid_key_generation_json();
        let retired_thumbprint = {
            let exc: MyJwkEcKey = serde_json::from_value(retired["exc"].clone()).expect("exc must parse");
            exc.thumbprint()
        };
        keys_json["retired"] = serde_json::json!([retired]);
        let keys = parse_tang_keys(&keys_json.to_string()).expect("a valid TangKeys");
        let rec = build_rec_tangy(keys.generations()).expect("a valid key set must build");
        let dummy_request = format!(r#"{{"kty":"EC","crv":"P-521","x":"{GENERATOR_X}","y":"{GENERATOR_Y}"}}"#);
        assert!(rec.rec(&retired_thumbprint, &dummy_request).is_ok());
    }

    #[test]
    fn test_is_p521_coordinate_accepts_exact_length() {
        assert!(is_p521_coordinate(&b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN)));
    }

    #[test]
    fn test_is_p521_coordinate_rejects_short_and_long_values() {
        assert!(!is_p521_coordinate(&b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN - 1)));
        assert!(!is_p521_coordinate(&b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN + 1)));
    }

    #[test]
    fn test_is_p521_coordinate_rejects_non_base64() {
        assert!(!is_p521_coordinate("not valid base64url!"));
    }

    #[test]
    fn test_looks_like_ec_point_accepts_a_well_formed_point() {
        assert!(looks_like_ec_point(&valid_rec_body()));
    }

    #[test]
    fn test_looks_like_ec_point_rejects_malformed_json() {
        assert!(!looks_like_ec_point("not json"));
    }

    #[test]
    fn test_looks_like_ec_point_rejects_the_wrong_curve() {
        let coord = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN);
        let body = format!(r#"{{"kty":"EC","crv":"P-256","x":"{coord}","y":"{coord}"}}"#);
        assert!(!looks_like_ec_point(&body));
    }

    #[test]
    fn test_looks_like_ec_point_rejects_the_wrong_key_type() {
        let coord = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN);
        let body = format!(r#"{{"kty":"RSA","crv":"P-521","x":"{coord}","y":"{coord}"}}"#);
        assert!(!looks_like_ec_point(&body));
    }

    #[test]
    fn test_looks_like_ec_point_rejects_wrong_length_coordinates() {
        let short = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN - 1);
        let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{short}","y":"{short}"}}"#);
        assert!(!looks_like_ec_point(&body));
    }

    /// Guards against a recognized `tangy_lib::MyJwkEcKey` field (e.g.
    /// `alg`) carrying the wrong JSON type, which would otherwise panic
    /// once the body reaches `MyJwkEcKey`'s own deserialize.
    #[test]
    fn test_looks_like_ec_point_rejects_a_known_field_with_the_wrong_type() {
        let coord = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN);
        let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{coord}","y":"{coord}","alg":123}}"#);
        assert!(!looks_like_ec_point(&body));
    }
}
