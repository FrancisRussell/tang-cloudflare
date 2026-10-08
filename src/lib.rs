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

/// Wrangler var: comma-separated CIDR ranges (v4 and/or v6) allowed to
/// reach `/adv` and `/rec`. See wrangler.toml for the operational guidance
/// on keeping this tight.
const ALLOWED_CIDRS_VAR: &str = "ALLOWED_CIDRS";

/// Secret holding both Tang keys as one JSON object, `{"sig": {...JWK...},
/// "exc": {...JWK...}}`, so it's set with a single direct paste rather
/// than assembled by hand from two separate values.
const TANG_KEYS_SECRET: &str = "TANG_KEYS";

/// The request's `CF-Connecting-IP` header, if present.
fn get_client_ip(req: &Request) -> Option<String> {
    req.headers().get(header_names::CF_CONNECTING_IP.as_str()).ok().flatten()
}

/// Parses a comma-separated CIDR list from a wrangler var. An entry that
/// fails to parse is dropped rather than failing the whole request, so one
/// typo in `ALLOWED_CIDRS` doesn't take the Worker down. An empty result
/// still fails every request closed, since `ip_allowed` treats "no ranges"
/// as "nothing matches".
fn parse_cidr_list(raw: &str) -> Vec<IpNetwork> {
    raw.split(',').map(str::trim).filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect()
}

/// True if `req`'s `CF-Connecting-IP` falls within one of `allowed`. Fails
/// closed: a missing or unparseable header is treated as not allowed.
fn ip_allowed(req: &Request, allowed: &[IpNetwork]) -> bool {
    let Some(ip) = get_client_ip(req).and_then(|s| s.parse().ok()) else {
        return false;
    };
    allowed.iter().any(|net| net.contains(ip))
}

/// True if `req` is allowed to reach `/adv` or `/rec`, per `ALLOWED_CIDRS`.
fn authorized(req: &Request, env: &Env) -> bool {
    let Ok(allowed_cidrs) = env.var(ALLOWED_CIDRS_VAR) else { return false };
    let allowed = parse_cidr_list(&allowed_cidrs.to_string());
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

/// A `Headers` with a single `content-type` entry set to `value`.
fn content_type_headers(value: &str) -> Headers {
    let headers = Headers::new();
    headers.set("content-type", value).expect("static header name and value are valid");
    headers
}

/// Loads both Tang keys from the combined `TANG_KEYS` secret and builds a
/// `TangyLib` for this request. Key loading is just JSON parsing, not real
/// computation, so there's no benefit to caching it across
/// requests/isolates.
fn load_tangy(env: &Env) -> std::result::Result<TangyLib, StatusCode> {
    let raw = env.secret(TANG_KEYS_SECRET).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let sig = parsed.get("sig").ok_or(StatusCode::INTERNAL_SERVER_ERROR)?.to_string();
    let exc = parsed.get("exc").ok_or(StatusCode::INTERNAL_SERVER_ERROR)?.to_string();
    TangyLib::init(KeySource::Vector(&vec![sig.as_str(), exc.as_str()])).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Handles `GET /adv`.
async fn handle_adv(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if !authorized(&req, &ctx.env) {
        return error_response(StatusCode::FORBIDDEN);
    }
    let tangy = match load_tangy(&ctx.env) {
        Ok(t) => t,
        Err(status) => return error_response(status),
    };
    match tangy.adv(None) {
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
    if !authorized(&req, &ctx.env) {
        return error_response(StatusCode::FORBIDDEN);
    }
    let Some(kid) = ctx.param(KID_PARAM).cloned() else {
        return error_response(StatusCode::BAD_REQUEST);
    };
    let body = req.text().await?;
    if !looks_like_ec_point(&body) {
        return error_response(StatusCode::BAD_REQUEST);
    }
    let tangy = match load_tangy(&ctx.env) {
        Ok(t) => t,
        Err(status) => return error_response(status),
    };
    match tangy.rec(&kid, &body) {
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
