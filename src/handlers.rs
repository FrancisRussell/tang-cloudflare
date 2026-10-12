use futures_util::StreamExt;
use http::StatusCode;
use tangy_lib::MyJwkEcKey;
use worker::*;

use crate::access_control::authorized;
use crate::keys::{decode_ec_point, TangKeys};

mod content_types {
    /// `/adv`'s content type in the Tang wire protocol, matching the
    /// reference `tangy` server.
    pub const JOSE_JSON: &str = "application/jose+json";
    /// `/rec`'s content type in the Tang wire protocol, matching the
    /// reference `tangy` server.
    pub const JWK_JSON: &str = "application/jwk+json";
}

/// The route pattern's named parameter for the recovery key ID, and the key
/// `ctx.param` looks it up by, kept as one constant so the two can't drift
/// apart silently.
pub(crate) const KID_PARAM: &str = "kid";

/// Same as `KID_PARAM`, for `/adv/:thp`'s optional requested signing key.
pub(crate) const THP_PARAM: &str = "thp";

/// Real `/rec` bodies are JWK EC points a few hundred bytes long; anything
/// past this is already implausible rather than a request this project
/// needs to accept. Also closes a gap `looks_like_ec_point` alone doesn't:
/// `MyJwkEcKey` has no `deny_unknown_fields`, so a body padded with a huge
/// unrecognized field would otherwise still parse and pass it.
const MAX_BODY_BYTES: usize = 4096;

/// `Response::error` using `status`'s own canonical reason phrase (e.g.
/// "Forbidden" for 403) as the message, for error paths that carry no extra
/// diagnostic detail beyond the status itself.
fn error_response(status: StatusCode) -> Result<Response> {
    Response::error(status.canonical_reason().expect("standard status code has a canonical reason"), status.as_u16())
}

/// A `Headers` with a single `content-type` entry set to `value`.
fn content_type_headers(value: &str) -> Headers {
    let headers = Headers::new();
    headers.set(http::header::CONTENT_TYPE.as_str(), value).expect("static header name and value are valid");
    headers
}

/// Handles `GET /adv`, `/adv/`, and `/adv/:thp`. See "`/adv/<thp>` and key
/// rotation" in the README: a requested `thp` can make an extra, retired
/// signing key co-sign the response, but the advertised exchange key is
/// always the current generation's. A `thp` matching no known signing key
/// at all is a 404.
pub(crate) async fn handle_adv(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if !authorized(&req, &ctx.env).await {
        return error_response(StatusCode::FORBIDDEN);
    }
    let keys = match TangKeys::load_from_env(&ctx.env) {
        Ok(k) => k,
        Err(status) => return error_response(status),
    };
    let thp = ctx.param(THP_PARAM).map(String::as_str);
    let Some(co_signer) = keys.find_adv_co_signer(thp) else { return error_response(StatusCode::NOT_FOUND) };
    let Ok(adv) = keys.build_adv_tangy(co_signer) else { return error_response(StatusCode::INTERNAL_SERVER_ERROR) };
    match adv.adv(None) {
        Ok(body) => Ok(Response::ok(body)?.with_headers(content_type_headers(content_types::JOSE_JSON))),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// `req`'s body, or `None` if it exceeds `MAX_BODY_BYTES`. A declared
/// `Content-Length` over the limit is refused without reading anything;
/// the read itself is also capped, so a chunked or under-declared body
/// can't be buffered past the limit either.
async fn read_capped_body(req: &mut Request) -> Result<Option<Vec<u8>>> {
    let declared_length =
        req.headers().get(http::header::CONTENT_LENGTH.as_str())?.and_then(|v| v.parse::<usize>().ok());
    if declared_length.is_some_and(|length| length > MAX_BODY_BYTES) {
        return Ok(None);
    }

    let Ok(mut stream) = req.stream() else { return Ok(Some(Vec::new())) };
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// True if `body` parses as the EC public JWK `tangy_lib::TangyLib::rec`
/// expects. `tangy-lib` parses its input with bare `.unwrap()`s rather than
/// returning an error, so anything malformed reaching it panics, and this
/// project's `panic = "abort"` profile turns that into a whole-instance
/// reinit rather than just a failed request. Deserializing into tangy-lib's
/// own `MyJwkEcKey`, instead of a hand-rolled subset of its fields, catches
/// every shape mismatch it would itself reject, including an unrelated
/// field present with the wrong JSON type; `decode_ec_point` catches a
/// syntactically valid but off-curve point the same way, which otherwise
/// needs the curve arithmetic `tangy-lib` itself does to detect.
fn looks_like_ec_point(body: &[u8]) -> bool {
    let Ok(key) = serde_json::from_slice::<MyJwkEcKey>(body) else { return false };
    key.kty == "EC" && key.crv == "P-521" && decode_ec_point(&key.x, &key.y).is_some()
}

/// Handles `POST /rec/:kid`.
pub(crate) async fn handle_rec(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if !authorized(&req, &ctx.env).await {
        return error_response(StatusCode::FORBIDDEN);
    }
    let Some(kid) = ctx.param(KID_PARAM).cloned() else {
        return error_response(StatusCode::BAD_REQUEST);
    };
    let Some(body) = read_capped_body(&mut req).await? else {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE);
    };
    if !looks_like_ec_point(&body) {
        return error_response(StatusCode::BAD_REQUEST);
    }
    let body = String::from_utf8(body).expect("looks_like_ec_point already deserialized this as valid UTF-8 JSON");
    let keys = match TangKeys::load_from_env(&ctx.env) {
        Ok(k) => k,
        Err(status) => return error_response(status),
    };
    let Some(generation) = keys.find_generation(&kid) else { return error_response(StatusCode::NOT_FOUND) };
    let Ok(rec) = generation.build_rec_tangy() else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    match rec.rec(&kid, &body) {
        Ok(body) => Ok(Response::ok(body)?.with_headers(content_type_headers(content_types::JWK_JSON))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => error_response(StatusCode::NOT_FOUND),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use base64ct::Encoding;

    use super::*;
    use crate::keys::{GENERATOR_X, GENERATOR_Y, P521_COORDINATE_BYTE_LEN};

    /// A valid base64url-encoded coordinate of exactly `byte_len` bytes, for
    /// exercising coordinate-length rejection without a hardcoded magic
    /// string. All-zero, so also off-curve: not a stand-in for a genuinely
    /// valid point (see `valid_rec_body`, which uses the real generator
    /// point for that).
    fn b64_coordinate_of_len(byte_len: usize) -> String {
        base64ct::Base64UrlUnpadded::encode_string(&vec![0u8; byte_len])
    }

    fn valid_rec_body() -> String { format!(r#"{{"kty":"EC","crv":"P-521","x":"{GENERATOR_X}","y":"{GENERATOR_Y}"}}"#) }

    #[test]
    fn test_looks_like_ec_point_accepts_a_well_formed_point() {
        assert!(looks_like_ec_point(valid_rec_body().as_bytes()));
    }

    #[test]
    fn test_looks_like_ec_point_rejects_an_off_curve_point() {
        let coord = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN);
        let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{coord}","y":"{coord}"}}"#);
        assert!(!looks_like_ec_point(body.as_bytes()));
    }

    /// A genuinely on-curve point's `x`/`y` bytes, re-split at a different
    /// offset than the real 66/66 boundary, must still be rejected: the
    /// concatenated total is the same valid, on-curve 132 bytes, so a check
    /// done only on the concatenation (rather than on `x` and `y`
    /// individually) would wrongly accept this, and tangy-lib's own,
    /// independent per-field decode would then panic on it instead.
    #[test]
    fn test_looks_like_ec_point_rejects_coordinates_resplit_at_the_wrong_offset() {
        let x = base64ct::Base64UrlUnpadded::decode_vec(GENERATOR_X).expect("GENERATOR_X must be valid base64url");
        let y = base64ct::Base64UrlUnpadded::decode_vec(GENERATOR_Y).expect("GENERATOR_Y must be valid base64url");
        let mut combined = x;
        combined.extend_from_slice(&y);
        assert_eq!(combined.len(), 2 * P521_COORDINATE_BYTE_LEN);

        let (short_x, long_y) = combined.split_at(P521_COORDINATE_BYTE_LEN - 1);
        let short_x = base64ct::Base64UrlUnpadded::encode_string(short_x);
        let long_y = base64ct::Base64UrlUnpadded::encode_string(long_y);
        let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{short_x}","y":"{long_y}"}}"#);
        assert!(!looks_like_ec_point(body.as_bytes()));
    }

    #[test]
    fn test_looks_like_ec_point_rejects_malformed_json() {
        assert!(!looks_like_ec_point(b"not json"));
    }

    #[test]
    fn test_looks_like_ec_point_rejects_the_wrong_curve() {
        let coord = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN);
        let body = format!(r#"{{"kty":"EC","crv":"P-256","x":"{coord}","y":"{coord}"}}"#);
        assert!(!looks_like_ec_point(body.as_bytes()));
    }

    #[test]
    fn test_looks_like_ec_point_rejects_the_wrong_key_type() {
        let coord = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN);
        let body = format!(r#"{{"kty":"RSA","crv":"P-521","x":"{coord}","y":"{coord}"}}"#);
        assert!(!looks_like_ec_point(body.as_bytes()));
    }

    #[test]
    fn test_looks_like_ec_point_rejects_wrong_length_coordinates() {
        let short = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN - 1);
        let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{short}","y":"{short}"}}"#);
        assert!(!looks_like_ec_point(body.as_bytes()));
    }

    /// Guards against a recognized `tangy_lib::MyJwkEcKey` field (e.g.
    /// `alg`) carrying the wrong JSON type, which would otherwise panic
    /// once the body reaches `MyJwkEcKey`'s own deserialize.
    #[test]
    fn test_looks_like_ec_point_rejects_a_known_field_with_the_wrong_type() {
        let coord = b64_coordinate_of_len(P521_COORDINATE_BYTE_LEN);
        let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{coord}","y":"{coord}","alg":123}}"#);
        assert!(!looks_like_ec_point(body.as_bytes()));
    }
}
