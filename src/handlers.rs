use futures_util::StreamExt;
use http::StatusCode;
use worker::*;

use crate::access_control::authorized;
use crate::keys::{CoSigner, TangKeys};

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
/// needs to accept. `MyJwkEcKey` has no `deny_unknown_fields`, so a body
/// padded with a huge unrecognized field would otherwise still parse.
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

/// True for the `tangy_lib::Error` variants `handle_adv` and `handle_rec`
/// both map to 404: by the time either reaches this, its own `thp`/`kid`
/// lookup has already resolved against the same keys, so these shouldn't
/// be reachable; handled rather than assumed in case that ever changes.
fn is_tangy_not_found(e: &tangy_lib::Error) -> bool {
    matches!(e, tangy_lib::Error::KeyNotFound { .. } | tangy_lib::Error::ForbiddenOperation { .. })
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
    // `TangyLib::adv` only serves its cheap, precomputed cache for `None`;
    // `Some(_)` always signs fresh, even when `skid` names the current
    // signing key. `CoSigner::None` means no co-signer was actually
    // resolved (whether `thp` was absent or just matched the current
    // signing key), so passing `None` here gets the cache instead of an
    // unneeded extra signature.
    let skid = match co_signer {
        CoSigner::None => None,
        CoSigner::Retired(_) => thp,
    };
    match adv.adv(skid) {
        Ok(body) => Ok(Response::ok(body)?.with_headers(content_type_headers(content_types::JOSE_JSON))),
        Err(e) if is_tangy_not_found(&e) => error_response(StatusCode::NOT_FOUND),
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
    let Ok(body) = String::from_utf8(body) else { return error_response(StatusCode::BAD_REQUEST) };
    let keys = match TangKeys::load_from_env(&ctx.env) {
        Ok(k) => k,
        Err(status) => return error_response(status),
    };
    let Some(generation) = keys.find_generation(&kid) else { return error_response(StatusCode::NOT_FOUND) };
    let Ok(rec) = generation.build_rec_tangy() else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    // tangy-lib validates `body` itself (shape, on-curve point, algorithm/
    // key_ops) and returns a typed error rather than panicking, so there's
    // no reason for a pre-check here beyond `find_generation`'s own cheap
    // `kid` lookup above.
    match rec.rec(&kid, &body) {
        Ok(body) => Ok(Response::ok(body)?.with_headers(content_type_headers(content_types::JWK_JSON))),
        Err(e) if is_tangy_not_found(&e) => error_response(StatusCode::NOT_FOUND),
        Err(tangy_lib::Error::InvalidRequest { .. }) => error_response(StatusCode::BAD_REQUEST),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
