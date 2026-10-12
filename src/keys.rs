use std::result::Result;

use base64ct::Encoding;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tangy_lib::{KeySource, MyJwkEcKey, TangyLib};
use worker::Env;

/// Secret holding every Tang key generation as one JSON object (see
/// `TangKeys`), so it's set with a single direct paste rather than
/// assembled by hand from separate values.
const TANG_KEYS_SECRET: &str = "TANG_KEYS";

/// The JWA (RFC 7518) algorithm identifier tangy-lib gives the ES512
/// signing key, used to tell it apart from the exchange key in a freshly
/// generated key set.
pub const SIGNING_KEY_ALG: &str = "ES512";
/// The JWA (RFC 7518) algorithm identifier tangy-lib gives the ECMR
/// exchange key, used to tell it apart from the signing key in a freshly
/// generated key set.
pub const EXCHANGE_KEY_ALG: &str = "ECMR";

/// A genuinely on-curve P-521 point, in the same JWK coordinate encoding
/// as a request body, used below purely as a throwaway: which point
/// doesn't matter, only that it's valid. The curve's generator point,
/// read off `p521::ProjectivePoint::generator()` rather than transcribed
/// from a spec.
pub(crate) const GENERATOR_X: &str =
    "AMaFjga3BATpzZ4-y2YjlbRCnGSBOQU_tSH4KK9ga009uqFLXnfv51ko_h3BJ6L_qN4zSLPBhWpCm_l-fjHC5b1m";
pub(crate) const GENERATOR_Y: &str =
    "ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT-tB2E1PHCGonLCQIi-lHaf0WZQ";

/// A P-521 field element's encoded length: 521 bits, rounded up to whole
/// bytes.
pub(crate) const P521_COORDINATE_BYTE_LEN: usize = 66;

/// A `/rec` request body wrapping `GENERATOR_X`/`GENERATOR_Y`.
fn generator_point_json() -> String {
    format!(r#"{{"kty":"EC","crv":"P-521","x":"{GENERATOR_X}","y":"{GENERATOR_Y}"}}"#)
}

/// One generation of Tang keys, generated and retired as a unit since
/// `sig`+`exc` are always minted together in one `keygen`/`rotate` call.
#[derive(Clone, Deserialize, Serialize)]
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

impl KeyGeneration {
    /// Serializes `self`'s two keys back to the raw JWK JSON strings
    /// `TangyLib::init` takes.
    fn to_jwk_strings(&self) -> Result<[String; 2], String> {
        Ok([self.sig_jwk_string()?, serde_json::to_string(&self.exc).map_err(|e| format!("exchange key: {e}"))?])
    }

    /// Serializes just `self`'s signing key, for `build_adv_tangy`'s
    /// retired-generation co-signing case: it needs this generation's
    /// signing key loaded, but never its exchange key.
    fn sig_jwk_string(&self) -> Result<String, String> {
        serde_json::to_string(&self.sig).map_err(|e| format!("signing key: {e}"))
    }

    /// Builds the `TangyLib` that serves `/rec` for this one generation:
    /// `init` signs a fresh advertisement per signing key given to it, so
    /// the live Worker only ever builds this for the single generation a
    /// request's `kid` actually matched (see `TangKeys::find_generation`),
    /// keeping that cost constant regardless of how many retired
    /// generations exist.
    pub(crate) fn build_rec_tangy(&self) -> Result<TangyLib, String> { build_tangy_from(std::iter::once(self)) }
}

/// The extra, retired generation (if any) whose signing key should
/// co-sign an `/adv`/`/adv/<thp>` response alongside the current
/// generation's own; see `TangKeys::find_adv_co_signer`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CoSigner<'a> {
    None,
    Retired(&'a KeyGeneration),
}

/// The `TANG_KEYS` secret's JSON shape: exactly one advertised generation
/// (`current`), plus however many retired generations are kept only so an
/// already-bound disk can keep completing `/rec` after a rotation.
/// `retired` is newest-first, so pruning the oldest is a pop from the
/// back.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TangKeys {
    pub current: KeyGeneration,
    #[serde(default)]
    pub retired: Vec<KeyGeneration>,
}

/// Parses the `TANG_KEYS` secret's JSON.
impl std::str::FromStr for TangKeys {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(raw).map_err(|e| format!("not valid JSON: {e}"))
    }
}

impl TangKeys {
    /// Every generation, current first: the full set `/rec` must serve.
    pub fn generations(&self) -> impl Iterator<Item = &KeyGeneration> {
        std::iter::once(&self.current).chain(self.retired.iter())
    }

    /// Finds the generation whose exchange key's thumbprint is `kid`, the
    /// only identifier `/rec` is ever asked for. A thumbprint is just a
    /// SHA-256 hash (see `tangy_lib`'s `MyJwkEcKey::thumbprint`), far
    /// cheaper than the real ECDSA signature `TangyLib::init` performs per
    /// signing key, so the live Worker checks this first and rejects an
    /// unknown `kid` without ever building a `TangyLib` for it.
    pub(crate) fn find_generation(&self, kid: &str) -> Option<&KeyGeneration> {
        self.generations().find(|generation| generation.exc.thumbprint() == kid)
    }

    /// Checks that `retired` is strictly newest-first, the invariant this
    /// type documents and `prune`'s default/`--keep` removal relies on to
    /// drop the right end of the list. Doesn't compare `current` against
    /// `retired`: reverting to an older generation (restoring it as
    /// current and retiring whatever was current instead) can legitimately
    /// leave `current` older than some retired generations, so that's not
    /// itself a sign of corruption.
    fn check_retired_order(&self) -> Result<(), String> {
        for (index, (newer, older)) in self.retired.iter().zip(self.retired.iter().skip(1)).enumerate() {
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

    /// Resolves `thp` to the extra, retired signing key (if any) that
    /// should co-sign an `/adv`/`/adv/<thp>` response alongside the
    /// current generation's own (see `build_adv_tangy`).
    ///
    /// Returns `None` if `thp` is given but matches no known signing
    /// key at all, current or retired: the caller's cue to 404, a
    /// normal client-supplied mismatch rather than a fault on this end.
    pub(crate) fn find_adv_co_signer(&self, thp: Option<&str>) -> Option<CoSigner<'_>> {
        let Some(thp) = thp else { return Some(CoSigner::None) };
        if thp == self.current.sig.thumbprint() {
            return Some(CoSigner::None);
        }
        self.retired.iter().find(|generation| generation.sig.thumbprint() == thp).map(CoSigner::Retired)
    }

    /// Builds the `TangyLib` serving `/adv` and `/adv/<thp>`, for a
    /// `co_signer` resolved by `find_adv_co_signer`. Always loads the
    /// current generation's signing and exchange key; `CoSigner::Retired`
    /// adds that generation's signing key alone, never its exchange key,
    /// so the advertised exchange key is always the current generation's
    /// (see "`/adv/<thp>` and key rotation" in the README).
    /// `TangyLib::init`'s precomputed advertisement signs with every
    /// signing key loaded, so this lets a client that already trusts
    /// the co-signer's key verify the response too.
    pub(crate) fn build_adv_tangy(&self, co_signer: CoSigner<'_>) -> Result<TangyLib, String> {
        let mut jwks = Vec::from(self.current.to_jwk_strings()?);
        if let CoSigner::Retired(retired) = co_signer {
            jwks.push(retired.sig_jwk_string()?);
        }
        build_tangy_from_jwks(&jwks)
    }

    /// Builds a `TangyLib` from every generation at once, current and
    /// retired. Used by `validate` to check them all against one shared
    /// instance; not used to serve `/adv` (see `build_adv_tangy`).
    fn build_all_generations_tangy(&self) -> Result<TangyLib, String> { build_tangy_from(self.generations()) }

    /// Validates a `TANG_KEYS` JSON more thoroughly than parsing it alone.
    /// Checks `retired`'s order (see `check_retired_order`), every key's
    /// public point against its own private scalar (see
    /// `check_key_point_matches_scalar`), then every generation's exchange
    /// key: parsing and `TangyLib::init` only ever exercise a signing
    /// key's private scalar (via the precomputed advertisement); an
    /// exchange key's private scalar is never converted until an actual
    /// `/rec` request names it by its own `kid`, so this exercises that
    /// path too, for every generation, with a throwaway on-curve point
    /// standing in for the client's half of the exchange. Used by
    /// `check-key`; the Worker itself has no reason to run any of these
    /// checks on every request.
    pub fn validate(&self) -> Result<(), String> {
        self.check_retired_order()?;
        for generation in self.generations() {
            check_key_point_matches_scalar(&generation.sig)
                .map_err(|e| format!("signing key rejected (created {}): {e}", generation.created_at))?;
            check_key_point_matches_scalar(&generation.exc)
                .map_err(|e| format!("exchange key rejected (created {}): {e}", generation.created_at))?;
        }
        let rec = self.build_all_generations_tangy()?;
        let dummy_request = generator_point_json();
        for generation in self.generations() {
            rec.rec(&generation.exc.thumbprint(), &dummy_request)
                .map(|_| ())
                .map_err(|e| format!("exchange key rejected (created {}): {e}", generation.created_at))?;
        }
        Ok(())
    }

    /// Parses every Tang key generation from the `TANG_KEYS` secret for
    /// this request. Key loading is just JSON parsing, not real
    /// computation, so there's no benefit to caching it across
    /// requests/isolates. Discards the specific parse error, rather than
    /// exposing key-handling details to the client.
    pub(crate) fn load_from_env(env: &Env) -> Result<TangKeys, StatusCode> {
        let raw = env.secret(TANG_KEYS_SECRET).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.to_string();
        raw.parse().map_err(|_: String| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Builds a `TangyLib` from whole generations at once: every key of
/// each, in pairs. Shared by `KeyGeneration::build_rec_tangy` (one
/// generation, for the live Worker's `/rec`) and
/// `TangKeys::build_all_generations_tangy` (every generation, for
/// `validate`). `TangKeys::build_adv_tangy` builds its own JWK list
/// directly instead, since it sometimes needs a generation's signing key
/// without its paired exchange key.
fn build_tangy_from<'a>(generations: impl Iterator<Item = &'a KeyGeneration>) -> Result<TangyLib, String> {
    let mut jwks = Vec::new();
    for generation in generations {
        jwks.extend(generation.to_jwk_strings()?);
    }
    build_tangy_from_jwks(&jwks)
}

/// Builds a `TangyLib` from raw JWK JSON strings, exactly as
/// `TangyLib::init` takes them: every key given is both advertised and
/// usable for its role (signing or key exchange) unconditionally, so
/// which keys end up in `jwks` is entirely the caller's decision.
/// Building a `TangyLib` performs a real signature per signing key
/// given, via `TangyLib::init`'s own precomputed advertisement.
fn build_tangy_from_jwks(jwks: &[String]) -> Result<TangyLib, String> {
    let jwk_refs: Vec<&str> = jwks.iter().map(String::as_str).collect();
    TangyLib::init(KeySource::Vector(&jwk_refs)).map_err(|e| e.to_string())
}

/// Decodes `x`/`y` as base64url and checks the resulting point is
/// actually on the P-521 curve, returning it if so. Shared by
/// `check_key_point_matches_scalar` (checking a stored key's own point)
/// and `looks_like_ec_point` (checking a client's submitted point, where
/// a wrong-but-right-shaped curve point would otherwise reach tangy-lib's
/// own unwrap rather than fail cleanly).
///
/// Checks `x` and `y` each decode to exactly `P521_COORDINATE_BYTE_LEN`
/// bytes, not just that the concatenated total is right: tangy-lib decodes
/// `x` and `y` independently into fixed-size buffers, so two coordinates
/// of the wrong individual lengths that happen to sum to a valid total
/// (e.g. a correctly-split point's bytes re-split at a different offset)
/// would pass an on-curve check done on the concatenation alone, yet still
/// reach tangy-lib's own unwrap and panic.
pub(crate) fn decode_ec_point(x: &str, y: &str) -> Option<p521::PublicKey> {
    let x = base64ct::Base64UrlUnpadded::decode_vec(x).ok()?;
    let y = base64ct::Base64UrlUnpadded::decode_vec(y).ok()?;
    if x.len() != P521_COORDINATE_BYTE_LEN || y.len() != P521_COORDINATE_BYTE_LEN {
        return None;
    }
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p521::PublicKey::from_sec1_bytes(&sec1).ok()
}

/// Checks that `key`'s public point (`x`, `y`) is actually on the P-521
/// curve and is the point its own private scalar `d` derives (i.e.
/// `(x, y) == d * G`). A wrong or off-curve `(x, y)` would otherwise pass
/// every other check in this file: it would be echoed verbatim into
/// `/adv`'s payload, and, more seriously, `TangyLib::init` and `rec` both
/// decode a stored key via `to_secret_key()`, which cross-checks the
/// derived public key against the JWK's own `(x, y)` and panics via
/// `.unwrap()` on a mismatch. Catching that here, with an exact-length
/// decode of `d` free of the padding ambiguity `tangy-lib`'s own decode
/// has, is what lets `TangKeys::validate` run without `catch_unwind`.
fn check_key_point_matches_scalar(key: &MyJwkEcKey) -> Result<(), String> {
    let claimed = decode_ec_point(&key.x, &key.y)
        .ok_or_else(|| "public point is not a valid, on-curve P-521 point".to_string())?;

    let d = key.d.as_deref().ok_or("missing private scalar \"d\"")?;
    let d = base64ct::Base64UrlUnpadded::decode_vec(d).map_err(|e| format!("d: {e}"))?;
    // p521::SecretKey::from_slice accepts a shorter-than-field-size slice by
    // left-zero-padding it, but tangy-lib's own decode of the same JWK field
    // (elliptic_curve::jwk's fixed-size, right-zero-padding decode) would
    // derive a different scalar from the same short bytes. Requiring the
    // exact field length up front avoids that divergence rather than
    // validating a scalar tangy-lib would actually interpret differently.
    if d.len() != P521_COORDINATE_BYTE_LEN {
        return Err("private scalar \"d\" is not a valid P-521 scalar's exact encoded length".to_string());
    }
    let secret = p521::SecretKey::from_slice(&d).map_err(|_| "private scalar \"d\" is invalid".to_string())?;

    if secret.public_key() != claimed {
        return Err("public point does not match the private scalar".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tang_keys_rejects_malformed_json() {
        assert!("not json".parse::<TangKeys>().is_err());
    }

    #[test]
    fn test_parse_tang_keys_rejects_a_missing_current_generation() {
        assert!("{}".parse::<TangKeys>().is_err());
    }

    #[test]
    fn test_parse_tang_keys_rejects_a_generation_missing_sig_exc_or_created_at() {
        assert!(r#"{"current":{"exc":{},"created_at":"2024-01-01T00:00:00Z"}}"#.parse::<TangKeys>().is_err());
        assert!(r#"{"current":{"sig":{},"created_at":"2024-01-01T00:00:00Z"}}"#.parse::<TangKeys>().is_err());
        assert!(r#"{"current":{"sig":{},"exc":{}}}"#.parse::<TangKeys>().is_err());
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
    fn valid_key_generation_json() -> serde_json::Value { valid_key_generation_json_at(chrono::Utc::now()) }

    /// A genuinely valid `TANG_KEYS` JSON with one current generation and
    /// no retired ones.
    fn valid_tang_keys_json() -> serde_json::Value {
        serde_json::json!({ "current": valid_key_generation_json(), "retired": [] })
    }

    /// Parses and validates `raw`, as `check-key` does in one step.
    fn parse_and_validate(raw: &str) -> Result<(), String> { raw.parse::<TangKeys>().and_then(|keys| keys.validate()) }

    #[test]
    fn test_check_tangy_keys_accepts_a_genuinely_valid_key_set() {
        // Also the test that GENERATOR_X/GENERATOR_Y are themselves valid:
        // if they weren't, rec()'s own conversion of the dummy request
        // body would panic before ever reaching the exchange key's check.
        assert!(parse_and_validate(&valid_tang_keys_json().to_string()).is_ok());
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
        assert!(parse_and_validate(&keys.to_string()).is_err());
    }

    #[test]
    fn test_check_tangy_keys_rejects_a_point_that_does_not_match_its_scalar() {
        let mut keys = valid_tang_keys_json();
        // Another genuinely valid key's point: on the curve, but not
        // the point this key's own `d` actually derives.
        let other = valid_key_generation_json();
        keys["current"]["exc"]["x"] = other["exc"]["x"].clone();
        keys["current"]["exc"]["y"] = other["exc"]["y"].clone();
        assert!(parse_and_validate(&keys.to_string()).is_err());
    }

    #[test]
    fn test_check_tangy_keys_rejects_a_corrupted_current_exchange_key() {
        let mut keys = valid_tang_keys_json();
        // A zero scalar: the right length, but out of a private key's
        // valid range, so parsing alone (which never exercises the
        // exchange key) would accept this. check_key_point_matches_scalar
        // rejects it cleanly, via p521::SecretKey::from_slice's own
        // validation, well before tangy-lib ever sees it.
        keys["current"]["exc"]["d"] =
            serde_json::Value::String(base64ct::Base64UrlUnpadded::encode_string(&[0u8; P521_COORDINATE_BYTE_LEN]));
        assert!(keys.to_string().parse::<TangKeys>().is_ok());
        assert!(parse_and_validate(&keys.to_string()).is_err());
    }

    #[test]
    fn test_check_tangy_keys_rejects_a_corrupted_retired_exchange_key() {
        let mut keys = valid_tang_keys_json();
        let mut retired = valid_key_generation_json();
        retired["exc"]["d"] =
            serde_json::Value::String(base64ct::Base64UrlUnpadded::encode_string(&[0u8; P521_COORDINATE_BYTE_LEN]));
        keys["retired"] = serde_json::json!([retired]);
        assert!(parse_and_validate(&keys.to_string()).is_err());
    }

    #[test]
    fn test_check_tangy_keys_rejects_a_short_exchange_key_scalar() {
        let mut keys = valid_tang_keys_json();
        // Shorter than P521_COORDINATE_BYTE_LEN: p521::SecretKey::from_slice
        // would silently left-zero-pad this back to some value, but
        // tangy-lib's own decode of the same field would derive a
        // different scalar from it, so this must be rejected outright
        // rather than validated against the wrong interpretation. The
        // dropped byte's value doesn't matter, only that the result is the
        // wrong length.
        let d =
            base64ct::Base64UrlUnpadded::decode_vec(keys["current"]["exc"]["d"].as_str().expect("d must be a string"))
                .expect("d must be valid base64url");
        keys["current"]["exc"]["d"] = serde_json::Value::String(base64ct::Base64UrlUnpadded::encode_string(&d[1..]));
        assert!(parse_and_validate(&keys.to_string()).is_err());
    }

    #[test]
    fn test_check_tangy_keys_accepts_correctly_ordered_retired_generations() {
        let now = chrono::Utc::now();
        let mut keys = valid_tang_keys_json();
        keys["retired"] = serde_json::json!([
            valid_key_generation_json_at(now - chrono::Duration::hours(1)),
            valid_key_generation_json_at(now - chrono::Duration::hours(2)),
        ]);
        assert!(parse_and_validate(&keys.to_string()).is_ok());
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
        assert!(parse_and_validate(&keys.to_string()).is_err());
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
        assert!(parse_and_validate(&keys.to_string()).is_ok());
    }

    /// Decodes an `adv()` response body into its payload's advertised
    /// keys and how many signatures are attached, so these tests can
    /// assert on both without repeating the JOSE-unwrapping each time.
    fn decode_adv(adv_body: &str) -> (Vec<MyJwkEcKey>, usize) {
        #[derive(serde::Deserialize)]
        struct Payload {
            keys: Vec<MyJwkEcKey>,
        }
        let adv_body: serde_json::Value = serde_json::from_str(adv_body).expect("adv body must be JSON");
        let payload = base64ct::Base64Url::decode_vec(adv_body["payload"].as_str().expect("adv body has a payload"))
            .expect("adv payload must be valid base64url");
        let payload: Payload = serde_json::from_slice(&payload).expect("adv payload must be JSON");
        let signature_count = match adv_body["signatures"].as_array() {
            Some(signatures) => signatures.len(),
            // A single signer serializes to one top-level `signature`
            // field instead of a `signatures` array; see tangy-lib's own
            // `adv_internal`.
            None => 1,
        };
        (payload.keys, signature_count)
    }

    /// Resolves `thp` and builds the resulting `TangyLib`, as
    /// `handlers::handle_adv` does, panicking instead of 404ing/500ing
    /// on a mismatch or build failure.
    fn build_adv_tangy_for_test(keys: &TangKeys, thp: Option<&str>) -> TangyLib {
        let co_signer = keys.find_adv_co_signer(thp).expect("thp must match a known signing key");
        keys.build_adv_tangy(co_signer).expect("a valid key set must build")
    }

    #[test]
    fn test_build_adv_tangy_with_no_thp_advertises_only_the_current_generation() {
        let mut keys_json = valid_tang_keys_json();
        keys_json["retired"] = serde_json::json!([valid_key_generation_json()]);
        let keys: TangKeys = keys_json.to_string().parse().expect("a valid TangKeys");
        let adv = build_adv_tangy_for_test(&keys, None);
        let (advertised_keys, signature_count) = decode_adv(&adv.adv(None).expect("adv must succeed"));
        assert_eq!(advertised_keys.len(), 2, "only the current generation's 2 keys should be advertised");
        assert_eq!(signature_count, 1, "only the current generation should sign");
    }

    #[test]
    fn test_build_adv_tangy_with_the_current_signing_thumbprint_is_the_same_as_no_thp() {
        let keys: TangKeys = valid_tang_keys_json().to_string().parse().expect("a valid TangKeys");
        let current_sig_thp = keys.current.sig.thumbprint();
        let adv = build_adv_tangy_for_test(&keys, Some(&current_sig_thp));
        let (advertised_keys, signature_count) = decode_adv(&adv.adv(None).expect("adv must succeed"));
        assert_eq!(advertised_keys.len(), 2, "only the current generation's 2 keys should be advertised");
        assert_eq!(signature_count, 1, "the current signing key is already loaded; it shouldn't sign twice");
    }

    /// The core rotation-safety property `/adv/<thp>` relies on: a `thp`
    /// naming a retired generation's signing key makes that key co-sign
    /// the response (so a client that already trusts it can verify this
    /// one too), but never adds that generation's exchange key to the
    /// payload. Advertising a second exchange key would leave a client
    /// creating a fresh binding with no way to tell which one is
    /// current.
    #[test]
    fn test_build_adv_tangy_with_a_retired_thp_co_signs_but_only_advertises_the_current_exchange_key() {
        let mut keys_json = valid_tang_keys_json();
        keys_json["retired"] = serde_json::json!([valid_key_generation_json()]);
        let keys: TangKeys = keys_json.to_string().parse().expect("a valid TangKeys");
        let retired_sig_thp = keys.retired[0].sig.thumbprint();
        let current_exc_thp = keys.current.exc.thumbprint();

        let adv = build_adv_tangy_for_test(&keys, Some(&retired_sig_thp));
        let (advertised_keys, signature_count) = decode_adv(&adv.adv(None).expect("adv must succeed"));

        assert_eq!(signature_count, 2, "both the current and the matched retired key should sign");
        let exchange_keys: Vec<_> =
            advertised_keys.iter().filter(|k| k.alg.as_deref() == Some(EXCHANGE_KEY_ALG)).collect();
        assert_eq!(exchange_keys.len(), 1, "only one exchange key should ever be advertised");
        assert_eq!(exchange_keys[0].thumbprint(), current_exc_thp, "the one advertised exchange key must be current's");
    }

    #[test]
    fn test_build_adv_tangy_with_an_unknown_thp_matches_nothing() {
        let keys: TangKeys = valid_tang_keys_json().to_string().parse().expect("a valid TangKeys");
        assert!(keys.find_adv_co_signer(Some("not-a-real-thumbprint")).is_none());
    }

    #[test]
    fn test_find_generation_locates_current_and_retired_by_thumbprint_but_not_an_unknown_one() {
        let mut keys_json = valid_tang_keys_json();
        keys_json["retired"] = serde_json::json!([valid_key_generation_json()]);
        let keys: TangKeys = keys_json.to_string().parse().expect("a valid TangKeys");

        let current_kid = keys.current.exc.thumbprint();
        let retired_kid = keys.retired[0].exc.thumbprint();

        assert!(keys.find_generation(&current_kid).is_some());
        assert!(keys.find_generation(&retired_kid).is_some());
        assert!(keys.find_generation("unknown-kid").is_none());
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
        let keys: TangKeys = keys_json.to_string().parse().expect("a valid TangKeys");
        let rec = keys.build_all_generations_tangy().expect("a valid key set must build");
        let dummy_request = generator_point_json();
        assert!(rec.rec(&retired_thumbprint, &dummy_request).is_ok());
    }
}
