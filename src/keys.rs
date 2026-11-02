use std::result::Result;

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

/// True if `key`'s thumbprint is exactly `kid`. A key whose fields are
/// malformed enough that `thumbprint()` itself fails (shouldn't happen
/// for anything that's passed `TangKeys::validate`) simply never
/// matches, rather than needing its own error path at every call site.
fn thumbprint_matches(key: &MyJwkEcKey, kid: &str) -> bool { key.thumbprint().is_ok_and(|t| t == kid) }

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
    /// signing key loaded, but never its exchange key. `TangyLib::rec`
    /// has no active/rotated gate of its own, so a loaded exchange key is
    /// just as usable for recovery as an active one; co-signing has no
    /// need to expose it.
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
    /// cheaper than the validation `TangyLib::init` performs per key, so
    /// the live Worker checks this first and rejects an unknown `kid`
    /// without ever building a `TangyLib` for it.
    pub(crate) fn find_generation(&self, kid: &str) -> Option<&KeyGeneration> {
        self.generations().find(|generation| thumbprint_matches(&generation.exc, kid))
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
        if thumbprint_matches(&self.current.sig, thp) {
            return Some(CoSigner::None);
        }
        self.retired.iter().find(|generation| thumbprint_matches(&generation.sig, thp)).map(CoSigner::Retired)
    }

    /// Builds the `TangyLib` serving `/adv` and `/adv/<thp>`, for a
    /// `co_signer` resolved by `find_adv_co_signer`. The current
    /// generation is always `active`; `CoSigner::Retired` additionally
    /// loads that one generation's signing key alone as `rotated`, never
    /// its exchange key (see `KeyGeneration::sig_jwk_string`).
    /// `TangyLib` only ever advertises `active` keys, so a rotated
    /// generation never appears in `/adv`'s payload regardless of role
    /// (see "`/adv/<thp>` and key rotation" in the README) — the caller
    /// still has to pass the matching `thp` to `adv()` itself for that
    /// generation's signing key to actually co-sign.
    pub(crate) fn build_adv_tangy(&self, co_signer: CoSigner<'_>) -> Result<TangyLib, String> {
        let active = self.current.to_jwk_strings()?;
        let rotated = match co_signer {
            CoSigner::None => Vec::new(),
            CoSigner::Retired(retired) => vec![retired.sig_jwk_string()?],
        };
        let active: Vec<&str> = active.iter().map(String::as_str).collect();
        let rotated: Vec<&str> = rotated.iter().map(String::as_str).collect();
        TangyLib::init(KeySource::KeySets { active: &active, rotated: &rotated }).map_err(|e| e.to_string())
    }

    /// Builds a `TangyLib` from every generation at once, current and
    /// retired, all `active`: `validate` doesn't care about the
    /// active/rotated split, only that every key loads and checks out.
    /// Not used to serve `/adv` (see `build_adv_tangy`).
    fn build_all_generations_tangy(&self) -> Result<TangyLib, String> { build_tangy_from(self.generations()) }

    /// Validates a `TANG_KEYS` JSON more thoroughly than parsing it alone:
    /// checks `retired`'s order (see `check_retired_order`), then builds a
    /// `TangyLib` from every generation, which validates every key's exact
    /// field encoding and that its public point matches its private
    /// scalar, signing and exchange keys alike. Used by `check-key`; the
    /// Worker itself has no reason to run this on every request.
    pub fn validate(&self) -> Result<(), String> {
        self.check_retired_order()?;
        self.build_all_generations_tangy()?;
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

/// Builds a `TangyLib` from whole generations at once, every key of
/// each, all `active`. Shared by `KeyGeneration::build_rec_tangy` (one
/// generation, for the live Worker's `/rec`) and
/// `TangKeys::build_all_generations_tangy` (every generation, for
/// `validate`). `TangKeys::build_adv_tangy` uses `KeySource::KeySets`
/// directly instead, since it needs the active/rotated split.
fn build_tangy_from<'a>(generations: impl Iterator<Item = &'a KeyGeneration>) -> Result<TangyLib, String> {
    let mut jwks = Vec::new();
    for generation in generations {
        jwks.extend(generation.to_jwk_strings()?);
    }
    let jwk_refs: Vec<&str> = jwks.iter().map(String::as_str).collect();
    TangyLib::init(KeySource::Vector(&jwk_refs)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use base64ct::Encoding;

    use super::*;

    /// A P-521 field element's encoded length: 521 bits, rounded up to
    /// whole bytes.
    const P521_COORDINATE_BYTE_LEN: usize = 66;

    /// `key.thumbprint()`, for a key that's already known to be valid
    /// (every key these tests use is fresh off `valid_tang_keys_json`/
    /// `valid_key_generation_json`).
    fn thumbprint(key: &MyJwkEcKey) -> String { key.thumbprint().expect("a valid key must have a thumbprint") }

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
        for key in tangy_lib::create_new_key_set().expect("tangy-lib key generation must succeed") {
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

    /// A `/rec` request body: a public exchange key fresh off
    /// `create_new_key_set`, valid on its own terms but otherwise
    /// unrelated to any stored key — all `rec` needs from it is a
    /// genuine on-curve point to derive against.
    fn valid_rec_request() -> String {
        for key in tangy_lib::create_new_key_set().expect("tangy-lib key generation must succeed") {
            let parsed: MyJwkEcKey = serde_json::from_str(&key).expect("tangy-lib must produce valid JSON");
            if parsed.alg.as_deref() == Some(EXCHANGE_KEY_ALG) {
                return serde_json::to_string(&parsed.to_public_key()).expect("serialization must succeed");
            }
        }
        unreachable!("tangy-lib always produces an ECMR key alongside an ES512 one")
    }

    #[test]
    fn test_check_tangy_keys_accepts_a_genuinely_valid_key_set() {
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
        // exchange key) would accept this. `TangyLib::init` rejects it
        // cleanly for every loaded key, signing or exchange.
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
        // One byte shorter than a P-521 field element's exact encoded
        // length. `tangy_lib`'s JWK field decoder requires that exact
        // length, rather than accepting a short value and silently
        // reinterpreting it. The dropped byte's value doesn't matter,
        // only that the result is the wrong length.
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
        let current_sig_thp = thumbprint(&keys.current.sig);
        let adv = build_adv_tangy_for_test(&keys, Some(&current_sig_thp));
        let (advertised_keys, signature_count) =
            decode_adv(&adv.adv(Some(&current_sig_thp)).expect("adv must succeed"));
        assert_eq!(advertised_keys.len(), 2, "only the current generation's 2 keys should be advertised");
        assert_eq!(signature_count, 1, "the current signing key is already loaded; it shouldn't sign twice");
    }

    /// The core rotation-safety property `/adv/<thp>` relies on: a `thp`
    /// naming a retired generation's signing key makes that key co-sign
    /// the response (so a client that already trusts it can verify this
    /// one too), but neither of that generation's own keys is advertised
    /// — only the current generation's pair is. Advertising a second
    /// exchange key would leave a client creating a fresh binding with
    /// no way to tell which one is current.
    #[test]
    fn test_build_adv_tangy_with_a_retired_thp_co_signs_without_being_advertised() {
        let mut keys_json = valid_tang_keys_json();
        keys_json["retired"] = serde_json::json!([valid_key_generation_json()]);
        let keys: TangKeys = keys_json.to_string().parse().expect("a valid TangKeys");
        let retired_sig_thp = thumbprint(&keys.retired[0].sig);
        let current_sig_thp = thumbprint(&keys.current.sig);
        let current_exc_thp = thumbprint(&keys.current.exc);

        let adv = build_adv_tangy_for_test(&keys, Some(&retired_sig_thp));
        let (advertised_keys, signature_count) =
            decode_adv(&adv.adv(Some(&retired_sig_thp)).expect("adv must succeed"));

        assert_eq!(signature_count, 2, "both the current and the matched retired key should sign");
        assert_eq!(advertised_keys.len(), 2, "only the current generation's 2 keys should be advertised");
        let advertised_thps: Vec<String> = advertised_keys.iter().map(thumbprint).collect();
        assert!(advertised_thps.contains(&current_sig_thp));
        assert!(advertised_thps.contains(&current_exc_thp));
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

        let current_kid = thumbprint(&keys.current.exc);
        let retired_kid = thumbprint(&keys.retired[0].exc);

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
            thumbprint(&exc)
        };
        keys_json["retired"] = serde_json::json!([retired]);
        let keys: TangKeys = keys_json.to_string().parse().expect("a valid TangKeys");
        let rec = keys.build_all_generations_tangy().expect("a valid key set must build");
        assert!(rec.rec(&retired_thumbprint, &valid_rec_request()).is_ok());
    }

    #[test]
    fn test_build_tangy_rec_rejects_an_off_curve_request() {
        let keys: TangKeys = valid_tang_keys_json().to_string().parse().expect("a valid TangKeys");
        let current_kid = thumbprint(&keys.current.exc);
        let rec = keys.build_all_generations_tangy().expect("a valid key set must build");
        // Swapping x and y leaves well-formed, correct-length
        // coordinates that are (overwhelmingly likely to be) off the
        // curve.
        let mut request: serde_json::Value = valid_rec_request().parse().expect("valid_rec_request must be JSON");
        let (x, y) = (request["x"].clone(), request["y"].clone());
        request["x"] = y;
        request["y"] = x;
        assert!(rec.rec(&current_kid, &request.to_string()).is_err());
    }

    /// A genuinely on-curve point's `x`/`y` bytes, re-split at a different
    /// offset than the real 66/66 boundary, must still be rejected: the
    /// concatenated total is the same valid, on-curve 132 bytes, so a
    /// check done only on the concatenation (rather than on `x` and `y`
    /// individually) would wrongly accept this.
    #[test]
    fn test_build_tangy_rec_rejects_coordinates_resplit_at_the_wrong_offset() {
        let keys: TangKeys = valid_tang_keys_json().to_string().parse().expect("a valid TangKeys");
        let current_kid = thumbprint(&keys.current.exc);
        let rec = keys.build_all_generations_tangy().expect("a valid key set must build");

        let request: serde_json::Value = valid_rec_request().parse().expect("valid_rec_request must be JSON");
        let x = base64ct::Base64UrlUnpadded::decode_vec(request["x"].as_str().expect("x must be a string"))
            .expect("x must be valid base64url");
        let y = base64ct::Base64UrlUnpadded::decode_vec(request["y"].as_str().expect("y must be a string"))
            .expect("y must be valid base64url");
        let mut combined = x;
        combined.extend_from_slice(&y);
        assert_eq!(combined.len(), 2 * P521_COORDINATE_BYTE_LEN);

        let (short_x, long_y) = combined.split_at(P521_COORDINATE_BYTE_LEN - 1);
        let short_x = base64ct::Base64UrlUnpadded::encode_string(short_x);
        let long_y = base64ct::Base64UrlUnpadded::encode_string(long_y);
        let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{short_x}","y":"{long_y}"}}"#);
        assert!(rec.rec(&current_kid, &body).is_err());
    }

    #[test]
    fn test_build_tangy_rec_rejects_malformed_json() {
        let keys: TangKeys = valid_tang_keys_json().to_string().parse().expect("a valid TangKeys");
        let current_kid = thumbprint(&keys.current.exc);
        let rec = keys.build_all_generations_tangy().expect("a valid key set must build");
        assert!(rec.rec(&current_kid, "not json").is_err());
    }
}
