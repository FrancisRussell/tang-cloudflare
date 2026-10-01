#![warn(clippy::pedantic)]
//
// Generates a fresh Tang key set and prints it as the combined JSON the
// Worker's `TANG_KEYS` secret and the password-manager backup both expect.
// Run natively (not part of the Worker's wasm32 build) -- once for initial
// setup, and again as a full replacement (not a merge) for key rotation.
//
// Usage:
//   cargo run --release --bin keygen > tang-keys.json
// Paste tang-keys.json into the password manager, then:
//   wrangler secret put TANG_KEYS < tang-keys.json
// Delete the local file once both copies exist.

use std::process::ExitCode;

use serde_json::Value;

fn main() -> ExitCode {
    let (mut sig, mut exc) = (None, None);
    for key in tangy_lib::create_new_key_set() {
        let Ok(parsed) = serde_json::from_str::<Value>(&key) else {
            eprintln!("tangy-lib produced an unparseable key");
            return ExitCode::FAILURE;
        };
        // Labelled by the key's own `alg` field rather than trusting
        // `create_new_key_set`'s return order, so a future reordering
        // there can't silently swap which key ends up under which name.
        match parsed.get("alg").and_then(Value::as_str) {
            Some("ES512") => sig = Some(parsed),
            Some("ECMR") => exc = Some(parsed),
            other => {
                eprintln!("unexpected key algorithm: {other:?}");
                return ExitCode::FAILURE;
            }
        }
    }

    let (Some(sig), Some(exc)) = (sig, exc) else {
        eprintln!("tangy-lib did not produce both a signing and an exchange key");
        return ExitCode::FAILURE;
    };

    match serde_json::to_string_pretty(&serde_json::json!({ "sig": sig, "exc": exc })) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to serialize key set: {e}");
            ExitCode::FAILURE
        }
    }
}
