#![warn(clippy::pedantic)]
//
// Validates a combined Tang key-set JSON (as `keygen` produces, and
// `TANG_KEYS` expects) by running it through the exact parsing and
// initialization the Worker itself uses, for both the signing and the
// exchange key, catching a corrupt or malformed key before it's ever
// uploaded.
//
// Usage:
//   cargo run --bin check-key < tang-keys.json

use std::io::Read;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        eprintln!("failed to read key JSON from stdin: {e}");
        return ExitCode::FAILURE;
    }
    match tang_cloudflare::check_tangy_keys(&raw) {
        Ok(()) => {
            println!("OK: key set parses and initializes correctly");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("invalid key set: {e}");
            ExitCode::FAILURE
        }
    }
}
