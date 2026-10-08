#![warn(clippy::pedantic)]
//
// Validates a combined Tang key-set JSON (as `keygen` produces, and
// `TANG_KEYS` expects) by running it through the exact parsing and
// initialization the Worker itself uses, for both the signing and the
// exchange key, catching a corrupt or malformed key before it's ever
// uploaded. A syntactically valid but off-curve point reaches tangy-lib's
// own unguarded `.unwrap()`s rather than a clean error, so this runs that
// call under `catch_unwind` to still report that case as an ordinary
// failure. Run without --release: catch_unwind needs unwinding, which
// this project's own [profile.release] disables for the deployed Worker.
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
    match std::panic::catch_unwind(|| tang_cloudflare::check_tangy_keys(&raw)) {
        Ok(Ok(())) => {
            println!("OK: key set parses and initializes correctly");
            ExitCode::SUCCESS
        }
        Ok(Err(e)) => {
            eprintln!("invalid key set: {e}");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("invalid key set: tangy-lib panicked initializing it (see the panic message above)");
            ExitCode::FAILURE
        }
    }
}
