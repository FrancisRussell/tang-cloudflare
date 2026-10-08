#![warn(clippy::pedantic)]
//
// Validates a comma-separated CIDR list using the exact parser the Worker
// itself uses, catching a typo before it's ever set as ALLOWED_CIDRS_KV's
// value: the Worker's own parser silently drops an entry that fails to
// parse rather than failing the whole request, so a typo there wouldn't
// otherwise be noticed until the VPS can't unlock.
//
// Usage:
//   cargo run --release --bin check-allowlist -- '203.0.113.4/32'

use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(raw) = std::env::args().nth(1) else {
        eprintln!("usage: check-allowlist <cidr>[,<cidr>...]");
        return ExitCode::FAILURE;
    };
    match tang_cloudflare::check_cidr_list(&raw) {
        Ok(()) => {
            println!("OK: every entry parses");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("invalid CIDR list: {e}");
            ExitCode::FAILURE
        }
    }
}
