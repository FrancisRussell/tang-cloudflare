#![warn(clippy::pedantic)]
//
// Generates, rotates, and prunes the combined JSON the Worker's
// `TANG_KEYS` secret and the password-manager backup both expect. Run
// natively (not part of the Worker's wasm32 build).
//
// Usage:
//   cargo run --bin keygen -- generate > tang-keys.json
//   cargo run --bin keygen -- rotate tang-keys.json > rotated.json
//   cargo run --bin keygen -- prune tang-keys.json > pruned.json
// Paste the result into the password manager, then:
//   wrangler secret put TANG_KEYS < tang-keys.json
// Delete the local file once both copies exist.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tang_cloudflare::{parse_tang_keys, KeyGeneration, TangKeys, EXCHANGE_KEY_ALG, SIGNING_KEY_ALG};
use tangy_lib::MyJwkEcKey;

#[derive(Debug, Clone, Parser)]
#[command(about = "Generates, rotates, and prunes tang-cloudflare's TANG_KEYS")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    /// Generate a fresh key set, with no retired generations.
    Generate {
        /// Free-form remark on why this generation was created.
        #[arg(long)]
        note: Option<String>,
    },
    /// Retire the current generation and generate a new one.
    Rotate {
        /// Path to the existing `TANG_KEYS` JSON file.
        file: PathBuf,
        /// Free-form remark on why this rotation happened.
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove a retired generation. Defaults to the single oldest.
    Prune {
        /// Path to the existing `TANG_KEYS` JSON file.
        file: PathBuf,
        /// Keep only this many of the newest retired generations,
        /// removing the rest.
        #[arg(long, conflicts_with_all = ["older_than", "thumbprint"])]
        keep: Option<usize>,
        /// Remove every retired generation older than this, e.g. "1y" or
        /// "6months" (parsed by the `humantime` crate).
        #[arg(long, conflicts_with_all = ["keep", "thumbprint"])]
        older_than: Option<String>,
        /// Remove one specific retired generation by its exchange key's
        /// thumbprint.
        #[arg(long, conflicts_with_all = ["keep", "older_than"])]
        thumbprint: Option<String>,
    },
}

/// Generates a fresh signing/exchange key pair as a new `KeyGeneration`,
/// labelled by each key's own `alg` rather than trusting
/// `create_new_key_set`'s return order.
fn generate_key_generation(note: Option<&str>) -> Result<KeyGeneration, String> {
    let (mut sig, mut exc) = (None, None);
    for key in tangy_lib::create_new_key_set() {
        let parsed: MyJwkEcKey =
            serde_json::from_str(&key).map_err(|e| format!("tangy-lib produced an unparseable key: {e}"))?;
        match parsed.alg.as_deref() {
            Some(SIGNING_KEY_ALG) => sig = Some(parsed),
            Some(EXCHANGE_KEY_ALG) => exc = Some(parsed),
            other => return Err(format!("unexpected key algorithm: {other:?}")),
        }
    }
    let (Some(sig), Some(exc)) = (sig, exc) else {
        return Err("tangy-lib did not produce both a signing and an exchange key".to_string());
    };
    Ok(KeyGeneration { sig, exc, created_at: chrono::Utc::now(), note: note.map(String::from) })
}

/// Reads and parses an existing `TANG_KEYS` JSON file, as `rotate` and
/// `prune` both start from.
fn read_tang_keys(path: &PathBuf) -> Result<TangKeys, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    parse_tang_keys(&raw)
}

/// Prints each generation's exchange-key thumbprint to stderr: the only
/// identifier `prune --thumbprint` takes, and otherwise only discoverable
/// via a bound client's own pinned copy (e.g. `clevis luks list`'s `thp`).
fn print_thumbprints(keys: &TangKeys) {
    let describe = |label: &str, generation: &KeyGeneration| {
        let note = generation.note.as_deref().map_or_else(String::new, |note| format!(" ({note})"));
        eprintln!("{label}: thumbprint {}, created {}{note}", generation.exc.thumbprint(), generation.created_at);
    };
    describe("current", &keys.current);
    for generation in &keys.retired {
        describe("retired", generation);
    }
}

/// Prints `keys`' thumbprint summary to stderr, then the full JSON to
/// stdout, the common final step of every `keygen` command.
fn print_tang_keys(keys: &TangKeys) -> Result<(), String> {
    print_thumbprints(keys);
    let text = serde_json::to_string_pretty(keys).map_err(|e| format!("failed to serialize key set: {e}"))?;
    println!("{text}");
    Ok(())
}

/// Implements `Command::Generate`.
fn generate(note: Option<&str>) -> Result<(), String> {
    let current = generate_key_generation(note)?;
    print_tang_keys(&TangKeys { current, retired: Vec::new() })
}

/// Implements `Command::Rotate`: retires the existing current generation
/// and mints a new one.
fn rotate(file: &PathBuf, note: Option<&str>) -> Result<(), String> {
    let mut keys = read_tang_keys(file)?;
    let new_current = generate_key_generation(note)?;
    keys.retired.insert(0, keys.current);
    keys.current = new_current;
    print_tang_keys(&keys)
}

/// Which retired generations `prune` should remove. Built from
/// `Command::Prune`'s three `--keep`/`--older-than`/`--thumbprint`
/// flags, which clap already guarantees are mutually exclusive; turning
/// that into an enum up front means `prune` itself can't be called with
/// a nonsensical combination.
#[derive(Debug, Clone)]
enum PruneSelector {
    /// No selector given: remove just the single oldest retired
    /// generation.
    Oldest,
    /// `--keep`: keep only this many of the newest retired generations,
    /// removing the rest.
    Keep(usize),
    OlderThan(chrono::Duration),
    Thumbprint(String),
}

/// Converts `Command::Prune`'s selector flags into a single
/// `PruneSelector`, parsing `--older-than`'s duration along the way.
fn prune_selector(
    keep: Option<usize>, older_than: Option<&str>, thumbprint: Option<String>,
) -> Result<PruneSelector, String> {
    match (keep, older_than, thumbprint) {
        (None, None, Some(thumbprint)) => Ok(PruneSelector::Thumbprint(thumbprint)),
        (None, Some(older_than), None) => {
            let max_age = humantime::parse_duration(older_than).map_err(|e| format!("invalid --older-than: {e}"))?;
            let max_age = chrono::Duration::from_std(max_age).map_err(|e| format!("--older-than is too large: {e}"))?;
            Ok(PruneSelector::OlderThan(max_age))
        }
        (Some(keep), None, None) => Ok(PruneSelector::Keep(keep)),
        (None, None, None) => Ok(PruneSelector::Oldest),
        _ => unreachable!("clap's conflicts_with_all already rules out combining these"),
    }
}

/// Implements `Command::Prune`: removes the retired generation(s)
/// `selector` identifies from `file`'s `TangKeys`.
fn prune(file: &PathBuf, selector: PruneSelector) -> Result<(), String> {
    let mut keys = read_tang_keys(file)?;
    let before = keys.retired.len();
    let pruned = match selector {
        PruneSelector::Thumbprint(thumbprint) => {
            let index = keys
                .retired
                .iter()
                .position(|generation| generation.exc.thumbprint() == thumbprint)
                .ok_or_else(|| format!("no retired generation found with thumbprint {thumbprint:?}"))?;
            keys.retired.remove(index);
            1
        }
        PruneSelector::OlderThan(max_age) => {
            let cutoff = chrono::Utc::now() - max_age;
            keys.retired.retain(|generation| generation.created_at >= cutoff);
            before - keys.retired.len()
        }
        // retired is newest-first (see TangKeys's doc comment), so
        // truncating to `keep` elements keeps the newest and drops the
        // oldest. `keep >= before` is a legitimate no-op, not an error:
        // there's nothing wrong with asking to keep more than exists.
        PruneSelector::Keep(keep) => {
            keys.retired.truncate(keep.min(before));
            before - keys.retired.len()
        }
        PruneSelector::Oldest => {
            if keys.retired.is_empty() {
                return Err("no retired generations to prune".to_string());
            }
            keys.retired.truncate(before - 1);
            1
        }
    };
    eprintln!("pruned {pruned} retired generation(s)");
    print_tang_keys(&keys)
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Generate { note } => generate(note.as_deref()),
        Command::Rotate { file, note } => rotate(&file, note.as_deref()),
        Command::Prune { file, keep, older_than, thumbprint } => {
            prune_selector(keep, older_than.as_deref(), thumbprint).and_then(|selector| prune(&file, selector))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
