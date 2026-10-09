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
//   cargo run --bin keygen -- list tang-keys.json
// Paste the result into the password manager, then:
//   wrangler secret put TANG_KEYS < tang-keys.json
// Delete the local file once both copies exist.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tang_cloudflare::{parse_tang_keys, KeyGeneration, TangKeys, EXCHANGE_KEY_ALG, SIGNING_KEY_ALG};
use tangy_lib::MyJwkEcKey;

#[derive(Debug, Clone, Parser)]
#[command(about = "Generates, rotates, prunes, and lists tang-cloudflare's TANG_KEYS")]
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
    /// List every generation's thumbprint, creation time, and note.
    List {
        /// Path to the existing `TANG_KEYS` JSON file.
        file: PathBuf,
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

/// Reads and parses an existing `TANG_KEYS` JSON file, as every
/// command but `generate` starts from.
fn read_tang_keys(path: &PathBuf) -> Result<TangKeys, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    parse_tang_keys(&raw)
}

/// Formats `note` as " (note)" if present, or "" if not: the suffix
/// every printed line below appends.
fn note_suffix(note: Option<&str>) -> String {
    note.map_or_else(String::new, |note| format!(" ({note})"))
}

/// Formats one generation's identifying info: its exchange key's
/// thumbprint (the only identifier `prune --thumbprint` takes, and
/// otherwise only discoverable via a bound client's own pinned copy,
/// e.g. `clevis luks list`'s `thp`), creation time, and note if any.
fn describe_generation(label: &str, generation: &KeyGeneration) -> String {
    // created_at's Display impl includes however many subsecond digits
    // the system clock reported, down to nanoseconds; seconds is all a
    // human reading this needs.
    let created_at = generation.created_at.format("%Y-%m-%d %H:%M:%S UTC");
    format!(
        "{label}: thumbprint {}, created {created_at}{}",
        generation.exc.thumbprint(),
        note_suffix(generation.note.as_deref())
    )
}

/// Prints `keys` as pretty JSON to stdout, the common final step of
/// `generate`, `rotate`, and `prune`.
fn print_json(keys: &TangKeys) -> Result<(), String> {
    let text = serde_json::to_string_pretty(keys).map_err(|e| format!("failed to serialize key set: {e}"))?;
    println!("{text}");
    Ok(())
}

/// Implements `Command::Generate`.
fn generate(note: Option<&str>) -> Result<(), String> {
    let current = generate_key_generation(note)?;
    print_json(&TangKeys { current, retired: Vec::new() })
}

/// Pure core of `Command::Rotate`: retires `keys.current` and mints a
/// fresh one, leaving the rest of `retired` untouched and in order.
fn rotate_keys(keys: TangKeys, note: Option<&str>) -> Result<TangKeys, String> {
    let new_current = generate_key_generation(note)?;
    let mut retired = keys.retired;
    retired.insert(0, keys.current);
    Ok(TangKeys { current: new_current, retired })
}

/// Implements `Command::Rotate`: reads `file`, rotates it, and prints
/// the result.
fn rotate(file: &PathBuf, note: Option<&str>) -> Result<(), String> {
    let keys = read_tang_keys(file)?;
    print_json(&rotate_keys(keys, note)?)
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

/// Pure core of `Command::Prune`: removes the retired generation(s)
/// `selector` identifies, returning the result and the generations
/// removed.
fn prune_keys(mut keys: TangKeys, selector: PruneSelector) -> Result<(TangKeys, Vec<KeyGeneration>), String> {
    let removed = match selector {
        PruneSelector::Thumbprint(thumbprint) => {
            let index = keys
                .retired
                .iter()
                .position(|generation| generation.exc.thumbprint() == thumbprint)
                .ok_or_else(|| format!("no retired generation found with thumbprint {thumbprint:?}"))?;
            vec![keys.retired.remove(index)]
        }
        PruneSelector::OlderThan(max_age) => {
            let cutoff = chrono::Utc::now() - max_age;
            let (keep, removed) = keys.retired.into_iter().partition(|generation| generation.created_at >= cutoff);
            keys.retired = keep;
            removed
        }
        // retired is newest-first (see TangKeys's doc comment), so the
        // first `keep` elements are the newest, and splitting there
        // keeps them and returns the (older) rest as removed. `keep >=
        // len` is a legitimate no-op, not an error: there's nothing
        // wrong with asking to keep more than exists.
        PruneSelector::Keep(keep) => keys.retired.split_off(keep.min(keys.retired.len())),
        PruneSelector::Oldest => {
            if keys.retired.is_empty() {
                return Err("no retired generations to prune".to_string());
            }
            vec![keys.retired.remove(keys.retired.len() - 1)]
        }
    };
    Ok((keys, removed))
}

/// Implements `Command::Prune`: reads `file`, prunes it, and prints the
/// result. Reports which generations were removed on stderr, since
/// once `file` is overwritten that's the only place this is still
/// visible.
fn prune(file: &PathBuf, selector: PruneSelector) -> Result<(), String> {
    let keys = read_tang_keys(file)?;
    let (keys, removed) = prune_keys(keys, selector)?;
    eprintln!("pruned {} retired generation(s):", removed.len());
    for generation in &removed {
        eprintln!("{}", describe_generation("pruned", generation));
    }
    eprintln!();
    print_json(&keys)
}

/// Implements `Command::List`: prints every generation's identifying
/// info from `file`, without modifying it.
fn list(file: &PathBuf) -> Result<(), String> {
    let keys = read_tang_keys(file)?;
    println!("{}", describe_generation("current", &keys.current));
    for generation in &keys.retired {
        println!("{}", describe_generation("retired", generation));
    }
    Ok(())
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Generate { note } => generate(note.as_deref()),
        Command::Rotate { file, note } => rotate(&file, note.as_deref()),
        Command::Prune { file, keep, older_than, thumbprint } => {
            prune_selector(keep, older_than.as_deref(), thumbprint).and_then(|selector| prune(&file, selector))
        }
        Command::List { file } => list(&file),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A genuinely valid, freshly generated `KeyGeneration` stamped with
    /// an explicit `created_at`, so tests can control ordering.
    fn test_generation(created_at: chrono::DateTime<chrono::Utc>) -> KeyGeneration {
        let mut generation = generate_key_generation(None).expect("key generation must succeed");
        generation.created_at = created_at;
        generation
    }

    #[test]
    fn test_rotate_keys_retires_the_old_current_unchanged_and_mints_a_new_one() {
        let now = chrono::Utc::now();
        let old_current = test_generation(now);
        let old_current_thumbprint = old_current.exc.thumbprint();
        let keys = TangKeys { current: old_current, retired: vec![test_generation(now - chrono::Duration::hours(1))] };

        let rotated = rotate_keys(keys, Some("rotation note")).expect("rotate must succeed");

        assert_ne!(rotated.current.exc.thumbprint(), old_current_thumbprint, "a fresh key must be generated");
        assert_eq!(rotated.current.note.as_deref(), Some("rotation note"));
        assert_eq!(rotated.retired.len(), 2, "the old current must join retired, not replace it");
        assert_eq!(
            rotated.retired[0].exc.thumbprint(),
            old_current_thumbprint,
            "the old current must be retired first"
        );
        assert_eq!(rotated.retired[0].created_at, now, "the retired copy must be unchanged");
    }

    #[test]
    fn test_prune_keys_oldest_removes_only_the_single_oldest() {
        let now = chrono::Utc::now();
        let newest = test_generation(now - chrono::Duration::hours(1));
        let newest_thumbprint = newest.exc.thumbprint();
        let oldest = test_generation(now - chrono::Duration::hours(2));
        let oldest_thumbprint = oldest.exc.thumbprint();
        let keys = TangKeys { current: test_generation(now), retired: vec![newest, oldest] };

        let (pruned_keys, removed) = prune_keys(keys, PruneSelector::Oldest).expect("prune must succeed");

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].exc.thumbprint(), oldest_thumbprint, "the removed generation must be reported");
        assert_eq!(pruned_keys.retired.len(), 1);
        assert_eq!(pruned_keys.retired[0].exc.thumbprint(), newest_thumbprint);
    }

    #[test]
    fn test_prune_keys_oldest_rejects_an_empty_retired_list() {
        let keys = TangKeys { current: test_generation(chrono::Utc::now()), retired: Vec::new() };
        assert!(prune_keys(keys, PruneSelector::Oldest).is_err());
    }

    #[test]
    fn test_prune_keys_keep_keeps_only_the_n_newest() {
        let now = chrono::Utc::now();
        let newest = test_generation(now - chrono::Duration::hours(1));
        let newest_thumbprint = newest.exc.thumbprint();
        let retired = vec![
            newest,
            test_generation(now - chrono::Duration::hours(2)),
            test_generation(now - chrono::Duration::hours(3)),
        ];
        let keys = TangKeys { current: test_generation(now), retired };

        let (pruned_keys, removed) = prune_keys(keys, PruneSelector::Keep(1)).expect("prune must succeed");

        assert_eq!(removed.len(), 2);
        assert_eq!(pruned_keys.retired.len(), 1);
        assert_eq!(
            pruned_keys.retired[0].exc.thumbprint(),
            newest_thumbprint,
            "keep must retain the newest, not the oldest"
        );
    }

    #[test]
    fn test_prune_keys_keep_more_than_present_is_a_no_op() {
        let now = chrono::Utc::now();
        let keys = TangKeys {
            current: test_generation(now),
            retired: vec![test_generation(now - chrono::Duration::hours(1))],
        };

        let (pruned_keys, removed) = prune_keys(keys, PruneSelector::Keep(10)).expect("prune must succeed");

        assert_eq!(removed.len(), 0);
        assert_eq!(pruned_keys.retired.len(), 1);
    }

    #[test]
    fn test_prune_keys_older_than_removes_only_generations_past_the_cutoff() {
        let now = chrono::Utc::now();
        let recent = test_generation(now - chrono::Duration::hours(1));
        let recent_thumbprint = recent.exc.thumbprint();
        let stale = test_generation(now - chrono::Duration::days(400));
        let stale_thumbprint = stale.exc.thumbprint();
        let keys = TangKeys { current: test_generation(now), retired: vec![recent, stale] };

        let (pruned_keys, removed) =
            prune_keys(keys, PruneSelector::OlderThan(chrono::Duration::days(365))).expect("prune must succeed");

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].exc.thumbprint(), stale_thumbprint, "the removed generation must be reported");
        assert_eq!(pruned_keys.retired.len(), 1);
        assert_eq!(pruned_keys.retired[0].exc.thumbprint(), recent_thumbprint);
    }

    #[test]
    fn test_prune_keys_thumbprint_removes_only_the_matching_generation() {
        let now = chrono::Utc::now();
        let keep = test_generation(now - chrono::Duration::hours(1));
        let keep_thumbprint = keep.exc.thumbprint();
        let drop = test_generation(now - chrono::Duration::hours(2));
        let drop_thumbprint = drop.exc.thumbprint();
        let keys = TangKeys { current: test_generation(now), retired: vec![keep, drop] };

        let (pruned_keys, removed) =
            prune_keys(keys, PruneSelector::Thumbprint(drop_thumbprint.clone())).expect("prune must succeed");

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].exc.thumbprint(), drop_thumbprint, "the removed generation must be reported");
        assert_eq!(pruned_keys.retired.len(), 1);
        assert_eq!(pruned_keys.retired[0].exc.thumbprint(), keep_thumbprint);
    }

    #[test]
    fn test_prune_keys_thumbprint_rejects_an_unknown_thumbprint() {
        let keys = TangKeys { current: test_generation(chrono::Utc::now()), retired: Vec::new() };
        assert!(prune_keys(keys, PruneSelector::Thumbprint("unknown".to_string())).is_err());
    }

    #[test]
    fn test_prune_selector_parses_an_older_than_duration() {
        let selector = prune_selector(None, Some("2days"), None).expect("a valid duration must parse");
        assert!(matches!(selector, PruneSelector::OlderThan(d) if d == chrono::Duration::days(2)));
    }

    #[test]
    fn test_prune_selector_rejects_an_invalid_duration() {
        assert!(prune_selector(None, Some("not a duration"), None).is_err());
    }
}
