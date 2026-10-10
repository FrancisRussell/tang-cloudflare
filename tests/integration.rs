// Exercises the real worker::* code paths unit tests can't reach: routing,
// header reading, and the actual tangy-lib wiring. Runs the actual compiled
// Worker under `wrangler dev` (Miniflare) and drives it with real HTTP
// requests, treating it as a black box exactly as Clevis would. This file
// deliberately never imports the `tang_cloudflare` crate itself.
//
// Requires Node/npm (for `npx wrangler`) and cargo (to install worker-build
// and run the `keygen` binary, both done automatically below). Gated behind
// the integration-tests feature (see Cargo.toml's required-features on this
// target) so a plain `cargo test` doesn't even attempt to build or run it.
// Run with: cargo test --features integration-tests --test integration
//
// Unix-only: process groups and the process-group kill below aren't
// portable. On other platforms this compiles to an empty, harmless test
// binary rather than failing to build.
#![cfg(unix)]

use std::io::Read;
use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64ct::Encoding;
use elliptic_curve::sec1::ToEncodedPoint;
use http::StatusCode;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use sha2::{Digest, Sha256};

const PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");
/// The `worker-build` version to install, matching wrangler.toml's build
/// command.
const WORKER_BUILD_CRATE: &str = "worker-build@0.8.6";
const READY_TIMEOUT: Duration = Duration::from_secs(45);
/// Per-request timeout for every HTTP call this test makes, so a hung
/// request fails with a clear error instead of hanging the whole test.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long Drop waits for the killed process to actually be reaped before
/// giving up (it's already dead at this point; this is just avoiding a
/// zombie, not waiting for anything uncertain).
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// `/adv`'s content type in the Tang wire protocol. Duplicated rather than
/// imported, since this file deliberately treats the Worker as a black box.
const JOSE_JSON: &str = "application/jose+json";
/// `/rec`'s content type in the Tang wire protocol. Duplicated for the same
/// reason as `JOSE_JSON`.
const JWK_JSON: &str = "application/jwk+json";

/// `ALLOWED_CIDRS_KV`'s key in the Worker's own KV store. Duplicated for
/// the same reason as `JOSE_JSON`.
const ALLOWED_CIDRS_KV_KEY: &str = "cidrs";

/// The CIDR this run's `ALLOWED_CIDRS_KV` is seeded with, and an address
/// inside and outside it.
const ALLOWED_CIDR: &str = "203.0.113.50/32";
const ALLOWED_IP: &str = "203.0.113.50";
const DISALLOWED_IP: &str = "8.8.8.8";

/// A P-521 field element's encoded length: 521 bits, rounded up to whole
/// bytes. Used for placeholder coordinates in request bodies that don't
/// need to be on the curve, only the right length.
const P521_COORDINATE_BYTE_LEN: usize = 66;

/// PGID of the currently-running `wrangler dev` process group, or 0 if none.
/// Shared with the SIGINT handler installed in `integration_test`: a signal
/// terminates the process without unwinding, so `Drop for WranglerDev` never
/// runs on Ctrl+C. Without this, an interrupted run leaks the whole
/// wrangler/node/workerd tree.
static WRANGLER_PGID: AtomicU32 = AtomicU32::new(0);

/// Kills whatever process group `WRANGLER_PGID` currently names, if any.
fn kill_wrangler_process_group() {
    let pgid = WRANGLER_PGID.swap(0, Ordering::SeqCst);
    if pgid != 0 {
        // A negative PID targets the whole process group, per kill(2).
        let group = Pid::from_raw(-i32::try_from(pgid).expect("a PID fits an i32"));
        if let Err(e) = signal::kill(group, Signal::SIGKILL) {
            eprintln!("warning: failed to kill wrangler dev process group {pgid}: {e}");
        }
    }
}

/// The conventional exit code for a process terminated by SIGINT: 128 plus
/// the signal number (2).
const SIGINT_EXIT_CODE: i32 = 130;

/// Installs a SIGINT handler that tears down the process tree before
/// exiting, so interrupting a hung/slow test doesn't leak it. Must be
/// called at most once per process; the single `#[test] fn
/// integration_test` here is the only caller.
fn install_sigint_cleanup() {
    ctrlc::set_handler(|| {
        kill_wrangler_process_group();
        std::process::exit(SIGINT_EXIT_CODE);
    })
    .expect("failed to install SIGINT handler");
}

/// Asks the OS for a free port rather than using a fixed one, so this test
/// doesn't race a previous run's leftover process for it.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("a bound listener has an address").port()
}

/// Drains `pipe` into `output` on a background thread until EOF, so the
/// child never blocks on a full pipe buffer going undrained.
fn spawn_output_reader(mut pipe: impl Read + Send + 'static, output: Arc<Mutex<Vec<u8>>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => output.lock().expect("a thread panicked while holding the lock").extend_from_slice(&buf[..n]),
            }
        }
    });
}

/// Writes a copy of wrangler.toml for `wrangler dev` to run from, without
/// its `[build]` section, which would rebuild the Worker on every (re)start
/// when this test has already built it. `main` is made absolute, since the
/// copy lives elsewhere.
fn write_test_wrangler_config(dir: &Path) -> PathBuf {
    let original =
        std::fs::read_to_string(Path::new(PROJECT_DIR).join("wrangler.toml")).expect("failed to read wrangler.toml");
    let mut copy = String::new();
    let mut in_build_section = false;
    for line in original.lines() {
        if line.starts_with('[') {
            in_build_section = line.trim() == "[build]";
        }
        if in_build_section {
            continue;
        }
        if let Some(main) = line.strip_prefix("main = \"") {
            copy.push_str(&format!("main = \"{PROJECT_DIR}/{main}\n"));
        } else {
            copy.push_str(line);
            copy.push('\n');
        }
    }
    let path = dir.join("wrangler.test.toml");
    std::fs::write(&path, copy).expect("failed to write the test wrangler config");
    path
}

/// Writes the `.dev.vars` file `wrangler dev` loads local secrets from.
/// `TANG_KEYS` is a secret, which `wrangler dev` only picks up this way.
fn write_dev_vars(dir: &Path, tang_keys_json: &str) {
    std::fs::write(dir.join(".dev.vars"), format!("TANG_KEYS='{tang_keys_json}'\n"))
        .expect("failed to write .dev.vars");
}

/// Runs the real `keygen generate` command, already built by Cargo as a
/// prerequisite of this test binary, and returns its stdout: the JSON the
/// `TANG_KEYS` secret expects.
fn generate_test_tang_keys() -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_keygen")).arg("generate").output().expect("failed to run keygen");
    assert!(output.status.success(), "keygen failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).expect("keygen's output must be valid UTF-8")
}

/// Manages a `wrangler dev` child process covering the whole test run:
/// builds the worker, starts it, and waits until it responds to requests.
/// The whole process tree is killed on drop. No `Clone`: it owns a live
/// child process handle, which can't be duplicated.
#[derive(Debug)]
struct WranglerDev {
    child: Child,
    port: u16,
    output: Arc<Mutex<Vec<u8>>>,
    persist_dir: PathBuf,
}

impl WranglerDev {
    /// Builds the Worker, starts `wrangler dev` against it, and waits
    /// until it's responding to requests.
    fn start(tang_keys_json: &str) -> Self {
        // Matches wrangler.toml's own [build] command: install (a no-op if
        // already present) rather than requiring a separate manual step.
        let status = Command::new("cargo")
            .args(["install", "-q", "--locked", WORKER_BUILD_CRATE])
            .status()
            .expect("failed to run `cargo install worker-build` (is cargo installed?)");
        assert!(status.success(), "cargo install worker-build failed");

        let status = Command::new("worker-build")
            .args(["--release", "--no-default-features"])
            .current_dir(PROJECT_DIR)
            .status()
            .expect("failed to run worker-build");
        assert!(status.success(), "worker-build failed");

        let persist_dir = std::env::temp_dir().join(format!("tang-cloudflare-test-{}", std::process::id()));
        std::fs::create_dir_all(&persist_dir).expect("failed to create --persist-to directory");

        let config_path = write_test_wrangler_config(&persist_dir);
        write_dev_vars(&persist_dir, tang_keys_json);

        let port = pick_free_port();
        let output = Arc::new(Mutex::new(Vec::new()));

        // Node, esbuild and workerd all fall back to the OS temp directory
        // for their own scratch files that --persist-to doesn't cover.
        // Pointing TMPDIR at a subdirectory of persist_dir keeps those out
        // of the shared system temp directory and lets Drop sweep them up.
        let node_tmp_dir = persist_dir.join("node-tmp");
        std::fs::create_dir_all(&node_tmp_dir).expect("failed to create the wrangler dev TMPDIR");

        let mut child = Command::new("npx")
            .args([
                "wrangler",
                "dev",
                "--config",
                config_path.to_str().expect("temp dir path must be valid UTF-8"),
                "--port",
                &port.to_string(),
                "--persist-to",
                persist_dir.to_str().expect("temp dir path must be valid UTF-8"),
            ])
            .current_dir(PROJECT_DIR)
            .env("TMPDIR", &node_tmp_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own process group, so the whole tree (node, workerd,
            // esbuild) can be killed together on Drop instead of leaving
            // orphans that accumulate and slow down every later run.
            .process_group(0)
            .spawn()
            .expect("failed to spawn `npx wrangler dev` (is Node/npm installed?)");
        // process_group(0) makes the child's PGID equal its own PID.
        WRANGLER_PGID.store(child.id(), Ordering::SeqCst);

        spawn_output_reader(child.stdout.take().expect("child spawned with piped stdout"), Arc::clone(&output));
        spawn_output_reader(child.stderr.take().expect("child spawned with piped stderr"), Arc::clone(&output));

        let dev = Self { child, port, output, persist_dir };
        dev.wait_until_ready();
        dev.seed_allowed_cidrs_kv();
        dev
    }

    /// The local base URL `wrangler dev` is listening on.
    fn base_url(&self) -> String { format!("http://127.0.0.1:{}", self.port) }

    /// The id `wrangler dev`'s local explorer API gives the (only) KV
    /// namespace declared in wrangler.toml.
    fn find_kv_namespace_id(&self) -> String {
        let url = format!("{}/cdn-cgi/local/explorer/api/storage/kv/namespaces", self.base_url());
        let listing = ureq::get(&url)
            .timeout(REQUEST_TIMEOUT)
            .call()
            .unwrap_or_else(|e| panic!("wrangler dev's local explorer API is unavailable ({e}); is wrangler current?"))
            .into_string()
            .expect("the namespace listing is readable");
        let after_id = listing.split_once("\"id\":\"").expect("the namespace listing has an id").1;
        after_id.split_once('"').expect("the id is quoted").0.to_string()
    }

    /// Seeds `ALLOWED_CIDRS_KV` through `wrangler dev`'s own local explorer
    /// API, which answers in milliseconds, rather than a separate `wrangler
    /// kv` CLI invocation, which pays Node's whole startup each time.
    fn seed_allowed_cidrs_kv(&self) {
        let namespace_id = self.find_kv_namespace_id();
        let url = format!(
            "{}/cdn-cgi/local/explorer/api/storage/kv/namespaces/{namespace_id}/values/{ALLOWED_CIDRS_KV_KEY}",
            self.base_url()
        );
        ureq::put(&url)
            .timeout(REQUEST_TIMEOUT)
            .send_string(ALLOWED_CIDR)
            .unwrap_or_else(|e| panic!("seeding ALLOWED_CIDRS_KV via the local explorer API failed: {e}"));
    }

    fn captured_output(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().expect("a thread panicked while holding the lock")).into_owned()
    }

    /// Polls `/adv` until it gets any HTTP response at all (even an error
    /// status), which proves the listener is up and routing requests.
    fn wait_until_ready(&self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            match ureq::get(&format!("{}/adv", self.base_url())).timeout(REQUEST_TIMEOUT).call() {
                Ok(_) | Err(ureq::Error::Status(..)) => return,
                Err(ureq::Error::Transport(_)) if Instant::now() < deadline => {
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(e) => panic!("wrangler dev did not become ready: {e}\noutput:\n{}", self.captured_output()),
            }
        }
    }
}

impl Drop for WranglerDev {
    fn drop(&mut self) {
        kill_wrangler_process_group();

        let deadline = Instant::now() + REAP_TIMEOUT;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                _ => std::thread::sleep(REAP_POLL_INTERVAL),
            }
        }

        if std::thread::panicking() {
            eprintln!("wrangler dev output:\n{}", self.captured_output());
        }

        let _ = std::fs::remove_dir_all(&self.persist_dir);
    }
}

#[derive(Debug, Clone)]
struct HttpResult {
    status: StatusCode,
    content_type: Option<String>,
    body: String,
}

/// Unwraps a `ureq` outcome into an `HttpResult`, treating an HTTP error
/// status as an ordinary response rather than failing the test.
fn to_result(outcome: Result<ureq::Response, ureq::Error>) -> HttpResult {
    let resp = match outcome {
        Ok(resp) | Err(ureq::Error::Status(_, resp)) => resp,
        Err(e) => panic!("request failed: {e}"),
    };
    let status = StatusCode::from_u16(resp.status()).expect("ureq gives a valid status code");
    let content_type = resp.header("content-type").map(str::to_owned);
    let body = resp.into_string().expect("response body must be valid UTF-8");
    HttpResult { status, content_type, body }
}

/// Sends a `GET /adv` request, optionally with a `CF-Connecting-IP` header.
fn get_adv(dev: &WranglerDev, client_ip: Option<&str>) -> HttpResult {
    let mut req = ureq::get(&format!("{}/adv", dev.base_url())).timeout(REQUEST_TIMEOUT);
    if let Some(ip) = client_ip {
        req = req.set("CF-Connecting-IP", ip);
    }
    to_result(req.call())
}

/// Sends a `POST /rec/<kid>` request with `body`, optionally with a
/// `CF-Connecting-IP` header.
fn post_rec(dev: &WranglerDev, kid: &str, client_ip: Option<&str>, body: &str) -> HttpResult {
    let mut req = ureq::post(&format!("{}/rec/{kid}", dev.base_url())).timeout(REQUEST_TIMEOUT);
    if let Some(ip) = client_ip {
        req = req.set("CF-Connecting-IP", ip);
    }
    to_result(req.send_string(body))
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Adv {
    payload: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct AdvKey {
    kty: String,
    crv: String,
    x: String,
    y: String,
    alg: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Payload {
    keys: Vec<AdvKey>,
}

/// The JWK thumbprint (RFC 7638) tangy-lib uses as a key's `kid`: SHA-256 of
/// the compact JSON object of its required EC members, in lexicographic
/// order (crv, kty, x, y), base64url-unpadded. Computed independently here
/// rather than trusting a server-supplied `kid`, matching what a real
/// client has to do, since the advertised keys carry no `kid` field.
fn jwk_thumbprint(key: &AdvKey) -> String {
    let json = format!(r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#, key.crv, key.kty, key.x, key.y);
    base64ct::Base64UrlUnpadded::encode_string(&Sha256::digest(json.as_bytes()))
}

/// Parses an `/adv` response body and returns the exchange (`alg: "ECMR"`)
/// key along with the `kid` a client derives for it.
fn exchange_key(adv_body: &str) -> (String, AdvKey) {
    let adv: Adv = serde_json::from_str(adv_body).expect("adv body must be valid JSON");
    // tangy-lib encodes the payload with the padded url-safe alphabet; see
    // its own `adv_internal`.
    let payload_json = base64ct::Base64Url::decode_vec(&adv.payload).expect("adv payload must be valid base64url");
    let payload: Payload = serde_json::from_slice(&payload_json).expect("adv payload must be valid JSON");
    let key = payload
        .keys
        .into_iter()
        .find(|k| k.alg.as_deref() == Some("ECMR"))
        .expect("adv must include an ECMR exchange key");
    let kid = jwk_thumbprint(&key);
    (kid, key)
}

/// A P-521 point from JWK coordinates, SEC1-uncompressed-encoded by hand
/// (`0x04 || x || y`) rather than going through `elliptic_curve::JwkEcKey`,
/// so this test's own decoding is independent of the server's.
/// `PublicKey::from_sec1_bytes` also validates the point is actually on the
/// curve.
fn public_key_from_coords(x: &str, y: &str) -> p521::PublicKey {
    let x_bytes = base64ct::Base64UrlUnpadded::decode_vec(x).expect("x coordinate must be valid base64url");
    let y_bytes = base64ct::Base64UrlUnpadded::decode_vec(y).expect("y coordinate must be valid base64url");
    let mut sec1 = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x_bytes);
    sec1.extend_from_slice(&y_bytes);
    p521::PublicKey::from_sec1_bytes(&sec1).expect("point must be a valid P-521 public key")
}

/// `scalar * point`, for independently recomputing the server's half of the
/// exchange. Mirrors tangy-lib's own `diffie_hellman_public_key`, done here
/// without depending on tangy-lib, as the test's independent check of it.
fn scalar_mul(
    scalar: &elliptic_curve::NonZeroScalar<p521::NistP521>, point: &elliptic_curve::AffinePoint<p521::NistP521>,
) -> elliptic_curve::AffinePoint<p521::NistP521> {
    (elliptic_curve::ProjectivePoint::<p521::NistP521>::from(*point) * scalar.as_ref()).to_affine()
}

/// Asserts that `rec` on `/rec/<kid>` for a freshly-generated client
/// ephemeral keypair returns the point that `secret_scalar * client_pub`
/// predicts, i.e. that the server performed the correct Diffie-Hellman
/// step: `server_secret * client_pub == client_secret * server_pub`.
fn scenario_rec_matches_expected_ecdh_point(dev: &WranglerDev, exc_kid: &str, exc_key: &AdvKey) {
    let server_pub = public_key_from_coords(&exc_key.x, &exc_key.y);

    let client_secret = p521::SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
    let client_pub = client_secret.public_key().to_encoded_point(false);
    let client_x = base64ct::Base64UrlUnpadded::encode_string(client_pub.x().expect("uncompressed point has x"));
    let client_y = base64ct::Base64UrlUnpadded::encode_string(client_pub.y().expect("uncompressed point has y"));
    let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{client_x}","y":"{client_y}"}}"#);

    let result = post_rec(dev, exc_kid, Some(ALLOWED_IP), &body);
    assert_eq!(result.status, StatusCode::OK, "body: {}", result.body);
    assert_eq!(result.content_type.as_deref(), Some(JWK_JSON));

    let returned: AdvKey = serde_json::from_str(&result.body).expect("rec body must be a JWK");
    let actual = public_key_from_coords(&returned.x, &returned.y);

    let expected = scalar_mul(&client_secret.to_nonzero_scalar(), server_pub.as_affine());

    assert_eq!(
        actual.as_affine(),
        &expected,
        "server's rec result doesn't match the independently computed ECDH point"
    );
}

/// Asserts `/adv` succeeds for an allowed IP, and returns the exchange
/// key and its `kid`.
fn scenario_adv_allowed_ip_returns_a_valid_advertisement(dev: &WranglerDev) -> (String, AdvKey) {
    let result = get_adv(dev, Some(ALLOWED_IP));
    assert_eq!(result.status, StatusCode::OK, "body: {}", result.body);
    assert_eq!(result.content_type.as_deref(), Some(JOSE_JSON));
    exchange_key(&result.body)
}

/// Asserts `/adv` is forbidden for an IP outside the allowlist.
fn scenario_adv_disallowed_ip_is_forbidden(dev: &WranglerDev) {
    let result = get_adv(dev, Some(DISALLOWED_IP));
    assert_eq!(result.status, StatusCode::FORBIDDEN);
}

/// Asserts `/adv` is forbidden when no client IP header is present.
fn scenario_adv_missing_ip_is_forbidden(dev: &WranglerDev) {
    let result = get_adv(dev, None);
    assert_eq!(result.status, StatusCode::FORBIDDEN);
}

/// Asserts `/rec` is forbidden for an IP outside the allowlist.
fn scenario_rec_disallowed_ip_is_forbidden(dev: &WranglerDev, exc_kid: &str) {
    let result = post_rec(dev, exc_kid, Some(DISALLOWED_IP), "{}");
    assert_eq!(result.status, StatusCode::FORBIDDEN);
}

/// Asserts `/rec` returns 404 for a `kid` that matches no stored key. Uses a
/// genuinely valid, on-curve point so this exercises kid lookup specifically,
/// not body validation.
fn scenario_rec_unknown_kid_is_not_found(dev: &WranglerDev) {
    let client_pub =
        p521::SecretKey::random(&mut elliptic_curve::rand_core::OsRng).public_key().to_encoded_point(false);
    let x = base64ct::Base64UrlUnpadded::encode_string(client_pub.x().expect("uncompressed point has x"));
    let y = base64ct::Base64UrlUnpadded::encode_string(client_pub.y().expect("uncompressed point has y"));
    let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{x}","y":"{y}"}}"#);
    let result = post_rec(dev, "not-a-real-kid", Some(ALLOWED_IP), &body);
    assert_eq!(result.status, StatusCode::NOT_FOUND);
}

/// A malformed body must be rejected without taking the server down, which
/// is the specific failure this scenario checks for: a second, well-formed
/// request to the same still-running process must succeed.
fn scenario_rec_malformed_body_is_rejected_without_crashing(dev: &WranglerDev, exc_kid: &str) {
    for body in
        ["not json", r#"{"kty":"RSA","crv":"P-521","x":"a","y":"a"}"#, r#"{"kty":"EC","crv":"P-256","x":"a","y":"a"}"#]
    {
        let result = post_rec(dev, exc_kid, Some(ALLOWED_IP), body);
        assert_eq!(result.status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    // A recognized MyJwkEcKey field (`alg`) carrying the wrong JSON type
    // must also be rejected cleanly, not just an unrecognized shape.
    let coord = base64ct::Base64UrlUnpadded::encode_string(&[0u8; P521_COORDINATE_BYTE_LEN]);
    let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{coord}","y":"{coord}","alg":123}}"#);
    let result = post_rec(dev, exc_kid, Some(ALLOWED_IP), &body);
    assert_eq!(result.status, StatusCode::BAD_REQUEST);

    // A point that's the right shape (kty, crv, coordinate lengths) but
    // off-curve, (0, 0), must also be rejected cleanly: this is the one
    // tangy-lib itself can't catch without the curve arithmetic `rec`
    // does internally, so it's the case that used to reach tangy-lib's
    // own unwrap and crash the request instead of failing it.
    let body = format!(r#"{{"kty":"EC","crv":"P-521","x":"{coord}","y":"{coord}"}}"#);
    let result = post_rec(dev, exc_kid, Some(ALLOWED_IP), &body);
    assert_eq!(result.status, StatusCode::BAD_REQUEST);

    // The process must still be serving requests after all of the above.
    let result = get_adv(dev, Some(ALLOWED_IP));
    assert_eq!(result.status, StatusCode::OK);
}

#[test]
fn integration_test() {
    install_sigint_cleanup();

    let tang_keys = generate_test_tang_keys();
    let dev = WranglerDev::start(&tang_keys);

    scenario_adv_disallowed_ip_is_forbidden(&dev);
    scenario_adv_missing_ip_is_forbidden(&dev);
    let (exc_kid, exc_key) = scenario_adv_allowed_ip_returns_a_valid_advertisement(&dev);

    scenario_rec_disallowed_ip_is_forbidden(&dev, &exc_kid);
    scenario_rec_unknown_kid_is_not_found(&dev);
    scenario_rec_malformed_body_is_rejected_without_crashing(&dev, &exc_kid);
    scenario_rec_matches_expected_ecdh_point(&dev, &exc_kid, &exc_key);
}
