#![warn(clippy::pedantic)]
// `use worker::*` is the crate's own idiom; naming every re-export
// individually buys nothing. This isn't a published library, so a per-fn
// `# Errors` section would be noise.
#![allow(clippy::wildcard_imports, clippy::missing_errors_doc)]
//
// Tang (Network-Bound Disk Encryption) server, deployed as a Cloudflare
// Worker. Serves the two stateless Tang endpoints (`/adv`, `/rec/<kid>`),
// with the actual protocol implemented by `tangy-lib`. A normal Tang
// deployment answers any caller; this one is gated to a single consumer
// (one VPS) by source IP, since the whole point here is limiting who can
// complete a recovery, not serving the public. There's no bearer
// credential on top of the IP check: the client is Clevis, which sends no
// header beyond `Content-Type` and has no config option to add one.

use worker::*;

mod access_control;
mod handlers;
mod keys;

pub use access_control::check_cidr_list;
pub use keys::{KeyGeneration, TangKeys, EXCHANGE_KEY_ALG, SIGNING_KEY_ALG};

/// The Worker's HTTP entry point, routing to `/adv` and `/rec/:kid`.
#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    let rec_pattern = format!("/rec/:{}", handlers::KID_PARAM);
    Router::new()
        .get_async("/adv", handlers::handle_adv)
        .post_async(&rec_pattern, handlers::handle_rec)
        .run(req, env)
        .await
}
