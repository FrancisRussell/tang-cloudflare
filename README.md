# tang-cloudflare

[![CI](https://github.com/FrancisRussell/tang-cloudflare/actions/workflows/ci.yml/badge.svg)](https://github.com/FrancisRussell/tang-cloudflare/actions/workflows/ci.yml)

A [Tang](https://github.com/latchset/tang) server, deployable as a Cloudflare
Worker.

## Background

There are many situations where it is desirable for a machine to have its
storage encrypted. For servers and other machines that should remain online
continuously, needing to manually unlock the machine is unacceptable, but for
encryption to provide any sort of benefit, encryption keys must be kept
off-machine.

Network-Bound Disk Encryption (NBDE) is a technology that allows the
unlocking of a machine to be tied to its local network by using a client
(Clevis) to communicate with a network-local server (Tang) to derive an
encryption key on the client. A defining feature of NBDE is the usage of
asymmetric cryptography, which makes this possible without secret key
material leaving either the server or the client, while remaining secure in
the presence of eavesdropping.

The unlock key is stored on the client's disk only in a wrapped, encrypted
form, and unwrapping it takes a live exchange with the Tang server, over the
network, at boot. Every unlock's server reply is useless without a one-time
secret the client invents fresh each time and never sends anywhere.
Consequently:

- A copy of the disk alone is useless since the wrapped key is worthless
  without the server's cooperation.
- Network access to the server alone is also useless since it holds nothing
  specific to any one machine, and can't decrypt anything by itself.

Only the combination of the disk and either a live connection to the Tang
server, or a copy of the keys stored on the Tang server can be used to
decrypt the client disk.

Tang is the open-source protocol and software that plays the server's part in
this (paired with Clevis, the Linux tooling that does the wrapping and
unwrapping). This project is an implementation of Tang as a Cloudflare worker.

## Security model

*Authorization*: Tang has no authorization. This is deliberate - any
credential a client machine could issue would need to be stored on the
machine and therefore potentially compromised by an attacker that has a copy
of the machine's data.

*Access control*: Tang is expected to be run on a trusted network, one that
an attacker does not have access to. Since a Cloudflare-hosted Tang can have
requests made to it from the entire Internet it is vital to provide a list
of CIDRs from which requests are expected to be made. If an attacker can
make a request from one of these addresses, then NBDE will provide no
protection.

## Required configuration

In order to deploy, two pieces of information are needed:

- A list of CIDRs which should be allowed to make requests to Tang. Both
  IPv4 and IPv6 are supported. Ideally these are restricted to a set of
  fixed IPs that your servers are located at.

- A list of key sets. Each key set consists of a signing key (`sig`) and an
  exchange key (`exc`). Tang advertises a single key set, but can serve
  requests for a number of retired key sets as well, in order to aid key
  rotation.

The active key set and the list of retired Tang key sets are stored as a
single JSON file. The `keygen` tool is provided which can generate and
rotate key sets. It is strongly recommended that you keep a copy of this
file somewhere safe (like a password manager). If this file is lost, any
client bound to those keys will be permanently unable to unlock. The list of
Tang key sets is stored in a Cloudflare secret, so it is non-trivial to
retrieve a copy. Also consider adding a separate key for any encrypted data
that is fully independent of Tang.

## Setup

### 1. Prerequisites

- A Cloudflare account
- Node.js/npm (for `wrangler`, Cloudflare's deployment tool), a Rust
  toolchain, and `jq`
- The machines this Worker will unlock, and their IPs.

### 2. Install dependencies

```sh
npm install
```

### 3. Generate and upload the Tang keys

Note that `keygen` never edits a file directly. Its output must be
redirected to a file. *Do not redirect output to the input file as that
would cause it to be erased if the command errored.*

```sh
cargo run --bin keygen -- generate > tang-keys.json
```

This generates the current generation's key set and renders it as one JSON
file. Both this and `rotate` (below) take an optional `--note <remark>`,
recorded with the generation and shown later by `list`, e.g. `--note "annual
rotation"`. There's no way to recover the keys if they're lost, so before
anything else:

1. Copy `tang-keys.json` into a password manager or other durable, offline
   backup.
2. Upload it to Cloudflare:

   ```sh
   npm run upload-key
   ```

   This first validates the file with `check-key`, which checks each key's
   cryptographic validity more thoroughly than the Worker does on a live
   request, catching a corrupt or malformed key before it ever reaches
   Cloudflare. Takes a path too, e.g. `npm run upload-key -- rotated-keys.json`,
   if the file isn't under `tang-keys.json`.
3. Delete the local file.

To rotate the keys later:

```sh
cargo run --bin keygen -- rotate tang-keys.json > rotated-keys.json
```

This retires the current generation (kept so a machine already bound to it
can keep unlocking) and generates a new one as the file's current
generation. Only the new current generation is ever advertised; retired
ones are still accepted by `/rec`. Re-run steps 1 and 2 above on the new
file once you're ready to rebind to it.

Once a retired generation is confirmed unused (every machine bound to it has
been rebound), remove it:

```sh
cargo run --bin keygen -- prune tang-keys.json > pruned-keys.json
```

Defaults to removing the single oldest retired generation; `--keep <N>`
(keep only the N newest retired generations, removing the rest),
`--older-than <DURATION>` (e.g. `1y`, `6months`), or `--thumbprint
<THUMBPRINT>` (either of a generation's two thumbprints below) select
differently. To see each generation's thumbprints, creation time, and note:

```sh
cargo run --bin keygen -- list tang-keys.json
```

```
current: created 2026-10-12 08:42:16 UTC (annual rotation)
  signing thumbprint:  oV6Cym3PZJ10CwEydYmcUdDSyPBvCrYsj4QOZ7-qqZA
  exchange thumbprint: yWJ8o7LoJrBrueO7lkz31E0-c-ccJSK2u3eVSOJBRpo

retired: created 2026-10-12 08:42:16 UTC (initial rollout)
  signing thumbprint:  IUvGdGzAmkW1422otDSVVoi7-UavLZ2WU1TETDIYFCc
  exchange thumbprint: ZDB_prwDEiixyOXNvfd7pXlyh3X4pdrrPvHmmtxndGU
```

The signing thumbprint is what a Clevis client's trust-on-first-use prompt
and `thp` pin show; check it against this output before trusting a server.
The exchange thumbprint is the `kid` that actually appears in `/rec/<kid>`
URLs and server logs.

### 4. Set the allowed IP addresses

By default the list of CIDRs allowed to access Tang is stored
in a KV namespace with the name `tang-allowed-cidrs`. To
customize this, create a `deploy.vars` file at the top-level
defining your desired name.

```sh
KV_NAMESPACE_NAME='some-other-name'
```

To then set the allowlist, run the following command, customized
with your desired CIDR ranges:

```sh
npm run set-allowlist -- "198.51.100.7, 203.0.113.0/24, 2001:db8::1"
```

Until the allow-list is set, every request to the server will be rejected. The
allow list comprises comma-separated CIDR ranges and IPs of machine(s) that
should be able to acces the server. This can be set before or after deploying,
and updated later without a redeploy. If the specified namespace does not exist
it will be automatically created. `npm run get-allowlist` reads the current
value back, if you ever need to check it.

### 5. Deploy

```sh
npm run deploy
```

The URL of the worker will be printed during this step. `wrangler.toml`
also declares a per-IP rate limit (60 requests/minute), applied as part of
this deploy; it's more a protection against a buggy client than a DOS
attack, since a client could still consume significant request budget.

### 6. Verify it's working

To do this `clevis` must be installed (`apt install clevis` on Debian/Ubuntu,
`dnf install clevis` on Fedora). This will only work on a machine configured to
have access to your Tang server.

```sh
echo -n "hello tang" | clevis encrypt tang '{"url":"https://tang.<your-subdomain>.workers.dev"}' > test.jwe
```

This fetches `/adv` and, the first time, asks you to confirm the advertised
signing key's thumbprint before trusting it (trust-on-first-use). Check it
against the signing thumbprint `cargo run --bin keygen -- list tang-keys.json`
printed (see step 3) rather than accepting on sight; a mismatch means this
isn't talking to the server you think it is.

```sh
clevis decrypt < test.jwe
```

This calls `/rec` to derive the key back and should print `hello tang`.
`test.jwe` itself isn't sensitive (it can't be decrypted without a live
exchange with this Tang server), so no need to keep or securely delete it.

### 7. Point any clients at Tang

On the machine being unlocked, `clevis` needs pointing at this Worker's
`*.workers.dev` URL (or a custom domain) as its Tang server. That side of
the setup (Clevis, the disk encryption itself, and the boot-time unlock
script) is beyond the scope of this README.

## Local development

```sh
npx wrangler dev
```

Needs its own local `TANG_KEYS` secret (see Cloudflare's docs on
`wrangler dev` for supplying secrets locally) and a local CIDR list in
`ALLOWED_CIDRS_KV`'s simulated namespace to answer requests, e.g.:

```sh
npx wrangler kv key put --binding=ALLOWED_CIDRS_KV --local cidrs 203.0.113.4/32
```

## Implementation notes

### tangy-lib panics

`tangy-lib` parses its input with bare `.unwrap()`s rather than returning
errors for malformed input ([rustfoo/tangy-lib#8][tangy-lib-panics]), which
panics the Worker and can corrupt isolate state shared with other requests
rather than just failing the one request.

For `/adv` and `/rec`, this is worked around: `decode_ec_point` rejects a
request body that's the right shape but not an actual point on the curve
before it ever reaches `tangy-lib`, so a client can't trigger this.

For the `TANG_KEYS` secret itself, there's no equivalent check on the live
request path: `TangKeys::validate` (the same validation, including the
exchange key's public point matching its own private scalar) only runs in
`check-key` at upload time, not again on every `/adv`/`/rec` call.

A `TANG_KEYS` secret set without going through that script, or corrupted after
being set, can still panic the Worker. Re-validating on every request would
cost one real cryptographic operation per key generation, current and
retired, so this relies on always setting `TANG_KEYS` via the upload script
instead.

### `/adv/<thp>` and key rotation

`/adv/<thp>` lets a client pinned to an old, now-retired signing key's
thumbprint still get a response co-signed by it, alongside the current
signing key. `tangy-lib` has no distinction between "advertised" and
"signable" keys: loading a key to sign with also advertises it
unconditionally, so naively loading a retired generation's signing key
would advertise its exchange key too, and a client making a fresh
binding could end up picking that one over the current one.

`TangKeys::build_adv_tangy` works around this by loading a retired
generation's signing key on its own, never paired with its exchange key.
This relies on undocumented `tangy-lib` behaviour: `TangyLib::init` only
checks that at least one signing and one exchange key are present
somewhere in the whole set, not that every signing key has its own
paired exchange key. Nothing states that's intentional, so a future
`tangy-lib` release enforcing pairing would break this.

[tangy-lib-panics]: https://github.com/rustfoo/tangy-lib/issues/8

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE).

## AI usage

This repository discloses AI involvement per the
[ai-disclosure](https://github.com/ggfevans/ai-disclosure) convention; see
[AI_DISCLOSURE.md](AI_DISCLOSURE.md) for details.
