# tang-cloudflare

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
- Node.js/npm (for `wrangler`, Cloudflare's deployment tool) and a Rust
  toolchain
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
2. Upload it to Cloudflare: `npm run upload-key`. This first validates the
   file with `check-key`, which checks each key's cryptographic validity
   more thoroughly than the Worker does on a live request, catching a
   corrupt or malformed key before it ever reaches Cloudflare. Takes a path
   e.g. `npm run upload-key -- rotated-keys.json`, if the file isn't under
   `tang-keys.json`.
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
<THUMBPRINT>` select differently. To see each generation's thumbprint, the
only identifier `--thumbprint` takes, along with its creation time and note:

```sh
cargo run --bin keygen -- list tang-keys.json
```

```
current: thumbprint E17UI1rXDxhAAZoWLo1d8_EZBy6-JUHvLvPeRV1EW9U, created 2026-10-09 15:29:07 UTC (annual rotation)
retired: thumbprint Im_OiAfxu6vI9dOW7kM9d6YBPgag2VdLiYLDZlB5L64, created 2026-10-09 15:29:07 UTC (initial rollout)
```

### 4. Create the allowlist's KV namespace

```sh
npx wrangler kv namespace create tang-allowed-cidrs
```

Paste the printed `id` into `wrangler.toml`'s `[[kv_namespaces]]` block, in
place of `REPLACE_WITH_NAMESPACE_ID`. A one-time step: every future deploy
reuses the same namespace once its `id` is there.

`wrangler.toml` also declares a per-IP rate limit (60 requests/minute). This
is more of a protection against a buggy client than a DOS attack as a
client could still consume significant request budget.

### 5. Set the allowed IP addresses

```sh
npm run set-allowlist -- "198.51.100.7, 203.0.113.0/24, 2001:db8::1"
```

The allow list comprises comma-separated CIDR ranges or IPs of the
machine(s) this Worker will serve. It's set directly in Cloudflare's KV
store, independent of `wrangler.toml` and of any deploy so the list can be
updated without a redeploy.

`npm run get-allowlist` reads the current value back, if you ever need to
check it.

### 6. Deploy

```sh
npm run deploy
```

The URL of the worker will be printed during this step.

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

`tangy-lib` parses its input with bare `.unwrap()`s rather than returning
errors for malformed input ([rustfoo/tangy-lib#8][tangy-lib-panics]), which
panics the Worker and can corrupt isolate state shared with other requests
rather than just failing the one request.

For `/adv` and `/rec`, this is worked around: `decode_ec_point` rejects a
request body that's the right shape but not an actual point on the curve
before it ever reaches `tangy-lib`, so a client can't trigger this.

For the `TANG_KEYS` secret itself, there's no equivalent check on the live
request path: `check_tangy_keys` (the same validation, including the exchange
key's public point matching its own private scalar) only runs in `check-key` at
upload time, not again on every `/adv`/`/rec` call. 

A `TANG_KEYS` secret set without going through that script, or corrupted after
being set, can still panic the Worker. Re-validating on every request would
roughly double its CPU cost, so this relies on always setting
`TANG_KEYS` via the upload script.

[tangy-lib-panics]: https://github.com/rustfoo/tangy-lib/issues/8

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE).

## AI usage

This repository discloses AI involvement per the
[ai-disclosure](https://github.com/ggfevans/ai-disclosure) convention; see
[AI_DISCLOSURE.md](AI_DISCLOSURE.md) for details.
