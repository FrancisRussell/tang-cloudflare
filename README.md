# tang-cloudflare

A [Tang](https://github.com/latchset/tang) server, deployed as a Cloudflare
Worker.

## Background

Unlocking a disk at boot, without someone typing a passphrase, usually means
keeping the real key off that disk and reachable from a remote server
instead: stored there directly, or recoverable by sending the server
something to decrypt. Either way, a single exchange with that server hands
over something durable and reusable, the key itself or whatever unlocks it.
Whoever ever sees that one exchange can decrypt that disk at any later
point, with no further contact with the server at all.

Network-Bound Disk Encryption (NBDE) is built so that observing the
exchange never gives you that. The unlock key is stored on disk only in a
wrapped, encrypted form, and unwrapping it takes a live exchange with a
separate server, over the network, at boot. Every unlock's server reply is
useless without a one-time secret the client invents fresh each time and
never sends anywhere, so recording any number of these exchanges, even for
the same disk, hands over nothing durable. Defeating it takes something far
more specific: extracting the server's actual private key, not just
watching it answer requests. So:

- A copy of the disk alone is useless: the wrapped key is worthless without
  the server's cooperation.
- The server alone is also useless: it holds nothing specific to any one
  machine, and can't decrypt anything by itself.

Only the combination of the disk and a live connection to that specific
server can unlock anything.

Tang is the open-source protocol and software that plays the server's part
in this (paired with Clevis, the Linux tooling that does the wrapping and
unwrapping). It's normally run on a machine you control, reachable only from
the systems it's meant to unlock. This project is that server, running as a
Cloudflare Worker instead of a machine you have to patch, back up, and keep
running yourself.

## How it works

Tang answers two HTTP requests: one that advertises its public key, and one
a client uses to complete the unlock exchange. The protocol itself has no
authentication; it relies entirely on network reachability, not
credentials, to control who can ask. A Tang server normally gets that for
free, running on a private network reachable only by the machines it's
meant to unlock.

A Cloudflare Worker doesn't: it's reachable from the whole internet by
default. This deployment recreates the same restriction at the application
layer instead, with an IP allowlist, so it only answers requests from the
known, fixed set of machines it's meant to serve. That's access control,
but not authentication: it's based on where a request comes from, not a
credential proving who sent it. The Linux tool that actually talks to Tang
(`clevis`) has no way to send a credential anyway, so network origin is
the only thing there is to check.

## Setup

### 1. Prerequisites

- A Cloudflare account
- Node.js/npm (for `wrangler`, Cloudflare's deployment tool) and a Rust
  toolchain
- The machine this Worker will unlock, reachable at a known IP address

### 2. Install dependencies

```sh
npm install
```

### 3. Generate the Tang keys

```sh
cargo run --bin keygen -- generate > tang-keys.json
```

This generates the current generation's two keys and prints them as one JSON
file. Both this and `rotate` (below) take an optional `--note <remark>`,
recorded with the generation and shown later by `list`, e.g. `--note "annual
rotation"`. There's no way to recover the keys if they're lost, so before
anything else:

1. Copy `tang-keys.json` into a password manager or other durable, offline
   backup.
2. Upload it to Cloudflare: `npm run upload-key`. This first validates the
   file with `check-key`, which checks each key's cryptographic validity
   more thoroughly than the Worker ever does on a live request, catching a
   corrupt or malformed key before it ever reaches Cloudflare. Takes a path
   other than `tang-keys.json`, e.g. `npm run upload-key -- rotated-keys.json`,
   if the file isn't under that name.
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

`wrangler.toml` also declares a per-IP rate limit (60 requests/minute), a
backstop against one source — an allowed IP with a retry-loop bug, or a
disallowed one probing — repeatedly paying for the KV read and whatever
follows it. Nothing to set up here: it takes effect straight from this
file once deployed.

### 5. Set the allowed IP address

```sh
npm run set-allowlist -- 203.0.113.4/32
```

The real IP address, or comma-separated CIDR ranges, of the machine(s) this
Worker will serve. It's set directly in Cloudflare's KV store, independent
of `wrangler.toml` and of any deploy, so the VPS's real IP never ends up
committed to this repo, and changing it later doesn't need a redeploy.
`npm run get-allowlist` reads the current value back, if you ever need to
check it.

`npm run set-allowlist` first validates the list with `check-allowlist`,
the same parser the Worker itself uses, since the Worker's own parsing
silently drops any entry that fails to parse rather than failing the whole
request. A typo here would otherwise go unnoticed until the VPS actually
needs to unlock.

### 6. Deploy

```sh
npm run deploy
```

### 7. Point the VPS at it

On the machine being unlocked, `clevis` needs pointing at this Worker's
`*.workers.dev` URL (or a custom domain) as its Tang server. That side of
the setup (Clevis, the disk encryption itself, and the boot-time unlock
script) lives elsewhere; this repo is only the server.

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

## Security notes

Losing the keys is unrecoverable by design: Tang has no backdoor, so there's
no way to reconstruct them, for you or anyone else. That's also what makes
it safe to let a third party (Cloudflare) hold them. Cloudflare gets the
keys, but the wrapped key on the VPS's disk never touches Cloudflare at all.
Neither half is useful without the other.

The IP allowlist narrows who can even ask. Without it, anyone who ever got a
copy of the VPS's disk (an old backup, a stolen snapshot) could complete the
unlock from anywhere, since Tang itself doesn't check who's asking. With it,
they'd also need to be making that request from the VPS's own network
address, which a copy of a disk alone doesn't get them.

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE).

## AI usage

This repository discloses AI involvement per the
[ai-disclosure](https://github.com/ggfevans/ai-disclosure) convention; see
[AI_DISCLOSURE.md](AI_DISCLOSURE.md) for details.
