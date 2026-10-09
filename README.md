# tang-cloudflare

A [Tang](https://github.com/latchset/tang) server, deployed as a Cloudflare
Worker.

## Background

Encrypting a disk "at rest" only protects it if the key to unlock it isn't
just sitting on the same machine. If the key does live there (so the
machine can boot on its own, without someone typing a passphrase), that
encryption doesn't protect against much: anyone who gets a copy of the disk
gets the key too.

Network-Bound Disk Encryption (NBDE) is a way around that. The unlock key is
stored on disk only in a wrapped, encrypted form. Unwrapping it requires
talking to a separate server, over the network, at boot, and that server
never learns the actual key either. So:

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
a client uses to complete the unlock exchange. Ordinarily it answers anyone
who asks, since it's designed to serve any number of clients and holds
nothing specific to any of them.

This deployment is narrower: it's meant to serve exactly one machine (a
VPS), so it only answers requests from that machine's IP address. There's no
password or token check layered on top. The Linux tool that actually talks
to Tang (`clevis`) has no way to send one, so the IP address is the only
thing there is to check.

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
file. There's no way to recover them if they're lost, so before anything
else:

1. Copy `tang-keys.json` into a password manager or other durable, offline
   backup.
2. Upload it to Cloudflare: `npm run upload-key`. This first validates the
   file with `check-key`, the same parsing and initialization the Worker
   itself runs, catching a corrupt or malformed key before it ever reaches
   Cloudflare. Takes a path other than `tang-keys.json`, e.g.
   `npm run upload-key -- rotated-keys.json`, if the file isn't under that
   name.
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
<THUMBPRINT>` select differently. Every `keygen` command prints each
generation's thumbprint to stderr, since that's the only identifier `prune
--thumbprint` takes.

### 4. Create the allowlist's KV namespace

```sh
npx wrangler kv namespace create tang-allowed-cidrs
```

Paste the printed `id` into `wrangler.toml`'s `[[kv_namespaces]]` block, in
place of `REPLACE_WITH_NAMESPACE_ID`. A one-time step: every future deploy
reuses the same namespace once its `id` is there.

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
