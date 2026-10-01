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
cargo run --release --bin keygen > tang-keys.json
```

This generates the two keys Tang needs and prints them together as one JSON
file. There's no way to recover them if they're lost, so before anything
else:

1. Copy `tang-keys.json` into a password manager or other durable, offline
   backup.
2. Upload it to Cloudflare: `wrangler secret put TANG_KEYS < tang-keys.json`
3. Delete the local file.

To rotate the keys later, repeat this whole process. It replaces the key set
entirely rather than extending it, so any machine still bound to the old
keys will need rebinding.

### 4. Set the allowed IP address

Edit `ALLOWED_CIDRS` in `wrangler.toml` to the real IP address of the
machine this Worker will serve, and commit the change: this file is the
record of who's allowed to reach it.

### 5. Deploy

```sh
npm run deploy
```

### 6. Point the VPS at it

On the machine being unlocked, `clevis` needs pointing at this Worker's
`*.workers.dev` URL (or a custom domain) as its Tang server. That side of
the setup (Clevis, the disk encryption itself, and the boot-time unlock
script) lives elsewhere; this repo is only the server.

## Local development

```sh
npx wrangler dev
```

Needs its own local `TANG_KEYS` secret and `ALLOWED_CIDRS` value to answer
requests; see Cloudflare's docs on `wrangler dev` for supplying secrets
locally.

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
