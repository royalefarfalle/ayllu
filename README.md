# ayllu

*Ayllu* (Quechua) is an Andean community organized around mutual aid. The same idea applies to the network: connectivity through cooperating nodes rather than one central box.

**What this repo is.** Zig 0.16 toolkit for SOCKS5 proxying with a pluggable outer transport (the "camouflage" layer). Built on `std.Io` for async + cancellation. The envelope layer in `core/` is transport-agnostic — a `Transport` vtable over `Envelope`, with `InMemoryTransport` today and WebSocket / WireGuard / LoRa left for later phases — so the same core can eventually ride whatever the wire turns out to be.

**What this repo is not.** Not a messenger, not a chat UI, no HTML. This is the transport and proxy infrastructure. Any user-facing surface lives in a separate repo.

**Target adversary.** TLS-fingerprinting, active-probing, short-id-enumerating middleboxes (DPI circa 2026). We don't claim resilience ahead of the work landing; incident reports go in commit messages, not the README.

Full specification: [SPEC.md](SPEC.md).

## Build

```sh
zig build                          # all binaries (ayllu, ayllu-proxy, ayllu-camouflage-*)
zig build test                     # runs full suite
zig build run-proxy -- --help      # SOCKS5 daemon
```

Requires Zig **0.16.0**. Prefer `-Doptimize=ReleaseFast` for production VPS builds.

## What is implemented

**Phase-1 core** (protocol primitives):

- `core/crypto` — Ed25519 + X25519 + SHA-256 peer fingerprint (domain-tag `ayllu.fp.v1`).
- `core/identity` — `Identity` (runa) + `PublicIdentity`; X25519 is always derived from Ed25519.
- `core/envelope` — `Envelope` (quipu) with signed digest, TTL, three Target variants.
- `core/transport` — vtable interface + `InMemoryTransport` loopback. Concrete transports land later.
- `core/registry` — OR-Set CRDT for future group membership.

**Phase-3 SOCKS5 proxy** (end-to-end verified):

- `proxy/socks5` — RFC 1928 parser/encoder with golden vectors.
- `proxy/auth` — RFC 1929 username/password auth, constant-time compare.
- `proxy/relay` — bidirectional TCP copy through `std.Io`; `bidirectionalWithDeadline` for absolute session caps.
- `proxy/timeouts` — `std.Io.Timeout`/`Select`-based wrappers for handshake read, upstream connect, relay deadlines.
- `proxy/daemon` — handshake + upstream connect (DNS via `std.Io.net.HostName.connect`); full session wrapped in a handshake-level deadline. Also `sessionOnPreparedStreamDirect` for transports that carry the target in-band.
- `ayllu-proxy` binary — accept loop on `std.Io.Threaded`.

Verified: `curl` through `socks5h://localhost:PORT` fetches HTTPS with domain names resolved on the proxy side.

**Phase-4 camouflage** (HTTP-like admission landed; REALITY TLS in progress):

- `camouflage/transport` — `OuterTransport` vtable so multiple outer wire-formats share one dispatcher.
- `camouflage/legacy_http_transport` — current HTTP-like admission as a first-class `OuterTransport` impl.
- `camouflage/reality` — X25519 admission + HMAC-SHA256 auth material.
- `camouflage/tokens` — time-keyed HMAC handshake tokens + replay cache.
- `camouflage/pivot` — HTTP-like admission parser + classify (fallback/pivot).
- `camouflage/reverse_proxy` — honest TCP-passthrough to a real cover host when admission fails; buffered head replayed so an active probe gets byte-for-byte what the cover site returned.
- `camouflage/cover_pool` — weighted multi-site cover rotation (per-connection pick).
- `camouflage/rate_limit` — per-/24 admission-failure token bucket; trips into silent-drop mode so short_id can't be enumerated for free.
- `camouflage/metrics` — Prometheus-style counter registry + `/metrics` HTTP endpoint on a separate listener.
- `camouflage/tls/record` — TLS 1.3 record layer (header parse/write, AEAD seal/open over AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305; nonce = iv XOR seq). RFC 8448 KAT.
- `camouflage/tls/keys` — TLS 1.3 key schedule (Early/Handshake/Master secrets + traffic keys via HKDF-Expand-Label). RFC 8448 KAT.
- `camouflage/tls/client_hello` — ClientHello parser (SNI, supported_versions, key_share, session_id, ALPN, sig_algs).
- `camouflage/server` + `camouflage/client` — gateway (outer admission → inner SOCKS5) and local bridge (local SOCKS5 → remote admission → pivot).
- Binaries: `ayllu-camouflage-proxy`, `ayllu-camouflage-client`, `ayllu-reality-keygen`.

`zig build test --summary all`: 242/242 passing.

## VPS deployment

Single-operator, small trusted group of SOCKS5-capable clients (Telegram, curl, qBittorrent, anything that takes a SOCKS5 setting). Not a multi-tenant service.

### 1. Provision a VPS

Pick a jurisdiction whose network path is outside the adversary's DPI (common European picks: NL, FI, EE). Minimum 1 CPU / 1 GB RAM. Use a clean IP — verify via `bgp.tools` or equivalent.

### 2. Build the binaries

```sh
wget https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz
tar xf zig-x86_64-linux-0.16.0.tar.xz
export PATH="$PWD/zig-x86_64-linux-0.16.0:$PATH"

git clone <url> ayllu && cd ayllu
zig build -Doptimize=ReleaseFast
sudo install -m 755 zig-out/bin/ayllu-camouflage-proxy /usr/local/bin/
sudo install -m 755 zig-out/bin/ayllu-reality-keygen   /usr/local/bin/
```

### 3. Generate REALITY keys + cover pool + auth file

```sh
sudo useradd -r -s /usr/sbin/nologin ayllu
sudo mkdir -p /etc/ayllu
sudo chown root:ayllu /etc/ayllu && sudo chmod 750 /etc/ayllu

ayllu-reality-keygen | sudo tee /etc/ayllu/reality.txt

sudo tee /etc/ayllu/credentials <<< 'alice:strongish-password'
sudo chown root:ayllu /etc/ayllu/credentials
sudo chmod 640 /etc/ayllu/credentials

sudo cp deploy/camouflage.env.example /etc/ayllu/camouflage.env
sudo chown root:ayllu /etc/ayllu/camouflage.env
sudo chmod 640 /etc/ayllu/camouflage.env
sudoedit /etc/ayllu/camouflage.env   # paste AYLLU_PRIVATE_KEY + AYLLU_SHORT_ID
```

### 4. Install the systemd unit

```sh
sudo cp deploy/ayllu-camouflage-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ayllu-camouflage-proxy
sudo journalctl -u ayllu-camouflage-proxy -f
```

The shipped unit already:

- Binds `${AYLLU_LISTEN}` (default `0.0.0.0:443`).
- Ships a weighted cover pool (Ubuntu/Debian/Microsoft mirrors) for the honest-fallback reverse proxy.
- Enforces the admission failure rate limit (20 failures / 60 s → 5 min silent drop).
- Requires `--auth-file /etc/ayllu/credentials`.
- Runs under systemd sandbox hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `RestrictAddressFamilies`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, …).

### 5. Firewall (recommended, not mandatory)

The built-in rate limiter + `--auth-file` keep anonymous abuse cheap, but a layer-3 filter still helps:

```sh
sudo ufw default deny incoming
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

For the strongest posture, replace the `443/tcp` blanket rule with an IP allowlist of your clients. Dynamic-IP clients should use `--auth-file` and leave `443/tcp` open.

### 6. Configure a client

On the client machine:

```sh
ayllu-camouflage-client \
  --listen 127.0.0.1:1080 \
  --remote <VPS IP or hostname>:443 \
  --server-name www.microsoft.com \
  --public-key <base64url> \
  --short-id <hex> \
  --auth-file ./credentials
```

Then point Telegram / any other SOCKS5 app at `127.0.0.1:1080`.

#### Optional metrics scraping

Add `--metrics-listen 127.0.0.1:9090` to the server unit; Prometheus or Grafana Agent can scrape counters for admission success/fallback/silent-drop, session counts, upstream errors. Counters tell you when your VPS is being actively probed.

### What is still not covered

- **Full Xray-compatible REALITY TLS 1.3** wire format on the outer socket. The current admission is HTTP-like over plain TCP and is detectable by sophisticated DPI on sustained observation. In progress — see [plans/generic-strolling-toast.md](.claude/plans/generic-strolling-toast.md) when present.
- **Shadowsocks-2022** as a second independent outer transport.
- **SIGHUP hot-reload** of keys and cover pool — currently `systemctl restart` is required after editing `/etc/ayllu/camouflage.env`.
- **UDP (ASSOCIATE)** in the SOCKS5 layer — TCP fallback is sufficient for Telegram voice/video.
- **iOS system-wide traffic**: SOCKS5 only covers apps that accept proxy settings. iOS Safari and native apps would need WireGuard-over-Ayllu.

## Structure

```
core/        phase-1 protocol primitives (done, hardened)
proxy/       phase-3 SOCKS5 + auth + timeouts (done, end-to-end verified)
camouflage/  outer-transport vtable + HTTP-like admission (done) + TLS/SS in progress
cli/         binaries: ayllu, ayllu-proxy, ayllu-camouflage-proxy,
             ayllu-camouflage-client, ayllu-reality-keygen
deploy/      systemd unit + env template for VPS rollout
```

## Terminology

- *ayllu* — the network
- *quipu* — envelope (traffic unit)
- *runa* — identity
- *tambo* — node (future)
