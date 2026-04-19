# ayllu

*Ayllu* (Quechua) is an Andean community organized around mutual aid. The same idea applies here: connectivity through cooperating nodes rather than centralized infrastructure.

Censorship-resistant protocol, polymorphic-camouflage transport layer, and async chat, written in Zig 0.16.

Designed for users whose ISP or state actor aggressively filters Telegram, WhatsApp, YouTube, or arbitrary TCP, and where an off-the-shelf VPN gets detected and blocked within hours.

Full specification: [SPEC.md](SPEC.md).

## Build

```sh
zig build                          # builds both CLIs: ayllu and ayllu-proxy
zig build run                      # ayllu: lists phase-1 subsystems
zig build run-proxy -- --help      # ayllu-proxy: SOCKS5 daemon
zig build test                     # runs all tests (core/ + proxy/)
```

Requires Zig **0.16.0** or newer. Prefer `-Doptimize=ReleaseFast` for production VPS builds.

## What is implemented

**Phase-1 core** (protocol):

- `core/crypto` — Ed25519 + X25519 + SHA-256 peer fingerprint (domain-tag `ayllu.fp.v1`).
- `core/identity` — `Identity` (runa) + `PublicIdentity`; X25519 is always derived from Ed25519.
- `core/envelope` — `Envelope` (quipu) with signed digest, TTL, three Target variants.
- `core/transport` — vtable-based interface + `InMemoryTransport` loopback.
- `core/registry` — OR-Set CRDT for group membership.

**Phase-3 SOCKS5 proxy**:

- `proxy/socks5` — RFC 1928 parser/encoder with golden vectors.
- `proxy/auth` — RFC 1929 username/password auth, constant-time compare.
- `proxy/relay` — bidirectional TCP copy through `std.Io`; `bidirectionalWithDeadline` for absolute session caps.
- `proxy/timeouts` — `std.Io.Timeout`/`Select`-based wrappers for handshake read, upstream connect, and relay deadlines.
- `proxy/daemon` — handshake + upstream connect (DNS via `std.Io.net.HostName.connect`); full session wrapped in a handshake-level deadline.
- `ayllu-proxy` binary — accept loop on `std.Io.Threaded`.

Verified end-to-end: `curl` through `socks5h://localhost:PORT` fetches HTTPS with domain names resolved on the proxy side.

**Phase-4 camouflage** (production hardening landed; full REALITY TLS wire-compat is next):

- `camouflage/reality` — X25519 admission + HMAC-SHA256 auth material.
- `camouflage/tokens` — time-keyed HMAC handshake tokens + replay cache.
- `camouflage/pivot` — HTTP-like admission parser + classify (fallback/pivot).
- `camouflage/reverse_proxy` — honest TCP-passthrough to a real cover host when admission fails; buffered head replayed so an active probe gets byte-for-byte what the cover site returned.
- `camouflage/cover_pool` — weighted multi-site cover rotation (per-connection pick).
- `camouflage/rate_limit` — per-/24 admission-failure token bucket; trips into silent-drop mode so short_id can't be enumerated for free.
- `camouflage/metrics` — Prometheus-style counter registry + `/metrics` HTTP endpoint on a separate listener.
- `camouflage/server` + `camouflage/client` — gateway (outer admission → inner SOCKS5) and local bridge (local SOCKS5 → remote admission → pivot).
- Binaries: `ayllu-camouflage-proxy`, `ayllu-camouflage-client`, `ayllu-reality-keygen`.

`zig build test --summary all`: 193/193 passing.

## VPS deployment

The deployment below is for a single operator running one VPS to serve a small trusted group of SOCKS5-capable clients (Telegram, qBittorrent, curl, any other app with a SOCKS5 setting). It is not a multi-tenant service.

### 1. Provision a VPS

Pick a jurisdiction whose network path is outside the censor's DPI (common European picks: Netherlands, Finland, Estonia). Minimum 1 CPU / 1 GB RAM. Use a clean IP that is not already in known block lists — verify via `bgp.tools` or equivalent.

### 2. Build the binaries

```sh
# on the VPS (Linux)
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

# REALITY keypair + short_id (save the public key somewhere the client can read it).
ayllu-reality-keygen | sudo tee /etc/ayllu/reality.txt

# Per-user credentials. One `username:password` per file.
sudo tee /etc/ayllu/credentials <<< 'alice:strongish-password'
sudo chown root:ayllu /etc/ayllu/credentials
sudo chmod 640 /etc/ayllu/credentials

# Copy the service environment template and fill in.
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

#### Local camouflage bridge (recommended)

On the client machine, run `ayllu-camouflage-client` pointed at your VPS:

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

In Telegram: `Settings` → `Data and Storage` → `Proxy Settings` → `Add Proxy` → `SOCKS5`:
- Server: `127.0.0.1`
- Port: `1080`
- Username / Password: as in the credentials file (or blank if the bridge handles it).

In Telegram Desktop, check `Use proxy for calls` so voice/video go through the bridge as well.

#### Optional metrics scraping

Add `--metrics-listen 127.0.0.1:9090` to the server unit; Prometheus or Grafana Agent can scrape counters for admission success/fallback/silent-drop, session counts, and upstream errors. Counters tell you when your VPS is being actively probed.

### What is still not covered

- **Full Xray-compatible REALITY TLS 1.3** wire format (plain TLS ClientHello on the outer socket). The current admission is HTTP-like-over-TCP and is detectable by sophisticated DPI on sustained observation. Next session's work.
- **SIGHUP hot-reload** of keys and cover pool — currently a `systemctl restart` is required after editing `/etc/ayllu/camouflage.env`.
- **UDP (ASSOCIATE)** in the SOCKS5 layer — TCP fallback is sufficient for Telegram voice/video.
- **iOS system-wide traffic**: SOCKS5 only covers apps that accept proxy settings. iOS Safari and native apps need WireGuard-over-Ayllu (phase 7).

## Structure

```
core/        phase-1 protocol primitives (done, hardened)
proxy/       phase-3 SOCKS5 + auth + timeouts (done, end-to-end verified)
camouflage/  phase-4 hardening landed; full REALITY TLS wire-compat next
cli/         binaries: ayllu, ayllu-proxy, ayllu-camouflage-proxy,
             ayllu-camouflage-client, ayllu-reality-keygen
deploy/      systemd unit + env template for VPS rollout
chat/        phase-2 — not started
mesh/        phase-13+ — later phases
prototypes/  mesh-chat-disposable.html — reference UI for phase-2
```

## Terminology

- *ayllu* — the network
- *quipu* — envelope (traffic unit)
- *runa* — identity
- *tambo* — node (phase-13)
