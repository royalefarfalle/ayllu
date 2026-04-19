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

**Phase-3 SOCKS5 proxy** (MVP):

- `proxy/socks5` — RFC 1928 parser/encoder.
- `proxy/relay` — bidirectional TCP copy through `std.Io`.
- `proxy/daemon` — handshake + upstream connect (including DNS via `std.Io.net.HostName.connect`).
- `ayllu-proxy` binary — accepts connections via an accept loop on `std.Io.Threaded`.

Verified end-to-end: `curl` through `socks5h://localhost:PORT` fetches HTTPS (ziglang.org), with domain names resolved on the proxy side (ATYP=domain).

## Example VPS deployment

The deployment below targets a single operator running one VPS to serve a small trusted group (typically a handful of SOCKS5-capable clients such as Telegram). It is not a multi-tenant service.

### 1. Provision a VPS

Prefer a jurisdiction whose network path is outside the censor's DPI (commonly the Netherlands, Finland, or Estonia for European users). Minimum 1 CPU / 1 GB RAM. Use a clean IP that is not already in known block lists — verify via `bgp.tools` or equivalent.

### 2. Build the binary

```sh
# on the VPS (Linux)
wget https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz
tar xf zig-x86_64-linux-0.16.0.tar.xz
export PATH="$PWD/zig-x86_64-linux-0.16.0:$PATH"

git clone <url> ayllu && cd ayllu
zig build -Doptimize=ReleaseFast
# produces zig-out/bin/ayllu-proxy (~500 KB)
```

### 3. Systemd unit (`/etc/systemd/system/ayllu-proxy.service`)

```ini
[Unit]
Description=Ayllu SOCKS5 proxy
After=network-online.target

[Service]
Type=simple
User=ayllu
ExecStart=/usr/local/bin/ayllu-proxy --listen 0.0.0.0:443
Restart=on-failure
RestartSec=3

# sandbox
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

**Port 443** blends best with ambient HTTPS traffic seen from outside. If the VPS already serves an HTTPS site, either use a different port (e.g. 8443) or run an nginx-stream SNI splitter in front.

```sh
sudo useradd -r -s /usr/sbin/nologin ayllu
sudo install -m 755 zig-out/bin/ayllu-proxy /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now ayllu-proxy
```

### 4. Firewall — mandatory

Without authentication anyone on the internet can relay traffic through your VPS (proxy-abuse puts your IP on spam lists). Restrict access to the static IPs of your intended clients:

```sh
# ufw example
sudo ufw default deny incoming
sudo ufw allow from <client IP> to any port 443 proto tcp
sudo ufw allow 22/tcp        # SSH for the operator
sudo ufw enable
```

If clients use a dynamic IP, either set up DDNS + a cron job that refreshes the rule, or wait for phase-4 Reality (camouflage), after which active-probing DPI reaches a legitimate whitelisted site instead of raw SOCKS5.

### 5. Configure a SOCKS5 client (Telegram as one example)

In the Telegram mobile or desktop client:
`Settings` → `Data and Storage` → `Proxy Settings` → `Add Proxy` → `SOCKS5`
- Server: `<VPS IP or hostname>`
- Port: `443`
- Username / Password: empty

In Telegram Desktop: same path, plus `Use proxy for calls` for voice and video.

Once enabled, Telegram works immediately: messages, calls, and the embedded browser (YouTube loads through it as well).

Any other SOCKS5-capable client follows the same pattern.

### What the current MVP does NOT cover

- **DPI active-probing**: plain SOCKS5 on `:443` can be fingerprinted within 10–30 minutes by sophisticated censors. The mitigation is phase-4 Reality (on the roadmap).
- **Authentication**: firewall-level IP allowlist only. Username/password auth is the next checkpoint.
- **UDP (ASSOCIATE)**: not implemented — Telegram's TCP fallback is sufficient for calls, but UDP would add roughly 100 lines if needed.
- **iOS system Safari and system-wide traffic**: SOCKS5 only covers apps that accept proxy configuration. System-level coverage requires phase-7 WireGuard-over-Ayllu.

## Structure

```
core/        phase-1 (done)
proxy/       phase-3 SOCKS5 MVP (done)
cli/         ayllu + ayllu-proxy binaries
chat/        phase-2 — not started
camouflage/  phase-4 Reality — not started
mesh/        phase-13+ — later phases
prototypes/  mesh-chat-disposable.html — reference UI for phase-2
```

## Terminology

- *ayllu* — the network
- *quipu* — envelope (traffic unit)
- *runa* — identity
- *tambo* — node (phase-13)
