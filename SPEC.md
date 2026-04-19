# ayllu — technical specification

> *Ayllu* (Quechua) is an Andean community built on mutual support. This repo inherits the principle at the wire level: connectivity through cooperating nodes rather than centralized infrastructure.

## What this is

Ayllu is a **Zig 0.16 toolkit for SOCKS5 proxying with a pluggable outer transport.** The outer transport ("camouflage" in this codebase) is what the DPI box sees; the inner proxy is a plain SOCKS5 session that any app with a proxy setting (Telegram, curl, qBittorrent, WhatsApp) can speak.

Core is transport-agnostic. Envelope delivery lives behind a `Transport` vtable in [core/transport.zig](core/transport.zig); the only shipping impl today is `InMemoryTransport` (for tests). TCP, WebSocket, WireGuard, and LoRa are left for later phases — the abstraction is already there.

## What this is **not**

- Not a messenger, not a chat UI. No HTML. No web shell. Any user-facing surface lives in a separate repo.
- Not a claim that traffic survives modern DPI. Individual outer-transport impls (REALITY TLS 1.3, Shadowsocks-2022) land one checkpoint at a time with tests and KAT. Resilience is demonstrated in commits, not asserted in docs.
- Not a VPN. Not yet, anyway — WireGuard-over-Ayllu is listed as future scope.

## Use cases (current and planned)

| Task | Transport | Status |
|---|---|---|
| Telegram messages | SOCKS5 via ayllu-camouflage | works, HTTP-like admission |
| Telegram voice/video | SOCKS5 + "Use Proxy for Calls" | works, TCP fallback |
| Telegram in-app browser | SOCKS5 | works |
| WhatsApp | SOCKS5 (in settings) | works |
| curl / qBittorrent / anything with SOCKS5 | SOCKS5 | works |
| All iOS system traffic | WireGuard-over-Ayllu | not started |

## Positioning

| System | Strength | Weakness |
|---|---|---|
| Xray/V2Ray | Proxy + camouflage fleet | Go runtime fingerprint, heavy deps |
| Tor | Anonymity | Not for daily proxying, detectable |
| Reticulum | Transport-agnostic mesh | Python, no camouflage |
| Shadowsocks-only deploys | Simple, wide client coverage | Outer shape is detectable |

Ayllu sits closer to Xray than anything else on that list: same use case (SOCKS5/VPN over a camouflaged outer), different stack (Zig, hand-rolled wire, smaller surface). The goal is to speak Xray's wire so the existing client ecosystem (v2rayN, Nekobox, sing-box, Streisand) works out of the box.

## Why Zig 0.16

- **`std.Io` as abstraction** — every transport is an implementation of the same Reader/Writer pair. `std.Io.Threaded` today; `std.Io.Uring` (Linux io_uring) and `std.Io.Kqueue` (BSD) are drop-in swaps.
- **Cancellation is built in** — `Io.Timeout`, `Io.Select`, `Io.Cancelable`. No hand-rolled deadline arithmetic.
- **`std.crypto` is cutting-edge** — Ed25519, X25519, AES-GCM, ChaCha20-Poly1305, HKDF, SHA-256/384 are all in the stdlib; `std.crypto.tls` has the record constants + `hkdfExpandLabel` for a hand-rolled TLS 1.3 server.
- **Static binary of 500 KB to 2 MB** — no runtime to fingerprint.
- **No background thread pool unless asked** — predictable syscalls under DPI observation.

## Architecture

### Core (transport-agnostic)

[core/](core/) holds the protocol primitives. None of these files know about TCP or TLS.

- **`crypto.zig`** — wrappers over `std.crypto`. Ed25519, X25519, SHA-256, fingerprint with domain tag `ayllu.fp.v1`.
- **`identity.zig`** — `Identity` (runa) holds both keypairs; `PublicIdentity` is the exportable half.
- **`envelope.zig`** — format:
  ```
  Envelope = {
    version: u8,
    id: [16]u8,
    from: Fingerprint,
    to: Target,            // broadcast | fingerprint | group
    created_at: i64,
    expires_at: i64,
    route_hints: []TransportHint,
    payload: EncryptedPayload,
    signature: [64]u8,
  }
  ```
- **`transport.zig`** — `Transport` vtable (`send`, `recv`, `name`) over `Envelope`. `InMemoryTransport` for tests. Future impls: WebSocket, WireGuard, LoRa.
- **`registry.zig`** — OR-Set CRDT for future group state.

### Proxy layer

[proxy/](proxy/) is a pure SOCKS5 implementation over `std.Io.Reader`/`std.Io.Writer`. No direct TCP — relay works on abstract Reader/Writer pairs, so anything that can provide those (plain TCP today, TLS tomorrow) can feed it.

- **`socks5.zig`** — RFC 1928 parser/encoder. Pure, fixed-stream.
- **`auth.zig`** — RFC 1929 username/password, constant-time compare.
- **`relay.zig`** — `pipeAll` + `bidirectionalWithDeadline`. The workhorse.
- **`timeouts.zig`** — `Io.Timeout` + `Io.Select` wrappers for accept / handshake / upstream / idle.
- **`daemon.zig`** — orchestrates one session: handshake → upstream connect → reply → relay. Two entry points:
  - `sessionOnPreparedStream` — runs full SOCKS5 handshake on an arbitrary Reader/Writer.
  - `sessionOnPreparedStreamDirect` — skips the handshake, relays straight to a known target. Used by transports that carry the target in-band (Shadowsocks).

### Camouflage layer

[camouflage/](camouflage/) is the outer wire. The `OuterTransport` vtable in [camouflage/transport.zig](camouflage/transport.zig) lets multiple outer impls share one dispatcher, one rate-limit, one metrics registry, one fallback path.

Current shipping impls:

- **`legacy_http_transport.zig`** — HTTP-like admission over plain TCP. Retained for local-bridge use and backward compat with the pre-TLS setup.

In flight (split across checkpoints, see `.claude/plans/generic-strolling-toast.md`):

- **REALITY TLS 1.3 server** (Xray v25.x wire-compat) — `camouflage/tls/{record,keys,handshake,xray_wire,reality_transport}.zig`. Record layer + key schedule + ClientHello parser landed; ForgedServerHello synth and Xray binding in progress.
- **Shadowsocks-2022** (blake3 AEAD, separate request/response salts) — `proxy/shadowsocks/{aead,wire,transport}.zig`. Not started.

Supporting pieces (all done):

- **`reality.zig`** — REALITY AuthKey derivation (X25519 + HMAC over transcript).
- **`tokens.zig`** — time-keyed HMAC tokens + replay cache.
- **`pivot.zig`** — classifier that turns a parsed request into pivot / fallback decisions.
- **`reverse_proxy.zig`** — honest TCP-passthrough to a real cover host on admission failure. The buffered preface is replayed byte-for-byte; the cover site's response is what the adversary sees.
- **`cover_pool.zig`** — weighted rotation across cover hosts.
- **`rate_limit.zig`** — per-/24 admission-failure bucket, silent-drop mode.
- **`metrics.zig`** — Prometheus-style counters + `/metrics` HTTP endpoint on a separate listener.

## Development phases (honest status)

| Phase | Deliverable | Status |
|---|---|---|
| 1 | core primitives | done |
| 3 | SOCKS5 proxy | done, end-to-end verified |
| 4a | HTTP-like camouflage + fallback + rate-limit + metrics | done |
| 4b | REALITY TLS 1.3 outer (Xray v25.x) | in progress — record+keys+ClientHello landed |
| 4c | Shadowsocks-2022 outer | not started |
| 5 | SIGHUP hot-reload + RCU state | not started |
| 6 | WireGuard-over-Ayllu (iOS system traffic) | future |
| 7 | mesh baseline (multi-hop via `Transport` vtable) | future |
| 8 | mesh transports (LoRa, APRS, …) | future |

Everything below phase 5 is speculative scaffolding; don't build expectations around it.

## Principles

- Essential surface ≤ 15 000 lines of Zig.
- Maximum use of `std.crypto`, `std.Io`.
- Private keys never leave the device.
- Standards only: Ed25519, X25519, AES-GCM, ChaCha20-Poly1305, HKDF, SHA-256/384.
- Tests 1:1 or 2:1 for crypto.
- Core stays transport-agnostic. TCP / TLS / LoRa are impl details, not assumptions in `core/`.

## Terminology

- *ayllu* — the network
- *quipu* — envelope
- *runa* — identity
- *tambo* — node

---

**Status:** v0.6. Dropped chat/PWA framing; this repo is now strictly proxy + camouflage infrastructure. Any user-facing surface is a separate project.
