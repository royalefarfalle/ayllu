# ayllu.sh — technical specification

> *Ayllu* (Quechua) is an Andean community built on mutual support and collective labor. This system inherits the same principle: connectivity through cooperating nodes rather than centralized infrastructure.

## What it is

**Ayllu is a censorship-resistant connectivity protocol and transport layer for tunneling** under aggressive DPI. It operates both as a standalone messenger and as an invisible transport for existing applications.

Three layers:

1. **PROTOCOL.md** (later) — wire-format specification
2. **ayllu-core** — reference implementation in Zig 0.16
3. **ayllu-apps** — reference applications:
   - `ayllu-chat` — standalone messenger (async + chat UI)
   - `ayllu-proxy` — transport layer for third-party protocols and a system-wide VPN

## Covered use cases

| Task | Transport | Works? |
|---|---|---|
| Telegram messages | SOCKS5 proxy | yes |
| Telegram voice/video calls | SOCKS5 + "Use Proxy for Calls" | yes (TCP fallback) |
| Telegram in-app browser → YouTube | SOCKS5 | yes |
| Telegram in-app browser → arbitrary blocked sites | SOCKS5 | yes |
| Telegram Web Apps and bots | SOCKS5 | yes |
| WhatsApp | SOCKS5 (in settings) | yes |
| System Safari/Chrome → blocked sites | WireGuard-over-Ayllu | yes |
| All device traffic (iOS system VPN) | WireGuard-over-Ayllu | yes |
| YouTube in the native app | WireGuard-over-Ayllu | yes |
| Standalone encrypted group chat | ayllu-chat PWA | yes |
| Video calls inside ayllu-chat | WebRTC in the PWA | yes |

**Two operating modes:**

1. **Targeted proxying** via SOCKS5 — configured inside Telegram or any other app that accepts a proxy. Covers that app and everything it opens (including embedded browsers).
2. **System-wide VPN** via WireGuard-over-Ayllu — all device traffic routes through Ayllu. Covers everything, including iOS Safari.

Both modes use polymorphic camouflage: the traffic looks benign to DPI.

## Positioning

| System | Strength | Weakness |
|---|---|---|
| Signal | E2E, UX | Centralized, detectable |
| Matrix | Federation | DPI-detectable, heavyweight |
| Briar | P2P, deniability | Android-only, slow |
| Meshtastic | LoRa mesh | No internet, no E2E groups |
| Tor | Anonymity | Not for chat, detectable |
| Reticulum | Transport-agnostic | Python, UX, no camouflage |
| Xray/V2Ray | Proxy + camouflage | Go fingerprints, no chat |

**Ayllu = Reticulum + Reality + modern UX + proxy platform + polymorphic protocol.**

## Why Zig 0.16

- **`Io` as abstraction**: every transport is an implementation of the same interface.
- **Cancellation is built in**: parallel attempts with automatic cancellation of the losers.
- **`std.crypto` is cutting-edge**: Ed25519, Curve25519, AES-GCM-SIV.
- **Static binary of 500 KB to 2 MB.**
- **No runtime fingerprint**: full byte-level control, unlike Go/Python stacks.
- **One codebase, every platform**: io_uring, Termux, ESP32.

## Architecture

### Async-first core with a chat-like UI

**Under the hood:** store-and-forward. Envelopes with an ID, TTL, and cryptographic framing.

**In the UI:** chat bubbles, timestamps, delivery status, transparent mode indication.

**Live mode:** WebRTC opened only when both peers are online via a fast transport.

### Ayllu as a proxy and VPN platform

- **MTProto proxy** — Telegram over `ayllu.sh:443`.
- **SOCKS5** — universal, works for any app (TCP + UDP through extensions).
- **Shadowsocks-over-Ayllu** — migration path for existing SS clients.
- **WireGuard-over-Ayllu** — system-wide VPN, routes all device traffic.

All proxy traffic is camouflaged through the polymorphic protocol. DPI sees ordinary HTTPS to an innocuous site.

### Polymorphic protocol — the cutting-edge goal

**Three-phase handshake with camouflage and pivot:**

**Phase 1 — camouflage:** the server answers a TLS ClientHello as if it were a whitelisted site (a major CDN, a cloud provider, or any other allowlisted target). The certificate is genuine via Reality. DPI sees whitelisted traffic.

**Phase 2 — secret handshake:** the client sends a cryptographic token disguised as an ordinary HTTP request. Time-based, not replayable.

**Phase 3 — pivot:** the server recognizes the token and switches to the Ayllu transport. If the token is wrong, the server transparently proxies to the cover domain (so an active-probing DPI sees real content from a real site).

**Polymorphic extensions:**

- **Multi-site camouflage**: rotation across a pool of whitelisted cover domains.
- **Protocol shape-shifting**: HTTPS/2 → HTTP/3 QUIC → WebSocket to commonly used services; same inner protocol, different outer shape.
- **Cover traffic**: synthetic requests that mimic ordinary browsing.
- **Time-keyed tokens**: handshake tokens expire within seconds.

**No one has seriously built a polymorphic protocol for mesh systems.** Zig 0.16 gives the byte-level control needed for it.

## Repository layout

```
ayllu.sh/
├── SPEC.md
├── PROTOCOL.md                # later
├── core/                      # ~3000 lines
│   ├── crypto.zig
│   ├── identity.zig
│   ├── envelope.zig
│   ├── transport.zig
│   └── registry.zig
├── chat/                      # ~3000 lines
│   ├── server.zig
│   ├── signaling.zig
│   └── web/
│       └── index.html
├── proxy/                     # ~4000 lines
│   ├── socks5.zig
│   ├── mtproto.zig
│   ├── shadowsocks.zig
│   └── wireguard.zig          # system-wide VPN
├── camouflage/                # ~3000 lines
│   ├── reality.zig
│   ├── multi_site.zig
│   ├── shape_shift.zig
│   ├── cover_traffic.zig
│   └── tokens.zig
├── mesh/                      # ~10000 lines, later
│   ├── node.zig
│   ├── routing.zig
│   ├── discovery.zig
│   └── transports/
├── prototypes/
│   └── mesh-chat-disposable.html
└── build.zig
```

## Shared core (`core/`)

- **`crypto.zig`** — wrappers over `std.crypto`.
- **`identity.zig`** — Ed25519 + Curve25519, fingerprint, multi-device.
- **`envelope.zig`** — format:
  ```
  Envelope = {
    version: u8,
    id: [16]u8,
    from: Fingerprint,
    to: Target,
    created_at: i64,
    expires_at: i64,
    route_hints: []TransportHint,
    payload: EncryptedPayload,
    signature: [64]u8,
  }
  ```
- **`transport.zig`** — abstraction over `Io`.
- **`registry.zig`** — CRDT for groups.

## ayllu-chat

**Threat model:** aggressive state DPI of the kind routinely deployed to block Telegram, WhatsApp, independent media, Tor, and WireGuard. We do not defend against targeted attacks, total network shutdowns, or physical device seizure.

- Server: Zig on a VPS in a calm jurisdiction.
- Client: PWA derived from the prototype, with P2P swapped for async HTTP.
- Camouflage: the polymorphic protocol.

## ayllu-proxy

- **`socks5.zig`** — universal, first priority (covers Telegram completely).
- **`mtproto.zig`** — native Telegram proxy.
- **`shadowsocks.zig`** — SS migration path.
- **`wireguard.zig`** — system-wide VPN for iOS Safari and everything else.

## camouflage/ — polymorphic protocol

- **`reality.zig`** — Reality baseline (port from Go/Xray).
- **`multi_site.zig`** — rotation across camouflage domains.
- **`shape_shift.zig`** — outer-signature mutation.
- **`cover_traffic.zig`** — background activity.
- **`tokens.zig`** — time-keyed handshake.

## Development phases

| Phase | Zig lines | User-visible outcome |
|------|-----------|----------------------|
| 1. core/ | ~3000 | Protocol ready |
| 2. basic chat | +2000 | Standalone group chat works |
| 3. proxy: SOCKS5 | +800 | Telegram fully works (messages, calls, YouTube in the in-app browser) |
| 4. camouflage: Reality | +2500 | Traffic invisible to DPI |
| 5. proxy: MTProto | +1000 | Native Telegram proxy |
| 6. chat video | +1000 | Calls inside the standalone chat |
| 7. proxy: WireGuard | +2200 | System-wide VPN, covers iOS Safari |
| 8. camouflage: multi-site | +1000 | Domain rotation |
| 9. camouflage: shape-shift | +1500 | Protocol mutation |
| 10. proxy: Shadowsocks | +700 | SS migration |
| 11. camouflage: cover traffic | +500 | Background activity |
| 12. chat mirrors | +500 | Fallback domains |
| 13. mesh baseline | +5000 | Multi-hop routing |
| 14. mesh transports | +3000 | LoRa, APRS |
| 15. mesh anonymity | +2000 | Onion, MLS |

**Essential (chat + SOCKS5 + Reality): ~8300 lines.** Enough for a standalone group chat plus fully working Telegram plus invisible traffic.

**With WireGuard (phase 7): +2200 = ~10500 lines.** Complete iOS story.

**With polymorphic extensions: +3000 = ~13500 lines.** Cutting-edge camouflage.

**Full with mesh: ~24500 lines.**

**Start with phases 1 + 2 + 3.** Core plus minimal chat plus SOCKS5. Users get a working Telegram plus a standalone group chat. That is already a lot.

After that: Reality (phase 4) for robustness, WireGuard (phase 7) for iOS Safari, polymorphic layers (8–9) for longer-term survivability.

## Principles

- Essential surface ≤ 15000 lines of Zig.
- Maximum use of `std.crypto`, `std.http`, `std.Io`.
- Private keys never leave the device.
- Only standards: Ed25519, Curve25519, AES-GCM-SIV, Noise, MLS.
- The entire codebase is readable in a week.
- Tests 1:1, 2:1 for crypto.

## Reused from the prototype

- Envelope format → `core/envelope.zig`.
- Registry CRDT → `core/registry.zig`.
- UX (panic-wipe, auto-wipe, passphrase lock, self-tests) → `chat/web/`.
- PWA structure → `chat/web/index.html`.

## Cutting-edge stack

- **Zig 0.16** — transport-agnostic, no runtime fingerprints.
- **Noise Protocol** — same lineage as WireGuard.
- **MLS (RFC 9420)** — newer than Double Ratchet.
- **Reality + polymorphic** — state-of-the-art camouflage.
- **AES-GCM-SIV** — misuse-resistant.
- **io_uring** — minimal latency.

## Terminology

- *ayllu* — the network
- *quipu* — envelope
- *runa* — identity
- *tambo* — node

## Open questions

1. Mnemonic encoding: BIP39 or a custom wordlist?
2. iOS distribution: PWA or AltStore?
3. TTL policy?
4. Meshtastic: Protobuf or a custom wrapper?
5. WireGuard-over-Ayllu: wrap stock WG or ship a bespoke protocol?
6. Default camouflage domains?
7. Shape-shifting: which outer protocols ship in the first release?

---

**Status:** v0.5. Use-case matrix added; WireGuard promoted (phase 7, no longer "later"). Essential set with SOCKS5 is sufficient for full coverage inside Telegram. WireGuard closes iOS Safari and system-wide traffic.
