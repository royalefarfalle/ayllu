# Camouflage Runtime

This is no longer just crypto-core. The project now has a complete baseline
path:

1. a local `SOCKS5` listener next to the client application;
2. a client-side bridge process that sits beside it;
3. an outer camouflage admission exchange against a remote node;
4. a `pivot` into the inner `SOCKS5` on the server;
5. a plain relay into the actual upstream.

## What this means in plain terms

A remote VPS on its own does not solve the problem for apps like Telegram.

Such apps only speak plain `SOCKS5`. That means there has to be a local bridge
right next to the application:

- App -> local `ayllu-camouflage-client`
- `ayllu-camouflage-client` -> remote `ayllu-camouflage-proxy`
- `ayllu-camouflage-proxy` -> inner `SOCKS5` session -> target site / service

That is why there are now two binaries, not one.

## What is ready now

- `ayllu-reality-keygen`
  - generates an X25519 keypair;
  - generates a `short id`.

- `ayllu-camouflage-proxy`
  - accepts an HTTP-like admission request;
  - verifies the Reality-derived admission material;
  - verifies the time-windowed token + replay cache;
  - on success, pivots the same TCP stream into inner `SOCKS5`;
  - on failure, does not emit a `SOCKS` fingerprint.

- `ayllu-camouflage-client`
  - listens on a local `SOCKS5` port;
  - performs the outer admission against the remote node;
  - after `101 Switching Protocols`, just forwards bytes;
  - inner `SOCKS5` auth, if enabled on the server, is carried through the
    tunnel.

## Minimal traffic path

1. The local application connects to `127.0.0.1:1080`.
2. The local bridge opens TCP to the remote camouflage gateway.
3. The bridge sends admission headers + token.
4. The server verifies admission and replies with `101 Switching Protocols`.
5. From here the application's `SOCKS5` bytes flow through the bridge verbatim.
6. On the server those bytes land in the inner `SOCKS5` daemon.
7. The server connects to the requested upstream and relays traffic.

## How to run it

Build the binaries and generate server keys:

```bash
zig build
zig-out/bin/ayllu-reality-keygen --short-id-bytes 4
```

Server-side example on a VPS:

```bash
zig build run-camouflage-proxy -- \
  --listen 0.0.0.0:443 \
  --target example.com:443 \
  --server-name example.com \
  --private-key YOUR_SERVER_PRIVATE_KEY \
  --short-id aabb \
  --auth-file /etc/ayllu/auth.txt \
  --min-client-ver 1.0.0 \
  --max-client-ver 2.0.0
```

Client-side example next to the application:

```bash
zig build run-camouflage-client -- \
  --listen 127.0.0.1:1080 \
  --connect YOUR_VPS_IP:443 \
  --target example.com:443 \
  --server-name example.com \
  --server-public-key YOUR_SERVER_PUBLIC_KEY \
  --client-private-key YOUR_CLIENT_PRIVATE_KEY \
  --short-id aabb \
  --client-ver 1.5.0 \
  --min-client-ver 1.0.0 \
  --max-client-ver 2.0.0
```

After this, the application (for example Telegram) should be configured to
point at `127.0.0.1:1080` rather than directly at the VPS.

If `--auth-file` is enabled on the server, the same `username`/`password`
must be entered in the client application: they traverse the bridge into the
inner `SOCKS5`.

## What this still does NOT do

- It is not wire-compatible Xray REALITY.
- It is not a true TLS camouflage listener.
- It is not an honest proxy fallback to a real site.
- There is no `HTTP/2`, `HTTP/3`, `QUIC`, or `WebSocket` shape-shifting yet.
- There is no cover traffic yet.
- There is no `WireGuard-over-Ayllu` yet.
- There is no iOS / Android / router packaging yet.

An honest summary of this phase:

> the working pieces are an outer admission layer + pivot runtime + local
> bridge for `SOCKS5`; this is not yet a full REALITY/TLS camouflage stack.
