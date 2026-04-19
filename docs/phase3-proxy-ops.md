# Phase 3 Proxy Ops

These are operational notes for what can be deployed *today*, not a preview of
the future full Ayllu stack. They also flag what is still visible on the wire
and therefore not yet safe against sophisticated DPI.

## What is ready now

- `ayllu-proxy` stands up a plain SOCKS5 TCP proxy.
- `CONNECT` is supported for IPv4, IPv6, and domain-name targets.
- Private mode is available via RFC 1929 (`username:password`).
- End-to-end tests cover:
  - unauthenticated operation;
  - authenticated operation;
  - real byte relay to an upstream server.

## What is NOT ready now

- No Reality.
- No camouflage / polymorphic handshake.
- No TLS camouflage.
- No `UDP ASSOCIATE`.
- No MTProto.
- No WireGuard-over-Ayllu.
- No multi-hop / mesh.

In short: the current phase is a solid private SOCKS5 relay, not yet an
"invisible transport".

## What a VPS is in this phase

A VPS here is simply a remote server with a public IP that stays online.

The current traffic path is:

1. The client (any SOCKS5-capable app, e.g. Telegram) opens a TCP connection
   to the VPS.
2. `ayllu-proxy` is listening on the VPS.
3. The client speaks SOCKS5 to it.
4. `ayllu-proxy` opens its own connection to the target site or service.
5. The response travels back through the same VPS.

At this stage it is a remote private proxy, not a camouflage system.

## How to deploy it today

The minimal sane shape for a single operator serving a small trusted group:

- one dedicated VPS;
- one dedicated port for `ayllu-proxy`;
- mandatory authentication via `--auth-file`;
- firewall open only on the chosen TCP port;
- never a public "open proxy" without a password.

Example auth file:

```text
alice:very-long-random-password
```

Example launch:

```bash
zig build run-proxy -- --listen 0.0.0.0:1080 --auth-file /etc/ayllu/auth.txt
```

Listening on `443` is possible, but note the constraint below: from the
outside it is still raw SOCKS5, not HTTPS.

## Important limitation of port 443

Raw SOCKS5 on `443` cannot honestly be hidden behind SNI-based routing in
`nginx-stream`.

Reason:

- SNI only works once the client sends a TLS ClientHello;
- a SOCKS5 client never sends a TLS ClientHello;
- so the SNI router has nothing to look at.

Practical conclusions:

- either dedicate a separate IP / port to plain SOCKS5;
- or wait for the Reality / camouflage layer, which itself accepts the first
  bytes as TLS-shaped traffic.

## Pre-flight checklist before any public exposure

- always enable `--auth-file`;
- use a long random password, not a human word;
- do not log secrets;
- never run the proxy with no access limits on the open internet;
- explicitly test reconnect and wrong-password behaviors.

## Manual verification before handing credentials to a user

1. `zig build test`
2. `zig build`
3. Start the server with `--auth-file`.
4. Connect a SOCKS5-capable client (Telegram Desktop is a convenient one).
5. Check:
   - regular messages;
   - photo / video uploads;
   - the in-app browser;
   - wrong-password behavior;
   - reconnect after a network drop.

## What the Reality / camouflage transition requires

Before the camouflage layer lands, the following decisions must be pinned down:

- which external domain (or set of domains) is impersonated;
- whether a dedicated IP is used for camouflage;
- what fallback is acceptable on an invalid token;
- where the boundary between "real site" and Ayllu transport lies;
- how to confirm that active probing never receives an obvious SOCKS
  fingerprint.

Until that layer exists, an honest description of the system is:

> a private SOCKS5 relay for a small trusted group, not yet a DPI-stealth
> transport.
