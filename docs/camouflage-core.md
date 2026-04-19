# Camouflage Core Status

This package is no longer empty, but its boundaries need to stay explicit.

If you want a runnable "local bridge -> camouflage gateway -> inner SOCKS5"
path today, see `docs/camouflage-runtime.md`.

## What is already implemented

- `camouflage/reality.zig`
  - X25519 key handling
  - `shortId` parsing / validation
  - `serverName` / version / time-window checks
  - derivation of admission material (`auth_key`, `response_seed`)

- `camouflage/tokens.zig`
  - time-windowed tokens
  - base64url wire format
  - MAC binding to method + path + `shortId`
  - replay cache

- `camouflage/pivot.zig`
  - parsing of an HTTP-like request head
  - extraction of `Host` and the token header
  - decision: `pivot` or honest `fallback`

## What this means in practice

The project now has a proper core for the following scheme:

1. an outer TLS-looking entry point
2. Reality admission
3. a disguised HTTP request carrying the token
4. `pivot` into the Ayllu transport
5. invalid token -> honest fallback

## What is still missing

- there is no real TLS/REALITY listener on the socket;
- there is no bridge code that, after `pivot`, hands the stream to
  `proxy/daemon`;
- there is no honest upstream fallback to a real site;
- there is no cover-traffic / multi-site / shape-shift yet.

In other words, this is already **camouflage core**, but not yet
**camouflage transport runtime**.
