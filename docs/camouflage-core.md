# Camouflage Core Status

Этот пакет уже не пустой, но важно честно фиксировать его границы.

## Что уже реализовано

- `camouflage/reality.zig`
  - X25519 key handling
  - `shortId` parsing/validation
  - `serverName` / version / time-window checks
  - derivation of admission material (`auth_key`, `response_seed`)

- `camouflage/tokens.zig`
  - time-windowed tokens
  - base64url wire format
  - MAC binding to method + path + `shortId`
  - replay cache

- `camouflage/pivot.zig`
  - parsing of HTTP-like request head
  - extraction of `Host` and token header
  - decision: `pivot` or honest `fallback`

## Что это означает practically

Теперь в проекте есть нормальное ядро для схемы:

1. внешний TLS-похожий вход
2. Reality admission
3. disguised HTTP request with token
4. `pivot` в Ayllu transport
5. invalid token -> honest fallback

## Чего пока ещё нет

- нет реального TLS/REALITY listener-а на сокете;
- нет bridge-кода, который после `pivot` переключает поток в `proxy/daemon`;
- нет честного upstream fallback к реальному сайту;
- нет cover-traffic / multi-site / shape-shift.

То есть это уже **camouflage core**, но ещё не **camouflage transport runtime**.
