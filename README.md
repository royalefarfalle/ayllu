# ayllu

*Ayllu* (кечуа) — андская община на взаимопомощи. То же и здесь: связь через взаимопомощь узлов, а не централизованную инфраструктуру.

Censorship-resistant protocol + polymorphic-camouflage transport layer + async chat, written in Zig 0.16.

Full specification: [SPEC.md](SPEC.md).

## Сборка

```sh
zig build           # собрать CLI
zig build run       # запустить CLI (печатает доступные подсистемы)
zig build test      # прогнать все тесты
```

Требуется Zig **0.16.0** или новее.

## Phase-1 — core/ (готово)

Первая фаза спеки: *"протокол готов"*. Ядро собрано из пяти модулей:

- **`core/crypto.zig`** — обёртки над `std.crypto`: Ed25519 для подписей, X25519 для DH, SHA-256 для digest + peer fingerprint (с domain-тегом `ayllu.fp.v1`).
- **`core/identity.zig`** — `Identity` (runa): Ed25519 keypair + X25519-ключ, производный через `fromEd25519` (один источник секрета, не может рассогласоваться). `PublicIdentity` для адресата verify.
- **`core/envelope.zig`** — `Envelope` (quipu): атомарная подписанная единица трафика. Domain-тег `ayllu.env.v1`, length-prefixed payload, Target-variant (broadcast / direct / multicast).
- **`core/transport.zig`** — vtable-интерфейс для любой доставки + `InMemoryTransport` (FIFO loopback на `std.Deque`), владеет payload-буферами.
- **`core/registry.zig`** — OR-Set CRDT для членства группы. Идемпотентно, коммутативно, сходится под асимметричной историей.

Сопровождается:
- **`core/testing.zig`** — тест-хелперы.
- **`cli/main.zig`** — баннер состояния.

Тесты покрывают golden vectors, property assertions, field-preservation, OOM-пути (`std.testing.FailingAllocator`) и public-surface smokes.

## Структура

```
core/       — ядро протокола (phase 1, готово)
cli/        — CLI-обёртка
chat/       — собственный мессенджер (phase 2+)
proxy/      — SOCKS5 / MTProto / Shadowsocks / WireGuard (phase 3-7)
camouflage/ — Reality / multi-site / shape-shift / cover-traffic (phase 4, 8-11)
mesh/       — многоузловая маршрутизация (phase 13-15)
prototypes/ — артефакты из прошлых итераций
```

## Терминология

- *ayllu* — сеть
- *quipu* (кипу) — envelope (единица трафика)
- *runa* — идентичность
- *tambo* — узел (приходит в phase-13 mesh)
