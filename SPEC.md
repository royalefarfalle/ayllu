# ayllu.sh — техническая спецификация

> *Ayllu* (кечуа) — андская община, основанная на взаимной поддержке и коллективном труде. Эта система наследует тот же принцип: связь через взаимопомощь узлов, а не через централизованную инфраструктуру.

## Что это

**Ayllu — протокол устойчивой связи и инфраструктурный слой для туннелирования** в условиях цензуры. Работает как собственный мессенджер и как невидимый транспорт для существующих приложений.

Три слоя:

1. **PROTOCOL.md** (позже) — текстовая спецификация
2. **ayllu-core** — reference implementation на Zig 0.16
3. **ayllu-apps** — reference приложения:
   - `ayllu-chat` — собственный мессенджер (async + chat-UI)
   - `ayllu-proxy` — транспортный слой для чужих протоколов и системный VPN

## Что решает для конечного пользователя

Матрица use cases для родителей в РФ 2026:

| Задача | Через что | Работает? |
|---|---|---|
| Telegram сообщения | SOCKS5 proxy | ✓ |
| Telegram видео/аудио звонки | SOCKS5 + "Use Proxy for Calls" | ✓ (TCP fallback) |
| Telegram встроенный браузер → YouTube | SOCKS5 | ✓ |
| Telegram встроенный браузер → любые заблокированные | SOCKS5 | ✓ |
| Telegram Web Apps и боты | SOCKS5 | ✓ |
| WhatsApp | SOCKS5 (в настройках) | ✓ |
| Системный Safari/Chrome → заблокированные сайты | WireGuard-over-Ayllu | ✓ |
| Весь трафик телефона (iOS system VPN) | WireGuard-over-Ayllu | ✓ |
| YouTube в нативном приложении | WireGuard-over-Ayllu | ✓ |
| Собственный зашифрованный чат с семьёй | ayllu-chat PWA | ✓ |
| Видеозвонки в ayllu-chat | WebRTC в PWA | ✓ |

**Два режима использования:**

1. **Точечное проксирование** через SOCKS5 — встраивается в настройки Telegram/других приложений. Работает для этих приложений и всего, что они открывают (включая встроенные браузеры).
2. **Системный VPN** через WireGuard-over-Ayllu — весь трафик устройства идёт через Ayllu. Решает всё, включая iOS Safari.

Оба режима используют polymorphic camouflage — трафик невидим для DPI.

## Позиционирование

| Система | Сильное | Слабое |
|---|---|---|
| Signal | E2E, UX | Централизовано, детектируется |
| Matrix | Федерация | DPI-детект, тяжёлое |
| Briar | P2P, deniability | Только Android, медленно |
| Meshtastic | LoRa-mesh | Нет интернета, нет E2E-групп |
| Tor | Анонимность | Не для чата, палится |
| Reticulum | Transport-agnostic | Python, UX, без маскировки |
| Xray/V2Ray | Proxy + маскировка | Go палится, нет чата |

**Ayllu = Reticulum + Reality + современный UX + proxy-платформа + polymorphic protocol.**

## Почему Zig 0.16

- **`Io` как абстракция**: каждый транспорт — реализация одного интерфейса
- **Отмена операций встроена**: параллельные попытки с автоотменой
- **`std.crypto` cutting-edge**: Ed25519, Curve25519, AES-GCM-SIV
- **Статический бинарник 500 КБ — 2 МБ**
- **Не палится DPI**: полный контроль над байтами, без runtime-сигнатур Go/Python
- **Один код — все платформы**: io_uring, Termux, ESP32

## Архитектура

### Async-first ядро с chat-like UI

**Под капотом:** store-and-forward. Envelope с ID, TTL, криптографией.

**В UI:** пузырьки чата, timestamps, статусы доставки, прозрачная индикация режима.

**Live-режим:** WebRTC только когда оба онлайн через быстрый транспорт.

### Ayllu как платформа прокси и VPN

- **MTProto proxy** — Telegram через `ayllu.sh:443`
- **SOCKS5** — универсальный для любого приложения (TCP + UDP через extensions)
- **Shadowsocks-over-Ayllu** — миграция с SS-клиентов
- **WireGuard-over-Ayllu** — системный VPN, весь трафик телефона

Весь прокси-трафик маскируется через polymorphic protocol. DPI видит обычный HTTPS к безобидному сайту.

### Polymorphic protocol — cutting-edge цель

**Трёхфазный handshake с camouflage и pivot:**

**Фаза 1 — camouflage:** сервер отвечает на TLS ClientHello как whitelisted-сайт (Microsoft, CloudFlare, госуслуги). Сертификат настоящий через Reality. DPI видит whitelisted-трафик.

**Фаза 2 — secret handshake:** клиент посылает криптографический токен, замаскированный под обычный HTTP-запрос. Time-based, replay невозможен.

**Фаза 3 — pivot:** сервер распознаёт токен → переключается на Ayllu-транспорт. Неправильный токен → продолжает честно проксировать к target-домену (активное зондирование DPI возвращает настоящий контент).

**Polymorphic-расширение:**

- **Multi-site camouflage**: ротация между whitelist-доменами
- **Protocol shape-shifting**: HTTPS/2 → HTTP/3 QUIC → WebSocket к Discord, внутри одно, снаружи разное
- **Cover traffic**: fake-запросы, имитирующие обычный серфинг
- **Time-keyed tokens**: handshake-токены устаревают за секунды

**Никто серьёзно не делал polymorphic protocol для mesh-систем.** Zig 0.16 даёт полный контроль над байтами.

## Структура репозитория

```
ayllu.sh/
├── SPEC.md
├── PROTOCOL.md                # позже
├── core/                      # ~3000 строк
│   ├── crypto.zig
│   ├── identity.zig
│   ├── envelope.zig
│   ├── transport.zig
│   └── registry.zig
├── chat/                      # ~3000 строк
│   ├── server.zig
│   ├── signaling.zig
│   └── web/
│       └── index.html
├── proxy/                     # ~4000 строк
│   ├── socks5.zig
│   ├── mtproto.zig
│   ├── shadowsocks.zig
│   └── wireguard.zig          # системный VPN
├── camouflage/                # ~3000 строк
│   ├── reality.zig
│   ├── multi_site.zig
│   ├── shape_shift.zig
│   ├── cover_traffic.zig
│   └── tokens.zig
├── mesh/                      # ~10000 строк, позже
│   ├── node.zig
│   ├── routing.zig
│   ├── discovery.zig
│   └── transports/
├── prototypes/
│   └── mesh-chat-disposable.html
└── build.zig
```

## Общее ядро (`core/`)

- **`crypto.zig`** — обёртки над `std.crypto`
- **`identity.zig`** — Ed25519 + Curve25519, fingerprint, multi-device
- **`envelope.zig`** — формат:
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
- **`transport.zig`** — абстракция через `Io`
- **`registry.zig`** — CRDT для групп

## ayllu-chat

**Модель угроз:** РФ/Иран 2026. Не защищаемся от адресной атаки, тотального отключения, изъятия устройств.

- Сервер: Zig на VPS в спокойной юрисдикции
- Клиент: PWA из прототипа с заменой P2P на async HTTP
- Маскировка: polymorphic protocol

## ayllu-proxy

- **`socks5.zig`** — универсальный, первый приоритет (покрывает Telegram полностью)
- **`mtproto.zig`** — native Telegram proxy
- **`shadowsocks.zig`** — миграция с SS
- **`wireguard.zig`** — системный VPN для iOS Safari и всего остального

## camouflage/ — polymorphic protocol

- **`reality.zig`** — базовая Reality (порт с Go/Xray)
- **`multi_site.zig`** — ротация camouflage-доменов
- **`shape_shift.zig`** — смена внешней сигнатуры
- **`cover_traffic.zig`** — фоновая активность
- **`tokens.zig`** — time-keyed handshake

## Фазы разработки

| Фаза | Строк Zig | Что даёт пользователю |
|------|-----------|----------------------|
| 1. core/ | ~3000 | Протокол готов |
| 2. chat базовый | +2000 | Семейный чат работает |
| 3. proxy: SOCKS5 | +800 | Telegram полностью работает (сообщения, звонки, YouTube в браузере) |
| 4. camouflage: Reality | +2500 | Трафик невидим для DPI |
| 5. proxy: MTProto | +1000 | Нативный Telegram proxy |
| 6. chat видео | +1000 | Звонки в семейном чате |
| 7. proxy: WireGuard | +2200 | Системный VPN, решает всё включая iOS Safari |
| 8. camouflage: multi-site | +1000 | Ротация доменов |
| 9. camouflage: shape-shift | +1500 | Смена протокола |
| 10. proxy: Shadowsocks | +700 | SS-миграция |
| 11. camouflage: cover traffic | +500 | Фоновая активность |
| 12. chat зеркала | +500 | Резервные домены |
| 13. mesh базовый | +5000 | Многоузловая маршрутизация |
| 14. mesh транспорты | +3000 | LoRa, APRS |
| 15. mesh анонимность | +2000 | Onion, MLS |

**Эссеншиал (chat + SOCKS5 + Reality): ~8300 строк.** Этого уже хватит для: семейного чата + Telegram работает полностью + невидимый трафик.

**С WireGuard (фаза 7): +2200 = ~10500 строк.** Полное решение для iOS.

**С polymorphic расширением: +3000 = ~13500 строк.** Cutting-edge маскировка.

**Полная с mesh: ~24500 строк.**

**Начинать с фаз 1+2+3.** Core + минимальный chat + SOCKS5. Родители получают рабочий Telegram + свой семейный чат. Этого уже много.

Дальше — Reality (фаза 4) для устойчивости, WireGuard (фаза 7) для iOS Safari, polymorphic (8-9) для будущего.

## Принципы

- Эссеншиал ≤ 15000 строк Zig
- Максимум из `std.crypto`, `std.http`, `std.Io`
- Приватные ключи не покидают устройство
- Только стандарты: Ed25519, Curve25519, AES-GCM-SIV, Noise, MLS
- Весь код читается за неделю
- Тесты 1:1, для крипто 2:1

## Переиспользуется из прототипа

- Envelope-формат → `core/envelope.zig`
- Registry CRDT → `core/registry.zig`
- UX (panic-wipe, auto-wipe, passphrase-lock, self-tests) → `chat/web/`
- PWA-структура → `chat/web/index.html`

## Cutting-edge стек

- **Zig 0.16** — transport-agnostic без runtime-сигнатур
- **Noise Protocol** — как в WireGuard
- **MLS (RFC 9420)** — новее Double Ratchet
- **Reality + polymorphic** — state-of-the-art маскировка
- **AES-GCM-SIV** — misuse-resistant
- **io_uring** — минимальная задержка

## Терминология

- *ayllu* — сеть
- *quipu* (кипу) — envelope
- *runa* — идентичность
- *tambo* — узел

## Открытые вопросы

1. Мнемоника: BIP39 или свой словарь?
2. iOS: PWA или AltStore?
3. TTL-политика?
4. Meshtastic: Protobuf или своя обёртка?
5. WireGuard-over-Ayllu: подменяем обычный WG или свой собственный протокол?
6. Camouflage-домены по умолчанию?
7. Shape-shifting: какие протоколы в первом релизе?

---

**Статус:** v0.5. Добавлена матрица use cases, WireGuard приоритизирован выше (фаза 7, не "позже"). Эссеншиал с SOCKS5 достаточен для полного обхода в Telegram. WireGuard закрывает iOS Safari и системный трафик.
