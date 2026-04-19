# Camouflage Runtime

Это уже не просто crypto-core. Теперь в проекте есть полный базовый путь:

1. локальный `SOCKS5` для Telegram;
2. client-bridge рядом с пользователем;
3. outer camouflage admission до удалённого узла;
4. `pivot` в inner `SOCKS5` на сервере;
5. обычная прокладка трафика до нужного upstream.

## Что это означает простыми словами

Удалённый VPS сам по себе не решает задачу для Telegram.

Telegram умеет говорить только с обычным `SOCKS5`. Значит, рядом с Telegram
должен быть локальный мост:

- Telegram -> локальный `ayllu-camouflage-client`
- `ayllu-camouflage-client` -> удалённый `ayllu-camouflage-proxy`
- `ayllu-camouflage-proxy` -> inner `SOCKS5` session -> нужный сайт/сервис

Именно поэтому теперь есть два бинарника, а не один.

## Что готово сейчас

- `ayllu-reality-keygen`
  - генерирует X25519 keypair;
  - генерирует `short id`.

- `ayllu-camouflage-proxy`
  - принимает HTTP-like admission request;
  - проверяет Reality-derived admission material;
  - проверяет time-windowed token + replay cache;
  - при успехе переключает тот же TCP stream во внутренний `SOCKS5`;
  - при неуспехе не шлёт `SOCKS` fingerprint.

- `ayllu-camouflage-client`
  - слушает локальный `SOCKS5` порт;
  - сам делает outer admission до удалённого узла;
  - после `101 Switching Protocols` просто прокидывает байты;
  - inner `SOCKS5` auth, если включён на сервере, проходит внутри тоннеля.

## Минимальный путь трафика

1. Telegram подключается к `127.0.0.1:1080`
2. Локальный bridge открывает TCP до удалённого camouflage gateway
3. Bridge отправляет admission headers + token
4. Сервер проверяет admission и отвечает `101 Switching Protocols`
5. С этого момента Telegram's `SOCKS5` bytes идут сквозь bridge как есть
6. На сервере эти байты попадают во внутренний `SOCKS5` daemon
7. Сервер подключается к нужному upstream и релеит трафик

## Как запускать

Сначала собрать бинарники и сгенерировать серверные ключи:

```bash
zig build
zig-out/bin/ayllu-reality-keygen --short-id-bytes 4
```

Пример server-side запуска на VPS:

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

Пример client-side запуска рядом с Telegram:

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

После этого Telegram надо настраивать не на VPS напрямую, а на локальный
`127.0.0.1:1080`.

Если на сервере включён `--auth-file`, те же `username/password` надо ввести
в Telegram: они пройдут через bridge во внутренний `SOCKS5`.

## Что это ещё НЕ делает

- Это не wire-compatible Xray REALITY.
- Это не настоящий TLS camouflage listener.
- Это не honest proxy fallback к реальному сайту.
- Здесь пока нет `HTTP/2`, `HTTP/3`, `QUIC`, `WebSocket` shape-shift.
- Здесь пока нет cover traffic.
- Здесь пока нет `WireGuard-over-Ayllu`.
- Здесь пока нет упаковки под iOS / Android / роутер.

Честная формулировка текущей фазы:

> уже есть рабочий outer admission + pivot runtime + local bridge для
> `SOCKS5`, но это ещё не full REALITY/TLS camouflage stack.
