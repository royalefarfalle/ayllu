# ayllu

*Ayllu* (кечуа) — андская община на взаимопомощи. То же и здесь: связь через взаимопомощь узлов, а не централизованную инфраструктуру.

Censorship-resistant protocol + polymorphic-camouflage transport layer + async chat, written in Zig 0.16.

Full specification: [SPEC.md](SPEC.md).

## Сборка

```sh
zig build                          # собирает обе CLI: ayllu и ayllu-proxy
zig build run                      # ayllu: список подсистем phase-1
zig build run-proxy -- --help      # ayllu-proxy: SOCKS5 daemon
zig build test                     # прогоняет все тесты (core/ + proxy/)
```

Требуется Zig **0.16.0** или новее. Предпочитается `-Doptimize=ReleaseFast` для production-сборок VPS.

## Что готово

**Phase-1 core** (протокол):

- `core/crypto` — Ed25519 + X25519 + SHA-256 peer fingerprint (domain-tag `ayllu.fp.v1`).
- `core/identity` — `Identity` (runa) + `PublicIdentity`; X25519 всегда derivируется из Ed25519.
- `core/envelope` — `Envelope` (quipu) с signed digest, TTL, three Target variants.
- `core/transport` — vtable-интерфейс + `InMemoryTransport` loopback.
- `core/registry` — OR-Set CRDT для членства группы.

**Phase-3 SOCKS5 proxy** (MVP):

- `proxy/socks5` — RFC 1928 parser/encoder.
- `proxy/relay` — bidirectional TCP copy через `std.Io`.
- `proxy/daemon` — handshake + connect upstream (включая DNS через `std.Io.net.HostName.connect`).
- `ayllu-proxy` бинарь — принимает connection'ы, делает accept loop через `std.Io.Threaded`.

Верифицировано живьём: curl через `socks5h://localhost:PORT` тянет HTTPS (ziglang.org), домены резолвятся на proxy-стороне (ATYP=domain).

## Deploy на VPS для Telegram

### 1. Поднять VPS

Лучше — в юрисдикции без российского DPI (Нидерланды / Финляндия / Эстония). Минимум 1 CPU / 1 GB RAM. Чистый IP (не в известных блок-листах — проверить через `bgp.tools` или аналогичное).

### 2. Собрать бинарь

```sh
# на VPS (Linux)
wget https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz
tar xf zig-x86_64-linux-0.16.0.tar.xz
export PATH="$PWD/zig-x86_64-linux-0.16.0:$PATH"

git clone <url> ayllu && cd ayllu
zig build -Doptimize=ReleaseFast
# получите zig-out/bin/ayllu-proxy (~500 KB)
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

**Порт 443** — максимально сливается с HTTPS-трафиком снаружи. Если на VPS уже есть HTTPS-сайт — либо взять другой порт (например 8443), либо пускать через nginx-stream балансировщик по SNI.

```sh
sudo useradd -r -s /usr/sbin/nologin ayllu
sudo install -m 755 zig-out/bin/ayllu-proxy /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now ayllu-proxy
```

### 4. Firewall — ОБЯЗАТЕЛЬНО

Без auth любой в интернете сможет гнать трафик через ваш VPS (proxy-abuse → ваш IP в спам-листах). IP-allowlist только для домашних статических IP родителей:

```sh
# ufw пример
sudo ufw default deny incoming
sudo ufw allow from <IP родителей> to any port 443 proto tcp
sudo ufw allow 22/tcp        # SSH — для вас
sudo ufw enable
```

Если у родителей динамический IP — либо ставить им **DDNS + cron-скрипт** обновлять правило, либо ждать phase-4 Reality (camouflage), после которой active-probing DPI получит "честный" whitelisted-сайт вместо SOCKS5.

### 5. Настроить Telegram

В мобильном/десктопном Telegram:
`Settings` → `Data and Storage` → `Proxy Settings` → `Add Proxy` → `SOCKS5`
- Server: `<IP или домен VPS>`
- Port: `443`
- Username / Password: пусто

В Telegram Desktop: та же цепочка + `Use proxy for calls` для голоса/видео.

После включения Telegram должен сразу заработать: сообщения, звонки, встроенный браузер (YouTube через него тоже пойдёт).

### Что НЕ закрывает текущий MVP

- **DPI active-probing**: на "голом" SOCKS5 РКН за 10-30 минут может пометить IP. Защита от этого — phase-4 Reality (в плане).
- **Аутентификация**: пока только IP-allowlist через firewall. Username/password auth — следующий чекпоинт.
- **UDP (ASSOCIATE)**: нет — для Telegram TCP звонков достаточно, но если в будущем понадобится — реализуется в 100 строк.
- **iOS системный Safari и системный трафик**: SOCKS5 работает только для приложений, которые позволяют настроить прокси. Для всего iOS-трафика — phase-7 WireGuard-over-Ayllu.

## Структура

```
core/        phase-1 (готово)
proxy/       phase-3 SOCKS5 MVP (готово)
cli/         ayllu + ayllu-proxy бинари
chat/        phase-2 — не начато
camouflage/  phase-4 Reality — не начато
mesh/        phase-13+ — далёкие фазы
prototypes/  mesh-chat-disposable.html — эталонный UI для phase-2
```

## Терминология

- *ayllu* — сеть
- *quipu* (кипу) — envelope (единица трафика)
- *runa* — идентичность
- *tambo* — узел (phase-13)
