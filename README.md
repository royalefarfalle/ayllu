# ayllu

*Ayllu* (кечуа) — андская община на взаимопомощи. То же и здесь: связь через взаимопомощь узлов, а не централизованную инфраструктуру.

Censorship-resistant protocol + polymorphic-camouflage transport layer + async chat, written in Zig 0.16.

Спецификация: [SPEC.md](SPEC.md).

## Сборка

```sh
zig build           # собрать CLI
zig build run       # запустить CLI (выводит версию/фазу)
zig build test      # прогнать все тесты
```

Требуется Zig **0.16.0** или новее.

## Структура

- `core/` — ядро протокола (crypto, identity, envelope, transport, registry)
- `cli/` — тонкая CLI-обёртка
- `chat/`, `proxy/`, `camouflage/`, `mesh/` — следующие фазы (см. SPEC.md)
- `prototypes/` — артефакты из прошлых итераций

## Терминология

- *ayllu* — сеть
- *quipu* (кипу) — envelope (единица трафика)
- *runa* — идентичность
- *tambo* — узел
