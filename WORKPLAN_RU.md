# План работ по Lariska Endpoint Inventory Agent

## Цель

Сделать Lariska production-ready endpoint-агентом для платформы Shapoclyack. Первый производственный сценарий — инвентаризация установленного ПО на Linux, Windows и macOS, регистрация агента, heartbeat и надёжная доставка версионированных inventory snapshots в API Shapoclyack.

## Этап 0 — Основа проекта

Цель: привести репозиторий к стандартной структуре Rust-проекта и добиться базовой сборки.

Задачи:

- переименовать `cargo.toml` в `Cargo.toml`;
- добавить секцию `[package]`, Rust edition и минимальную metadata;
- перенести `main.rs` в `src/main.rs`;
- добавить `.gitignore`;
- убрать вывод placeholder JWT и любых секретов;
- описать contributor commands в `README.md`;
- добавить CI skeleton;
- добиться прохождения `cargo fmt`, `cargo clippy` и `cargo test`.

Критерии приёмки:

- clean checkout собирается стабильным Rust;
- тесты проходят локально;
- CI запускается минимум на Linux;
- в логах нет секретов или токенов.

## Этап 1 — Архитектура, конфигурация и identity

Цель: заложить модульную архитектуру агента без сетевой отправки inventory.

Задачи:

- разделить код на модули `app`, `config`, `identity`, `model`, `telemetry`;
- реализовать загрузку TOML-конфига и environment overrides;
- валидировать `server_url`, `provisioning_key_file`, `state_dir`, интервалы и HTTPS policy;
- реализовать persistent `agent_id` в защищённом state directory;
- создавать identity атомарно;
- детектировать повреждённый state без молчаливого создания второго identity;
- добавить команды `lariska run`, `lariska check-config`, `lariska inventory --output json`.

Критерии приёмки:

- перезапуск сохраняет тот же `agent_id`;
- повреждённый identity-файл приводит к понятной ошибке;
- secrets не попадают в diagnostics.

## Этап 2 — Wire models и API-контракт

Цель: зафиксировать формат обмена с Shapoclyack API.

Задачи:

- добавить versioned Serde-модели для auth, registration, heartbeat и inventory;
- отделить transport-модели от внутренних domain-моделей;
- добавить `schema_version` для inventory payload;
- подготовить shared JSON fixtures;
- согласовать с сервером endpoints:
  - `POST /api/v1/auth/exchange`;
  - `POST /api/agent/register`;
  - `POST /api/agent/heartbeat`;
  - `POST /api/v1/endpoint/inventory`;
- согласовать payload limits, idempotency behavior и response codes.

Критерии приёмки:

- golden JSON fixture совпадает с контрактом сервера;
- модели сериализуются детерминированно;
- неизвестные или optional-значения обрабатываются явно.

## Этап 3 — Authentication, registration и heartbeat

Цель: реализовать безопасный жизненный цикл агента.

Задачи:

- реализовать HTTP-клиент с timeout, TLS verification и ограничением размера ответов;
- обменивать provisioning key на short-lived JWT;
- хранить JWT только в памяти;
- обновлять JWT до истечения срока с jitter;
- на `401` выполнять один refresh и один retry исходного запроса;
- реализовать idempotent registration;
- реализовать heartbeat loop со статусами `idle`, `busy`, `error`;
- редактировать логи так, чтобы в них не попадали токены и authorization headers.

Критерии приёмки:

- mock-server lifecycle tests проходят;
- transient network/server errors восстанавливаются без restart;
- provisioning key и JWT отсутствуют в captured logs.

## Этап 4 — Inventory collectors

Цель: реализовать кроссплатформенный сбор установленного ПО.

Задачи:

- добавить общий collector trait;
- добавить абстракцию command execution для тестов;
- реализовать Linux collectors для `dpkg-query`, `rpm`, `pacman`, опционально Snap и Flatpak;
- реализовать Windows collectors через uninstall registry, не используя `Win32_Product`;
- реализовать macOS collectors для application bundles, Homebrew и `pkgutil`;
- нормализовать whitespace, Unicode, architecture и source names;
- удалять exact duplicates;
- сортировать entries детерминированно;
- возвращать warnings при частичных ошибках collector-ов.

Критерии приёмки:

- fixture tests покрывают каждый поддерживаемый source;
- command timeout и non-zero exit не приводят к panic;
- одинаковый input даёт одинаковый canonical output.

## Этап 5 — Durable delivery и retry policy

Цель: гарантировать доставку inventory при временных сбоях сети или сервера.

Задачи:

- реализовать локальную durable spool queue;
- записывать snapshot атомарно до отправки;
- генерировать `snapshot_id` один раз и сохранять его между retries;
- сериализовать canonical JSON;
- считать SHA-256 digest;
- не отправлять unchanged snapshot до full-refresh deadline;
- отправлять inventory с `Idempotency-Key`;
- удалять snapshot только после server acknowledgement;
- retry-ить network errors, `408`, `425`, `429` и `5xx`;
- уважать `Retry-After`;
- использовать exponential backoff with full jitter;
- quarantine malformed spool entries.

Критерии приёмки:

- crash во время upload не теряет snapshot;
- duplicate delivery создаёт один server-side snapshot;
- disk limits и malformed spool files покрыты тестами.

## Этап 6 — Service lifecycle и packaging

Цель: подготовить агент к запуску как native background service.

Задачи:

- реализовать graceful shutdown по SIGTERM/Ctrl-C;
- добавить single-instance lock для одного `state_dir`;
- подготовить systemd unit для Linux;
- подготовить Windows Service integration;
- подготовить launchd plist для macOS;
- задокументировать platform-specific paths;
- добавить hardened service settings;
- описать upgrade, rollback и uninstall behavior.

Критерии приёмки:

- install/start/restart/stop работает на каждой целевой платформе;
- state переживает upgrade;
- сервис запускается с минимальными привилегиями.

## Этап 7 — Observability и security hardening

Цель: сделать агент безопасным и сопровождаемым в production.

Задачи:

- добавить structured logs;
- логировать event name, snapshot id, durations, counts, retry decisions и status codes;
- не логировать provisioning keys, JWT, Authorization headers, raw machine identifiers и полный software inventory;
- добавить counters/timings для collection, queue, upload, auth refresh и heartbeat;
- включить TLS verification по умолчанию;
- добавить dependency audit;
- добавить license policy;
- добавить secret scanning;
- задокументировать собираемые данные и privacy implications.

Критерии приёмки:

- production diagnostics не раскрывают чувствительные данные;
- audit и secret scanning проходят в CI;
- security expectations описаны в документации.

## Этап 8 — Testing strategy

Цель: покрыть критичные сценарии автоматизированными тестами.

Задачи:

- unit tests для config, identity, collectors, normalization, retry, spool и redaction;
- contract tests с mock server для auth/register/heartbeat/inventory;
- platform smoke tests на Linux, Windows и macOS;
- end-to-end test с disposable Shapoclyack stack.

Критерии приёмки:

- тесты не зависят от конкретного набора ПО на машине разработчика;
- контрактные fixtures защищают client/server integration;
- CI проверяет все целевые платформы.

## Этап 9 — CI/CD и release

Цель: автоматизировать сборку, проверку и выпуск артефактов.

Задачи:

- настроить build matrix для Linux, Windows и macOS;
- публиковать binaries для x86_64/aarch64, где применимо;
- генерировать SHA-256 checksums;
- генерировать SBOM;
- вести changelog и upgrade notes;
- подготовить `.deb`, `.rpm`, MSI и macOS package после стабилизации binary workflow.

Критерии приёмки:

- release artifacts проверяемы;
- checksums опубликованы;
- rollback и upgrade procedures документированы.

## Рекомендуемые PR-границы

1. Cargo layout, README и CI skeleton.
2. CLI, config loading и validation.
3. Persistent identity.
4. Wire models и JSON fixtures.
5. HTTP client, auth exchange и JWT refresh.
6. Registration и heartbeat.
7. Linux inventory collector.
8. Windows inventory collector.
9. macOS inventory collector.
10. Normalization и deduplication.
11. Durable spool queue.
12. Inventory submission и retry policy.
13. Service lifecycle.
14. Packaging и platform service files.
15. End-to-end tests и release workflow.

## Открытые решения

Перед реализацией production delivery нужно согласовать:

- финальный inventory API contract;
- server payload limits;
- inventory retention period;
- необходимость compression;
- identifier hashing/privacy policy;
- необходимость user-scope inventory для Windows/macOS service mode;
- правила software canonicalization;
- periodic full snapshot policy для unchanged endpoints;
- минимальные поддерживаемые версии ОС и CPU architectures;
- ownership и custody для code-signing keys.
