# Актуальный план работ Lariska

Статус на 23 сентября 2026 года. Документ описывает оставшуюся работу после стабилизации ветки 0.3.x и заменяет исторический список задач, большая часть которого уже выполнена.

## 1. Цель продукта

Lariska должна быть production-ready endpoint-агентом Shapoclyack, который:

- достоверно собирает системное и runtime-ПО на Linux, Windows и macOS;
- создаёт предсказуемо малую нагрузку на конечный хост;
- не теряет данные при перезапуске, сетевом сбое или недоступности API;
- не превращает частичный сбор в ложные удаления и переустановки;
- безопасно принимает ограниченную управляющую политику;
- обновляется проверяемым и восстанавливаемым способом;
- предоставляет оператору измеримые показатели свежести, полноты и влияния на хост.

## 2. Текущий baseline 0.3.x

| Направление | Статус | Что уже есть |
| --- | --- | --- |
| Основа Rust-проекта | Выполнено | Модульная структура, CLI, cross-platform build и CI |
| Identity и auth | Выполнено | Persistent `agent_id`, hashed identifiers, provisioning exchange, JWT refresh |
| Heartbeat и управление | Выполнено | Registration/heartbeat, managed intervals и log level с локальной валидацией |
| Коллекторы ОС | Выполнено для v1 | dpkg/RPM/pacman, Windows Registry/CBS, macOS bundles/Homebrew |
| Runtime-инвентаризация | Выполнено для v1 | Python, глобальный Node.js, Java/JDK |
| Низкое влияние | Выполнено на архитектурном уровне | Background QoS, лимиты, jitter, battery-aware schedule, запрет overlapping scans |
| Cache | Выполнено | Persistent fingerprint cache, ограничения размера/обхода, forced full refresh |
| Полнота | Выполнена консервативная модель | Неполный цикл не публикуется целиком |
| Delivery | Выполнено | zstd spool, independent worker, retry, quarantine, persisted accepted digest |
| Packaging | Частично | systemd/launchd/Windows SCM и заготовки deb/RPM; production signing не завершён |
| Self-update | Частично | TLS policy, target triple и SHA-256; нет signed manifest и health rollback |
| Документация | Актуализируется | README EN/RU, versioned wiki, Plan и этот roadmap |

## 3. Приоритет P0: точность данных

### 3.1 Inventory schema v2: installation identity

Проблема: schema v1 использует product comparison key без installation instance. Параллельные версии JDK, Visual C++ Runtime, Python environments и другие side-by-side установки могут схлопываться, скрывая старую уязвимую копию.

Задачи:

- отделить `product_identity` от `installation_identity`;
- добавить стабильный `package_id` там, где он существует: MSI ProductCode, bundle ID, package-manager ID;
- добавить `scope`: system, user, runtime, container;
- добавить privacy-safe `install_instance_id`;
- передавать нормализованный или хешированный install location только когда он нужен для различения;
- различать архитектуру, канал и user scope без передачи имени пользователя;
- подготовить migration/dual-read в Shapoclyack;
- обновить golden fixtures в обоих репозиториях;
- сохранить приём schema v1 на период обновления флота.

Критерии приёмки:

- JDK 17 и JDK 21 на одном хосте остаются двумя записями;
- уязвимая старая версия не скрывается более новой;
- повторная отправка не создаёт дубликаты installation instances;
- mixed fleet из v1/v2 агентов корректно отображается на сервере.

Зависимость: синхронный PR в Shapoclyack для schema, хранения, diff и CVE matching.

### 3.2 Source-aware completeness

Проблема: текущая безопасная модель отклоняет весь snapshot, если один обязательный collector неполон. Это исключает ложные удаления, но задерживает обновления здоровых источников.

Задачи:

- добавить статусы источников: `complete`, `partial`, `failed`, `not_applicable`;
- добавить timestamp последнего полного результата по источнику;
- передавать collector version и bounded diagnostic code;
- научить Shapoclyack сохранять предыдущий effective set для failed/partial source;
- разрешать diff/removal только для источника со статусом `complete`;
- не запускать CVE rematch для источника, чьё effective state не изменилось;
- сохранить fallback «не публиковать весь snapshot» для старого сервера.

Критерии приёмки:

- падение Python collector не мешает обновить dpkg inventory;
- падение dpkg не создаёт ни одного `removed` для пакетов dpkg;
- восстановление источника создаёт только реальные изменения;
- UI показывает degraded source и возраст последнего полного результата.

Зависимость: server-side effective inventory и обратная совместимость контракта.

## 4. Приоритет P0: безопасное обновление агента

### 4.1 Streaming download и строгие лимиты

- использовать `size_bytes` из update policy;
- ввести hard maximum независимо от ответа сервера;
- писать download в staging-файл потоково;
- считать SHA-256 в процессе записи;
- выполнять `fsync` файла и каталога до swap;
- удалять staging при любой ошибке.

### 4.2 Подписанный release manifest

- выбрать Ed25519 для подписи manifest;
- встроить доверенный public key или версионированный keyring;
- подписывать version, platform, size, SHA-256 и срок действия;
- добавить rotation/revocation procedure;
- запретить rollback ниже зафиксированной безопасной версии, кроме локального аварийного override.

### 4.3 Native install и health rollback

- Linux package installs обновлять через deb/RPM path, а не записью в `/usr/bin` из непривилегированного service;
- Windows использовать signed MSI/service updater;
- macOS использовать signed/notarized package;
- после restart требовать health acknowledgement;
- автоматически восстанавливать previous build при отсутствии healthy heartbeat;
- сохранять bounded update history и причину rollback.

Критерии приёмки:

- interrupted, oversized, foreign-platform, unsigned и downgraded build не меняет текущий executable;
- неуспешный запуск новой версии автоматически возвращает предыдущую;
- стандартная hardened service-конфигурация не конфликтует с update path.

## 5. Приоритет P1: budgets, метрики и benchmark

### 5.1 Общий collection budget

Добавить cooperative budget:

- общий deadline цикла;
- deadline каждого источника;
- `max_files`, `max_entries`, `max_bytes_read`;
- cancellation token при shutdown;
- статус `partial` при исчерпании бюджета;
- отсутствие detached blocking work после остановки service.

### 5.2 Наблюдаемость по источникам

Логировать и агрегировать без раскрытия inventory:

- duration, CPU time и item count;
- cache hit/miss и причина invalidation;
- complete/partial/failed;
- число файлов и прочитанных байтов;
- external process count и timeout;
- queue depth, oldest entry age, retries и quarantine count;
- время последнего accepted snapshot.

### 5.3 Benchmark suite

Сценарии:

- 1 000, 10 000 и 50 000 software entries;
- cold scan и warm-cache scan;
- 1, 50 и 200 spool entries;
- сутки offline;
- compression bomb и повреждённый cache/spool;
- battery/AC;
- collector timeout;
- shutdown во время filesystem scan и upload;
- массовый fleet restart с одинаковой policy.

Результаты должны публиковать wall time, process CPU, peak RSS, disk reads/files, cache ratio и freshness. Числовые regression thresholds фиксируются после получения baseline на типовых workstation/server profiles, а не выбираются методом корпоративной астрологии.

## 6. Приоритет P1: расширение покрытия

### Linux

- Snap и Flatpak;
- RPM epoch и distro-specific package identity;
- явный source для pacman вместо `other`;
- container image/package scope только при безопасной и ограниченной модели.

### Windows

- MSIX/AppX;
- ARM64 и эмуляционные views;
- package IDs для non-MSI uninstall entries;
- улучшенная user-scope модель без монтирования offline hives;
- code-signing publisher evidence при приемлемой стоимости.

### macOS

- `pkgutil` receipts;
- MacPorts при наличии;
- bundle ID и signing team ID;
- корректная архитектура universal/native приложений.

### Runtime ecosystems

- opt-in user-level Python/pyenv/venv;
- nvm и дополнительные Node.js roots;
- SDKMAN;
- .NET runtimes/SDK;
- строгие бюджеты и privacy policy для user scope.

Зависимость: параллельное развитие advisory providers и matching в Shapoclyack. Собирать данные, которыми сервер не умеет пользоваться, можно, но это дорогой способ пополнять JSON.

## 7. Приоритет P1: production packaging

- реально собирать и устанавливать `.deb`/RPM в CI;
- добавить package smoke tests в контейнерах/VM;
- подготовить signed MSI;
- подготовить signed/notarized macOS pkg;
- определить ownership конфигурации, identity и cache при upgrade/uninstall;
- проверить upgrade N-1 → N и rollback N → N-1;
- выпускать SBOM, provenance/attestation и checksums;
- документировать минимальные версии ОС и архитектуры.

Критерии приёмки:

- clean install, restart, upgrade, rollback и uninstall проверяются автоматически;
- identity и pending spool не теряются при штатном upgrade;
- package manager остаётся владельцем установленного binary.

## 8. Приоритет P2: транспорт

### Wire compression

- добавить bounded streaming zstd decode в Shapoclyack;
- проверять compressed и decompressed size;
- отклонять неизвестный `Content-Encoding`;
- включить agent wire compression только после server hardening;
- измерить реальный выигрыш CPU/network.

### Delta transport

- определить base snapshot acknowledgement;
- хранить full snapshot recovery point;
- обрабатывать потерянную базу и out-of-order delivery;
- периодически отправлять full snapshot;
- не усложнять v2 rollout одновременно с installation identity без отдельного решения.

Критерий: delta никогда не может оставить сервер в состоянии, которое нельзя восстановить полной отправкой.

## 9. Приоритет P2: операторская диагностика

Добавить `lariska diagnostics` с безопасным bounded output:

- версия и target triple;
- возраст identity без raw identifier;
- статус/возраст cache по источникам;
- последний complete collection;
- queue depth и oldest age;
- last accepted timestamp;
- managed revision и причина последнего rejection;
- update staging/rollback state;
- проверка прав на state/config/secret paths;
- connectivity probe без вывода credentials.

Подготовить runbooks:

- server unavailable;
- invalid provisioning key;
- collector timeout;
- incomplete inventory;
- growing spool;
- corrupt cache/spool;
- failed update and rollback;
- duplicate identity after manual state deletion.

## 10. Рекомендуемые PR-границы

1. Schema v2 models и fixtures в Lariska.
2. Schema v2 ingest/storage/diff в Shapoclyack.
3. Dual-stack rollout и migration tests.
4. Source completeness model в агенте.
5. Effective per-source inventory в сервере.
6. Streaming update download и size limits.
7. Signed manifest и key rotation.
8. Platform-native updater/rollback отдельно для каждой ОС.
9. Collection budget и cancellation.
10. Per-source telemetry и benchmark harness.
11. Linux collector expansion.
12. Windows collector expansion.
13. macOS/runtime expansion.
14. Native packaging CI.
15. Wire compression.
16. Operator diagnostics и runbooks.

Не объединять cross-repository schema, updater и новые collectors в один PR. Такое изменение сложно проверить, откатить и даже честно описать.

## 11. Definition of Done для каждого изменения

- `cargo fmt --check`;
- strict Clippy без warnings;
- полный Rust test suite;
- native CI на Linux, Windows и macOS;
- dependency/license policy и secret scan;
- APEX contract validation;
- cross-repository fixture при изменении wire model;
- тесты malformed/oversized/interrupted path;
- документация и upgrade/rollback notes;
- отсутствие новых неограниченных чтений, очередей и background tasks;
- измеримый performance impact для изменений collectors/cache/delivery.

## 12. Риски и решения

| Риск | Мера |
| --- | --- |
| Ложные удаления из-за неполного сбора | Authoritative-only v1; source-aware carry-forward в v2 |
| Скрытая старая версия ПО | Installation identity в schema v2 |
| Рост I/O на больших runtime trees | Fingerprint cache, budgets, opt-in user scope |
| OOM на backlog или сжатом payload | Поштучная обработка и лимиты до/во время распаковки |
| Fleet thundering herd | Детерминированный jitter и rollout waves |
| Компрометация update control plane | Signed manifest, anti-rollback, health rollback |
| Несогласованный rollout client/server | Dual-stack contract, fixtures, documented order |
| Документация снова отстанет от кода | README/wiki/Plan обновляются в том же PR, где меняется поведение |
