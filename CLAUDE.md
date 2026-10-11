# CLAUDE.md

Инструкции для Claude при работе с репозиторием SLeep.

## О проекте

SLeep — учебный проект для выпускной квалификационной работы (КФУ) на тему
**«Сервис для выявления уязвимостей и расследования инцидентов системы»**.

Это мультиарендная (multi-tenant) платформа для аналитиков SOC:

- агент собирает с Linux- и Windows-серверов факты о системе (пакеты, порты,
  процессы, конфигурацию, журналы, учётные записи);
- облако сопоставляет установленное ПО с CVE, группирует сырые записи в события
  и считает объяснимый риск;
- аналитик объединяет события и CVE в инцидент и расследует его по хронологии.

Две половины темы ВКР соответствуют двум частям продукта: **выявление
уязвимостей** — это CVE-находки, риск и безопасные проверки; **расследование
инцидентов** — события, инциденты, хронология и вердикт.

Перед содержательными изменениями прочитай документацию:

- `docs/product-plan.md` — цели, принятая архитектура, граница MVP;
- `docs/incident-investigation.md` — спецификация упрощённого расследования
  инцидентов (модель данных, хронология, подсказки, API, интерфейс);
- `docs/vulnerability-database.md` — база знаний об уязвимостях: источники,
  схема `vulndb`, алгоритм синхронизации, сравнение версий dpkg;
- `docs/self-hosting.md` — запуск и развёртывание.

## Текущее состояние

- **API** хранит данные в PostgreSQL: SQLAlchemy, Alembic (миграции
  `0001`–`0004`), seed демо-данных по флагу, `/ready`, тесты на изоляцию
  организаций. Ветка `feature/postgres-persistence` влита в `main` (PR #1).
- **Доступ к сайту** закрыт HTTP basic auth в Caddy (локально
  `analyst` / `sleep-local`) — временно, до настоящей аутентификации.
- **База знаний об уязвимостях** (`services/vulndb`) — готова: отдельный
  сервис загружает OSV (Debian, Ubuntu), EPSS и CISA KEV в схему PostgreSQL
  `vulndb` (своя история Alembic), обновляет их по расписанию и умеет отвечать,
  какие CVE затрагивают версию пакета (`sleep-vulndb lookup`).
- **Агент на Go** (`agent/`) — не начат: в репозитории только пустые каталоги.
- **Обработка данных** — сопоставление инвентаризации с базой знаний (создание
  `cve_findings`), кластеризация событий, расчёт риска и план исправлений не
  начаты.
- **Расследование инцидентов** — специфицировано, не реализовано.
- **Веб-интерфейс** не обращается к API: данные захардкожены в
  `apps/web/app/page.tsx`.

Если какое-то утверждение здесь расходится с кодом, верь коду и обнови этот
файл.

## Структура репозитория

```text
agent/                 Go-агент (пусто): cmd/sleep-agent, internal/{collector,config,transport}
apps/web/              Интерфейс аналитика: React 19, TypeScript, Vite 8, Tailwind 4, shadcn/ui
  app/page.tsx         Единственный экран (устройства, вкладки CVE и Events)
  app/globals.css      Тема и CSS-переменные
  components/ui/       Сгенерированные компоненты shadcn (стиль base-nova, @base-ui/react)
  src/main.tsx         Точка входа Vite
services/api/          FastAPI
  src/sleep_api/
    main.py            Маршруты и зависимости
    models.py          Pydantic-модели — контракт API
    db_models.py       SQLAlchemy-модели
    repository.py      Доступ к данным (SqlRepository)
    database.py        Engine и сессии
    seed.py            Демо-данные
  migrations/          Alembic
  tests/               pytest
services/vulndb/       Обновление базы знаний об уязвимостях (единственный сервис с выходом в интернет)
  src/sleep_vulndb/
    cli.py             Команды run, sync, status, lookup, health
    scheduler.py       Цикл обновления по интервалам, пульс для healthcheck
    sync.py            Запуск источника: одна транзакция, журнал sync_runs, блокировка
    sources/           osv.py (Debian, Ubuntu), epss.py, kev.py
    http.py            Скачивание: условные запросы, повторы, лимит размера
    lookup.py          Какие CVE затрагивают версию пакета
    debversion.py      Сравнение версий как в dpkg
    cvss.py            Базовый балл CVSS v3.1 по вектору
    db_models.py       Таблицы схемы vulndb
  migrations/          Alembic, версия в vulndb.alembic_version
  tests/               pytest; источники подменяются фейковым HTTP
deploy/Caddyfile       Единая точка входа: / → web, /api/* → api
compose.yaml           gateway (Caddy), web (nginx), api, vulndb, postgres
compose.dev.yaml       Только для разработки: PostgreSQL на 127.0.0.1:5432
docs/                  Документация продукта
```

## Команды

Полный стек (из корня):

```bash
cp .env.example .env
docker compose up --build -d      # http://localhost:8080 (analyst / sleep-local), API: /api/docs
docker compose down
```

Без `POSTGRES_PASSWORD`, `BASIC_AUTH_USER` и `BASIC_AUTH_HASH` в `.env` стек не
запустится — так задумано. Хеш пароля в `.env` держи в одинарных кавычках:
иначе Compose съест символы `$`.

API (из `services/api`, нужен Python 3.12+):

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest                             # unit-тесты и проверка миграций на SQLite
uvicorn sleep_api.main:app --reload
```

Работа с БД (в основном compose PostgreSQL наружу не публикуется):

```bash
docker compose -f compose.yaml -f compose.dev.yaml up -d postgres   # БД на 127.0.0.1:5432
export SLEEP_DATABASE_URL='postgresql+psycopg://sleep:sleep@localhost:5432/sleep'
alembic upgrade head
python -m sleep_api.seed
alembic revision -m "описание"     # новая миграция, имя файла — см. ниже
SLEEP_TEST_DATABASE_URL='postgresql+psycopg://…/test_db' pytest   # тест миграций на PostgreSQL
```

Сервис базы уязвимостей (из `services/vulndb`, Python 3.12+):

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest                             # SQLite; HTTP-источники подменены, интернет не нужен
SLEEP_TEST_DATABASE_URL='postgresql+psycopg://…/test_db' pytest   # + PostgreSQL
sleep-vulndb sync --source kev     # разовое обновление (нужен интернет)
sleep-vulndb status
sleep-vulndb lookup --ecosystem Ubuntu:22.04:LTS --package openssh --version 1:8.9p1-3ubuntu0.6
docker compose exec vulndb sleep-vulndb status   # в запущенном стеке
```

Веб-интерфейс (из `apps/web`, Node 22.13+, pnpm). Версия pnpm закреплена в
`package.json` (`packageManager`), Dockerfile ставит именно её. Не убирай
закрепление: без него в образ попадает самая новая pnpm, и сборка ломается.
Обновляй версию осознанно, вместе с `pnpm-lock.yaml`.

```bash
pnpm install
pnpm dev        # Vite dev server
pnpm build      # tsc --noEmit + vite build
pnpm lint       # oxlint (с проверкой типов)
pnpm format     # oxfmt
```

После изменений запускай тесты и линтер той части, которую менял.

## CI

Два workflow в `.github/workflows/`:

**`test.yml` (Test)** — на push в любую ветку и вручную (отдельного триггера
`pull_request` нет: PR показывает статусы push-прогонов своей ветки):

- `api` — `pytest` на Python 3.12 с сервисом PostgreSQL 16, включая проверку
  миграций на PostgreSQL (`SLEEP_TEST_DATABASE_URL`);
- `vulndb` — `pytest` сервиса базы уязвимостей на Python 3.12 с PostgreSQL 16
  (миграции в схеме `vulndb`, синхронизация, блокировки); интернет не нужен;
- `web` — `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm build`;
- `stack` — после `api`, `vulndb` и `web`: собирает весь `docker compose` с
  демо-данными и `SLEEP_VULNDB_SOURCES=none` (без внешних источников), ждёт
  `healthy` и проверяет через шлюз, что без логина отвечает `401`, а с логином
  открываются интерфейс, `/api/health`, `/api/ready` и устройства; затем
  проверяет `sleep-vulndb status` и `health` внутри контейнера.

**`publish.yml` (Publish)** — запускается событием `workflow_run`, когда Test
успешно завершился на push в `main`. Публикует ровно протестированный коммит
(`workflow_run.head_sha`) в GitHub Container Registry:
`ghcr.io/uni-999/sleep-api`, `ghcr.io/uni-999/sleep-vulndb` и
`ghcr.io/uni-999/sleep-web` с тегами
`<12 символов SHA>` и `latest`. Право `packages: write` есть только у этого
workflow; pull request'ы его не запускают. Публикации идут по одной
(`concurrency: publish`), чтобы `latest` указывал на последний push. Push в другие ветки
только тестируется, образы из них не публикуются.

Сервера пока нет, поэтому автоматического развёртывания (CD) нет. Когда
появится VM, задача деплоя добавится в `publish.yml` после публикации.

Новая функциональность должна проходить Test. Если меняешь способ запуска,
порты, логин или healthcheck, обнови смоук-тест в задаче `stack`. Имя
workflow `Test` используется в `publish.yml` — переименовываешь одно, меняй и
другое.

## Архитектурные инварианты

Не нарушай их без явного решения автора; если задача их затрагивает, сначала
предупреди.

1. **Изоляция организаций.** Каждый объект принадлежит `organization_id`.
   Каждый запрос к данным фильтруется по организации. Связи между таблицами
   задаются составными внешними ключами `(organization_id, …)`, чтобы БД сама
   запрещала ссылки между организациями. Чужой объект в API — `404`, а не `403`.
2. **`X-Organization-ID` — временная граница.** Это не аутентификация. Не строй
   на этом заголовке логику прав; в будущем организация и роль будут браться из
   проверенного токена. Пока её нет, весь сайт (включая `/api`) должен оставаться
   за `basic_auth` в `deploy/Caddyfile` — не убирай и не ослабляй его.
3. **Никакого удалённого управления хостами.** Платформа отправляет агенту
   только декларативные задания из разрешённого списка (сейчас `probe = "safe"`),
   никогда — произвольные команды.
4. **Агент лёгкий.** Граф и тяжёлые вычисления — только в облаке.
5. **Детерминированность и объяснимость.** Расчёт риска, кластеризация событий и
   подсказки в инцидентах — правила, а не «чёрный ящик». Каждый результат
   возвращает причины и ссылки на доказательства.
6. **Доказательства не теряются.** Событие хранит `raw_record_refs`; CVE-находка
   хранит `evidence`.
7. **Производные значения не храним.** Счётчики CVE устройства
   (`cve_count`, `critical_cve_count`) вычисляются запросом из `cve_findings`
   (`SqlRepository._devices_with_cve_counts`). Не возвращай их в таблицу
   `devices`. `risk_score` пока хранится и будет записываться движком риска.
8. **Внешние и внутренние ID.** В БД — UUID; в API — внешние идентификаторы
   (`prod-web-01`, `evt-01842`, `CVE-2024-6387`, `INC-0001`). Внутренние UUID
   наружу не отдаются.
9. **Выход в интернет — только у `vulndb`.** Он подключён к сети `egress`;
   API, PostgreSQL и веб остаются во внутренней сети `backend`. Новые внешние
   источники данных добавляются в `vulndb` (интерфейс `FeedSource`), а не в API.
10. **База знаний — общая и отдельная.** Таблицы `vulndb.*` — справочные данные
    для всех организаций, без `organization_id`; данные организаций туда не
    пишутся. У схемы своя история Alembic; таблицы API в `public` её не
    касаются, и наоборот. Обновление источника атомарно: данные, курсор и
    запись журнала фиксируются одной транзакцией.

## Соглашения по коду

### Бэкенд

- Python 3.12+, аннотации типов везде, `StrEnum` для перечислений,
  `datetime.now(UTC)` — только aware-время.
- `models.py` — контракт API (Pydantic); `db_models.py` — хранение
  (SQLAlchemy). Не возвращай ORM-объекты из маршрутов: преобразуй их в
  репозитории.
- Зависимости FastAPI оформляются через `Annotated[..., Depends(...)]`, как в
  `main.py`.
- Ограничения домена (допустимые статусы, диапазоны) дублируются в БД через
  `CheckConstraint` — так сделано для существующих таблиц.

### Миграции

- Имя файла: `YYYYMMDD_NNNN_short_name.py`, `revision = "YYYYMMDD_NNNN"`.
- Используй `op.batch_alter_table`, чтобы миграции работали и на SQLite.
- Обязательно пиши `downgrade()`.
- Модели и миграции должны совпадать: `test_migration_chain_on_sqlite` выполняет
  `upgrade head`, `alembic check` и `downgrade base`.

### Тесты

- Тест API поднимает SQLite в памяти с `PRAGMA foreign_keys=ON` и seed
  (фикстура `api` в `tests/test_api.py`).
- Тесты `vulndb` не ходят в интернет: фикстура `feeds` (`tests/conftest.py`)
  отдаёт фейковые ответы OSV, EPSS и KEV через `httpx.MockTransport`. На SQLite
  схема `vulndb` снимается через `schema_translate_map`.
- Для каждой новой сущности, принадлежащей организации, добавляй тест, что её
  нельзя прочитать или связать из другой организации — через API и напрямую
  через БД (`IntegrityError`).

### Фронтенд

- React 19 + TypeScript strict, Vite, Tailwind CSS 4, shadcn/ui на
  `@base-ui/react`, иконки `lucide-react`. Импорты через алиас `@/`.
- Тексты интерфейса — на русском.
- `components/ui/*` генерирует shadcn: не правь их вручную без необходимости,
  добавляй новые через `pnpm dlx shadcn add …`.
- Скрипт `lint` перечисляет файлы явно: **добавляй новые файлы в список** в
  `package.json`, иначе линтер их не проверит.
- Форматирование: oxfmt, одинарные кавычки, ширина строки 80.

## Документация и язык

- Общайся с автором на русском.
- `docs/product-plan.md`, `docs/self-hosting.md` и README написаны на английском,
  `docs/incident-investigation.md` — на русском. При правке сохраняй язык файла.
- Принятые продуктовые решения фиксируй в `docs/`, а не только в коде.
  Изменилась архитектура или граница MVP — обнови `product-plan.md`.
- Текст ВКР (пояснительная записка) — на русском. Документы в `docs/` — основа
  для её глав.

## Git

- Основная ветка — `main`; новая работа — в `feature/<кратко>`.
- Сообщения коммитов — на русском, в прошедшем времени, кратко
  («Добавил таблицы инцидентов»).
- Не коммить `.env` и секреты; пароль БД в `.env.example` — только для
  локального запуска.
- Ничего не пушь и не вливай ветки без просьбы автора.

## Что не трогать

- `apps/web/.wrangler`, `.vinext`, `.openai`, `.git.sites-backup` — остатки
  прежнего развёртывания на ChatGPT Sites / Cloudflare. Они в `.gitignore` и не
  используются; удалять только по просьбе автора.
- `apps/web/public/og.png` — картинка для превью ссылок.

## Ближайшие задачи

1. Реализовать расследование инцидентов по `docs/incident-investigation.md`
   (раздел «Этапы реализации»).
2. Подключить веб-интерфейс к API вместо захардкоженных данных.
3. Начать Go-агента: сбор пакетов и ОС, отправка снимка инвентаризации.
4. Сопоставление пакетов из инвентаризации с базой знаний (`lookup.find_affecting`)
   → `cve_findings`, пересчёт после обновления базы, расчёт риска (CVSS, EPSS, KEV).
