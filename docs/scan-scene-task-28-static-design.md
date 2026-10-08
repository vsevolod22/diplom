# DIP-TASK-28 — «Паспорт исследования», новая статичная итерация

## Sign-off до кода

- Run: `7fe1e0be-b7bc-4929-9b1c-93176d81a90c`; последовательные preparatory lead → architect → author, один агент `ui28:lead-author` (GPT-6.1-Sol). Это авторский дизайн-sign-off, НЕ независимое ревью и НЕ пользовательская приёмка.
- Текущий отзыв `9024e5ec-6f71-455c-bcbd-d1f824fa9cf5` отклоняет вращающиеся блоки; старое done/025e597 не является одобрением этого дизайна.
- Выбор подписан архитектором `ui28:lead-author` до production edits: **«Паспорт исследования»**. Спокойная выразительность через контраст светлой бумаги и тёмного A1, тонкие координатные линии, крупный номер/типографику и вложенные статичные области. Lime — list, coral — create, cyan — detail. Никаких 3 равных square cards.

## Конкретная композиция

Общий маршрут «цель → область проверки → отчёт» — иллюстрация чтения, не реальный статус. Все сцены целиком `aria-hidden`, без focusable controls, процентов, badges успеха или временной шкалы.

- **List / каталог:** вертикальный паспорт. Крупная цель с Lucide Box, ниже scope с двумя строками «Проверки / Ограничения», внизу узкий линейный лист отчёта с FileText. Маленький фолио «01 / КАТАЛОГ» и подпись «Схема чтения · не результат». Нижняя часть сцены оставляет место существующему CTA.
- **Create / границы:** тот же визуальный язык, иной акцент: заголовок «Сначала границы», выделенная рамкой вложенная область «Образ / Доступ», конечная строка «Отчёт / После проверки», не иллюзия работающего запуска. Ни disabled CTA, ни фактическая форма не анимируются и не переносятся.
- **Detail / доказательства:** компактный разворот на 170px: слева типографическая цель, справа две вложенные ruled строки scope→report. Никакого большого слова, вращения, декоративного прогресса или перекрытия следующего блока coverage.
- На 320/375px текст декора переносится, `minmax(0, 1fr)` на каждой вложенной grid; факты и controls существуют отдельно от декора и видимы сразу. Detail использует компактные размеры, create сохраняет достаточную собственную высоту вместо прежнего сжатия до 150px.

## Проверенные constraints и write set

Прочитаны текущие ScanScene, GlowEffect, MagicCard и соответствующие диапазоны scan-a1.css; peer scan-detail-a1.css **только прочитан**: `.scan-a1__detail-divider` height 170px, legacy scene-art inset/padding, scene-word font size, tracks/footnote display:none. Новые внутренние классы не конфликтуют с этим контрактом; peer stylesheet НЕ меняется.
List: absolute scene внутри intro-art, CTA z-index 1. Create: relative scene min-height390 desktop/150 mobile. Scope CSS изменений — только scene/glow/spotlight и необходимые scene-container размеры; nav/auth/shell selectors не меняются.
Write ONLY `src/features/scans/{ScanScene.tsx,GlowEffect.tsx,MagicCard.tsx,scan-a1.css}`, отдельные новые scene tests и этот документ. Backend/egress/OCI resolver/SQLite ledger неприменимы к этой визуальной задаче: никаких transport changes, LIVE, auth, private files, model calls, commit, spec apply или task close.

## Эффекты и происхождение

- ScanScene — оригинальная project composition; Lucide уже установлен, новый registry source не копируется. Existing Radix guide tabs/accordion остаются на страницах, не дублируются в декоративной сцене.
- GlowEffect сохраняет статическую адаптацию градиента, удаляет mode rotate/pulse и infinite transitions; по умолчанию статичен. Исходное происхождение/MIT сохранены в `docs/notices/motion-primitives.md` (upstream commit `120f64f6ca60348e251f929e9c81f11ccbe45eda`, source SHA256 `cd9f31a6d7cf261801569547241530794f578b37b946ff320bd6192897658949`). Историческое описание анимационного адаптера там относится к прежней версии; в новой сцене glow не используется, статический adapter оставлен без animation API.
- MagicCard сохраняет существующий upstream pointer gradient и notice `docs/notices/magic-card.md` (commit `d7207e5692d14c00dceafa8488d6d01f197fa0e4`, source SHA256 `6139e78ed228ebca18ed144f4a2714a89214c2ef604f1f82bc2f61204c3f3fa3`). Только конечный pointer response; reduced motion не двигает spotlight, touch не создаёт эффект. Keyboard — существующий видимый focus, без дополнительных tab stops.
- Существующие notices и четыре foreign untracked notice-файла не переписываются. Нет новых dependencies, canvas, registry imports, global reset.

## План проверки / handoff

Отдельные component tests на все 3 variants: immediate static markup, aria-hidden/no controls, статический GlowEffect, MagicCard facts outside decoration. Отдельный browser suite на fixture routes: 320/375/1280 × normal/reduced; geometry каждого декоративного текста внутри scene, coverage/reasons/percent=null вне art, pointer gradient normal vs reduce, keyboard tabs/accordion/filter return. Сохранить до/после screens без перезаписи старых, сравнить actual scene geometry; typecheck, targeted lint, focused Vitest, build на общем дереве с явной атрибуцией. Full suite и LIVE не запускать. DOC-2 v6 допускает оформление без изменения documented contracts; task-level no-spec-impact только при подтверждении такого результата. Ровно три независимых review work items передать, ни один не claim самим автором.

## Evidence

### Фактический результат автора (2026-10-08)

Подписанный выбор записан в task comment `bf69bd77-62bb-451f-b850-dab270fa24ee` перед production edits. Реализованы три passport variants; ScanScene больше не импортирует Motion/GlowEffect и не зависит от IntersectionObserver. GlowEffect static-only; MagicCard finite mouse-only с reduced guard и pointercancel reset, без внешнего clipping focus/content. На mobile list найдено перекрытие декоративной подписи соседним CTA, устранено собственными container dimensions; browser assertion теперь сравнивает footer.bottom и CTA.top.

| Проверка | Наблюдаемый результат |
| --- | --- |
| `SCENE_BASELINE=1 pnpm exec playwright test -c tests-e2e/scan-scene-task-28.config.ts` до production edits | 9 before capture tests passed, 9 reduced cases intentionally skipped |
| `pnpm exec vitest run tests-vite/ui/scans/ScanSceneTask28.test.tsx` | 5/5 passed: 3 route variants, static SSR/DOM, GlowEffect default, MagicCard semantic children |
| `pnpm exec playwright test -c tests-e2e/scan-scene-task-28.config.ts` финальный прогон | 19/19 passed, Chromium: 320/375/1280 × no-preference/reduce на list/create/detail + long-stage/decor-disabled case |
| `pnpm typecheck` | passed на shared tree |
| targeted ESLint: 3 owned TSX components + dedicated component test/browser spec/config | passed, zero reported diagnostics |
| `pnpm build` (после formatter) | passed, Vite 7.2.2, 2298 transformed modules, shared tree |
| `git diff --check` | passed на shared diff |
| Дополнительный существующий `ScanPages.test.tsx` | **16/18 passed, 2 failed** на concurrently modified shared tree; не выдаётся за зелёный suite |

Новый browser suite проверяет actual Range.getClientRects каждого decorative text node в границах сцены; detail height ровно170px, transform:none/opacity:1, отсутствие browser animations в scene subtree и стабильную geometry. Отдельно: длинный 280-character stage переносится внутри facts cell на320px; disable-decoration case сохраняет unknown progress, failed coverage/reason и disabled launch. Fixture case зарегистрировал zero `/api/v1/` requests; guard aborts API, не JS modules. Mouse gradient changes normal, не меняется reduced, touch не двигает gradient; keyboard guide tabs, report accordion, mobile filter Escape/focus return работают. Tests не доказывают независимую эстетическую приёмку.

У дополнительного shared-tree `ScanPages.test.tsx` два наблюдаемых failure: `labels every fixture...` использует singular query для текста «Выполнено (не гарантия безопасности)», который теперь совпадает с badge и отдельным `<p>Secrets:…</p>`; `confirms live cancellation...` ожидает resultReads=1, наблюдается0. Это mock-тест, не LIVE-запрос. Их причина/согласование принадлежит независимому integration review изменённого peer report, здесь tests/pages/transports не правились. Не утверждаем, что весь общий UI suite прошёл. Full suite не запускался; ручной VoiceOver, browser zoom, Safari/Firefox, LIVE, long-digest успешного GET, not_authorized/error-results отдельно НЕ проверены.

### Кадры

В `docs/scan-scene-task-28-screens/` сохранены **36 PNG**: 9 before scene crops, 18 after crops (все viewport/preferences), 9 full-page reduced screenshots. Before — текущий repo baseline этого прогона, НЕ восстановленный fbff6be. After page screenshots включают текущие peer39 report changes, потому визуальный вклад TASK28 сравнивается прежде всего по scene crops.

- `before-{list,create,detail}-{320,375,1280}.png`
- `after-{list,create,detail}-{320,375,1280}-{no-preference,reduce}.png`
- `page-{list,create,detail}-{320,375,1280}.png`

### Shared-tree attribution и размеры

HEAD при сборке/хешировании `127e93b7ef19d69743ff9af2a4147e72949dc36b`, существующая ветка `feat/dip-task-30-21st-components`; новая ветка/commit не создавались. В начале только четыре foreign notice-файла были untracked. Во время работы другой автор изменил `src/pages/scans/{ScanDetailPage.tsx,VulnAdvisoryCard.tsx,scan-detail-a1.css}` и добавил `CursorReportPager.tsx`, `ScanReportSections.tsx`, `tests-vite/ui/scans/reportPaging.test.tsx`. Всё это **не write set ui28:lead-author**; не переписывал, не откатывал, не включаю в собственное авторство. Typecheck/build и дополнительные integration tests читают общее дерево; полный diff не равен TASK28.

Final shared-tree build raw/gzip (Vite-rounded): `ScanScene.js`14.74/5.75kB, `ScanScene.css`15.89/3.52kB, `ScanListPage.js`5.64/2.42kB, `ScanDetailPage.js`85.88/27.10kB. Размер scene chunk включает shared imports/CSS, не только ScanScene.tsx; не складывать чанки как route load. Изолированного before build на неизменном peer tree нет, поэтому bundle diff не заявляется; сборка включает чужие report changes. Новых dependencies нет.

SHA256 собственных production files:
- ScanScene.tsx: `73e3336320c5e0368a128b514b39cedb98846f0c887694d46e7b25a4ac770a2f`
- GlowEffect.tsx: `8388be36fec36c92eab2939563f50ee835ca6c8fdbb4d59f6a0f919297b5df71`
- MagicCard.tsx: `03b7d479700e95375fca65861bd997d03a1b9899c26e83f4454a59efb13c5b67`
- scan-a1.css: `144f753de745af2d9f3076a2833e8d563590450a656877dec0c716d1c0e350a8`

Task-level no-spec-impact **для DIP-TASK-28** объявлен2026-10-08: только декоративное оформление и необязательный конечный effect; contracts DOC2v6, fixture/live, facts/controls/coverage неизменны. Spec не применялся, история не удалялась; task остаётся для независимой приёмки, не closed. Автор передаёт результат ровно3review work items; роли reviewer/integrator не claim. Usage недоступен агенту, нули/стоимость/токены не выдумываются.
