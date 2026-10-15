# DIP-TASK-28 — A1 dark/lime паспорт, bounded handoff

## Контекст и границы

Run `c94e9dbe-2434-4982-9d79-814cc059def6`, agent `ui-laptop:lead-author`, GPT-6.1-Sol. Подготовительные lead `9db664b3-2391-44a7-92bb-d20ab9b04f23` → technical architect `055c064f-c011-4a17-a7ab-1c1d9b9bfe7b` → author `358d7cba-f160-4fc9-92f7-6d3db989b65a` последовательно взяты только после появления actual ready work. Это НЕ три независимые оценки.

Новый отзыв `9050fe35-3849-49dc-829c-5a8ed16d8791` сохраняет понравившуюся статичную композицию, но supersedes светлую/бирюзовую палитру принятого `741e4aaf4b6c41dd176ddfe6ff175781958f8f73`. До production edits записан architect signoff `d46d2766-34a9-4130-8302-e6eda9286020`. Исторический design doc и evidence не переписаны.

## Изменение

Единственный изменённый production файл — `src/features/scans/scan-a1.css`, только `.scan-a1__scene`/`passport` color declarations. Local `--passport-*` наследуют реальные `--a1-*` из detail с идентичными fallback на list/create:

| Роль | A1 значение |
| --- | --- |
| Background | `#141324` |
| Nested surface | `#211f34` |
| Ink | `#faf8ff` |
| Muted notes | `#c6c0d6` |
| Accent | `#d1ff5e` |
| Lines | `#605b74` |

Все варианты теперь dark/lime; выделенная фраза — тёмный текст на lime. Никаких новых эффектов, компонентов, зависимостей, upstream copy или global reset. `ScanScene.tsx`, `GlowEffect.tsx`, `MagicCard.tsx` не изменены. Их static/aria-hidden/immediate DOM/finite pointer contracts сохранены. CSS font/layout/padding/height не менялись; detail остаётся 170px. Факты, coverage/reasons, unknown progress и реальные controls вне декоративной сцены.

## Own write set и SHA-256

Все пути относительно repository `startup/diplom/`:

- `src/features/scans/scan-a1.css` — `f14f874da02200d369902d62a3f9bcfdd1a570e833e825e164e20b6238fc986b`
- `tests-vite/ui/scans/ScanSceneTask28Palette.test.tsx` — `c80b7a2175e3c391b11bfef5bc659c8a7bbcda22e6e0f949c6a4fe7f960b74eb`
- `tests-e2e/scan-scene-task-28-palette.config.ts` — `94688980b3e2c5d3e7a4453e18c402bde4fd5591c170910f6d4ffb92566c994a`
- `tests-e2e/scan-scene-task-28-palette.spec.ts` — `ee778d471345cd13b01a6a252add2cc32583f604947c0e7f3960f268318e2a45`
- `tests-e2e/scan-scene-task-28-palette.vite.config.ts` — `8fc77ec7c56d69824bf9fcdf451ff84af5dcd70684da4a34db4fb297e02ca97c`
- `tests-e2e/scan-scene-task-28-palette.vitest.config.ts` — `ae0d3a9d62c1ad5c3036b725ad7f50657b60690eee0a091b74007ddc0d0b01f0`
- Этот новый handoff `docs/scan-scene-task-28-palette.md` (его hash записывается отдельно после сохранения).

Unchanged ScanScene SHA-256 `73e3336320c5e0368a128b514b39cedb98846f0c887694d46e7b25a4ac770a2f`; baseline CSS hash `144f753de745af2d9f3076a2833e8d563590450a656877dec0c716d1c0e350a8`.

## Выполненная focused validation

Новые Vite/Vitest configs используют `envDir:false`, без proxy/private env reads. Browser fixtures ограничены локальным Vite origin, actual `/api/` abort; API requests в прошедших сценариях отсутствуют. Docker, LIVE/scanner/provider/model calls не выполнялись.

- Intentional palette-red: исправленный source-reader тест до CSS change упал на отсутствующем A1 token. Две предшествующие попытки source-reader были ошибками самого теста (jsdom URL, Vitest CSS stub), не доказательством production дефекта.
- `pnpm exec vitest run --config tests-e2e/scan-scene-task-28-palette.vitest.config.ts` — **6/6 PASS**, 2 dedicated files: прежний static component contract5 + palette regression1.
- Targeted ESLint новых пяти TS/TSX test/config файлов — **PASS**. После test-only guard repair повторён только ESLint browser spec — PASS.
- `pnpm exec playwright test --config tests-e2e/scan-scene-task-28-palette.config.ts` — **15 PASS / 1 FAIL** в единственном исходном browser run. Все color/geometry/controls сценарии list/create/detail на **320/1024/1280/1440 normal + 320 reduce** прошли. Последний decor-disabled сценарий ошибочно abort Vite imports в `src/shared/api` из-за glob `**/api/**`; это test-only failure, не production regression.
- После сужения guard до URL pathname `/api/` повторён **только 1 failed case**: `PLAYWRIGHT_JSON_OUTPUT_NAME=test-results/scan-scene-task-28-palette/recheck-results.json pnpm exec playwright test --config tests-e2e/scan-scene-task-28-palette.config.ts --grep 'semantic facts' --output test-results/scan-scene-task-28-palette/recheck-output --reporter=list,json` — **1/1 PASS**. Это фактически выполненная команда; относительный JSON reporter path разрешился от каталога config `tests-e2e/`, поэтому сохранённый успешный JSON находится в `tests-e2e/test-results/scan-scene-task-28-palette/recheck-results.json`, НЕ в repository-root `test-results/`. Whole browser suite заново не запускался; не заявляем фиктивный единый 16/16 run.
- `git diff --check -- src/features/scans/scan-a1.css` — PASS; reviewed production diff содержит только palette declarations/removal пустого create color override, не геометрию/другие selectors.

Browser checks: exact computed background/surface/ink/muted/accent/line; inherited token override; every actual decorative text Range.getClientRects inside scene; no horizontal document/button clipping; unchanged170px detail; zero scene animations/interactive elements; opacity1/transformnone; list footer above CTA; link focus; disabled create launch; immediate unknown progress и failed coverage reason. Последний case сохраняет смысл при display:none декоре. Это fixture UI, не реальная CVE/LLM проверка.

## Screens и результаты, НЕ для commit

`test-results/scan-scene-task-28-palette/` содержит 15 scene crops +15 full-page PNG. Имена `{list,create,detail}-{320,1024,1280,1440}-no-preference.png`, `{list,create,detail}-320-reduce.png`; full-page — prefix `page-`. Production palette screenshot сделан ДО test-local inherited-token override.

Исходный JSON с15pass/1fail: `test-results/scan-scene-task-28-palette/initial-results.json` (копия `tests-e2e/test-results/scan-scene-task-28-palette/results.json`). Failed error-context сохранён в `test-results/scan-scene-task-28-palette/playwright-results/`. Successful recheck JSON — отдельный `tests-e2e/test-results/scan-scene-task-28-palette/recheck-results.json`; recheck output — `test-results/scan-scene-task-28-palette/recheck-output/`. Не перезаписывали historical `docs/scan-scene-task-28-screens/`.

Автор визуально прочитал list1280, detail320/detail1024, create320/create1440 crops; все30PNG передаются independent reviewers. Нет новой before-capture: принятый baseline741e и исторические кадры доступны, композиция доказуемо не менялась по production diff. Screens и test-results не добавлялись в git.

Fullsuite, typecheck/build/bundle delta, VoiceOver/zoom, physical touch/other browsers, credentialed live/CVE scans не запускались в этой color-only итерации и не заявляются. Прежние shared-tree legacy failures не исправлялись/не перепроверялись.

## Preservation и spec impact

Foreign4notice files остаются untracked/нетронутыми: обе LICENSE копии SHA `1564074e13439397221ffd522e2e504d56561994a23d371aa5e3ad43e4f5423f`, обе md копии SHA `f563a63f69cb42d04df66e48ddd61d156b951fa0a79dc3cf1827a53d472c3fc1`, совпали до/после. Source API/shared transport/server/landing/pageCSS39/ScanSummaryPanel/AI-chat не редактировались. Никаких commit/branch/deploy/spec apply/close.

DOC2v6 прочитан: color-only decoration меняет не описанные контракты fixture/live/coverage/facts/controls. Рекомендуется текущий task-level no-spec-impact при independent acceptance; author не применяет delta и не закрывает task. Council/spec_needed не требовался, архитектура не выдумывалась. TASK28 остаётся testing для трёх новых независимых reviewers; author их не claim.

TASK39 остаётся regression и НЕ реализована здесь. После приёмки TASK28 её later author должен расследовать actual unsupported CVE из решения `ec5606c1`, а не рисовать несуществующие страницы: compact laptop summary/coverage, full-width dominant report, ясно именованный CVE pager top/bottom только для actual available pages; отсутствующие/unsupported/scanning-empty без pages controls не рисовать. Не придумывать totalPages/global filter. ScanSummaryPanel/AI integration остаются peer-owned.
