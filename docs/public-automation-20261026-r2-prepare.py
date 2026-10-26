"""Local docs only; no network/runtime/MCP. Exclusive new artifact writes."""
from pathlib import Path
import hashlib,json,re
D=Path(__file__).resolve().parent
P='public-automation-20261026-r2-'
BASES={2:(9,'public-progress-20261025-doc2-reconciled-full.md'),8:(5,'public-progress-20261025-doc8-finish-diagnostic-full.md'),9:(3,'public-progress-20261025-doc9-proposed-full.md'),15:(4,'public-progress-20261025-doc15-reconciled-full.md'),16:(4,'public-progress-20261025-doc16-reconciled-full.md')}
def once(t,a,b):
 assert t.count(a)==1,a
 return t.replace(a,b,1)
def add(t,s):return once(t,'\n## Non-goals\n','\n'+s.strip()+'\n\n## Non-goals\n')
B={n:(D/f'public-automation-20261026-doc{n}-full.md').read_text() for n in BASES}
purposes={2:'Fixture/live граница bounded public Docker Hub scan и интерфейс выполнения отдельно от серверной admission/coverage authority. Явно приблизительная локальная неравновесная оценка не меняет native percent=null, durable-outcomes-v1 или terminal reducer. Checked не означает безопасность; public и legacy profiles независимы.',8:'Безопасная серверная OpenRouter сводка, дополняющая, но не заменяющая scanner report. Исторический LOCAL Apodex/Novita и общий legacy профиль сохраняются; fixed public Xing/Phala получает operation-specific structured output и ограниченное process-lifetime чтение уже полученной сводки.',9:'Браузерная панель сводки завершённого owner report отдельно от серверного контракта DOC8. Public account opt-in разрешает ограниченную автоматику, но не автоматические chat questions; passive recovery уже сохранённого результата не является generation.',15:'Безопасный ручной чат текущего scan и конечная доставка уже проверенного полного ответа, не provider token streaming. Сохраняются NDJSON v1/JSON, durable history/CAS, receipt/accounting/authority и транспортные границы DOC8/11/14.',16:'Отдельный public selected-advisory ru перевод через существующий LLM контур. Оригинал, provenance, unknown language, identifiers/counts/coverage неизменны. Public account preference разрешает только открытые source slots; машинная производная не официальный NVD/БДУ источник.'}
for n in B:
 title=B[n].splitlines()[0]
 B[n]=title+'\n\n## Purpose\n'+purposes[n]+'\n\nПолная superseding редакция26.10.2026 от DIP-TASK-'+('9' if n==2 else '42')+' поверх свежей серверной базы v'+str(BASES[n][0])+'. Новое явное поручение владельца supersedes прежние no-estimate/no-auto/button-only ограничения только в указанной области. Предыдущие authoring/transcription/FAIL/UNKNOWN записи остаются в неизменённых прежних файлах и серверной истории; прежние пять pending proposals discarded как рассмотренные-superseded, не исправленные задним числом. Это SOURCE-BOUNDED PROPOSAL, NOT APPLIED и не deployed/native/provider/semantic/privacy/billing acceptance. APPLY HOLD до нового coordinator source GO/deploy. Принятые задачи и родители не переоткрываются.\n\n## Requirements\n'+B[n].split('## Requirements\n',1)[1]
B[2]=once(B[2],'либо наблюдается новый queued','либо наблюдается новый queued или регрессия durable outcomes/checked credit')
B[2]=once(B[2],'невидимый restart running→running этим UI надёжно не определяется.','наблюдаемая потеря прежнего nonnull outcome либо checked credit сбрасывает оценку даже при running→running. Одно отсутствие metadata не доказывает регрессию. Невидимый внутренний retry без изменения outcomes надёжно не определяется; оценка может расти без новых фактов и не измеряет текущую attempt.')
B[2]=once(B[2],'list/detail показывают resolvedChecks','деталь читает status, а список выполняет один scoped list query каждые2000ms только при активных queued/running/cancelling записях без per-card status GET/N+1; access error останавливает poll, demo не poll. List/detail показывают resolvedChecks')
B[8]=once(B[8],'открытие/focus/reconnect/context GET не являются разрешением и не вызывают модель.','открытие/focus/reconnect/context GET не являются разрешением и не вызывают модель.') if 'открытие/focus/reconnect/context GET не являются разрешением и не вызывают модель.' in B[8] else B[8]
B[8]=once(B[8],'Cookie-bound context GET доступен','Только public composition дополнительно допускает passive summary GET на том же exact path по требованию process-lifetime retrieval ниже; legacy/LOCAL summary ingress остаётся POST-only. Cookie-bound context GET доступен')
B[8]=add(B[8],'''### Requirement: Public passive чтение process-lifetime сводки
Сервер SHALL только в public composition возвращать уже успешно опубликованную validated summary через GET `/api/v1/browser/scans/:scanId/llm/summary` после свежих session/owner/current-report/policy guards, не вызывая generation, provider/key lookup, quota или history.

#### Scenario: Успешный POST и повторное чтение
- GIVEN bounded consent-bound public POST прошёл validation и синхронный final publication guard
- WHEN тот же owner с текущим digest/platform/reportVersion/policyVersion запрашивает GET, в том числе после browser reload или fresh login
- THEN пока entry существует в том же LlmService instance, возвращается detached exact enriched summary DTO без cache wrapper/новых cached/available/generatedAt/policyVersion полей, JSON200/no-store/X-LLM-Summary-Retention:process-lifetime. POST сохраняет результат только после успешного guarded write; failed/invalid generation не создаёт новый safe result, прежний exact safe result может сохраниться. GET не требует generation consent и никогда не переходит к POST/provider/quota.

#### Scenario: Bounded lifetime и отсутствие
- GIVEN cache ограничен64entries,2MiB accounted result/key/scope UTF-8 bytes и65536result bytes/entry с LRU, либо результат отсутствует/evicted/API instance заменён
- WHEN авторизованный owner читает текущий report
- THEN miss404 LLM_SUMMARY_MISSING не сообщает причину и не разрешает новую generation; API restart/destruction/replica/eviction теряют cache, гарантированного срока или DB/file durability нет. Owner+scan/full binding изолированы, encountered report/policy change или disabled policy инвалидирует obsolete scope; восстановление прежней настройки не оживляет удалённый entry. Heap object overhead не называется точным byte accounting.

#### Scenario: Foreign и actual publication race
- GIVEN scan чужой/отсутствует либо session/access/report/policy изменились до HTTP write
- WHEN GET либо POST пытается публиковать результат
- THEN чужой/несуществующий scan даёт404 SCAN_NOT_FOUND до policy/cache disclosure; legacy/nonpublic GET также не читает cache. Current session/report/policy fences действуют непосредственно при synchronous write, POST дополнительно проверяет abort; stale/private result не публикуется, raw exception не раскрывается. Dispatched/unknown consumption не refund. Public ingress GET+POST требует отдельного deployment; API-only tests не доказывают proxy/browser acceptance.
''')
B[9]=once(B[9],'смена раскрываемого профиля/области требует новой automation revision и повторного Save, не автопринятия.','автоматика принимает только exact fixed disclosure: OpenRouter, xingchen-agi/xing4.0-29b-a4b:free, providers=[phala], global, no-storage, freeOnly=true, requestBudgetUsd=0, operatorApprovedRouting=true, providerComplianceNotProvenByDeclaration=true и maxPrice ровно prompt/completion/request=0, без лишних keys. Summary data ровно `Sanitized scanner findings and coverage; no raw evidence or credentials.`; другая модель/endpoint/data/retention/flags/caps/extra metadata запрещают POST и публикацию. Constant report-automation-v1 не является dynamic policy grant; fresh operation policyVersion и full context обязательны. Изменённое раскрытие требует новой поддержанной версии согласия, не молчаливого принятия новым Save старой версии.')
B[9]=once(B[9],'Успешное сохранение original/off отзывает будущую автоматику, не уже отправленные данные;','Каждый Save заменяет snapshot identity; сравнение только постоянного revision недостаточно. Прямые subscriptions и свежий read проверяют ту же identity/session и применимый autoSummary либо ru флаг перед POST и publication, включая cached reply и callback ignoring abort. Успешное сохранение original/off отзывает будущую автоматику, не уже отправленные данные;')
B[9]=once(B[9],'настройки не синхронизируются на другие устройства.','настройки не синхронизируются на другие устройства. Failed persistence запрещает автоматику текущего memory scope, но не обещает durable revocation прежней записи после следующего login.')
B[9]=once(B[9],'одну активную локальную automation job','одну активную локальную scheduled job')
B[9]=once(B[9],'Outputs остаются только в памяти и очищаются при смене сессии, reload их не восстанавливает.','Browser outputs остаются только в памяти и очищаются при смене сессии; translation после reload не восстанавливается. Public summary сначала пытается passive GET recovery по следующему требованию, независимо от browser marker и autoSummary opt-in. Miss не очищает marker и не разрешает replay; без прежнего marker первая допустимая auto-попытка по отдельному сохранённому opt-in остаётся возможной.')
B[9]=add(B[9],'''### Requirement: Passive summary recovery до attempt marker
Интерфейс SHALL для completed public report читать fresh context и existing summary до проверки generation attempt marker, восстанавливая только текущий owner/report/policy-bound результат без требования autoSummary opt-in.

#### Scenario: Reload или новый login с выключенной автоматикой
- GIVEN тот же owner заново открыл completed public report, autoSummary может быть off, backend ещё сохраняет exact result
- WHEN выполняются context GET и `existing(context)` GET summary
- THEN reply проходит tuple/schema, authorised citations/source pages и postflight context checks; текущие preference snapshot/session/permissions ограждают publication. Read не является новым consent/POST/квотой; отключение автоматики не запрещает owner чтение прежнего результата. Иной owner/report/policy и stale callback не получают summary. Recovery GET не выполняется для legacy report, его generation contract не меняется.

#### Scenario: Missing и ограниченное удержание
- GIVEN GET вернул LLM_SUMMARY_MISSING либо endpoint недоступен/контекст stale
- WHEN UI решает, что показывать
- THEN отсутствующий retained result не выдаётся за пустую сводку или guaranteed durable history; ошибка не запускает replay и marker не сбрасывается. При уже отмеченной попытке нет автоматического POST; первоначальная разрешённая попытка без marker отдельно проходит opt-in/fresh guards. API restart/eviction/другая replica теряют summary cache по DOC8, не scanner report.

### Requirement: Bounded passive metadata scheduling
Интерфейс SHALL ограничивать passive summary/translation metadata pending singleflight тем же локальным serial scheduler, что и automation jobs, без attempt marker или сохранения stale readiness результата.

#### Scenario: Несколько открытых source panels
- GIVEN разные открытые source slots читают context/readiness либо summary recovery
- WHEN passive metadata планируются параллельно
- THEN одна scheduled job активна, до8 ждут; pending metadata keys не более9 и scoped текущим session+operation binding, одинаковый pending key разделяется подписчиками. Task допускает до2 параллельных GET, generation job не вкладывает scheduler в самого себя; отсутствие metadata capacity безопасно отказывает без provider dispatch/retry. Settled entry удаляется, не становится долгоживущим readiness cache.

#### Scenario: Отмена и граница локальной сериализации
- GIVEN pending metadata имеет нескольких подписчиков либо сессия изменилась
- WHEN один подписчик отменён либо освобождён последний/изменён session
- THEN отменённый подписчик не публикует stale result, общий read отменяется после последнего, session change отменяет jobs/clears maps. Metadata не создаёт generation marker. Освобождение локального slot после abort не доказывает остановку игнорирующего abort внешнего транспорта; это не распределённый lock/глобальный exactly-once.
''')
B[15]=once(B[15],'scope change отменяет stale draft/callback.','scope change отменяет stale draft/callback. Прямая подписка и свежая identity preference snapshot ограждают callbacks при Save/отзыве; explicit chat/history не требуют autoSummary либо ru флага, но старый snapshot не разрешает публикацию после изменения настроек.')
B[16]=once(B[16],'Смена раскрываемых модели/провайдера/данных/условий требует новой automation revision и повторного Save; local grant не серверная authority.','Exact account disclosure проверяется до POST и публикации: fixed поля DOC9 плюс targetLanguage=ru, machineTranslation=true, automaticDispatch ровно строка account-preference, persistentTranslationCache=false и data ровно `Only the selected normalized advisory title and description eligible for translation; no other report metadata, package data, history, raw evidence or credentials. Identifiers within the selected text remain unchanged.`. Producer/strict decoder/helper/runner принимают эту строку, не прежние boolean false/true или похожие значения. Это client opt-in declaration, не dispatch от server GET. Extra/mismatched model/providers/data/privacy/flags/caps запрещают send/publication; изменённые условия требуют новой поддержанной версии согласия, local grant не server authority.')
B[16]=once(B[16],'validated in-memory reply может использоваться лишь после fresh context/readiness/source проверки,','validated in-memory reply может использоваться лишь после fresh context/readiness/source/exact-disclosure и fresh preference snapshot identity+ru flag проверки,')
B[16]=once(B[16],'Закрытие отменяет ожидание и stale publication;','Прямые preference/session subscriptions отменяют ожидание/результат при Save/отзыве ещё до React rerender; одинаковая constant revision не разрешает прежний callback. Закрытие отменяет ожидание и stale publication;')
B[16]=once(B[16],'без persistent translation cache или скрытого обхода отчёта.','без persistent translation cache или скрытого обхода отчёта; passive metadata pending singleflight/bounds/abort соответствуют DOC9.')
# Clearly label inherited authoring/review prose as historical; never rewrite original artifacts.
for n in B:
 if '\n## Review и последующее применение\n' in B[n]:
  B[n]=B[n].replace('\n## Review и последующее применение\n','\n## Исторический review и последующее применение\nНиже сохранены датированные сведения прежних редакций, не текущие policy/GO/runtime claims. Текущая policy revision требований выше — russian-prose-v4-structured; новый APPLY HOLD не снят.\n\n',1)
 # Remove historical non-goal ambiguity only where current cache is in scope.
 if n==8:
  B[n]=once(B[n],'Чат, история, retrieval/сжатие контекста, кэш и cost UI относятся к TASK14–16, не TASK13/37.','Чат, история, retrieval/сжатие контекста и cost UI относятся к TASK14–16. Public process-lifetime summary retrieval выше — отдельное новое TASK42 дополнение, не durable output/history cache или изменение исторического TASK13/37 scope.')
 def clauses(t):
  out={}
  for s in re.split(r'^### Requirement: ',t,flags=re.M)[1:]:
   name,body=s.split('\n',1);out[name]=re.split(r'^## ',body,flags=re.M)[0].strip()
  return out
 base=(D/BASES[n][1]).read_text();a,c=clauses(base),clauses(B[n]);assert a.keys()<=c.keys()
 assert not re.search(r'[ \t]+$',B[n],re.M)
 target=D/f'{P}doc{n}-full.md'
 with target.open('x') as f:f.write(B[n])
record=[]
for n,t in B.items():
 a,c=clauses((D/BASES[n][1]).read_text()),clauses(t)
 record.append({'doc':n,'base_version':BASES[n][0],'source':'DIP-TASK-'+('9' if n==2 else '42'),'path':f'docs/{P}doc{n}-full.md','bytes':len(t.encode()),'sha256':hashlib.sha256(t.encode()).hexdigest(),'requirements':len(c),'scenarios':len(re.findall(r'^#### Scenario:',t,re.M)),'local_expected_ops':[{'kind':'modified','name':k} for k in a if a[k]!=c[k]]+[{'kind':'added','name':k} for k in c if k not in a]})
with (D/f'{P}preparation.json').open('x') as f:json.dump(record,f,ensure_ascii=False,indent=2);f.write('\n')
print(json.dumps(record,ensure_ascii=False,indent=2))
