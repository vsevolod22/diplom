import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { ArrowLeft, LockKeyhole } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useLiveScanSession } from '@/features/scans/liveScanContext';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { GuideTabs, GuideTabsContent, GuideTabsList, GuideTabsTrigger } from '@/features/scans/GuideTabs';
import { ScanShell } from '@/features/scans/ScanShell';
import { ScanScene } from '@/features/scans/ScanScene';
import { ScanAccessError, ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import { scanChecks } from '@/shared/api/scans/scanTransport';
import { scanSession } from '@/shared/api/auth/scanSession';

const alpineTargets = [
  { label: 'Alpine · latest', reference: 'registry-1.docker.io/library/alpine:latest' },
  { label: 'Alpine · 3.21', reference: 'registry-1.docker.io/library/alpine:3.21' },
  { label: 'Alpine · 3.20', reference: 'registry-1.docker.io/library/alpine:3.20' },
  { label: 'Alpine · 3.16 (архивный · CVE-пример)', reference: 'registry-1.docker.io/library/alpine@sha256:0db9d004361b106932f8c7632ae54d56e92c18281e2dd203127d77405020abf6' },
] as const;
type ImageSuggestion = { label: string; reference: string; scannable: boolean; reason?: string; tagConfirmed?: boolean };
const searchPageSchema = z.object({
  items: z.array(z.object({ label: z.string().min(1).max(256), reference: z.string().regex(/^registry-1\.docker\.io\/[a-z0-9._/-]+:[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$/), scannable: z.boolean(), eligibility: z.enum(['alpine-only', 'unsupported']), reason: z.string().min(1).max(256), kind: z.enum(['tag', 'repository']), tagConfirmed: z.boolean(), checks: z.object({ secret: z.boolean(), sbom: z.boolean(), vuln: z.enum(['conditional', 'unsupported']) }) })).max(12),
  nextCursor: z.string().regex(/^[a-f0-9]{48}$/).nullable(), state: z.enum(['more-available', 'terminal', 'quota-exhausted']), loaded: z.number().int().min(0).max(60), pages: z.number().int().min(1).max(5),
  policy: z.object({ pageSize: z.literal(12), maxPages: z.literal(5), maxCandidates: z.literal(60), maxActivePerProcess: z.literal(8), maxActivePerSubject: z.literal(2), maxRequestsPerSubject: z.literal(30), rateWindowMs: z.literal(60_000), maxSessions: z.literal(1024), maxRateEntries: z.literal(1024), scope: z.literal('process-local') }),
}).superRefine((page, context) => {
  if ((page.state === 'more-available') !== (page.nextCursor !== null) || page.loaded < page.items.length || page.items.some(item => item.scannable !== (item.eligibility === 'alpine-only') || (item.scannable && (!item.reference.startsWith('registry-1.docker.io/library/alpine:') || !item.checks.secret || !item.checks.sbom || item.checks.vuln !== 'conditional')) || item.tagConfirmed !== (item.kind === 'tag'))) context.addIssue({ code: 'custom', message: 'Invalid discovery eligibility' });
});
const formSchema = z.object({
  imageReference: z.string().regex(/^registry-1\.docker\.io\/library\/alpine(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}|@sha256:[a-f0-9]{64})$/, 'Выберите доступный образ Alpine'),
  checks: z.array(z.enum(scanChecks)).min(1, 'Выберите хотя бы одну проверку'),
});
type FormValues = z.infer<typeof formSchema>;
type FocusActivation = { element: HTMLButtonElement; keyboard: boolean; moved: boolean; stop: () => void };
export function ScanCreatePage({ demo = false }: { demo?: boolean }) {
  const {
    register,
    control,
    setValue,
    handleSubmit,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { imageReference: '', checks: ['secret'] },
  });
  const imageReference = useWatch({ control, name: 'imageReference' });
  const checks = useWatch({ control, name: 'checks' }) ?? [];
  const [search, setSearch] = useState('');
  const [suggestions, setSuggestions] = useState<ImageSuggestion[]>([]);
  const [searchState, setSearchState] = useState<'idle' | 'loading' | 'ready' | 'error' | 'expired'>('idle');
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [pageState, setPageState] = useState<'more-available' | 'terminal' | 'quota-exhausted' | null>(null);
  const [pageRequest, setPageRequest] = useState(0);
  const searchGeneration = useRef(0);
  const loadedSuggestions = useRef<ImageSuggestion[]>([]);
  const restarting = useRef(false);
  const [retainedResults, setRetainedResults] = useState(false);
  const discoveryStatus = useRef<HTMLParagraphElement>(null);
  const restartButton = useRef<HTMLButtonElement>(null);
  const activatedControl = useRef<FocusActivation | null>(null);
  const focusHandoff = useRef<{ activation: FocusActivation; generation: number; subject: string; epoch: number } | null>(null);
  const discovery = useRef<{ generation: string; cursor: string | null; identity: string; query: string; pages: number }>({ generation: '', cursor: null, identity: '', query: '', pages: 0 });
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const selectedTarget = useRef<ImageSuggestion | null>(null);
  const attempt = useRef<{ target: string; checks: string; key: string } | null>(null);
  const live = useLiveScanSession();
  const navigate = useNavigate();
  useEffect(() => {
    const query = search.trim().toLowerCase().replace(/ +/g, ' ');
    const generation = ++searchGeneration.current;
    const activation = activatedControl.current;
    activatedControl.current = null;
    const identity = live?.scope.join(':') ?? '';
    if (discovery.current.identity !== identity) {
      setConfirmed(false); attempt.current = null; selectedTarget.current = null;
      setValue('imageReference', '');
    }
    const append = pageRequest > 0 && discovery.current.cursor !== null && discovery.current.identity === identity && discovery.current.query === query;
    const restart = restarting.current && discovery.current.identity === identity && discovery.current.query === query;
    restarting.current = false;
    if (!append) {
      discovery.current = { generation: restart ? discovery.current.generation : crypto.randomUUID(), cursor: null, identity, query, pages: 0 };
      loadedSuggestions.current = [];
      if (!restart) { setSuggestions([]); setRetainedResults(false); }
      setNextCursor(null); setPageState(null);
    }
    if (demo || !live || query.length < 2 || query.length > 64 || !/^[a-zA-Z0-9_./: -]+$/.test(query) || query.includes('..') || query.includes('//') || query.includes('://')) {
      setSuggestions([]);
      setSearchState('idle');
      activation?.stop();
      return;
    }
    setSearchState('loading');
    const controller = new AbortController();
    const current = () => {
      const session = scanSession();
      return searchGeneration.current === generation && !controller.signal.aborted && session.generation === live.scope[1] && session.subject === live.scope[2];
    };
    const cursor = append ? discovery.current.cursor : null;
    const serverGeneration = discovery.current.generation;
    const handoff = () => {
      if (current() && activation) focusHandoff.current = { activation, generation, subject: live.scope[2], epoch: live.scope[1] };
    };
    if (restart) handoff();
    const timer = window.setTimeout(async () => {
      if (!current()) return;
      try {
        const response = await fetch(`/api/v1/browser/scans/images?q=${encodeURIComponent(query)}&generation=${encodeURIComponent(serverGeneration)}${cursor ? `&cursor=${cursor}` : ''}`, {
          credentials: 'same-origin', signal: controller.signal, headers: { accept: 'application/json' },
        });
        if (!response.ok) {
          let code: unknown;
          try { code = z.object({ errorCode: z.string().max(64) }).parse(await response.json()).errorCode; } catch { /* Never display upstream error details. */ }
          if (!current()) return;
          discovery.current.cursor = null;
          setNextCursor(null); setPageState(null); setRetainedResults(true);
          setSearchState(response.status === 410 && code === 'IMAGE_SEARCH_EXPIRED' ? 'expired' : 'error');
          handoff();
          return;
        }
        const data: unknown = await response.json();
        const page = searchPageSchema.parse(data);
        if (!current()) return;
        const merged = [...new Map([...(append ? loadedSuggestions.current : []), ...page.items].map(item => [item.reference, item])).values()];
        if (page.pages !== (append ? discovery.current.pages + 1 : 1) || page.loaded !== merged.length || (page.state === 'more-available' && page.pages >= 5)) throw new Error('Invalid page sequence');
        setSuggestions(merged);
        loadedSuggestions.current = merged;
        discovery.current.pages = page.pages;
        setNextCursor(page.nextCursor); setPageState(page.state);
        discovery.current.cursor = page.nextCursor;
        setRetainedResults(false);
        setSearchState('ready');
        handoff();
      } catch {
        if (current()) {
          discovery.current.cursor = null;
          setNextCursor(null); setPageState(null); setRetainedResults(true); setSearchState('error');
          handoff();
        }
      }
    }, append ? 0 : 350);
    return () => { controller.abort(); window.clearTimeout(timer); activation?.stop(); };
  }, [search, demo, live, pageRequest, setValue]);
  useLayoutEffect(() => {
    const pending = focusHandoff.current;
    if (!pending) return;
    focusHandoff.current = null;
    const { activation } = pending;
    // A surviving control is still disabled during the loading commit.
    if (activation.element.isConnected && activation.element.disabled && searchState === 'loading') {
      focusHandoff.current = pending;
      return;
    }
    activation.stop();
    const session = scanSession();
    if (pending.generation !== searchGeneration.current || session.subject !== pending.subject || session.generation !== pending.epoch || activation.moved) return;
    const active = document.activeElement;
    if (active !== activation.element && active !== document.body) return;
    if (!activation.element.isConnected) {
      (restartButton.current ?? discoveryStatus.current)?.focus({ preventScroll: true });
    } else if (activation.keyboard && !activation.element.disabled && active === document.body) {
      activation.element.focus({ preventScroll: true });
    }
  }, [searchState, nextCursor]);
  function captureActivation(element: HTMLButtonElement, keyboard: boolean) {
    activatedControl.current?.stop();
    activatedControl.current = null;
    if (document.activeElement !== element) return;
    const activation: FocusActivation = { element, keyboard, moved: false, stop: () => {
      document.removeEventListener('focusin', onFocus);
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('pointerdown', onPointer);
    } };
    const onFocus = (event: FocusEvent) => {
      if (event.target !== element && event.target !== document.body) activation.moved = true;
    };
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Tab') activation.moved = true; };
    const onPointer = () => { activation.moved = true; };
    document.addEventListener('focusin', onFocus);
    document.addEventListener('keydown', onKey);
    document.addEventListener('pointerdown', onPointer);
    activatedControl.current = activation;
  }
  function restartSearch(element: HTMLButtonElement) {
    ++searchGeneration.current;
    captureActivation(element, false);
    discovery.current = { ...discovery.current, generation: crypto.randomUUID(), cursor: null, pages: 0 };
    loadedSuggestions.current = [];
    restarting.current = true;
    setRetainedResults(true); setNextCursor(null); setPageState(null);
    setPageRequest(value => value + 1);
  }
  const matches = alpineTargets.filter(target => `${target.label} ${target.reference}`.toLowerCase().includes(search.trim().toLowerCase()));
  const visible: ImageSuggestion[] = [
    ...matches.map(target => ({ ...target, scannable: true })),
    ...suggestions.filter(target => !matches.some(item => item.reference === target.reference)),
  ];
  async function create(values: FormValues) {
    if (demo || !live || !confirmed || busy) return;
    const eligible = alpineTargets.some(target => target.reference === values.imageReference) || (selectedTarget.current?.reference === values.imageReference && selectedTarget.current.scannable === true);
    if (!eligible) { setConfirmed(false); setError('Выберите цель с подтверждённым допуском Alpine.'); return; }
    setBusy(true);
    setError('');
    try {
      const selected = scanChecks.filter(check => values.checks.includes(check));
      if (attempt.current?.target !== values.imageReference || attempt.current?.checks !== selected.join(',')) {
        attempt.current = { target: values.imageReference, checks: selected.join(','), key: crypto.randomUUID() };
      }
      const receipt = await live.transport.create({ imageReference: values.imageReference, scope: 'image', checks: selected, idempotencyKey: attempt.current.key });
      navigate(`/scans/${encodeURIComponent(receipt.scanId)}`);
    } catch (reason) {
      if (reason instanceof ScanAccessError) {
        setError(reason.status === 403 ? 'Аккаунту не выдан доступ к сканированию. Проверьте разрешение на странице аккаунта.' : 'Сессия недействительна. Войдите заново.');
      } else if (reason instanceof ScanHttpError && reason.status === 400) {
        setError('Сервер отклонил цель или параметры сканирования. Скан не создан.');
      } else if (reason instanceof ScanHttpError && reason.status === 429) {
        setError('Лимит запусков исчерпан. Скан не создан, повторите позже.');
      } else if (reason instanceof ScanHttpError && reason.status === 503) {
        setError(values.checks.includes('vuln') ? 'Проверка CVE недоступна: база уязвимостей не настроена или недоступна. Запуск не подтверждён; обратитесь к администратору и проверьте список перед повтором.' : 'Сканер или registry сейчас недоступны. Запуск не подтверждён; проверьте список перед повтором.');
      } else if (reason instanceof ScanHttpError && reason.code === 'IDEMPOTENCY_CONFLICT') {
        setError('Параметры повторного запуска изменились. Обновите страницу перед новой попыткой.');
      } else {
        setError('Не удалось подтвердить запуск. Проверьте список перед повтором: результат запроса неизвестен.');
      }
    } finally {
      setBusy(false);
    }
  }
  return (
    <ScanShell demo={demo}>
      <section className="min-w-0 space-y-8 pb-8" aria-labelledby="new-scan">
        <div className="scan-a1__chapter">
          <span>ГЛАВА 02 / НОВАЯ ПРОВЕРКА</span>
          <Link className="scan-a1__link" to={demo ? '/demo/scans' : '/scans'}>
            <ArrowLeft size={16} aria-hidden="true" /> К списку
          </Link>
        </div>
        <div className="scan-a1__create-hero">
          <div className="min-w-0">
            <span className="scan-a1__folio">СИГНАЛ / 02 — ГРАНИЦА ДОВЕРИЯ</span>
            <h2 id="new-scan" className="scan-a1__heading">
              Задайте <em>границы.</em>
            </h2>
            <p className="scan-a1__muted mt-6 max-w-xl text-lg">
              Ищите образы Docker Hub по названию или тегу. Сейчас сканируются только образы Alpine; остальные результаты отмечены как недоступные для запуска. Запуск требует действующей сессии и разрешения сервера.
            </p>
          </div>
          <ScanScene variant="create" />
        </div>

        <div className="scan-a1__form-grid scan-a1__form-grid--story">
          <form className="scan-a1__form" aria-label="Параметры скана" onSubmit={handleSubmit(create)}>
            <div>
              <input type="hidden" {...register('imageReference')} />
              <label htmlFor="image-search">Поиск по доступным образам</label>
              <input
                id="image-search"
                type="search"
                value={search}
                onChange={event => {
                  ++searchGeneration.current;
                  discovery.current.cursor = null;
                  setSuggestions([]); setNextCursor(null); setPageState(null); setPageRequest(0);
                  setSearch(event.target.value);
                }}
                placeholder="Alpine 3.16, nginx, postgres…"
                autoComplete="off"
              />
              <div className="scan-a1__targets" role="group" aria-label="Выбор образа" aria-describedby={errors.imageReference ? 'image-reference-error' : undefined}>
                {visible.map(target => (
                  <button
                    key={target.reference}
                    type="button"
                    className="scan-a1__target"
                    aria-pressed={imageReference === target.reference}
                    disabled={!target.scannable}
                    onClick={() => {
                      selectedTarget.current = target;
                      setValue('imageReference', target.reference, { shouldValidate: true });
                      setConfirmed(false);
                      if (imageReference !== target.reference) attempt.current = null;
                      setError('');
                    }}
                  >
                    <strong>{target.label}</strong>
                    <span>{target.reference}{target.reason ? ` · ${target.reason}` : ''}{target.tagConfirmed === false ? ' · latest — предлагаемая цель, наличие тега и платформы не подтверждено' : ''}{alpineTargets.some(saved => saved.reference === target.reference) ? ' · сохранённая цель' : ' · найдено в Docker Hub'}</span>
                  </button>
                ))}
                <p ref={discoveryStatus} role="status" tabIndex={-1} aria-label="Состояние поиска Docker Hub">
                  {searchState === 'expired' ? 'Поиск истёк. Начните новый поиск; загруженные результаты неполные, выбранная цель сохранена.' :
                    searchState === 'error' ? 'Поиск Docker Hub сейчас недоступен; загруженные результаты неполные. Сохранённые цели остаются доступны.' :
                    searchState === 'loading' ? `Ищем в Docker Hub…${retainedResults ? ' Предыдущие результаты сохранены как неполные.' : ''}` :
                    pageState === 'quota-exhausted' ? 'Достигнут лимит поиска; результаты неполные (не более 5 страниц / 60 образов).' :
                    searchState === 'ready' && pageState === 'terminal' ? suggestions.length ? 'Поиск завершён.' : 'Ничего не найдено в Docker Hub.' : ''}
                </p>
                {nextCursor ? <button type="button" disabled={searchState === 'loading'} onClick={event => {
                  captureActivation(event.currentTarget, event.detail === 0);
                  setPageRequest(value => value + 1);
                }}>Показать ещё</button> : null}
                {searchState === 'error' || searchState === 'expired' ? <button ref={restartButton} type="button" onClick={event => restartSearch(event.currentTarget)}>Начать новый поиск</button> : null}
                {imageReference ? <p className="scan-a1__muted">Выбранная цель (сохраняется отдельно от поиска): {imageReference}</p> : null}
              </div>
              {imageReference === alpineTargets[3].reference ? <p className="scan-a1__muted">Архивный образ: при проверке закреплённого digest 04.10.2026 локальная DB нашла 4 CVE. Результат нового запуска зависит от актуальной DB и доступности scanner; этот образ не используйте для рабочих нагрузок.</p> : null}
              {errors.imageReference ? <p id="image-reference-error" role="alert">{errors.imageReference.message}</p> : null}
            </div>
            <fieldset>
              <legend>Проверки · одновременно, область registry IMAGE</legend>
              <label>
                <input type="checkbox" value="secret" {...register('checks', { onChange: () => { setConfirmed(false); attempt.current = null; setError(''); } })} />
                Secrets · проверка образа
              </label>
              <label>
                <input type="checkbox" value="sbom" {...register('checks', { onChange: () => { setConfirmed(false); attempt.current = null; setError(''); } })} />
                SBOM · перечень пакетов, не проверка уязвимостей
              </label>
              <label>
                <input type="checkbox" value="vuln" {...register('checks', { onChange: () => { setConfirmed(false); attempt.current = null; setError(''); } })} />
                CVE · доступно только при настроенной сервером базе уязвимостей
              </label>
              <label>
                <input type="checkbox" disabled />
                Host / running container · не поддерживаются (только registry IMAGE)
              </label>
              {errors.checks ? <p role="alert">{errors.checks.message}</p> : null}
            </fieldset>
            <label>
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
              />
              <span>
                Подтверждаю выбранную цель и область:{' '}
                <strong className="[overflow-wrap:anywhere]">{imageReference || 'цель не указана'} · {scanChecks.filter(item => checks.includes(item)).join(', ') || 'проверки не выбраны'}</strong>
              </span>
            </label>
            <button
              className="scan-a1__disabled"
              type="submit"
              disabled={demo || !live || !confirmed || !checks.length || busy}
              title={demo ? 'Демо не запускает реальные сканы' : undefined}
            >
              <LockKeyhole size={17} className="mr-2 inline" aria-hidden="true" />
              {demo || !live ? 'Запуск недоступен' : busy ? 'Запускаем…' : 'Запустить скан'}
            </button>
            {error ? <p role="alert">{error}</p> : null}
            <p className="text-sm">
              {confirmed
                ? demo ? 'Демо не отправляет запросы.' : 'Цель подтверждена; разрешение проверяет сервер.'
                : 'До запуска подтвердите цель и scope.'}{' '}
              Даже после квитанции POST digest/platform остаются неподтверждёнными до авторизованного GET
              status.
            </p>
            {demo ? (
              <Link className="scan-a1__link" to="/demo/scans/partial-demo">
                Посмотреть отдельный образец отчёта · другая фикстура
              </Link>
            ) : null}
          </form>
          <aside className="scan-a1__trust-note">
            <span className="scan-a1__folio">ГРАНИЦА / 01—03</span>
            <strong>Область доверия</strong>
            <p>
              Один запрос запускает выбранные Secrets, SBOM и CVE для registry IMAGE. SBOM — инвентарь, не оценка CVE. CVE требует настроенной сервером базы; host и running container не поддерживаются.
            </p>
            <p>POST 202 — квитанция, не подтверждение закреплённого digest/platform.</p>
            <GuideTabs defaultValue="target" className="scan-a1__guide">
              <GuideTabsList aria-label="Памятка о подготовке скана">
                <GuideTabsTrigger value="target">01 / Цель</GuideTabsTrigger>
                <GuideTabsTrigger value="limits">02 / Границы</GuideTabsTrigger>
              </GuideTabsList>
              <GuideTabsContent value="target">
                <span className="scan-a1__guide-kicker">ПЕРЕД ПРОВЕРКОЙ</span>
                <h3>Начните с точного адреса.</h3>
                <p>
                  Выберите Alpine из доступных тегов и подтвердите область. Другие репозитории сервер сейчас
                  не принимает. Tag сам по себе не доказывает digest.
                </p>
              </GuideTabsContent>
              <GuideTabsContent value="limits">
                <span className="scan-a1__guide-kicker">ПОСЛЕ КВИТАНЦИИ</span>
                <h3>Доверяйте только статусу.</h3>
                <p>
                  Закреплённые digest/platform подтверждает авторизованный GET status. Демо показывает только
                  вымышленные записи; live-статус возвращает сервер.
                </p>
              </GuideTabsContent>
            </GuideTabs>
          </aside>
        </div>
        <div className="scan-a1__trust-path" aria-label="Этапы настройки">
          <div>
            <span>01 / ЦЕЛЬ</span>
            <p>Выберите образ из каталога.</p>
          </div>
          <div>
            <span>02 / ОБЛАСТЬ</span>
            <p>Проверьте доступные категории.</p>
          </div>
          <div>
            <span>03 / РАЗРЕШЕНИЕ</span>
            <p>Подтвердите цель. Доступ проверяет сервер.</p>
          </div>
        </div>
      </section>
    </ScanShell>
  );
}
