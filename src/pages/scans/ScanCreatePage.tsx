import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, LockKeyhole } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useLiveScanSession } from '@/features/scans/liveScanContext';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { ScanShell } from '@/features/scans/ScanShell';
import { ScanInfoDialog } from '@/shared/ui/ScanInfoDialog';
import { scanCheckLabels } from '@/features/scans/scanProgressPresentation';
import { ScanAccessError, ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import { scanChecks } from '@/shared/api/scans/scanTransport';
import { scanSession } from '@/shared/api/auth/scanSession';
import { acknowledgePendingCreateIntent, readPendingCreateIntent, rememberPendingCreateIntent, type PendingCreateIntent } from '@/shared/api/scans/pendingCreateIntent';
import { EligibilityClient, type ScanWait } from '@/shared/api/scans/eligibilityClient';
import { RuntimeScanPanel } from '@/features/scans/RuntimeScanPanel';
import { publicImageReference } from '@/shared/api/scans/publicImageProfile';
import { imageFailureDetailSchema, parseImageFailureDetail, presentImageFailure, type ImageFailureDetail } from '@/shared/api/scans/imageFailure';
import { normalizeDockerHubReference, OLDER_IMAGE_PRESETS, repositoryFromReference, tagFromReference, validDiscoveryQuery } from './imageSelection';
import './scan-create-selection.css';

const pinnedExample = { label: 'nginx · закреплённый пример с большим числом находок', reference: 'registry-1.docker.io/library/nginx@sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3', scannable: false };
type ImageSuggestion = { label: string; reference: string; scannable: boolean; reason?: string; kind?: 'tag' | 'repository'; tagConfirmed?: boolean;
  eligibility?: 'alpine-only' | 'isolated-exact-profile' | 'qualified-exact-profile' | 'public-hub-profile' | 'unsupported'; allowedCheckSets?: readonly (readonly string[])[]; qualificationId?: string };
const checkSetSchema = z.array(z.enum(scanChecks)).min(1).max(4).refine(set =>
  JSON.stringify(set) === JSON.stringify(scanChecks.filter(check => set.includes(check))), 'Invalid canonical check set');
const eligibilitySchema = z.object({ imageReference: publicImageReference, eligible: z.boolean(),
  eligibility: z.enum(['alpine-only', 'isolated-exact-profile', 'qualified-exact-profile', 'public-hub-profile', 'unsupported']),
  allowedCheckSets: z.array(checkSetSchema).max(15), qualificationId: z.string().max(64).optional(),
  reason: z.enum(['READY', 'UNSUPPORTED_SCAN', 'SCANNER_UNAVAILABLE', 'DB_UNAVAILABLE']),
  failureDetail: imageFailureDetailSchema.optional() }).strict().superRefine((result, context) => {
    if (result.eligible !== (result.reason === 'READY') ||
      result.failureDetail !== undefined && (result.eligible || result.reason !== 'SCANNER_UNAVAILABLE') ||
      new Set(result.allowedCheckSets.map(set => set.join(','))).size !== result.allowedCheckSets.length ||
      result.eligibility === 'unsupported' && (result.eligible || result.allowedCheckSets.length || result.qualificationId) ||
      result.eligibility === 'qualified-exact-profile' && (!result.qualificationId || !result.allowedCheckSets.length || result.allowedCheckSets.some(set => set.includes('config')))) {
      context.addIssue({ code: 'custom', message: 'Invalid current eligibility' });
    }
  });
const searchPageSchema = z.object({
  items: z.array(z.object({ label: z.string().min(1).max(256), reference: z.string().regex(/^registry-1\.docker\.io\/[a-z0-9._/-]+(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}|@sha256:[a-f0-9]{64})$/), scannable: z.boolean(), eligibility: z.enum(['alpine-only', 'isolated-exact-profile', 'qualified-exact-profile', 'public-hub-profile', 'unsupported']), allowedCheckSets: z.array(checkSetSchema).max(15).optional(), qualificationId: z.string().max(64).optional(), reason: z.string().min(1).max(256), kind: z.enum(['tag', 'repository']), tagConfirmed: z.boolean(), checks: z.object({ secret: z.boolean(), sbom: z.boolean(), vuln: z.enum(['conditional', 'unsupported']) }) })).max(12),
  nextCursor: z.string().regex(/^[a-f0-9]{48}$/).nullable(), state: z.enum(['more-available', 'terminal', 'quota-exhausted']), loaded: z.number().int().min(0).max(60), pages: z.number().int().min(1).max(5),
  policy: z.object({ pageSize: z.literal(12), maxPages: z.literal(5), maxCandidates: z.literal(60), maxActivePerProcess: z.literal(8), maxActivePerSubject: z.literal(2), maxRequestsPerSubject: z.literal(30), rateWindowMs: z.literal(60_000), maxSessions: z.literal(1024), maxRateEntries: z.literal(1024), scope: z.literal('process-local') }),
}).superRefine((page, context) => {
  if ((page.state === 'more-available') !== (page.nextCursor !== null) || page.loaded < page.items.length || page.items.some(item => (item.eligibility === 'public-hub-profile' ? item.scannable || !publicImageReference.safeParse(item.reference).success : item.scannable !== (item.eligibility !== 'unsupported')) || (item.eligibility === 'alpine-only' && !item.reference.startsWith('registry-1.docker.io/library/alpine:')) || (['isolated-exact-profile', 'qualified-exact-profile'].includes(item.eligibility) && !/^registry-1\.docker\.io\/library\/nginx@sha256:[a-f0-9]{64}$/.test(item.reference)) || (item.scannable && (!item.checks.secret || !item.checks.sbom || item.checks.vuln !== 'conditional')) || item.tagConfirmed !== (item.kind === 'tag'))) context.addIssue({ code: 'custom', message: 'Invalid discovery eligibility' });
});
const formSchema = z.object({
  imageReference: publicImageReference,
  checks: z.array(z.enum(scanChecks)).min(1, 'Выберите хотя бы одну проверку'),
});
// Remembering a convenient target is optional; storage denial must not disable scan creation.
function readSavedTarget(key: string): string | null {
  try { return sessionStorage.getItem(key); } catch { return null; }
}
function writeSavedTarget(key: string, value: string | null) {
  try {
    if (value === null) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, value);
  } catch { /* The current form and owner-bound pending intent remain usable without storage. */ }
}

function failureDetailMessage(value: ImageFailureDetail): string {
  const detail = presentImageFailure(value);
  return `${detail.title}. ${detail.description} ${detail.nextStep}`;
}

function imageFailureMessage(error: unknown): string | null {
  if (!(error instanceof ScanHttpError) || !('failureDetail' in error) || error.failureDetail === undefined) return null;
  try {
    return failureDetailMessage(parseImageFailureDetail(error.failureDetail));
  } catch {
    // Malformed optional detail is not evidence. Keep the generic error and all existing retry gates.
    return null;
  }
}

type FormValues = z.infer<typeof formSchema>;
type FocusActivation = { element: HTMLButtonElement; keyboard: boolean; moved: boolean; stop: () => void };
export function ScanCreatePage({ demo = false }: { demo?: boolean }) {
  const live = useLiveScanSession();
  const subject = live?.scope[2] ?? null;
  const epoch = live?.scope[1] ?? -1;
  const sessionIdentity = live?.scope.join(':') ?? '';
  const [initialIntent] = useState(() => demo ? null : readPendingCreateIntent({ subject, generation: epoch }));
  const {
    register,
    control,
    setValue,
    getValues,
    handleSubmit,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      imageReference: initialIntent?.target ?? '',
      checks: initialIntent ? scanChecks.filter(check => initialIntent.checks.split(',').includes(check)) : ['secret'],
    },
  });
  const imageReference = useWatch({ control, name: 'imageReference' });
  const checks = useWatch({ control, name: 'checks' }) ?? [];
  const [search, setSearch] = useState('');
  const [repository, setRepository] = useState<string | null>(null);
  const [tagFilter, setTagFilter] = useState('');
  const pickerInput = useRef<HTMLInputElement>(null);
  const focusPicker = useRef(false);
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
  const discovery = useRef<{ generation: string; cursor: string | null; identity: string; query: string; repository: string | null; pages: number }>({ generation: '', cursor: null, identity: '', query: '', repository: null, pages: 0 });
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const [error, setError] = useState('');
  const selectedTarget = useRef<ImageSuggestion | null>(null);
  const [localEligibility, setLocalEligibility] = useState<z.infer<typeof eligibilitySchema> | null>(null);
  const [eligibilityBusy, setEligibilityBusy] = useState(false);
  const [eligibilityRefresh, setEligibilityRefresh] = useState(0);
  const manualEligibilityRefresh = useRef(false);
  const [eligibilityAccessError, setEligibilityAccessError] = useState<401 | 403 | null>(null);
  const savedIdentity = useRef('');
  const attempt = useRef<PendingCreateIntent | null>(initialIntent);
  const [restoredAttempt, setRestoredAttempt] = useState(!!initialIntent);
  const [recoveryApproval, setRecoveryApproval] = useState('');
  // Changing back to the same values must not revive a preflight for an earlier consent.
  const submissionVersion = useRef(0);
  const [eligibilityWait, setEligibilityWait] = useState<ScanWait | null>(null);
  const [admissionWait, setAdmissionWait] = useState<ScanWait | null>(null);
  const [eligibilityError, setEligibilityError] = useState('');
  const eligibilityClient = useMemo(() => subject && !demo ? new EligibilityClient(
    () => scanSession().subject === subject && scanSession().generation === epoch, wait => {
      setEligibilityWait(wait);
      setLocalEligibility(previous => previous ? { ...previous, eligible: false } : null);
    }) : null, [subject, epoch, demo]);
  useEffect(() => {
    eligibilityClient?.activate();
    manualEligibilityRefresh.current = false;
    setEligibilityAccessError(null);
    setLocalEligibility(null); setEligibilityWait(null); setAdmissionWait(null); setEligibilityError(''); setError(''); setBusy(false);
    return () => eligibilityClient?.retire();
  }, [eligibilityClient]);
  const wait = admissionWait ?? eligibilityWait;
  const [waitSeconds, setWaitSeconds] = useState(0);
  useEffect(() => {
    if (!wait) { setWaitSeconds(0); return; }
    const tick = () => setWaitSeconds(Math.max(0, Math.ceil((wait.until - Date.now()) / 1000)));
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [wait]);
  const eligibilityWaiting = !!eligibilityWait && eligibilityWait.until > Date.now();
  const admissionWaiting = !!admissionWait && admissionWait.until > Date.now();
  const navigate = useNavigate();
  useEffect(() => () => { ++submissionVersion.current; }, []);
  useEffect(() => {
    if (!subject || demo) return;
    const key = `scan-target-v1:${subject}`;
    if (savedIdentity.current && savedIdentity.current !== key) writeSavedTarget(savedIdentity.current, null);
    savedIdentity.current = key;
    const saved = readSavedTarget(key);
    if (saved && /^registry-1\.docker\.io\/library\/nginx@sha256:[a-f0-9]{64}$/.test(saved)) {
      selectedTarget.current = { label: 'Сохранённая закреплённая цель', reference: saved, scannable: false };
      setValue('imageReference', saved);
    } else if (saved) writeSavedTarget(key, null);
    const currentEpoch = epoch;
    return () => {
      const session = scanSession();
      if (session.subject !== subject || session.generation !== currentEpoch) writeSavedTarget(key, null);
    };
  }, [subject, epoch, demo, setValue]);
  const eligibilityReference = publicImageReference.safeParse(imageReference).success ? imageReference : null;
  const canonicalSelected = scanChecks.filter(check => checks.includes(check));
  const checkIdentity = canonicalSelected.join(',');
  useEffect(() => {
    setRecoveryApproval('');
    if (!eligibilityClient || !eligibilityReference) {
      setLocalEligibility(null); setEligibilityBusy(false);
      return;
    }
    if (restoredAttempt && !manualEligibilityRefresh.current) {
      setEligibilityBusy(false);
      return;
    }
    let mounted = true;
    const current = () => mounted && scanSession().subject === subject && scanSession().generation === epoch;
    setEligibilityBusy(true);
    setLocalEligibility(previous => previous?.imageReference === eligibilityReference ? { ...previous, eligible: false } : null);
    const timer = window.setTimeout(async () => {
      try {
        const validate = (value: unknown) => {
          const result = eligibilitySchema.parse(value);
          if (result.imageReference !== eligibilityReference || result.eligible &&
            !result.allowedCheckSets.some(set => set.join(',') === (checkIdentity || 'secret'))) throw new Error('Eligibility identity mismatch');
          return result;
        };
        const manual = manualEligibilityRefresh.current;
        manualEligibilityRefresh.current = false;
        const selectedChecks = checkIdentity ? checkIdentity.split(',') : ['secret'];
        const result = manual
          ? await eligibilityClient.retryAuthorization(eligibilityReference, selectedChecks, validate, current)
          : validate(await eligibilityClient.request(eligibilityReference, selectedChecks, false, current));
        if (current()) {
          setLocalEligibility(result); setEligibilityError('');
          if (manual && result.eligible) setRecoveryApproval(JSON.stringify([epoch, eligibilityReference, checkIdentity]));
          setEligibilityAccessError(previous => manual && previous === 403 ? null : previous);
        }
      } catch (reason) {
        if (!current()) return;
        if (reason instanceof ScanAccessError) setEligibilityAccessError(reason.status);
        if (reason instanceof ScanHttpError && reason.status === 429) {
          setLocalEligibility(previous => previous ? { ...previous, eligible: false } : null);
        } else {
          setLocalEligibility(null);
          setEligibilityError(imageFailureMessage(reason) ?? (reason instanceof ScanAccessError ? reason.status === 401 ? 'Сессия недействительна. Войдите заново.' : 'Аккаунту не выдан доступ к сканированию.' : 'Не удалось проверить доступность. Повторите проверку вручную.'));
        }
      }
      finally { if (current()) setEligibilityBusy(false); }
    }, 150);
    return () => { mounted = false; window.clearTimeout(timer); };
  }, [eligibilityClient, subject, epoch, eligibilityReference, checkIdentity, eligibilityRefresh, restoredAttempt]);
  useEffect(() => {
    const refresh = () => { if (!restoredAttempt && eligibilityClient?.focusAllowed()) setEligibilityRefresh(value => value + 1); };
    window.addEventListener('focus', refresh);
    return () => window.removeEventListener('focus', refresh);
  }, [eligibilityClient, restoredAttempt]);
  useEffect(() => {
    const query = repository === null ? search.trim().replace(/ +/g, ' ') : tagFilter;
    const generation = ++searchGeneration.current;
    const activation = activatedControl.current;
    activatedControl.current = null;
    const identity = sessionIdentity;
    if (discovery.current.identity !== identity) {
      ++submissionVersion.current;
      setRepository(null); setTagFilter(''); setSearch('');
      setConfirmed(false); attempt.current = null; selectedTarget.current = null;
      const pending = !demo ? readPendingCreateIntent({ subject, generation: epoch }) : null;
      setRestoredAttempt(!!pending);
      setLocalEligibility(null);
      // Restore only the same revalidated owner's intent, never consent or eligibility.
      const saved = subject ? readSavedTarget(`scan-target-v1:${subject}`) : null;
      if (pending) {
        setEligibilityBusy(false);
        attempt.current = pending;
        setValue('imageReference', pending.target);
        setValue('checks', scanChecks.filter(check => pending.checks.split(',').includes(check)));
      } else if (saved && /^registry-1\.docker\.io\/library\/nginx@sha256:[a-f0-9]{64}$/.test(saved)) {
        selectedTarget.current = { label: 'Сохранённая закреплённая цель', reference: saved, scannable: false };
        setValue('imageReference', saved);
      } else setValue('imageReference', '');
    }
    const sameSearch = discovery.current.identity === identity && discovery.current.query === query && discovery.current.repository === repository;
    const append = pageRequest > 0 && discovery.current.cursor !== null && sameSearch;
    const restart = restarting.current && sameSearch;
    restarting.current = false;
    if (!append) {
      discovery.current = { generation: restart ? discovery.current.generation : crypto.randomUUID(), cursor: null, identity, query, repository, pages: 0 };
      loadedSuggestions.current = [];
      if (!restart) { setSuggestions([]); setRetainedResults(false); }
      setNextCursor(null); setPageState(null);
    }
    if (demo || !subject || !validDiscoveryQuery(query, repository)) {
      setSuggestions([]);
      setSearchState('idle');
      activation?.stop();
      return;
    }
    setSearchState('loading');
    const controller = new AbortController();
    const current = () => {
      const session = scanSession();
      return searchGeneration.current === generation && !controller.signal.aborted && session.generation === epoch && session.subject === subject;
    };
    const cursor = append ? discovery.current.cursor : null;
    const serverGeneration = discovery.current.generation;
    const handoff = () => {
      if (current() && activation) focusHandoff.current = { activation, generation, subject, epoch };
    };
    if (restart) handoff();
    let deadline: number | undefined;
    const timer = window.setTimeout(async () => {
      if (!current()) return;
      try {
        const response = await Promise.race([
          fetch(`/api/v1/browser/scans/images?q=${encodeURIComponent(query)}${repository ? `&repository=${encodeURIComponent(repository)}` : ''}&generation=${encodeURIComponent(serverGeneration)}${cursor ? `&cursor=${cursor}` : ''}`, {
            credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal, headers: { accept: 'application/json' },
          }).then(async response => ({ ok: response.ok, status: response.status, data: await response.json() as unknown })),
          new Promise<never>((_, reject) => {
            deadline = window.setTimeout(() => reject(new Error('Image catalog read timed out')), 15_000);
          }),
        ]);
        if (!response.ok) {
          let code: unknown;
          try { code = z.object({ errorCode: z.string().max(64) }).parse(response.data).errorCode; } catch { /* Never display upstream error details. */ }
          if (!current()) return;
          discovery.current.cursor = null;
          setNextCursor(null); setPageState(null); setRetainedResults(true);
          setSearchState(response.status === 410 && code === 'IMAGE_SEARCH_EXPIRED' ? 'expired' : 'error');
          handoff();
          return;
        }
        const page = searchPageSchema.parse(response.data);
        if (page.items.some(item => !repositoryFromReference(item.reference) || repository !== null &&
          (item.kind !== 'tag' || !item.tagConfirmed || tagFromReference(item.reference) === null || repositoryFromReference(item.reference) !== repository)))
          throw new Error('Discovery repository mismatch');
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
      } finally {
        window.clearTimeout(deadline);
        controller.abort();
      }
    }, append ? 0 : 350);
    return () => { controller.abort(); window.clearTimeout(timer); window.clearTimeout(deadline); activation?.stop(); };
  }, [search, repository, tagFilter, demo, subject, epoch, sessionIdentity, pageRequest, setValue]);
  useLayoutEffect(() => {
    if (!focusPicker.current) return;
    focusPicker.current = false;
    pickerInput.current?.focus();
  }, [repository]);
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
  function changeDiscovery(nextRepository: string | null, nextQuery: string, navigateStep = false) {
    if (busy || submitting.current) return;
    ++searchGeneration.current;
    discovery.current.cursor = null;
    restarting.current = false;
    setSuggestions([]); setNextCursor(null); setPageState(null); setPageRequest(0); setSearchState('idle'); setRetainedResults(false);
    setRepository(nextRepository);
    if (nextRepository === null) setSearch(nextQuery); else setTagFilter(nextQuery);
    if (navigateStep) {
      ++submissionVersion.current;
      setConfirmed(false);
      focusPicker.current = true;
    }
  }
  function selectTarget(target: ImageSuggestion) {
    if (busy || submitting.current || !publicImageReference.safeParse(target.reference).success) return;
    ++submissionVersion.current;
    selectedTarget.current = target;
    if (target.reference.includes('/nginx@') && live) writeSavedTarget(`scan-target-v1:${live.scope[2]}`, target.reference);
    setValue('imageReference', target.reference, { shouldValidate: true });
    setConfirmed(false);
    if (imageReference !== target.reference) attempt.current = null;
    setError('');
  }
  function normalizeManualReference(showError: boolean) {
    if (busy || submitting.current) return;
    const raw = getValues('imageReference');
    const normalized = normalizeDockerHubReference(raw);
    if (!normalized) {
      if (showError) setError('Укажите публичный образ Docker Hub с тегом, например nginx:1.24 или owner/name:Tag. URL, другие реестры и учётные данные не принимаются.');
      return;
    }
    if (normalized !== raw) selectTarget({ label: 'Введённый адрес', reference: normalized, scannable: false });
  }
  const repositories = [...new Set(suggestions.flatMap(target => {
    const name = repositoryFromReference(target.reference);
    return name ? [name] : [];
  }))];
  const localSelected = localEligibility?.imageReference === imageReference && localEligibility.eligibility === 'qualified-exact-profile';
  const localCheckSets = localSelected ? localEligibility.allowedCheckSets : [];
  const selectionEligible = !eligibilityBusy && localEligibility?.imageReference === imageReference && localEligibility.eligible &&
    localEligibility.allowedCheckSets.some(set => set.join(',') === checkIdentity);
  const samePendingAttempt = attempt.current?.target === imageReference && attempt.current?.checks === checkIdentity;

  const recoveryEligible = !restoredAttempt || recoveryApproval === JSON.stringify([epoch, imageReference, checkIdentity]) &&
    !eligibilityBusy && localEligibility?.imageReference === imageReference && localEligibility.eligible &&
    localEligibility.allowedCheckSets.some(set => set.join(',') === checkIdentity);

  async function create(values: FormValues) {
    if (demo || !live || !confirmed || busy || submitting.current || eligibilityAccessError !== null || !recoveryEligible) return;
    const retained = readPendingCreateIntent({ subject, generation: epoch }, {
      target: values.imageReference, checks: scanChecks.filter(check => values.checks.includes(check)).join(','),
    });
    if (retained && retained.key !== attempt.current?.key) {
      attempt.current = retained;
      setRestoredAttempt(true); setConfirmed(false); setLocalEligibility(null);
      setError('Для этой цели сохранён неподтверждённый запуск. Проверьте допуск вручную и подтвердите повтор с прежним ключом.');
      return;
    }
    const eligible = selectionEligible && localEligibility?.imageReference === values.imageReference;
    const sameAttempt = attempt.current?.target === values.imageReference && attempt.current?.checks === scanChecks.filter(check => values.checks.includes(check)).join(',');
    if (admissionWaiting || eligibilityWaiting && !sameAttempt) return;
    if (!eligible && !sameAttempt) { setConfirmed(false); setError('Выберите цель с подтверждённым серверным допуском.'); return; }
    const selected = scanChecks.filter(check => values.checks.includes(check));
    const version = submissionVersion.current;
    const current = () => {
      const session = scanSession();
      return submissionVersion.current === version && session.subject === live.scope[2] && session.generation === live.scope[1] &&
        getValues('imageReference') === values.imageReference && scanChecks.filter(check => getValues('checks').includes(check)).join(',') === selected.join(',');
    };
    if (!current()) return;
    submitting.current = true;
    setBusy(true);
    setError('');
    try {
      if (!sameAttempt || restoredAttempt) {
        const result = eligibilityClient ? eligibilitySchema.parse(await eligibilityClient.request(values.imageReference, selected, true, current)) : null;
        if (!current()) return;
        if (!result?.eligible || result.imageReference !== values.imageReference ||
          !result.allowedCheckSets.some(set => set.join(',') === selected.join(','))) {
          setConfirmed(false);
          setError(result?.failureDetail ? `${failureDetailMessage(result.failureDetail)} Новый запрос запуска не отправлен.` : 'Сервер пока не разрешает запуск. Новый запрос запуска не отправлен.');
          return;
        }
        if (!sameAttempt) attempt.current = { target: values.imageReference, checks: selected.join(','), key: crypto.randomUUID() };
      }
      if (!current() || !attempt.current) return;
      const sentIntent = attempt.current;
      const sentSession = { subject, generation: epoch };
      if (!rememberPendingCreateIntent(sentSession, sentIntent)) {
        setError('Не удалось сохранить безопасный повтор: слишком много неподтверждённых запусков или сессия изменилась. Проверьте список сканов; новый запрос не отправлен.');
        return;
      }
      const receipt = await live.transport.create({ imageReference: values.imageReference, scope: 'image', checks: selected, idempotencyKey: sentIntent.key });
      if (current()) {
        acknowledgePendingCreateIntent(sentSession, sentIntent.key);
        navigate(`/scans/${encodeURIComponent(receipt.scanId)}`);
      }
    } catch (reason) {
      if (!current()) return;
      if (reason instanceof ScanAccessError) {
        setEligibilityAccessError(reason.status);
        setLocalEligibility(previous => previous ? { ...previous, eligible: false } : null);
        setError(reason.status === 403 ? 'Аккаунту не выдан доступ к сканированию. Проверьте разрешение на странице аккаунта.' : 'Сессия недействительна. Войдите заново.');
      } else if (reason instanceof ScanHttpError && reason.status === 400) {
        setError('Сервер отклонил цель или параметры сканирования. Скан не создан.');
      } else if (reason instanceof ScanHttpError && reason.status === 429) {
        if (reason.code === 'SCAN_CAPACITY') {
          setAdmissionWait({ until: Date.now() + (reason.retryAfterSeconds ?? 60) * 1000, reason: 'admission' });
          setError('Сервер пока не принимает новый запуск. Скан не создан; повтор возможен вручную после ожидания.');
        } else setError('Сервер ограничил проверку допуска. Цель и проверки сохранены; повтор возможен вручную после ожидания.');
      } else if (reason instanceof ScanHttpError && reason.status === 503) {
        setError('Сервис проверки или хранилище образов сейчас недоступны. Запуск не подтверждён; проверьте список перед повтором.');
      } else if (reason instanceof ScanHttpError && reason.code === 'IDEMPOTENCY_CONFLICT') {
        setError('Параметры повторного запуска изменились. Обновите страницу перед новой попыткой.');
      } else {
        setError('Не удалось подтвердить запуск. Проверьте список перед повтором: результат запроса неизвестен.');
      }
      const failureMessage = imageFailureMessage(reason);
      if (failureMessage) setError(`${failureMessage} Запуск не подтверждён: перед повтором проверьте список проверок.`);
    } finally {
      submitting.current = false;
      if (scanSession().subject === subject && scanSession().generation === epoch) setBusy(false);
    }
  }
  return (
    <ScanShell demo={demo} compact>
      <section className="scan-create-page grid min-w-0 gap-4 pb-8" aria-labelledby="new-scan">
        <div className="scan-a1__chapter">
          <span>НОВАЯ ПРОВЕРКА</span>
          <Link className="scan-a1__link" to={demo ? '/demo/scans' : '/scans'}>
            <ArrowLeft size={16} aria-hidden="true" /> К списку
          </Link>
        </div>
        <div className="scan-a1__create-hero">
          <div className="min-w-0">

            <h2 id="new-scan" className="scan-a1__heading">
              Новая проверка
            </h2>
            <p className="scan-a1__muted mt-3 max-w-xl">Выберите публичный образ Docker Hub и нужные проверки.</p>
            <p className="scan-a1__muted mt-2 text-sm">Linux amd64 · только публичные образы</p>
          </div>

        </div>

        <div className="scan-a1__form-grid scan-a1__form-grid--story">
          <form className="scan-a1__form" aria-label="Параметры скана" aria-busy={busy} onSubmit={handleSubmit(create)}>
            {restoredAttempt ? <p role="status">Предыдущий запуск не подтверждён. Сначала <Link to="/scans">проверьте список</Link>. Если нужен повтор, нажмите «Проверить доступность снова» и заново подтвердите цель. Повтор использует прежний запрос; автоматического запуска нет.</p> : null}
            <div className="scan-image-selection">
              <h3>1. Образ</h3>
              <p className="scan-image-selection__subtitle">{repository ? 'Выберите версию' : 'Найдите репозиторий'}</p>
              {repository ? <div className="scan-image-selection__step">
                <button type="button" disabled={busy} onClick={() => changeDiscovery(null, search, true)}>Назад к репозиториям</button>
                <strong>{repository}</strong>
              </div> : <p>Найдите семейство образов, затем выберите один из его тегов. Выбор сам по себе не запускает проверку.</p>}
              {demo ? <p>В демо поиск отключён. Можно выбрать пример ниже или попробовать ручной адрес — без запросов и запуска.</p> : null}
              <label htmlFor="image-search">{repository ? 'Фильтр тегов' : 'Репозиторий Docker Hub'}</label>
              <input
                id="image-search"
                ref={pickerInput}
                disabled={busy || demo}
                type="search"
                value={repository ? tagFilter : search}
                onChange={event => changeDiscovery(repository, event.target.value)}
                onKeyDown={event => { if (event.key === 'Enter') event.preventDefault(); }}
                placeholder={repository ? 'Например, 1.24 или Alpine — регистр важен' : 'nginx, node, owner/name…'}
                maxLength={64}
                aria-invalid={repository !== null && !validDiscoveryQuery(tagFilter, repository)}
                aria-describedby="image-search-help"
                spellCheck={false}
                autoComplete="off"
              />
              <p id="image-search-help">{repository ? !validDiscoveryQuery(tagFilter, repository)
                              ? 'В фильтре допустимы латинские буквы, цифры, точка, дефис и подчёркивание, без пробелов; до 64 символов.'
                              : 'Пустой фильтр покажет список тегов. Наличие тега не подтверждает возможность сканирования.'
                              : 'Введите минимум два символа. Каталог содержит только публичные репозитории.'}</p>
              <div className="scan-a1__targets" role="group" aria-label={repository ? 'Выбор версии образа' : 'Выбор репозитория'}>
                {repository ? suggestions.map(target => (
                  <button key={target.reference} type="button" className="scan-a1__target"
                    aria-pressed={imageReference === target.reference} disabled={busy}
                    onClick={() => selectTarget(target)}>
                    <strong>{tagFromReference(target.reference)}</strong>
                    <span>{repository} · проверить доступность этой версии</span>
                  </button>
                )) : repositories.map(name => (
                  <button key={name} type="button" className="scan-a1__target" disabled={busy}
                    onClick={() => changeDiscovery(name, '', true)}>
                    <strong>{name}</strong><span>Выбрать версию →</span>
                  </button>
                ))}
                <p ref={discoveryStatus} role="status" tabIndex={-1} aria-label="Состояние поиска Docker Hub">
                  {searchState === 'expired' ? 'Поиск истёк. Повторите вручную; выбранная версия сохранена.' :
                    searchState === 'error' ? 'Каталог недоступен. Загруженные результаты могут быть неполными; повторите вручную.' :
                    searchState === 'loading' ? `Загружаем ${repository ? 'теги' : 'репозитории'}…${retainedResults ? ' Предыдущие результаты неполные.' : ''}` :
                    pageState === 'quota-exhausted' ? 'Достигнут предел поиска: до 5 страниц / 60 записей. Уточните запрос; список неполный.' :
                    searchState === 'ready' && pageState === 'terminal' ? suggestions.length ? 'Список загружен.' : repository ? 'Тегов по этому фильтру нет. Измените фильтр или вернитесь к репозиториям.' : 'Репозитории не найдены. Попробуйте другое название.' : ''}
                </p>
                {nextCursor ? <button type="button" disabled={busy || searchState === 'loading'} onClick={event => {
                  captureActivation(event.currentTarget, event.detail === 0);
                  setPageRequest(value => value + 1);
                }}>Показать ещё</button> : null}
                {searchState === 'error' || searchState === 'expired' ? <button ref={restartButton} type="button" disabled={busy} onClick={event => restartSearch(event.currentTarget)}>Начать новый поиск</button> : null}
              </div>
              <details className="scan-image-selection__examples">
                <summary>Тестовые образы</summary>
              <fieldset className="scan-image-selection__presets" disabled={busy}>
                <legend>Устаревшие версии — только для тестирования, не для рабочих приложений</legend>
                <p>Первый пример — устаревшая сборка Node.js сентября 2023 года для изучения уязвимостей. Используйте её только для тестирования, не для рабочих приложений. Число находок определяется проверкой; остальные примеры тоже не являются рекомендацией для работы.</p>
                <div className="scan-a1__targets">
                  {OLDER_IMAGE_PRESETS.map(target => <button key={target.reference} type="button" className="scan-a1__target"
                    aria-pressed={imageReference === target.reference} onClick={() => selectTarget({ ...target, scannable: false })}>
                    <strong>{target.label}</strong><span>Выбрать и проверить доступность</span>
                  </button>)}
                </div>
              </fieldset>
              </details>
              <details className="scan-image-selection__manual">
                <summary>Указать адрес вручную</summary>
                <label htmlFor="image-reference">Адрес образа в Docker Hub</label>
                <input id="image-reference" disabled={busy} {...register('imageReference', {
                  onChange: () => { ++submissionVersion.current; selectedTarget.current = null; setConfirmed(false); attempt.current = null; setError(''); },
                  onBlur: () => normalizeManualReference(false),
                })} placeholder="nginx:1.24 или owner/name:Tag" autoComplete="off" spellCheck={false}
                  onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); normalizeManualReference(true); } }}
                  aria-invalid={!!errors.imageReference} aria-describedby="image-reference-help image-reference-error" />
                <p id="image-reference-error" role={errors.imageReference ? 'alert' : undefined}>{errors.imageReference ? 'Укажите публичный образ Docker Hub с версией, например nginx:1.24. Ссылки на сайты и другие реестры не подходят.' : null}</p>
                <p id="image-reference-help">Например: nginx:1.24 или owner/name:Tag. Адрес дополним после ввода, регистр версии сохраним. Не вводите пароли, токены или ссылки на сайты.</p>
                                <details><summary>Полный адрес и точная сборка</summary><p>Также принимаются docker.io/… и registry-1.docker.io/… с явным тегом или @sha256:… для точной сборки. Другие реестры не поддерживаются.</p></details>
                <button type="button" disabled={busy} onClick={() => normalizeManualReference(true)}>Использовать адрес</button>
                <details><summary>Сохранённый пример для прежнего профиля</summary>
                  <button type="button" disabled={busy} onClick={() => selectTarget(pinnedExample)}>Выбрать закреплённый nginx</button>
                  <p>Совместимость с прежним профилем тоже требует актуального допуска сервера.</p>
                </details>
              </details>
              {imageReference ? <div className="scan-image-selection__chosen" role="status">
                <strong>Выбранный адрес</strong><p>{imageReference}</p>
                <p>{localEligibility?.imageReference === imageReference && localEligibility.eligible && !eligibilityBusy
                  ? 'Выбранные проверки доступны. Перед запуском проверим ещё раз.'
                  : localEligibility?.imageReference === imageReference && !eligibilityBusy
                    ? localEligibility.failureDetail ? failureDetailMessage(localEligibility.failureDetail)
                      : `Запуск недоступен: ${{ READY: 'проверяем доступность', UNSUPPORTED_SCAN: 'образ или набор проверок не поддерживается', SCANNER_UNAVAILABLE: 'сканер недоступен', DB_UNAVAILABLE: 'база уязвимостей недоступна' }[localEligibility.reason]}.`
                    : eligibilityBusy ? 'Проверяем доступность выбранной версии…' : 'Доступность этой версии пока не подтверждена.'}</p>
              </div> : null}
              {eligibilityError ? <p role="alert">{eligibilityError}</p> : null}
              {eligibilityAccessError === 401 ? <Link to="/login" state={{ returnTo: '/scans/new' }}>Войдите заново</Link> : null}
            </div>
            <fieldset id="scan-checks" disabled={busy} aria-invalid={!!errors.checks}
              aria-describedby={errors.checks ? 'scan-checks-error' : undefined}
              aria-errormessage={errors.checks ? 'scan-checks-error' : undefined}>
              <legend>2. Что проверить</legend>
              {localSelected ? <div role="group" aria-label="Доказанные наборы локального профиля">
                {localCheckSets.map(set => <label key={set.join(',')}><input type="radio" name="local-check-set"
                  checked={JSON.stringify(canonicalSelected) === JSON.stringify(set)} onChange={() => { ++submissionVersion.current; setValue('checks', [...set]); setConfirmed(false); attempt.current = null; setError(''); }} />
                  <span>{set.map(check => scanCheckLabels[check]).join(' + ')}</span></label>)}
                <p>Для этого образа доступны только показанные наборы проверок. Проверка настроек образа недоступна.</p>
              </div> : <>
              <label>
                <input type="checkbox" value="secret" {...register('checks', { onChange: () => { ++submissionVersion.current; setConfirmed(false); attempt.current = null; setError(''); } })} />
                <span>Возможные секреты · поиск ключей и паролей</span>
              </label>
              <label>
                <input type="checkbox" value="sbom" {...register('checks', { onChange: () => { ++submissionVersion.current; setConfirmed(false); attempt.current = null; setError(''); } })} />
                <span>Состав образа · список пакетов и версий</span>
              </label>
              <label>
                <input type="checkbox" value="vuln" {...register('checks', { onChange: () => { ++submissionVersion.current; setConfirmed(false); attempt.current = null; setError(''); } })} />
                <span>Уязвимости · сравнение пакетов с базой известных проблем</span>
              </label>
              <label>
                <input type="checkbox" value="config" {...register('checks', { onChange: () => { ++submissionVersion.current; setConfirmed(false); attempt.current = null; setError(''); } })} />
                <span>Настройки · от какого пользователя запускается образ</span>
              </label>
              </>}
              <p>Проверяем сам образ, не работающий контейнер и не сервер. Список пакетов не заменяет проверку уязвимостей.</p>
              {errors.checks ? <p id="scan-checks-error" role="alert">{errors.checks.message}</p> : null}
            </fieldset>
            <h3>3. Подтверждение</h3>
            <label>
              <input
                type="checkbox"
                checked={confirmed}
                disabled={busy}
                onChange={(event) => { ++submissionVersion.current; setConfirmed(event.target.checked); }}
              />
              <span>
                Подтверждаю выбранную цель и область:{' '}
                <strong className="[overflow-wrap:anywhere]">{imageReference || 'цель не указана'} · {scanChecks.filter(item => checks.includes(item)).map(check => scanCheckLabels[check]).join(', ') || 'проверки не выбраны'}</strong>
              </span>
            </label>
            {wait ? <p role="status" aria-label="Ожидание сервера">
              {wait.reason === 'admission' ? 'Ожидание допуска запуска' : wait.reason === 'capacity' ? 'Сервер проверки допуска заполнен' : wait.reason === 'concurrency' ? 'Проверка допуска уже выполняется' : 'Лимит частоты проверки допуска'}:
              {waitSeconds > 0 ? ` повтор не раньше чем через ${waitSeconds} с.` : ' можно повторить вручную.'} Это не гарантия доступности; автоматического запуска нет.
            </p> : null}
            {!demo && live ? <button type="button" disabled={busy || eligibilityBusy || eligibilityWaiting || admissionWaiting || eligibilityAccessError === 401}
              onClick={() => {
                if (submitting.current || eligibilityBusy || eligibilityWaiting || admissionWaiting || eligibilityAccessError === 401) return;
                manualEligibilityRefresh.current = true;
                setEligibilityBusy(true);
                setLocalEligibility(previous => previous ? { ...previous, eligible: false } : null);
                setConfirmed(false);
                setError('');
                setEligibilityWait(null); setAdmissionWait(null); setEligibilityRefresh(value => value + 1);
              }}>Проверить доступность снова</button> : null}
            <button
              className="scan-a1__disabled"
              type="submit"
              disabled={demo || !live || !confirmed || !checks.length || busy || eligibilityAccessError !== null || !recoveryEligible || admissionWaiting ||
                (eligibilityWaiting && !samePendingAttempt) || (!samePendingAttempt && !selectionEligible)}
              title={demo ? 'Демо не запускает реальные сканы' : undefined}
              aria-describedby="scan-launch-help"
            >
              <LockKeyhole size={17} className="mr-2 inline" aria-hidden="true" />
              {demo || !live ? 'Запуск недоступен' : busy ? 'Запускаем…' : 'Запустить проверку'}
            </button>
            <p id="scan-launch-help" role="status">
              {demo ? 'Демо: запуск реальной проверки отключён.' : !live ? 'Для запуска войдите в аккаунт.'
                : busy ? 'Запускаем проверку, дождитесь подтверждения.'
                : !imageReference ? 'Сначала выберите образ.'
                : eligibilityAccessError !== null ? 'Доступ к запуску не подтверждён. Проверьте сообщение выше.'
                : eligibilityBusy ? 'Проверяем доступность выбранного образа.'
                : admissionWaiting || eligibilityWaiting ? 'Сервер просит подождать. Время повтора указано выше.'
                : !checks.length ? 'Выберите хотя бы одну проверку.'
                : !recoveryEligible ? 'Исход предыдущего запуска не подтверждён. Проверьте список и доступность перед повтором.'
                : !samePendingAttempt && !selectionEligible ? 'Доступность выбранных проверок пока не подтверждена.'
                : !confirmed ? 'Подтвердите выбранный образ и проверки.' : 'Можно запускать. Доступ повторно проверит сервер.'}
            </p>
            {error ? <div className="scan-create-page__error" role="alert"><p>{error}</p><Link to={demo ? '/demo/scans' : '/scans'}>Проверить список перед повтором</Link></div> : null}
            <p className="text-sm">
              {confirmed
                ? demo ? 'Демо не отправляет запросы.' : 'Цель подтверждена; разрешение проверяет сервер.'
                : 'До запуска подтвердите образ и выбранные проверки.'}{' '}
              Точная проверенная сборка появится в отчёте после подтверждения сервером.
            </p>
            {demo ? (
              <Link className="scan-a1__link" to="/demo/scans/partial-demo">
                Посмотреть пример отчёта
              </Link>
            ) : null}
          </form>
          <aside className="scan-a1__trust-note">

            <strong>Что вы получите</strong>
            <p>
              Находки, состав образа и следующие шаги по выбранным проверкам.
            </p>
            <p>Пустой результат не гарантирует безопасность. В отчёте будут видны непроверенные области.</p>
            <ScanInfoDialog title="Ограничения проверки" description="Что проверяем и почему некоторые образы могут быть недоступны.">
            <p>Ограничены размер образа и отдельных файлов, число слоёв, время обработки и временное место на диске. Найденная в каталоге версия может не пройти эти ограничения; выберите меньшую сборку, если сервер сообщает о превышении.</p>
            <p>Проверка уязвимостей зависит от доступной базы и поддерживаемых пакетов. Проверка настроек читает пользователя запуска из образа, но не исследует Dockerfile, права работающего контейнера или сервер.</p>
            <p>ИИ-объяснение необязательно и включается отдельно в отчёте. Данные передаются внешнему провайдеру, запрос может быть платным. Условия и согласие показываются перед отправкой.</p>
            <p>Проверка работающего контейнера — отдельный сценарий со своими разрешениями; она не входит в проверку образа.</p>
            </ScanInfoDialog>
            <Link className="scan-a1__link" to="/demo/scans/partial-demo">Посмотреть пример отчёта без запуска</Link>
          </aside>
          {!demo && subject ? (
            <details className="scan-create-page__advanced"><summary>Отдельная проверка работающего контейнера</summary>
              <p>Это другой сценарий со своими разрешениями. Для проверки образа выше он не нужен.</p>
              <RuntimeScanPanel key={sessionIdentity} subject={subject} generation={epoch} />
            </details>
          ) : null}
        </div>

      </section>
    </ScanShell>
  );
}
