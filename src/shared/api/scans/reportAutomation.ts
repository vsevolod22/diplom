import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import {
  REPORT_AUTOMATION_REVISION,
  readReportPreferences,
  type ReportPreferences,
} from '@/shared/api/preferences/reportPreferences';

/** A consent-version string is not a change token. Every save/revocation replaces the snapshot. */
export function reportPreferencesCurrent(accepted: ReportPreferences, kind?: 'summary' | 'translation') {
  const fresh = readReportPreferences();
  if (fresh !== accepted) return false;
  if (!kind) return true; // Explicit chat/history does not require automation opt-in.
  return (
    fresh.authorized &&
    fresh.revision === REPORT_AUTOMATION_REVISION &&
    (kind === 'summary' ? fresh.autoSummary : fresh.language === 'ru')
  );
}

const SUMMARY_DATA = 'Sanitized scanner findings and coverage; no raw evidence or credentials.';
const TRANSLATION_DATA =
  'Only the selected normalized advisory title and description eligible for translation; no other report metadata, package data, history, raw evidence or credentials. Identifiers within the selected text remain unchanged.';

/** Exact account disclosure for report-automation-v1; a new server policy is not new user consent. */
export function allowAutomationDisclosure(value: unknown, kind: 'summary' | 'translation'): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  const keys = [
    'provider',
    'model',
    'providers',
    'region',
    'retention',
    'operatorApprovedRouting',
    'providerComplianceNotProvenByDeclaration',
    'requestBudgetUsd',
    'freeOnly',
    'maxPrice',
    'data',
  ];
  if (kind === 'translation')
    keys.push('targetLanguage', 'machineTranslation', 'automaticDispatch', 'persistentTranslationCache');
  if (Object.keys(v).sort().join(',') !== keys.sort().join(',')) return false;
  const price = v.maxPrice;
  if (!price || typeof price !== 'object' || Array.isArray(price)) return false;
  const p = price as Record<string, unknown>;
  return (
    v.provider === 'OpenRouter' &&
    v.model === 'xingchen-agi/xing4.0-29b-a4b:free' &&
    Array.isArray(v.providers) &&
    v.providers.length === 1 &&
    v.providers[0] === 'phala' &&
    v.region === 'global' &&
    v.retention === 'no-storage' &&
    v.freeOnly === true &&
    v.requestBudgetUsd === 0 &&
    v.operatorApprovedRouting === true &&
    v.providerComplianceNotProvenByDeclaration === true &&
    Object.keys(p).sort().join(',') === 'completion,prompt,request' &&
    p.prompt === 0 &&
    p.completion === 0 &&
    p.request === 0 &&
    v.data === (kind === 'summary' ? SUMMARY_DATA : TRANSLATION_DATA) &&
    (kind !== 'translation' ||
      (v.targetLanguage === 'ru' &&
        v.machineTranslation === true &&
        v.automaticDispatch === 'account-preference' &&
        v.persistentTranslationCache === false))
  );
}

const MAX_RESULTS = 64;
const MAX_ATTEMPTS = 256;
const MAX_QUEUE = 8;
const LEDGER = 'report-automation-v1:attempts';
const results = new Map<string, Promise<unknown>>();
const failed = new Set<string>();
const controllers = new Set<AbortController>();
type MetadataEntry = { controller: AbortController; promise: Promise<unknown>; users: Set<symbol> };
const metadata = new Map<string, MetadataEntry>();
type Job = { start: () => void; cancel: () => void };
const queue: Job[] = [];
let active = false;

export class ReportAutomationError extends Error {
  constructor(readonly code: 'ATTEMPTED' | 'CAPACITY' | 'STORAGE' | 'ABORTED' | 'DISCLOSURE') {
    super(code);
  }
}

export function reportAutomationKey(kind: 'summary' | 'translation', revision: string, fence: string) {
  // Session generation is deliberately absent: reauthentication does not authorize a replay.
  return JSON.stringify([kind, scanSession().subject, revision, fence]);
}

async function recordAttempt(key: string, signal: AbortSignal, retry: boolean) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
  if (signal.aborted) throw new ReportAutomationError('ABORTED');
  const id = Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, '0')).join('');
  try {
    const saved: unknown = JSON.parse(sessionStorage.getItem(LEDGER) ?? '[]');
    if (
      !Array.isArray(saved) ||
      saved.length > MAX_ATTEMPTS ||
      saved.some((value) => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value))
    )
      throw new ReportAutomationError('STORAGE');
    const attempts = new Set<string>(saved);
    if (!retry && attempts.has(id)) throw new ReportAutomationError('ATTEMPTED');
    if (!attempts.has(id) && attempts.size >= MAX_ATTEMPTS) throw new ReportAutomationError('CAPACITY');
    attempts.add(id);
    // Only opaque attempt hashes survive a reload, never owner IDs, source text or model output.
    sessionStorage.setItem(LEDGER, JSON.stringify([...attempts]));
  } catch (error) {
    throw error instanceof ReportAutomationError ? error : new ReportAutomationError('STORAGE');
  }
}

function drain() {
  if (active) return;
  queue.shift()?.start();
}

function schedule<T>(signal: AbortSignal, task: () => Promise<T>): Promise<T> {
  if (signal.aborted) return Promise.reject(new ReportAutomationError('ABORTED'));
  if (active && queue.length >= MAX_QUEUE) return Promise.reject(new ReportAutomationError('CAPACITY'));
  return new Promise<T>((resolve, reject) => {
    let started = false;
    const abort = () => {
      if (started) return;
      const index = queue.indexOf(job);
      if (index >= 0) queue.splice(index, 1);
      signal.removeEventListener('abort', abort);
      reject(new ReportAutomationError('ABORTED'));
    };
    const job: Job = {
      cancel: abort,
      start: () => {
        started = true;
        active = true;
        signal.removeEventListener('abort', abort);
        let cleanup = () => {};
        const stopped = new Promise<never>((_, fail) => {
          const cancel = () => fail(new ReportAutomationError('ABORTED'));
          signal.addEventListener('abort', cancel, { once: true });
          cleanup = () => signal.removeEventListener('abort', cancel);
          if (signal.aborted) cancel();
        });
        // Defer task invocation so a synchronous session/close cancellation wins before any I/O.
        void Promise.race([
          Promise.resolve().then(() => {
            if (signal.aborted) throw new ReportAutomationError('ABORTED');
            return task();
          }),
          stopped,
        ])
          .then(resolve, reject)
          .finally(() => {
            cleanup();
            active = false;
            drain();
          });
      },
    };
    signal.addEventListener('abort', abort, { once: true });
    if (active) queue.push(job);
    else job.start();
  });
}

/** Passive GET single-flight only while pending: no attempt ledger, no stale readiness cache.
 * The task may issue at most two parallel GETs. It shares the mutation queue (one active, eight waiting).
 * Do not nest this scheduler in runReportAutomation: its task already owns the queue slot.
 */
export function runReportMetadata<T>(
  key: string,
  signal: AbortSignal,
  task: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  if (signal.aborted) return Promise.reject(new ReportAutomationError('ABORTED'));
  const scopedKey = JSON.stringify([scanSession(), key]);
  let entry = metadata.get(scopedKey);
  if (entry?.controller.signal.aborted) entry = undefined;
  if (!entry) {
    if (metadata.size >= MAX_QUEUE + 1) return Promise.reject(new ReportAutomationError('CAPACITY'));
    const controller = new AbortController();
    controllers.add(controller);
    const next: MetadataEntry = { controller, users: new Set(), promise: Promise.resolve() };
    next.promise = schedule(controller.signal, () => task(controller.signal)).finally(() => {
      controllers.delete(controller);
      if (metadata.get(scopedKey) === next) metadata.delete(scopedKey);
    });
    metadata.set(scopedKey, next);
    entry = next;
  }
  const shared = entry;
  const user = Symbol();
  shared.users.add(user);
  return new Promise<T>((resolve, reject) => {
    const release = () => {
      signal.removeEventListener('abort', abort);
      shared.users.delete(user);
      queueMicrotask(() => {
        if (!shared.users.size) shared.controller.abort();
      });
    };
    const abort = () => {
      release();
      reject(new ReportAutomationError('ABORTED'));
    };
    signal.addEventListener('abort', abort, { once: true });
    shared.promise.then(
      (value) => {
        release();
        if (signal.aborted) reject(new ReportAutomationError('ABORTED'));
        else resolve(value as T);
      },
      (error: unknown) => {
        release();
        reject(error);
      },
    );
    if (signal.aborted) abort();
  });
}

/** Bounded, fail-closed single-flight cache. Rejected/aborted work is never retried by mounting again. */
export function runReportAutomation<T>(
  key: string,
  signal: AbortSignal,
  task: () => Promise<T>,
  retry = false,
): Promise<T> {
  const cached = results.get(key);
  if (cached && (!retry || !failed.has(key))) return cached as Promise<T>;
  failed.delete(key);
  if (!cached && results.size >= MAX_RESULTS) return Promise.reject(new ReportAutomationError('CAPACITY'));
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  controllers.add(controller);
  const promise = schedule(controller.signal, async () => {
    await recordAttempt(key, controller.signal, retry);
    if (controller.signal.aborted) throw new ReportAutomationError('ABORTED');
    return task();
  })
    .catch((error: unknown) => {
      if (results.get(key) === promise) failed.add(key);
      throw error;
    })
    .finally(() => {
      controllers.delete(controller);
      signal.removeEventListener('abort', abort);
    });
  results.set(key, promise);
  return promise;
}

subscribeScanSession(() => {
  for (const controller of controllers) controller.abort();
  for (const job of [...queue]) job.cancel();
  metadata.clear();
  results.clear();
  failed.clear();
});

export function reportAutomationMessage(error: unknown): string | null {
  if (!(error instanceof ReportAutomationError)) return null;
  if (error.code === 'DISCLOSURE')
    return 'Условия сервера не совпадают с разрешением аккаунта. Автоматическая отправка запрещена; требуется новая версия согласия в настройках аккаунта.';
  if (error.code === 'ATTEMPTED')
    return 'Автоматический запрос уже выполнялся. После перезагрузки ответ не восстанавливается из браузерного хранилища; автоматического повтора нет.';
  if (error.code === 'CAPACITY')
    return 'Достигнут предел очереди или кэша автоматических запросов. Автоматического повтора нет.';
  if (error.code === 'STORAGE')
    return 'Не удалось безопасно сохранить отметку запроса для защиты от повтора после перезагрузки. Автоматическая отправка остановлена.';
  return 'Ожидание остановлено. Передача уже могла начаться; автоматического повтора нет.';
}
