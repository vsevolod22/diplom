import { useSyncExternalStore } from 'react';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';

export const REPORT_AUTOMATION_REVISION = 'report-automation-v1';
const STORAGE_PREFIX = 'report-preferences:v1:';

type Session = ReturnType<typeof scanSession>;
export type ReportPreferencesInput = Readonly<{
  language: 'original' | 'ru';
  autoSummary: boolean;
}>;
export type ReportPreferences = ReportPreferencesInput &
  Readonly<{
    authorized: boolean;
    /** The disclosure/policy version affirmatively saved by this owner, or null when unauthorized. */
    revision: typeof REPORT_AUTOMATION_REVISION | null;
  }>;

const defaults = { language: 'original', autoSummary: false, authorized: false, revision: null } as const;
const serverSnapshot: ReportPreferences = Object.freeze({ ...defaults });
let snapshot = serverSnapshot;
let deniedSnapshot = serverSnapshot;
let observedSession = scanSession();
let observedRaw: string | null | undefined;
let observedReadable = false;
let writeFailed = false;
let invalidate = false;
const listeners = new Set<() => void>();
let unsubscribeSession: (() => void) | undefined;

function storageKey(subject: string) {
  return `${STORAGE_PREFIX}${encodeURIComponent(subject)}`;
}

function decode(raw: string | null): ReportPreferences {
  if (!raw || raw.length > 256) return defaults;
  try {
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return defaults;
    const record = value as Record<string, unknown>;
    if (
      Object.keys(record).sort().join(',') !== 'autoSummary,automationRevision,language,version' ||
      record.version !== 1 ||
      record.automationRevision !== REPORT_AUTOMATION_REVISION ||
      (record.language !== 'original' && record.language !== 'ru') ||
      typeof record.autoSummary !== 'boolean'
    )
      return defaults;
    return {
      language: record.language,
      autoSummary: record.autoSummary,
      authorized: true,
      revision: REPORT_AUTOMATION_REVISION,
    };
  } catch {
    return defaults;
  }
}

/** Only the active owner can be read; an optional subject fences stale callers. */
export function readReportPreferences(subject?: string | null): ReportPreferences {
  const session = scanSession();
  const sessionChanged =
    session.subject !== observedSession.subject || session.generation !== observedSession.generation;
  if (sessionChanged) writeFailed = false;
  let raw: string | null = null;
  let readable = false;
  if (session.subject && typeof window !== 'undefined' && !writeFailed) {
    try {
      raw = window.localStorage.getItem(storageKey(session.subject));
      readable = true;
    } catch {
      // No memory-only consent fallback: unavailable storage closes automation.
    }
  }
  if (sessionChanged || invalidate || raw !== observedRaw || readable !== observedReadable) {
    observedSession = session;
    observedRaw = raw;
    observedReadable = readable;
    invalidate = false;
    // A new identity also fences drafts when the same owner starts another session generation.
    snapshot = Object.freeze({ ...(readable ? decode(raw) : defaults) });
    deniedSnapshot = Object.freeze({ ...defaults });
  }
  return subject !== undefined && subject !== session.subject ? deniedSnapshot : snapshot;
}

function notify() {
  readReportPreferences();
  for (const listener of listeners) listener();
}

function onStorage(event: StorageEvent) {
  const { subject } = scanSession();
  if (!subject) return;
  try {
    if (event.storageArea && event.storageArea !== window.localStorage) return;
    if (event.key === null || event.key === storageKey(subject)) notify();
  } catch {
    notify();
  }
}

/** Includes local saves, other-tab storage updates, and every session generation change. */
export function subscribeReportPreferences(listener: () => void): () => void {
  if (!listeners.size) {
    unsubscribeSession = subscribeScanSession(notify);
    if (typeof window !== 'undefined') window.addEventListener('storage', onStorage);
  }
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
    if (!listeners.size) {
      unsubscribeSession?.();
      unsubscribeSession = undefined;
      if (typeof window !== 'undefined') window.removeEventListener('storage', onStorage);
    }
  };
}

/** Call only from an affirmative save action; pass the form's captured session to fence stale saves. */
export function saveReportPreferences(
  preferences: ReportPreferencesInput,
  session: Session = scanSession(),
): boolean {
  const current = scanSession();
  if (!session.subject || session.subject !== current.subject || session.generation !== current.generation)
    return false;
  if (
    (preferences.language !== 'original' && preferences.language !== 'ru') ||
    typeof preferences.autoSummary !== 'boolean'
  )
    return false;
  readReportPreferences();
  try {
    const key = storageKey(session.subject);
    const raw = JSON.stringify({
      version: 1,
      automationRevision: REPORT_AUTOMATION_REVISION,
      language: preferences.language,
      autoSummary: preferences.autoSummary,
    });
    window.localStorage.setItem(key, raw);
    if (window.localStorage.getItem(key) !== raw) throw new Error('Preferences not persisted');
    writeFailed = false;
  } catch {
    writeFailed = true;
    invalidate = true;
    notify();
    return false;
  }
  invalidate = true;
  notify();
  return true;
}

export function useReportPreferences(): ReportPreferences {
  return useSyncExternalStore(subscribeReportPreferences, readReportPreferences, () => serverSnapshot);
}
