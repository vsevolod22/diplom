import { useSyncExternalStore } from 'react';
import { z } from 'zod';
import { moduleApiDisclosureSchema, openAiDisclosureSchema } from '@/shared/api/scans/llmPublicContract';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';

export const REPORT_AUTOMATION_REVISION = 'report-automation-v4-remediation';
const STORAGE_PREFIX = 'report-preferences:v1:';

export const openAiSummaryConsentSchema = z
  .strictObject({
    version: z.literal(1),
    policyVersion: z.string().regex(/^[a-f0-9]{64}$/),
    disclosure: openAiDisclosureSchema,
  })
  // Freeze every object in this closed schema, not just the preferences snapshot.
  // Copy each level so neither parsing nor saving retains or freezes caller-owned references.
  .transform((grant) =>
    Object.freeze({
      ...grant,
      disclosure: Object.freeze({
        ...grant.disclosure,
        estimatedPrice: Object.freeze({ ...grant.disclosure.estimatedPrice }),
      }),
    }),
  );
export type OpenAiSummaryConsent = z.infer<typeof openAiSummaryConsentSchema>;

// Independent grant: no migration of a free or OpenAI permission to this recipient.
export const moduleApiSummaryConsentSchema = z
  .strictObject({
    version: z.literal(1),
    policyVersion: z.string().regex(/^[a-f0-9]{64}$/),
    disclosure: moduleApiDisclosureSchema,
  })
  .transform((grant) =>
    Object.freeze({
      ...grant,
      disclosure: Object.freeze({
        ...grant.disclosure,
        estimatedPrice: Object.freeze({ ...grant.disclosure.estimatedPrice }),
      }),
    }),
  );
export type ModuleApiSummaryConsent = z.infer<typeof moduleApiSummaryConsentSchema>;

type Session = ReturnType<typeof scanSession>;
export type ReportPreferencesInput = Readonly<{
  language: 'original' | 'ru';
  autoSummary: boolean;
  /** Only an explicit action after the exact paid disclosure may populate this grant. */
  openAiSummaryConsent?: OpenAiSummaryConsent;
  moduleApiSummaryConsent?: ModuleApiSummaryConsent;
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
  if (!raw || raw.length > 4096) return defaults;
  try {
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return defaults;
    const record = value as Record<string, unknown>;
    const hasOpenAi = Object.hasOwn(record, 'openAiSummaryConsent');
    const hasModuleApi = Object.hasOwn(record, 'moduleApiSummaryConsent');
    const keys = ['autoSummary', 'automationRevision', 'language', 'version'];
    if (hasOpenAi) keys.push('openAiSummaryConsent');
    if (hasModuleApi) keys.push('moduleApiSummaryConsent');
    if (
      (hasOpenAi && hasModuleApi) ||
      Object.keys(record).sort().join(',') !== keys.sort().join(',') ||
      record.version !== 1 ||
      record.automationRevision !== REPORT_AUTOMATION_REVISION ||
      (record.language !== 'original' && record.language !== 'ru') ||
      typeof record.autoSummary !== 'boolean'
    )
      return defaults;
    const consent =
      record.openAiSummaryConsent === undefined
        ? undefined
        : openAiSummaryConsentSchema.parse(record.openAiSummaryConsent);
    const moduleApiConsent = hasModuleApi
      ? moduleApiSummaryConsentSchema.parse(record.moduleApiSummaryConsent)
      : undefined;
    if ((consent || moduleApiConsent) && !record.autoSummary) return defaults;
    return {
      ...(consent ? { openAiSummaryConsent: consent } : {}),
      ...(moduleApiConsent ? { moduleApiSummaryConsent: moduleApiConsent } : {}),
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
  const parsedConsent =
    preferences.openAiSummaryConsent === undefined
      ? null
      : openAiSummaryConsentSchema.safeParse(preferences.openAiSummaryConsent);
  const parsedModuleApiConsent =
    preferences.moduleApiSummaryConsent === undefined
      ? null
      : moduleApiSummaryConsentSchema.safeParse(preferences.moduleApiSummaryConsent);
  if (parsedConsent && parsedModuleApiConsent) return false;
  if (parsedConsent && (!parsedConsent.success || !preferences.autoSummary)) return false;
  if (parsedModuleApiConsent && (!parsedModuleApiConsent.success || !preferences.autoSummary)) return false;
  readReportPreferences();
  try {
    const key = storageKey(session.subject);
    const raw = JSON.stringify({
      version: 1,
      automationRevision: REPORT_AUTOMATION_REVISION,
      language: preferences.language,
      autoSummary: preferences.autoSummary,
      ...(parsedConsent?.success ? { openAiSummaryConsent: parsedConsent.data } : {}),
      ...(parsedModuleApiConsent?.success ? { moduleApiSummaryConsent: parsedModuleApiConsent.data } : {}),
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
