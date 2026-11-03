import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import {
  REPORT_AUTOMATION_REVISION,
  readReportPreferences,
  saveReportPreferences,
  subscribeReportPreferences,
  useReportPreferences,
  type OpenAiSummaryConsent,
} from './reportPreferences';
import { allowSummaryAutomation, reportPreferencesCurrent } from '@/shared/api/scans/reportAutomation';
import { OPENAI_COST_BASIS, OPENAI_MODEL } from '@/shared/api/scans/llmPublicContract';

const client = new QueryClient();
const key = (subject: string) => `report-preferences:v1:${encodeURIComponent(subject)}`;
const granted = { language: 'ru', autoSummary: true } as const;
const defaults = { language: 'original', autoSummary: false, authorized: false, revision: null };
const record = { version: 1, automationRevision: REPORT_AUTOMATION_REVISION, ...granted };
const login = (subject: string | null, force = false) => transitionScanSession(subject, client, force);

beforeEach(() => {
  localStorage.clear();
  login('owner-a', true);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  login(null, true);
  localStorage.clear();
  client.clear();
});

function paidConsent(): OpenAiSummaryConsent {
  return {
    version: 1,
    policyVersion: 'c'.repeat(64),
    disclosure: {
      provider: 'OpenAI',
      model: OPENAI_MODEL,
      retention: 'no-training',
      operatorApprovedRouting: true,
      providerComplianceNotProvenByDeclaration: true,
      zeroDataRetentionVerified: false,
      costBasis: OPENAI_COST_BASIS,
      estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 750000, output: 4500000 },
      data: 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.',
      monetaryLimit: 'capped',
      requestBudgetMicros: 10000,
      userBudgetMicros: 100000,
      scanBudgetMicros: 50000,
    },
  };
}
function consentContext(consent: OpenAiSummaryConsent) {
  return { enabled: true, policyVersion: consent.policyVersion, disclosure: consent.disclosure };
}
function loadPaidConsent(origin: 'save' | 'parsed-storage', consent: OpenAiSummaryConsent) {
  const preferences = { language: 'original', autoSummary: true, openAiSummaryConsent: consent } as const;
  if (origin === 'save') expect(saveReportPreferences(preferences)).toBe(true);
  else
    localStorage.setItem(
      key('owner-a'),
      JSON.stringify({
        version: 1,
        automationRevision: REPORT_AUTOMATION_REVISION,
        ...preferences,
      }),
    );
  return readReportPreferences();
}

describe.each(['save', 'parsed-storage'] as const)('nested paid consent from %s', (origin) => {
  it.each(['policy', 'disclosure', 'prices', 'capped-to-uncapped'] as const)(
    '%s mutation cannot create authority while snapshot identity remains current',
    (attack) => {
      const original = paidConsent();
      const accepted = loadPaidConsent(origin, original);
      const nested = accepted.openAiSummaryConsent;
      if (!nested) throw new Error('Expected parsed paid grant');
      const before = JSON.stringify(accepted);
      const stored = localStorage.getItem(key('owner-a'));
      const base = paidConsent();
      const target: OpenAiSummaryConsent =
        attack === 'policy'
          ? { ...base, policyVersion: 'd'.repeat(64) }
          : attack === 'prices'
            ? {
                ...base,
                disclosure: {
                  ...base.disclosure,
                  estimatedPrice: { ...base.disclosure.estimatedPrice, input: 900000 },
                },
              }
            : {
                ...base,
                disclosure: {
                  ...base.disclosure,
                  monetaryLimit: 'uncapped',
                  requestBudgetMicros: null,
                  userBudgetMicros: null,
                  scanBudgetMicros: null,
                },
              };
      expect(allowSummaryAutomation(accepted, consentContext(original))).toBe(true);
      expect(allowSummaryAutomation(accepted, consentContext(target))).toBe(false);
      const save = vi.spyOn(Storage.prototype, 'setItem');
      // Reflect attempts runtime mutation even if the public TypeScript type becomes readonly.
      const writes =
        attack === 'policy'
          ? [Reflect.set(nested, 'policyVersion', target.policyVersion)]
          : attack === 'disclosure'
            ? [Reflect.set(nested, 'disclosure', target.disclosure)]
            : attack === 'prices'
              ? [Reflect.set(nested.disclosure.estimatedPrice, 'input', 900000)]
              : ['monetaryLimit', 'requestBudgetMicros', 'userBudgetMicros', 'scanBudgetMicros'].map(
                  (field) => Reflect.set(nested.disclosure, field, Reflect.get(target.disclosure, field)),
                );
      expect(readReportPreferences()).toBe(accepted);
      expect(reportPreferencesCurrent(accepted, 'summary')).toBe(true);
      expect(allowSummaryAutomation(accepted, consentContext(target))).toBe(false);
      expect(allowSummaryAutomation(accepted, consentContext(original))).toBe(true);
      expect(JSON.stringify(accepted)).toBe(before);
      expect(localStorage.getItem(key('owner-a'))).toBe(stored);
      expect(save).not.toHaveBeenCalled();
      expect(writes.every((result) => result === false)).toBe(true);
      for (const value of [accepted, nested, nested.disclosure, nested.disclosure.estimatedPrice])
        expect(Object.isFrozen(value)).toBe(true);
    },
  );

  it('detaches caller-owned grant/disclosure/price aliases; mutating them is not a save', () => {
    const supplied = paidConsent();
    const original = paidConsent();
    const accepted = loadPaidConsent(origin, supplied);
    const nested = accepted.openAiSummaryConsent;
    if (!nested) throw new Error('Expected parsed paid grant');
    expect(nested).not.toBe(supplied);
    expect(nested.disclosure).not.toBe(supplied.disclosure);
    expect(nested.disclosure.estimatedPrice).not.toBe(supplied.disclosure.estimatedPrice);
    const raw = localStorage.getItem(key('owner-a'));
    const save = vi.spyOn(Storage.prototype, 'setItem');
    expect(Object.isFrozen(supplied)).toBe(false);
    expect(Object.isFrozen(supplied.disclosure)).toBe(false);
    expect(Object.isFrozen(supplied.disclosure.estimatedPrice)).toBe(false);
    expect(Reflect.set(supplied, 'policyVersion', 'd'.repeat(64))).toBe(true);
    expect(Reflect.set(supplied.disclosure.estimatedPrice, 'input', 900000)).toBe(true);
    const changed = {
      ...supplied.disclosure,
      monetaryLimit: 'uncapped',
      requestBudgetMicros: null,
      userBudgetMicros: null,
      scanBudgetMicros: null,
    } as const;
    Reflect.set(supplied, 'disclosure', changed);
    expect(readReportPreferences()).toBe(accepted);
    expect(reportPreferencesCurrent(accepted, 'summary')).toBe(true);
    expect(accepted.openAiSummaryConsent).toEqual(original);
    expect(allowSummaryAutomation(accepted, consentContext(original))).toBe(true);
    expect(allowSummaryAutomation(accepted, consentContext(supplied))).toBe(false);
    expect(localStorage.getItem(key('owner-a'))).toBe(raw);
    expect(save).not.toHaveBeenCalled();
  });
});

describe('owner-scoped report automation preferences', () => {
  it('defaults closed, keeps snapshots stable, and never sends requests', () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const preferences = readReportPreferences();
    expect(preferences).toMatchObject(defaults);
    expect(readReportPreferences()).toBe(preferences);
    const { result } = renderHook(useReportPreferences);
    expect(result.current).toBe(preferences);
    expect(localStorage.length).toBe(0);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('persists only a minimal versioned record on affirmative save and restores it', () => {
    expect(saveReportPreferences(granted)).toBe(true);
    expect(localStorage.length).toBe(1);
    expect(JSON.parse(localStorage.getItem(key('owner-a'))!)).toEqual(record);
    expect(readReportPreferences('owner-a')).toMatchObject({ ...granted, authorized: true });
    const savedSnapshot = readReportPreferences();
    login(null);
    expect(readReportPreferences()).toMatchObject(defaults);
    login('owner-a');
    expect(readReportPreferences()).toMatchObject({ ...granted, authorized: true });
    expect(readReportPreferences()).not.toBe(savedSnapshot);
    expect(readReportPreferences().revision).toBe(REPORT_AUTOMATION_REVISION);
  });

  it('isolates owners and rejects reads and stale saves for another owner', () => {
    const oldSession = scanSession();
    saveReportPreferences(granted);
    login('owner-b');
    expect(readReportPreferences()).toMatchObject(defaults);
    expect(readReportPreferences('owner-a')).toMatchObject(defaults);
    expect(saveReportPreferences(granted, oldSession)).toBe(false);
    expect(localStorage.getItem(key('owner-b'))).toBeNull();
    saveReportPreferences({ language: 'original', autoSummary: false });
    expect(readReportPreferences()).toMatchObject({
      language: 'original',
      autoSummary: false,
      authorized: true,
    });
    login('owner-a');
    expect(readReportPreferences()).toMatchObject({ ...granted, authorized: true });
  });

  it('notifies and fences a new generation even when the same owner logs in again', () => {
    saveReportPreferences(granted);
    const oldSession = scanSession();
    const listener = vi.fn();
    const unsubscribe = subscribeReportPreferences(listener);
    const { result } = renderHook(useReportPreferences);
    const oldSnapshot = result.current;
    act(() => login('owner-a', true));
    expect(listener).toHaveBeenCalledTimes(1);
    expect(result.current).not.toBe(oldSnapshot);
    expect(result.current.revision).toBe(REPORT_AUTOMATION_REVISION);
    expect(saveReportPreferences({ language: 'original', autoSummary: false }, oldSession)).toBe(false);
    expect(result.current).toMatchObject({ ...granted, authorized: true });
    act(() => login(null));
    expect(result.current).toMatchObject(defaults);
    unsubscribe();
  });

  it('updates the hook for local saves, revocation and owner switches', () => {
    const { result } = renderHook(useReportPreferences);
    const initialSnapshot = result.current;
    act(() => {
      saveReportPreferences(granted);
    });
    expect(result.current).toMatchObject({ ...granted, authorized: true });
    expect(result.current).not.toBe(initialSnapshot);
    expect(result.current.revision).toBe(REPORT_AUTOMATION_REVISION);
    act(() => {
      saveReportPreferences({ language: 'original', autoSummary: false });
    });
    expect(result.current).toMatchObject({ language: 'original', autoSummary: false, authorized: true });
    act(() => login('owner-b'));
    expect(result.current).toMatchObject(defaults);
  });

  it('observes other-tab changes and clearing, but ignores unrelated owners and session storage', () => {
    const { result } = renderHook(useReportPreferences);
    const initial = result.current;
    act(() => {
      localStorage.setItem(key('owner-b'), JSON.stringify(record));
      window.dispatchEvent(new StorageEvent('storage', { key: key('owner-b'), storageArea: localStorage }));
      window.dispatchEvent(new StorageEvent('storage', { key: key('owner-a'), storageArea: sessionStorage }));
    });
    expect(result.current).toBe(initial);
    act(() => {
      localStorage.setItem(key('owner-a'), JSON.stringify(record));
      window.dispatchEvent(new StorageEvent('storage', { key: key('owner-a'), storageArea: localStorage }));
    });
    expect(result.current).toMatchObject({ ...granted, authorized: true });
    act(() => {
      localStorage.clear();
      window.dispatchEvent(new StorageEvent('storage', { key: null, storageArea: localStorage }));
    });
    expect(result.current).toMatchObject(defaults);
  });

  it.each([
    '{',
    'null',
    '[]',
    '"ru"',
    JSON.stringify({ ...record, version: 2 }),
    JSON.stringify({ ...record, automationRevision: 'report-automation-v0' }),
    JSON.stringify({ ...record, automationRevision: 'report-automation-v2' }),
    JSON.stringify({ ...record, automationRevision: 'report-automation-v2-nvidia-no-training' }),
        JSON.stringify({ ...record, automationRevision: 'report-automation-v3-dots-no-training' }),
    JSON.stringify({ ...record, language: 'en' }),
    JSON.stringify({ ...record, autoSummary: 'true' }),
    JSON.stringify({ language: 'ru', autoSummary: true }),
    JSON.stringify({ ...record, password: 'must-not-be-accepted' }),
    'x'.repeat(257),
  ])('fails closed for invalid or obsolete stored settings: %s', (raw) => {
    localStorage.setItem(key('owner-a'), raw);
    expect(readReportPreferences()).toMatchObject(defaults);
    expect(localStorage.getItem(key('owner-a'))).toBe(raw);
  });

  it('revokes a live hook when another tab writes settings for a different policy revision', () => {
    saveReportPreferences(granted);
    const { result } = renderHook(useReportPreferences);
    act(() => {
      localStorage.setItem(
        key('owner-a'),
        JSON.stringify({ ...record, automationRevision: 'future-policy' }),
      );
      window.dispatchEvent(new StorageEvent('storage', { key: key('owner-a'), storageArea: localStorage }));
    });
    expect(result.current).toMatchObject(defaults);
    act(() => {
      saveReportPreferences(granted);
    });
    expect(result.current).toMatchObject({
      ...granted,
      authorized: true,
      revision: REPORT_AUTOMATION_REVISION,
    });
  });

  it('fails closed if accessing localStorage itself is forbidden', () => {
    const storage = vi.spyOn(window, 'localStorage', 'get').mockImplementation(() => {
      throw new DOMException('Denied', 'SecurityError');
    });
    expect(readReportPreferences()).toMatchObject(defaults);
    expect(saveReportPreferences(granted)).toBe(false);
    storage.mockRestore();
    expect(readReportPreferences()).toMatchObject(defaults);
  });

  it('detaches storage and session subscriptions after unsubscribe', () => {
    const listener = vi.fn();
    const unsubscribe = subscribeReportPreferences(listener);
    saveReportPreferences(granted);
    expect(listener).toHaveBeenCalledTimes(1);
    unsubscribe();
    login('owner-b');
    window.dispatchEvent(new StorageEvent('storage', { key: null, storageArea: localStorage }));
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('fails closed when storage cannot be read and recovers only from a real record', () => {
    saveReportPreferences(granted);
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('Denied', 'SecurityError');
    });
    expect(readReportPreferences()).toMatchObject(defaults);
    expect(readReportPreferences()).toBe(readReportPreferences());
    get.mockRestore();
    expect(readReportPreferences()).toMatchObject({ ...granted, authorized: true });
  });

  it('revokes in-memory authorization if a save fails, even with an old grant on disk', () => {
    saveReportPreferences(granted);
    const { result } = renderHook(useReportPreferences);
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Full', 'QuotaExceededError');
    });
    act(() => {
      expect(saveReportPreferences({ language: 'original', autoSummary: false })).toBe(false);
    });
    expect(result.current).toMatchObject(defaults);
    set.mockRestore();
    expect(readReportPreferences()).toMatchObject(defaults);
    act(() => {
      expect(saveReportPreferences({ language: 'original', autoSummary: false })).toBe(true);
    });
    expect(result.current).toMatchObject({ language: 'original', autoSummary: false, authorized: true });
  });

  it('requires persisted writes, does not use an in-memory fallback, and cannot save logged out', () => {
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {});
    expect(saveReportPreferences(granted)).toBe(false);
    expect(readReportPreferences()).toMatchObject(defaults);
    set.mockRestore();
    login(null);
    expect(saveReportPreferences(granted)).toBe(false);
    expect(localStorage.length).toBe(0);
  });
});
