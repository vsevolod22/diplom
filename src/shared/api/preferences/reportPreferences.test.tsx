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
} from './reportPreferences';

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
    JSON.stringify({ ...record, language: 'en' }),
    JSON.stringify({ ...record, autoSummary: 'true' }),
    JSON.stringify({ language: 'ru', autoSummary: true }),
    JSON.stringify({ ...record, password: 'must-not-be-accepted' }),
    'x'.repeat(257),
  ])('fails closed for invalid or obsolete stored settings: %s', (raw) => {
    localStorage.setItem(key('owner-a'), raw);
    expect(readReportPreferences()).toMatchObject(defaults);
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
