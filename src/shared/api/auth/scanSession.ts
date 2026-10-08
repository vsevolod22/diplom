import type { QueryClient } from '@tanstack/react-query';

// A generation also distinguishes two logins by the same subject in one tab.
let subject: string | null = null;
let generation = 0;
const listeners = new Set<() => void>();

export function subscribeScanSession(listener: () => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function scanSession() {
  return { subject, generation };
}

export function transitionScanSession(next: string | null, client: QueryClient, force = false) {
  if (!force && subject === next) return;
  generation++;
  subject = next;
  for (const listener of listeners) listener();
  void client.cancelQueries({ queryKey: ['live-scans'] });
  client.removeQueries({ queryKey: ['live-scans'] });
}
