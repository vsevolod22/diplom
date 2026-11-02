import type { QueryClient } from '@tanstack/react-query';
import { transitionPendingCreateSession } from '../scans/pendingCreateIntent';

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

export function transitionScanSession(next: string | null, client: QueryClient, force = false, verification: 'confirmed' | 'unverified' = 'confirmed') {
  const changed = force || subject !== next;
  if (changed) {
    generation++;
    subject = next;
  }
  // A confirmed anonymous result must clear retained intents even after an outage already set subject=null.
  transitionPendingCreateSession(next, generation, verification === 'unverified' && !force);
  if (!changed) return;
  for (const listener of listeners) listener();
  void client.cancelQueries({ queryKey: ['live-scans'] });
  client.removeQueries({ queryKey: ['live-scans'] });
}
