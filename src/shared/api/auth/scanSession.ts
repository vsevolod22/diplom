import type { QueryClient } from '@tanstack/react-query';

// A generation also distinguishes two logins by the same subject in one tab.
let subject: string | null = null;
let generation = 0;

export function scanSession() {
  return { subject, generation };
}

export function transitionScanSession(next: string | null, client: QueryClient, force = false) {
  if (!force && subject === next) return;
  generation++;
  subject = next;
  void client.cancelQueries({ queryKey: ['live-scans'] });
  client.removeQueries({ queryKey: ['live-scans'] });
}
