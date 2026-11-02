import { scanChecks } from './types';

export type PendingCreateIntent = Readonly<{ target: string; checks: string; key: string }>;
type Session = { subject: string | null; generation: number };

// Tab-memory only. Never evict an uncertain key to make room for a new POST.
const MAX_PENDING_CREATES = 8;
let owner: string | null = null;
let active: Session = { subject: null, generation: 0 };
const intents = new Map<string, PendingCreateIntent>();
const identity = (intent: Pick<PendingCreateIntent, 'target' | 'checks'>) => JSON.stringify([intent.target, intent.checks]);

export function transitionPendingCreateSession(subject: string | null, generation: number, unverified = false): void {
  active = { subject, generation };
  if (subject === null && unverified) return;
  if (subject === null || subject !== owner) intents.clear();
  owner = subject;
}

function authorized(session: Session): boolean {
  return session.subject !== null && session.subject === owner && session.subject === active.subject && session.generation === active.generation;
}

export function readPendingCreateIntent(session: Session, match?: Pick<PendingCreateIntent, 'target' | 'checks'>): PendingCreateIntent | null {
  if (!authorized(session)) return null;
  const intent = match ? intents.get(identity(match)) : [...intents.values()].at(-1);
  return intent ? { ...intent } : null;
}

export function rememberPendingCreateIntent(session: Session, intent: PendingCreateIntent): boolean {
  if (!authorized(session) || !intent.target || intent.target.length > 1024 || !intent.key || intent.key.length > 128 ||
      !intent.checks || scanChecks.filter(check => intent.checks.split(',').includes(check)).join(',') !== intent.checks) return false;
  const id = identity(intent);
  const previous = intents.get(id);
  if (previous && previous.key !== intent.key || !previous && intents.size >= MAX_PENDING_CREATES) return false;
  intents.delete(id);
  intents.set(id, { ...intent });
  return true;
}

export function acknowledgePendingCreateIntent(session: Session, key: string): void {
  if (!authorized(session)) return;
  for (const [id, intent] of intents) {
    if (intent.key === key) intents.delete(id);
  }
}
