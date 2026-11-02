import type { QueryClient } from '@tanstack/react-query';
import { currentDemoUser, type DemoUser } from './demoAuth';
import { scanSession, transitionScanSession } from './scanSession';

const revisions = new WeakMap<QueryClient, number>();

/** Use only for a confirmed 204 belonging to the initiating screen/session. */
export async function invalidateConfirmedBrowserSession(client: QueryClient): Promise<boolean> {
  const revision = (revisions.get(client) ?? 0) + 1;
  revisions.set(client, revision);
  transitionScanSession(null, client, true);
  const generation = scanSession().generation;
  // Wait for cancellation/reversion before replacing the cached /me result.
  await client.cancelQueries({ queryKey: ['demo-auth', 'me'], exact: true });
  if (revisions.get(client) !== revision || scanSession().generation !== generation) return false;
  client.setQueryData(['demo-auth', 'me'], null);
  return true;
}

/** A settled auth POST may have changed the cookie even after its screen was left. */
export async function revalidateBrowserSession(client: QueryClient): Promise<DemoUser | null | undefined> {
  const revision = (revisions.get(client) ?? 0) + 1;
  revisions.set(client, revision);
  const current = () => revisions.get(client) === revision;
  const queryKey = ['demo-auth', 'me'];
  // Hide private data without declaring logout or erasing a recoverable create intent.
  transitionScanSession(null, client, false, 'unverified');
  await client.cancelQueries({ queryKey, exact: true });
  if (!current()) return undefined;
  try {
    return await client.fetchQuery({
      queryKey,
      staleTime: 0,
      retry: false,
      networkMode: 'always',
      queryFn: async ({ signal }) => {
        const user = await currentDemoUser(signal);
        signal.throwIfAborted();
        if (!current()) throw new Error('Проверка сессии устарела');
        transitionScanSession(user?.id ?? null, client);
        return user;
      },
    });
  } catch (error) {
    if (!current()) return undefined;
    transitionScanSession(null, client, false, 'unverified');
    throw error;
  }
}
