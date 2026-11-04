import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useQueryClient, type QueryClient, type QueryKey } from '@tanstack/react-query';
import { ScanAccessError } from '@/shared/api/scans/httpScanTransport';
import { ScanListIdentityError, type ScanSummary, type ScanTransport } from '@/shared/api/scans/scanTransport';

const ACTIVE_BATCH_SIZE = 5;
const ACTIVE_REFRESH_MS = 2000;
const isActive = (scan: ScanSummary) => ['queued', 'running', 'cancelling'].includes(scan.state);
type Snapshot = { scans: ScanSummary[]; nextCursor: string | null; cursors: string[] };

async function read<T>(client: QueryClient, key: QueryKey, controller: AbortController,
  load: (signal: AbortSignal) => Promise<T>): Promise<T> {
  return client.fetchQuery({
    queryKey: key, staleTime: 0, gcTime: 0, retry: false, networkMode: 'always',
    queryFn: async ({ signal }) => {
      const abort = () => controller.abort();
      signal.addEventListener('abort', abort, { once: true });
      try {
        signal.throwIfAborted();
        controller.signal.throwIfAborted();
        const result = await load(controller.signal);
        signal.throwIfAborted();
        controller.signal.throwIfAborted();
        return result;
      } finally { signal.removeEventListener('abort', abort); }
    },
  });
}

/** Mounted inside an owner/session-keyed list; no observer can refetch a whole cursor chain. */
export function useScanListPages(transport: ScanTransport, scope: readonly unknown[], demo: boolean) {
  const client = useQueryClient();
  const instance = useId();
  const baseKey = useRef([...scope, 'list-pages', instance]).current;
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const confirmed = useRef<Snapshot | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [refreshError, setRefreshError] = useState<Error | null>(null);
  const [refreshPending, setRefreshPending] = useState(false);
  const pageRequest = useRef<AbortController | null>(null);
  const refreshRequest = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const activeOffset = useRef(0);

  const load = useCallback(async (cursor?: string) => {
    if (!transport.capabilities.list || pageRequest.current) return;
    const controller = new AbortController();
    pageRequest.current = controller;
    refreshRequest.current?.abort();
    setRefreshPending(false);
    setPending(true);
    setError(null);
    if (cursor === undefined) generation.current++;
    try {
      const page = await read(client, [...baseKey, generation.current, 'page', cursor ?? null], controller,
        signal => transport.listPage ? transport.listPage(cursor, signal) : transport.list(signal).then(scans => ({ scans, nextCursor: null })));
      controller.signal.throwIfAborted();
      const previous = cursor === undefined ? null : confirmed.current;
      if (cursor !== undefined && (!previous || previous.nextCursor !== cursor)) throw new ScanListIdentityError();
      const ids = new Set(previous?.scans.map(scan => scan.scanId));
      for (const scan of page.scans) {
        if (ids.has(scan.scanId)) throw new ScanListIdentityError();
        ids.add(scan.scanId);
      }
      const cursors = [...(previous?.cursors ?? []), ...(cursor === undefined ? [] : [cursor])];
      if (page.nextCursor !== null && (!page.scans.length || cursors.includes(page.nextCursor))) throw new ScanListIdentityError();
      const next = { scans: [...(previous?.scans ?? []), ...page.scans], nextCursor: page.nextCursor, cursors };
      confirmed.current = next;
      setSnapshot(next);
      setRefreshError(null);
    } catch (failure) {
      if (!controller.signal.aborted) setError(failure instanceof Error ? failure : new Error('Не удалось загрузить список'));
    } finally {
      if (pageRequest.current === controller) {
        pageRequest.current = null;
        setPending(false);
      }
    }
  }, [baseKey, client, transport]);

  useEffect(() => {
    void load();
    return () => {
      pageRequest.current?.abort();
      pageRequest.current = null;
      refreshRequest.current?.abort();
    };
  }, [load]);

  useEffect(() => {
    if (demo || !snapshot || pending || error instanceof ScanAccessError || error instanceof ScanListIdentityError ||
        refreshError || !transport.capabilities.list || !snapshot.scans.some(isActive)) return;
    const controller = new AbortController();
    refreshRequest.current = controller;
    const timer = window.setTimeout(async () => {
      // Round-robin only over rows the user has loaded, with at most five GETs per tick.
      const active = snapshot.scans.filter(isActive);
      const start = activeOffset.current % active.length;
      const batch = Array.from({ length: Math.min(ACTIVE_BATCH_SIZE, active.length) }, (_, index) => active[(start + index) % active.length]);
      activeOffset.current = (start + batch.length) % active.length;
      setRefreshPending(true);
      try {
        const updates = await Promise.all(batch.map(async scan => {
          const incoming = await read(client, [...baseKey, generation.current, 'active', scan.scanId], controller,
            signal => transport.get(scan.scanId, signal));
          if (incoming.scanId !== scan.scanId || incoming.digest !== undefined && incoming.digest !== scan.digest ||
              incoming.platform !== undefined && incoming.platform !== scan.platform) throw new ScanListIdentityError();
          return { ...scan, ...incoming, targetLabel: scan.targetLabel };
        }));
        controller.signal.throwIfAborted();
        const current = confirmed.current;
        if (current !== snapshot) return;
        const byId = new Map(updates.map(scan => [scan.scanId, scan]));
        const next = { ...current, scans: current.scans.map(scan => byId.get(scan.scanId) ?? scan) };
        confirmed.current = next;
        setSnapshot(next);
      } catch (failure) {
        if (!controller.signal.aborted) {
          controller.abort();
          const problem = failure instanceof Error ? failure : new Error('Не удалось обновить проверки');
          if (problem instanceof ScanAccessError || problem instanceof ScanListIdentityError) setError(problem);
          else setRefreshError(problem);
        }
      } finally {
        if (refreshRequest.current === controller) setRefreshPending(false);
      }
    }, ACTIVE_REFRESH_MS);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
      if (refreshRequest.current === controller) refreshRequest.current = null;
    };
  }, [baseKey, client, demo, error, pending, refreshError, snapshot, transport]);

  return {
    snapshot, pending, error, refreshError, refreshPending,
    reload: () => void load(),
    next: () => { if (confirmed.current?.nextCursor) void load(confirmed.current.nextCursor); },
    retryRefresh: () => setRefreshError(null),
  };
}
