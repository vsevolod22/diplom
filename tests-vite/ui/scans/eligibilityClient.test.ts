import { afterEach, describe, expect, it, vi } from 'vitest';
import { EligibilityClient } from '@/shared/api/scans/eligibilityClient';

function pendingFetch() {
  const reads: Array<{ checks: string; signal: AbortSignal; finish: (response: Response) => void }> = [];
  vi.stubGlobal('fetch', vi.fn((_path: string, init: RequestInit) => new Promise<Response>((resolve, reject) => {
    const signal = init.signal as AbortSignal;
    signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
    reads.push({ checks: JSON.parse(String(init.body)).checks.join(','), signal, finish: resolve });
  })));
  return reads;
}
const response = () => new Response(JSON.stringify({ eligible: true }));
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('TASK35 eligibility consumers', () => {
  it('invalidates a consumer without aborting the active read shared by another consumer', async () => {
    const reads = pendingFetch();
    const client = new EligibilityClient(() => true, vi.fn());
    let current = true;
    const first = client.request('image', ['secret'], false, () => current);
    const shared = client.request('image', ['secret']);
    current = false;
    expect(reads).toHaveLength(1);
    expect(reads[0].signal.aborted).toBe(false);
    reads[0].finish(response());
    await expect(shared).resolves.toEqual({ eligible: true });
    await first; // Reply fences belong to consumers; shared work is allowed to finish.
    expect(reads[0].signal.aborted).toBe(false);
  });

  it('skips obsolete hints and stale preflight before network I/O; fresh reads remain distinct FIFO', async () => {
    const reads = pendingFetch();
    const client = new EligibilityClient(() => true, vi.fn());
    const active = client.request('image', ['secret']);
    let current = true;
    const obsolete = client.request('image', ['sbom'], false, () => current).catch(error => error);
    const staleSubmit = client.request('image', ['vuln'], true, () => current).catch(error => error);
    const fresh1 = client.request('image', ['secret'], true);
    const fresh2 = client.request('image', ['vuln'], true);
    current = false;
    reads[0].finish(response());
    await active;
    expect(await obsolete).toMatchObject({ name: 'AbortError' });
    expect(await staleSubmit).toMatchObject({ name: 'AbortError' });
    expect(reads.map(read => read.checks)).toEqual(['secret', 'secret']);
    reads[1].finish(response());
    await fresh1;
    expect(reads.map(read => read.checks)).toEqual(['secret', 'secret', 'vuln']);
    reads[2].finish(response());
    await fresh2;
  });

  it('rejects queued work after the owning session changes', async () => {
    const reads = pendingFetch();
    let current = true;
    const client = new EligibilityClient(() => current, vi.fn());
    const active = client.request('image', ['secret']).catch(error => error);
    const queued = client.request('image', ['sbom']).catch(error => error);
    current = false;
    reads[0].finish(response());
    expect(await active).toMatchObject({ message: 'Сессия изменилась' });
    expect(await queued).toMatchObject({ message: 'Сессия изменилась' });
    expect(reads).toHaveLength(1);
  });

  for (const abort of ['retire', 'timeout'] as const) it(`aborts active work on ${abort} and never sends an invalid queued consumer`, async () => {
    vi.useFakeTimers();
    const reads = pendingFetch();
    const client = new EligibilityClient(() => true, vi.fn());
    const active = client.request('image', ['secret']).catch(error => error);
    let current = true;
    const queued = client.request('image', ['sbom'], false, () => current).catch(error => error);
    current = false;
    if (abort === 'retire') client.retire();
    else await vi.advanceTimersByTimeAsync(10_000);
    expect(await active).toMatchObject({ name: 'AbortError' });
    expect(await queued).toMatchObject({ name: 'AbortError' });
    expect(reads[0].signal.aborted).toBe(true);
    expect(reads).toHaveLength(1);
  });
});
