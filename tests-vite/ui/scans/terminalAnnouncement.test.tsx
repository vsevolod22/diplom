import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { StrictMode } from 'react';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LiveScanContext, type LiveContext } from '@/features/scans/liveScanContext';
import { ScanStatusAnnouncement } from '@/features/scans/ScanStatusAnnouncement';
import { stateLabels } from '@/features/scans/scanStateLabels';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { ScanAccessError, ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import type { ScanStatus, ScanTransport } from '@/shared/api/scans/scanTransport';

const terminalStates = ['completed', 'partial', 'failed', 'cancelled'] as const;
const clients: QueryClient[] = [];
const initial: ScanStatus = {
  scanId: 'announcement-a',
  state: 'running',
  stage: 'secret',
  percent: null,
  imageReference: 'library/alpine:synthetic-announcement',
};
const selector = '.scan-a1-detail > [aria-live="polite"][aria-atomic="true"]';
const announcement = () => document.querySelector<HTMLElement>(selector);

beforeEach(() => {
  vi.stubGlobal(
    'IntersectionObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  // All I/O is synthetic, including optional read-only AI-panel probes at terminal state.
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('{}', { status: 503 })),
  );
});
afterEach(() => {
  cleanup();
  clients.splice(0).forEach((client) => client.clear());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function mount(status: ScanStatus = initial, events = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
  clients.push(client);
  const get = vi.fn<ScanTransport['get']>().mockResolvedValue(status);
  const subscribe = vi.fn<NonNullable<ScanTransport['subscribeEvents']>>(() => vi.fn());
  const transport: ScanTransport = {
    ...unavailableScanTransport,
    kind: 'live',
    get,
    capabilities: { list: true, create: false, cancel: false, events },
    subscribeEvents: subscribe,
  };
  const scope: LiveContext['scope'] = ['live-scans', 1, 'synthetic-alice'];
  const content = (currentScope = scope, visible = true) => (
    <StrictMode>
      <QueryClientProvider client={client}>
        <LiveScanContext.Provider value={{ scope: currentScope, transport }}>
          <MemoryRouter initialEntries={[`/scans/${status.scanId}`]}>
            <Link to="/scans/announcement-b">Другой синтетический скан</Link>
            <Routes>
              <Route path="/scans/:scanId" element={visible ? <ScanDetailPage /> : null} />
            </Routes>
          </MemoryRouter>
        </LiveScanContext.Provider>
      </QueryClientProvider>
    </StrictMode>
  );
  return {
    ...render(content()),
    client,
    get,
    subscribe,
    scope,
    content,
    key: [...scope, 'scan', status.scanId],
  };
}

function recordUpdates(region: HTMLElement) {
  const updates: string[] = [];
  const observer = new MutationObserver((records) => {
    records.forEach(() => updates.push(region.textContent ?? ''));
  });
  observer.observe(region, { childList: true, characterData: true, subtree: true });
  return { updates, disconnect: () => observer.disconnect() };
}

async function expectReady() {
  await screen.findByLabelText('Показать находки');
  await waitFor(() => expect(announcement()).not.toBeNull());
  return announcement()!;
}

async function refetch(view: ReturnType<typeof mount>) {
  await act(async () => {
    await view.client.refetchQueries({ queryKey: view.key, exact: true });
    // QueryObserver batches notifications on a timer after the GET promise settles.
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

describe('stable terminal live region on the real detail page', () => {
  it.each(terminalStates)(
    'announces running → %s once without remount, focus/scroll change or moving technical details above findings',
    async (state) => {
      const view = mount();
      const region = await expectReady();
      expect(region).toHaveTextContent('');
      expect(region).toHaveClass('sr-only');
      const select = screen.getByLabelText('Показать находки');
      select.focus();
      const scroll = window.scrollY;
      const changes = recordUpdates(region);
      view.get.mockResolvedValue({ ...initial, state, stage: 'report' });
      await refetch(view);
      const message = `Итог скана: ${stateLabels[state]}`;
      await waitFor(() => expect(region.textContent).toBe(message));
      expect(announcement()).toBe(region);
      expect(region.closest('details')).toBeNull();
      const findings = screen.getByRole('heading', { name: 'Находки и исправления' });
      const technical = screen.getByText('Подробности · ход завершённой проверки').closest('details')!;
      expect(technical.open).toBe(false);
      expect(findings.compareDocumentPosition(technical) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      for (let i = 0; i < 3; i++) {
        view.get.mockResolvedValue({ ...initial, state, stage: `terminal-metadata-${i}`, percent: i });
        await refetch(view);
      }
      expect(changes.updates).toEqual([message]);
      changes.disconnect();
      expect(announcement()).toBe(region);
      expect(region.textContent).toBe(message);
      expect(document.activeElement).toBe(select);
      expect(window.scrollY).toBe(scroll);
      expect(vi.mocked(fetch).mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(
        true,
      );
    },
  );

  it.each(terminalStates)(
    'keeps an initial %s snapshot and its same-scan page remount quiet',
    async (state) => {
      const status = { ...initial, state, stage: 'report' };
      const view = mount(status);
      const first = await expectReady();
      expect(first.textContent).toBe('');
      view.get.mockResolvedValue({ ...status, stage: 'terminal-metadata' });
      await refetch(view);
      expect(first.textContent).toBe('');
      view.rerender(view.content(view.scope, false));
      expect(announcement()).toBeNull();
      view.rerender(view.content());
      const second = await expectReady();
      expect(second).not.toBe(first);
      expect(second.textContent).toBe('');
    },
  );

  it.each([
    ['owner', ['live-scans', 1, 'synthetic-bob']],
    ['session generation', ['live-scans', 2, 'synthetic-alice']],
  ] as const)(
    'clears prior text on %s change even when the new scope uses the same scan ID',
    async (_kind, nextScope) => {
      const view = mount();
      const first = await expectReady();
      view.get.mockResolvedValue({ ...initial, stage: 'report' });
      await refetch(view);
      expect(first.textContent).toBe('Этап скана: report');
      let finish!: (status: ScanStatus) => void;
      view.get.mockReturnValue(
        new Promise((resolve) => {
          finish = resolve;
        }),
      );
      view.rerender(view.content(nextScope));
      expect(first.isConnected).toBe(false);
      expect(announcement()).toBeNull();
      expect(screen.queryByText('Этап скана: report')).toBeNull();
      act(() => view.client.setQueryData(view.key, { ...initial, state: 'failed' }));
      expect(announcement()).toBeNull();
      await act(async () => {
        finish({ ...initial, state: 'completed', stage: 'report' });
      });
      const next = await expectReady();
      expect(next.textContent).toBe('');
      expect(next).not.toBe(first);
    },
  );

  it('clears the old scan announcement immediately on route change and ignores its late cache updates', async () => {
    const view = mount();
    const first = await expectReady();
    view.get.mockResolvedValue({ ...initial, stage: 'report' });
    await refetch(view);
    expect(first.textContent).toBe('Этап скана: report');
    let finish!: (status: ScanStatus) => void;
    view.get.mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }),
    );
    fireEvent.click(screen.getByRole('link', { name: 'Другой синтетический скан' }));
    expect(first.isConnected).toBe(false);
    expect(announcement()).toBeNull();
    act(() => view.client.setQueryData(view.key, { ...initial, state: 'partial' }));
    expect(announcement()).toBeNull();
    await act(async () => {
      finish({ ...initial, scanId: 'announcement-b', state: 'partial' });
    });
    expect((await expectReady()).textContent).toBe('');
  });

  it('clears a prior stage while status is stale, then keeps the recovered initial terminal snapshot quiet', async () => {
    const view = mount();
    const first = await expectReady();
    view.get.mockResolvedValue({ ...initial, stage: 'report' });
    await refetch(view);
    expect(first.textContent).toBe('Этап скана: report');
    view.get.mockRejectedValue(new ScanHttpError(503, 'SCANNER_UNAVAILABLE'));
    await refetch(view);
    expect(screen.getByText(/Показан последний подтверждённый снимок/)).toBeTruthy();
    expect(announcement()).toBeNull();
    expect(first.isConnected).toBe(false);
    expect(screen.queryByText('Этап скана: report')).toBeNull();
    view.get.mockResolvedValue({ ...initial, state: 'partial', stage: 'report' });
    await refetch(view);
    expect((await expectReady()).textContent).toBe('');
  });

  it.each([401, 403] as const)(
    'removes text after access failure %s and never announces retained cache data',
    async (code) => {
      const view = mount();
      const first = await expectReady();
      view.get.mockResolvedValue({ ...initial, stage: 'report' });
      await refetch(view);
      expect(first.textContent).toBe('Этап скана: report');
      view.get.mockRejectedValue(new ScanAccessError(code));
      await refetch(view);
      expect(announcement()).toBeNull();
      expect(first.isConnected).toBe(false);
      expect(screen.queryByText('Этап скана: report')).toBeNull();
      act(() => view.client.setQueryData(view.key, { ...initial, state: 'completed' }));
      expect(announcement()).toBeNull();
    },
  );

  it('does not announce terminal state from SSE/reconnect hints or pending GET; only a confirmed transition changes the region', async () => {
    const view = mount(initial, true);
    const region = await expectReady();
    await waitFor(() => expect(view.subscribe).toHaveBeenCalled());
    const [, hint, failed, opened] = view.subscribe.mock.calls.at(-1)!;
    const changes = recordUpdates(region);
    let finish!: (status: ScanStatus) => void;
    view.get.mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }),
    );
    const reads = view.get.mock.calls.length;
    act(() => {
      failed();
      opened();
      hint();
      hint();
    });
    expect(region.textContent).toBe('');
    expect(announcement()).toBe(region);
    await waitFor(() => expect(view.get.mock.calls.length).toBe(reads + 1), { timeout: 1800 });
    expect(region.textContent).toBe('');
    await act(async () => {
      finish({ ...initial, state: 'cancelled', stage: 'report' });
    });
    await waitFor(() => expect(region.textContent).toBe('Итог скана: Отменён'));
    act(() => {
      opened();
      hint();
      failed();
    });
    expect(changes.updates).toEqual(['Итог скана: Отменён']);
    changes.disconnect();
    expect(announcement()).toBe(region);
  });
});

describe('announcer snapshot transition boundaries', () => {
  it.each(['queued', 'cancelling'] as const)(
    'announces %s → terminal once, preferring the terminal message over the changed stage',
    (state) => {
      const view = render(<ScanStatusAnnouncement scan={{ ...initial, state }} />);
      const region = document.querySelector('[aria-live="polite"]')!;
      expect(region.textContent).toBe('');
      view.rerender(<ScanStatusAnnouncement scan={{ ...initial, state: 'cancelled', stage: 'report' }} />);
      expect(region.textContent).toBe('Итог скана: Отменён');
      view.rerender(
        <ScanStatusAnnouncement scan={{ ...initial, state: 'cancelled', stage: 'metadata-only' }} />,
      );
      expect(region.textContent).toBe('Итог скана: Отменён');
    },
  );
});
