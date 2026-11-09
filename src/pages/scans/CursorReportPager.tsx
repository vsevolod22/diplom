import { useCallback, useContext, useEffect, useRef, useState } from 'react';
import { hashKey, isCancelledError, QueryClientContext } from '@tanstack/react-query';
import type { QueryKey } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { ScanAccessError } from '@/shared/api/scans/httpScanTransport';
import { ReportCursorResetError, ReportQueryError, ReportViewContractError } from '@/shared/api/scans/reportView';
import { CveReportContractError } from '@/shared/api/scans/cveDbMetadata';
import { Alert, Button } from '@/shared/ui/scan-primitives';
import { ChevronLeft, ChevronRight } from 'lucide-react';

export type PageDescription = {
  checked: boolean;
  identity: string;
  rowIds: string[];
  rowFingerprint: string;
  total: number | null;
  wholeTotal?: number | null;
  offset?: number;
  nextCursor: string | null;
};
export class ReportIdentityError extends Error {}
class ReportReplayError extends ReportIdentityError {}

type Entry = {
  cursor: string | undefined;
  start: number;
  rowIds: string[];
  rowFingerprint: string;
  nextCursor: string | null;
};
type Snapshot<T> = { data: T; description: PageDescription; index: number; start: number; entries: Entry[] };
type Attempt = { cursor: string | undefined; index: number; start: number };
type Props<T> = {
  reportKey: string;
  queryKey?: QueryKey;
  label: string;
  enabled: boolean;
  waiting: string;
  load: (cursor: string | undefined, signal: AbortSignal) => Promise<T>;
  describe: (data: T) => PageDescription;
  controls?: (pending: boolean) => ReactNode;
  numberedPageSize?: number;
  children: (data: T) => ReactNode;
};

export function CursorReportPager<T>(props: Props<T>) {
  // A new scope/status identity destroys confirmed data, cursor history and pending work.
  return <PagerSession key={JSON.stringify([props.reportKey, hashKey(props.queryKey ?? [props.reportKey])])} {...props} />;
}

function PagerSession<T>({ reportKey, queryKey, label, enabled, waiting, load, describe, controls, children, numberedPageSize }: Props<T>) {
  // Standalone renderers may omit the provider; application reports use its existing client.
  const queryClient = useContext(QueryClientContext);
  // The keyed session remounts whenever this query identity changes.
  const baseQueryKey = useRef(queryKey ?? [reportKey]).current;
  const [snapshot, setSnapshot] = useState<Snapshot<T> | null>(null);
  const confirmed = useRef<Snapshot<T> | null>(null);
  const displayed = useRef<Snapshot<T> | null>(null);
  const [historyInvalid, setHistoryInvalid] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const [denied, setDenied] = useState(false);
  const [attempt, setAttempt] = useState<Attempt>({ cursor: undefined, index: 0, start: 0 });
  const request = useRef<{ controller: AbortController; queryKey: QueryKey } | null>(null);

  const fetchPage = useCallback(
    async (target: Attempt) => {
      if (request.current || !enabled) return;
      const controller = new AbortController();
      const pageQueryKey = [...baseQueryKey, target.cursor ?? null];
      const active = { controller, queryKey: pageQueryKey };
      request.current = active;
      let querySignal: AbortSignal | undefined;
      const abort = () => controller.abort();
      setPending(true);
      setError('');
      setAttempt(target);
      try {
        const data = queryClient ? await queryClient.fetchQuery({
          queryKey: pageQueryKey,
          queryFn: async ({ signal }) => {
            querySignal = signal;
            signal.addEventListener('abort', abort, { once: true });
            if (signal.aborted) abort();
            const page = await load(target.cursor, controller.signal);
            controller.signal.throwIfAborted();
            return page;
          },
          // Revisits must reach the backend to detect changed content under the same identity.
          staleTime: 0,
          gcTime: 0,
          retry: false,
          networkMode: 'always',
          structuralSharing: false,
        }) : await load(target.cursor, controller.signal);
        if (controller.signal.aborted) return;
        const description = describe(data);
        const previous = confirmed.current;
        if (description.offset !== undefined && description.offset !== target.start) throw new ReportViewContractError();
        if (
          previous &&
          (description.identity !== previous.description.identity ||
            description.total !== previous.description.total ||
            !description.checked)
        ) {
          throw new ReportIdentityError();
        }
        const visited = previous?.entries[target.index];
        if (
          visited &&
          (visited.cursor !== target.cursor ||
            visited.start !== target.start ||
            visited.nextCursor !== description.nextCursor ||
            JSON.stringify(visited.rowIds) !== JSON.stringify(description.rowIds))
        )
          throw new ReportIdentityError();
        if (visited && visited.rowFingerprint !== description.rowFingerprint) throw new ReportReplayError();
        // Back changes the displayed index, not the fingerprints of visited forward pages.
        const entries = previous?.entries.slice() ?? [];
        const earlierEntries = entries.slice(0, target.index);
        const ids = new Set(description.rowIds);
        const checkedEntries = numberedPageSize ? entries.filter((_, index) => index !== target.index) : earlierEntries;
        const earlierIds = new Set(checkedEntries.flatMap((entry) => entry.rowIds));
        const end = target.start + description.rowIds.length;
        const inconsistentTotal =
          description.checked &&
          description.total !== null &&
          (description.nextCursor === null ? end !== description.total : end >= description.total);
        if (
          ids.size !== description.rowIds.length ||
          description.rowIds.some((id) => earlierIds.has(id)) ||
          (description.nextCursor !== null &&
            (description.rowIds.length === 0 ||
              description.nextCursor === target.cursor ||
              earlierEntries.some((entry) => entry.cursor === description.nextCursor))) ||
          inconsistentTotal
        ) {
          if (description.offset !== undefined) throw new ReportViewContractError();
          throw new Error('Invalid pagination');
        }
        entries[target.index] = {
          cursor: target.cursor,
          start: target.start,
          rowIds: description.rowIds,
          rowFingerprint: description.rowFingerprint,
          nextCursor: description.nextCursor,
        };
        const next = { data, description, index: target.index, start: target.start, entries };
        confirmed.current = next;
        displayed.current = next;
        setSnapshot(next);
        setHistoryInvalid(false);
        setDenied(false);
      } catch (failure) {
        if (controller.signal.aborted || isCancelledError(failure)) return;
        const accessLost =
          failure instanceof ScanAccessError ||
          (failure instanceof Error &&
            (failure.message === 'Скан недоступен' || failure.message.startsWith('Сессия изменилась:')));
        if (!accessLost && failure instanceof ReportReplayError) {
          // Same scope/metadata: keep only the last confirmed view, not the rejected payload/history.
          const retained = displayed.current ? { ...displayed.current, entries: [] } : null;
          confirmed.current = null;
          displayed.current = retained;
          setSnapshot(retained);
          setHistoryInvalid(true);
          setAttempt({ cursor: undefined, index: 0, start: 0 });
          setError(
            'Содержимое отчёта изменилось. Показана предыдущая подтверждённая страница, её актуальность неизвестна. Повторная загрузка начнётся с первой страницы.',
          );
        } else if (accessLost || failure instanceof ReportIdentityError || failure instanceof CveReportContractError || failure instanceof ReportViewContractError || failure instanceof ReportCursorResetError) {
          confirmed.current = null;
          displayed.current = null;
          setHistoryInvalid(false);
          setSnapshot(null);
          setAttempt({ cursor: undefined, index: 0, start: 0 });
          setDenied(accessLost);
          setError(
            accessLost
              ? 'Доступ к отчёту утрачен. Подтвердите сессию заново.'
              : failure instanceof ReportQueryError
                ? 'Исправьте фильтры отчёта. Прежние данные скрыты; повторная загрузка начнётся с первой страницы.'
                : 'Не удалось подтвердить, что ответ относится к текущему отчёту. Прежние данные скрыты; повторите загрузку с первой страницы.',
          );
        } else {
          setError(
            `Не удалось подтвердить страницу ${label}. ${
              displayed.current
                ? 'Показана предыдущая подтверждённая страница, а не результат неудавшегося перехода.'
                : 'Данные и число строк неизвестны.'
            }${displayed.current && !confirmed.current ? ' Повторная загрузка начнётся с первой страницы.' : ''}`,
          );
        }
      } finally {
        querySignal?.removeEventListener('abort', abort);
        if (request.current === active) {
          // Only the imperative, validated snapshot survives; no private rows persist in QueryCache.
          queryClient?.removeQueries({ queryKey: pageQueryKey, exact: true });
          request.current = null;
          setPending(false);
        }
      }
    },
    [enabled, load, describe, label, queryClient, baseQueryKey, numberedPageSize],
  );

  useEffect(() => {
    void fetchPage({ cursor: undefined, index: 0, start: 0 });
    return () => {
      const active = request.current;
      request.current = null;
      if (active) {
        active.controller.abort();
        void queryClient?.cancelQueries({ queryKey: active.queryKey, exact: true });
        queryClient?.removeQueries({ queryKey: active.queryKey, exact: true });
      }
    };
  }, [fetchPage, queryClient]);

  const page = snapshot?.description.checked ? snapshot : null;
  const previous = page && !historyInvalid && page.index > 0 ? page.entries[page.index - 1] : null;
  const nextCursor = page?.description.nextCursor ?? null;
  const navigable = !!page && page.description.rowIds.length > 0 && (page.index > 0 || nextCursor !== null);
  const pageCount = page && numberedPageSize && page.description.total !== null
    ? Math.ceil(page.description.total / numberedPageSize) : 0;
  function goToPage(index: number) {
    if (!page || !numberedPageSize || pending || historyInvalid || denied || index < 0 || index >= pageCount || index === page.index) return;
    const visited = page.entries[index];
    if (visited) { void fetchPage({ ...visited, index }); return; }
    if (index === 0) { void fetchPage({ cursor: undefined, index: 0, start: 0 }); return; }
    // Cursor offsets are coordinates, never authority. Keep the server-issued
    // query/snapshot hashes intact; the backend rechecks ownership and both hashes.
    const basis = page.entries[page.index]?.cursor ?? page.description.nextCursor;
    if (!basis || page.description.offset === undefined) return;
    try {
      const token = JSON.parse(atob(basis.replace(/-/g, '+').replace(/_/g, '/')));
      if (token.v !== 1 || !/^[a-f0-9]{64}$/.test(token.q) || !/^[a-f0-9]{64}$/.test(token.r)) return;
      const start = index * numberedPageSize;
      const cursor = btoa(JSON.stringify({ v: 1, q: token.q, r: token.r, o: start })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      void fetchPage({ cursor, index, start });
    } catch { /* A non-report-v1 cursor does not authorize arbitrary page jumps. */ }
  }
  const numberedNavigation = (position: 'top' | 'bottom') => {
    if (!page || !numberedPageSize || pageCount < 2 || page.description.offset === undefined) return null;
    const indexes = Array.from({ length: pageCount }, (_, index) => index)
      .filter(index => index === 0 || index === pageCount - 1 || Math.abs(index - page.index) <= 1);
    return <nav className="scan-report-numbered-pages" aria-label={`Пагинация ${label} · ${position === 'top' ? 'сверху' : 'снизу'}`}>
      <button type="button" aria-label="Предыдущая страница" disabled={pending || historyInvalid || denied || page.index === 0} onClick={() => goToPage(page.index - 1)}><ChevronLeft size={18} aria-hidden="true" /></button>
      {indexes.map((index, i) => <span key={index}>
        {i > 0 && index > indexes[i - 1] + 1 ? <span className="scan-report-page-gap" aria-hidden="true">…</span> : null}
        <button type="button" aria-label={`Страница ${index + 1}`} aria-current={index === page.index ? 'page' : undefined}
          disabled={pending || historyInvalid || denied} onClick={() => goToPage(index)}>{index + 1}</button>
      </span>)}
      <button type="button" aria-label="Следующая страница" disabled={pending || historyInvalid || denied || page.index === pageCount - 1} onClick={() => goToPage(page.index + 1)}><ChevronRight size={18} aria-hidden="true" /></button>
    </nav>;
  };
  const navigation = (position: 'top' | 'bottom') => numberedPageSize && page?.description.offset !== undefined ? numberedNavigation(position) : navigable ? (
    <nav className="scan-report-pages__controls" aria-label={`Пагинация ${label} · ${position === 'top' ? 'сверху' : 'снизу'}`}>
      <strong>Страницы {label}</strong>
      <Button type="button" variant="secondary" disabled={pending || historyInvalid || !previous || denied}
        onClick={() => previous && void fetchPage({ ...previous, index: (page?.index ?? 0) - 1 })}>
        Назад · {label}{position === 'top' ? ' · сверху' : ''}
      </Button>
      <Button type="button" variant="secondary" disabled={pending || historyInvalid || nextCursor === null || denied}
        onClick={() => page && nextCursor !== null && void fetchPage({ cursor: nextCursor, index: page.index + 1, start: page.start + page.description.rowIds.length })}>
        Далее · {label}{position === 'top' ? ' · сверху' : ''}
      </Button>
    </nav>
  ) : null;
  return (
    <div className="scan-report-pages" aria-busy={pending}>
      {controls?.(pending)}
      {!enabled ? (
        <p>{waiting}</p>
      ) : (
        <>
          <div className="scan-report-pages__status" role="status" aria-live="polite" aria-atomic="true">
            {page ? (
              <>
                <strong>Страница {page.index + 1}</strong>
                <span>
                  {page.description.rowIds.length
                    ? `Строки ${page.start + 1}–${page.start + page.description.rowIds.length}`
                    : 'На подтверждённой странице строк нет'}
                </span>
                <span>
                  {page.description.total !== null
                    ? `${page.description.wholeTotal !== undefined ? 'Совпадений во всём отчёте' : 'Подтверждённый итог'} ${label}: ${page.description.total}`
                    : `Итог ${label} неизвестен`}
                </span>
                {page.description.wholeTotal !== undefined && page.description.wholeTotal !== page.description.total ? <span>{page.description.wholeTotal === null ? `Полный итог ${label} неизвестен` : `Полный итог ${label}: ${page.description.wholeTotal}`}</span> : null}
              </>
            ) : (
              <span>Число {label} неизвестно до подтверждения выполненной проверки.</span>
            )}
            {historyInvalid ? (
              <span>
                Сохранён прежний подтверждённый снимок; актуальность повторного ответа не подтверждена.
              </span>
            ) : null}
            {pending ? <span>Загружаем {label}… {page ? 'Пока показана предыдущая страница.' : ''}</span> : null}
          </div>
          {error ? (
            <Alert tone="danger" role="alert">
              <p>{error}</p>
              {!denied ? (
                <Button
                  type="button"
                  variant="secondary"
                  disabled={pending}
                  onClick={() => void fetchPage(attempt)}
                >
                  Повторить загрузку {label}
                </Button>
              ) : null}
            </Alert>
          ) : null}
          {navigation('top')}
          {snapshot && !denied ? children(snapshot.data) : null}
          {navigation('bottom')}

        </>
      )}
    </div>
  );
}
