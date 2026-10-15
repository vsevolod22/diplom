import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ScanAccessError } from '@/shared/api/scans/httpScanTransport';
import { ReportCursorResetError, ReportQueryError, ReportViewContractError } from '@/shared/api/scans/reportView';
import { CveReportContractError } from '@/shared/api/scans/cveDbMetadata';
import { Alert, Button } from '@/shared/ui/scan-primitives';

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
  label: string;
  enabled: boolean;
  waiting: string;
  load: (cursor: string | undefined, signal: AbortSignal) => Promise<T>;
  describe: (data: T) => PageDescription;
  controls?: (pending: boolean) => ReactNode;
  children: (data: T) => ReactNode;
};

export function CursorReportPager<T>(props: Props<T>) {
  // A new scope/status identity destroys confirmed data, cursor history and pending work.
  return <PagerSession key={props.reportKey} {...props} />;
}

function PagerSession<T>({ label, enabled, waiting, load, describe, controls, children }: Props<T>) {
  const [snapshot, setSnapshot] = useState<Snapshot<T> | null>(null);
  const confirmed = useRef<Snapshot<T> | null>(null);
  const displayed = useRef<Snapshot<T> | null>(null);
  const [historyInvalid, setHistoryInvalid] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const [denied, setDenied] = useState(false);
  const [attempt, setAttempt] = useState<Attempt>({ cursor: undefined, index: 0, start: 0 });
  const request = useRef<AbortController | null>(null);

  const fetchPage = useCallback(
    async (target: Attempt) => {
      if (request.current || !enabled) return;
      const controller = new AbortController();
      request.current = controller;
      setPending(true);
      setError('');
      setAttempt(target);
      try {
        const data = await load(target.cursor, controller.signal);
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
        const earlierIds = new Set(earlierEntries.flatMap((entry) => entry.rowIds));
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
        if (controller.signal.aborted) return;
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
            'Содержимое посещённой страницы изменилось при прежней идентичности отчёта. История cursors сброшена. Показана последняя подтверждённая страница, а не несовместимый ответ; повтор начинается с первой страницы.',
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
                ? 'Исправьте фильтры отчёта. Прежние данные и cursors сброшены; повтор начинается с первой страницы.'
                : 'Идентичность или версия отчёта изменилась. Прежние данные и cursors сброшены.',
          );
        } else {
          setError(
            `Не удалось подтвердить страницу ${label}. ${
              displayed.current
                ? 'Показана предыдущая подтверждённая страница, а не результат неудавшегося перехода.'
                : 'Данные и число строк неизвестны.'
            }${displayed.current && !confirmed.current ? ' История cursors сброшена; повтор начинается с первой страницы.' : ''}`,
          );
        }
      } finally {
        if (!controller.signal.aborted) {
          request.current = null;
          setPending(false);
        }
      }
    },
    [enabled, load, describe, label],
  );

  useEffect(() => {
    void fetchPage({ cursor: undefined, index: 0, start: 0 });
    return () => {
      request.current?.abort();
      request.current = null;
    };
  }, [fetchPage]);

  const page = snapshot?.description.checked ? snapshot : null;
  const previous = page && !historyInvalid && page.index > 0 ? page.entries[page.index - 1] : null;
  const nextCursor = page?.description.nextCursor ?? null;
  const navigable = !!page && page.description.rowIds.length > 0 && (page.index > 0 || nextCursor !== null);
  const navigation = (position: 'top' | 'bottom') => navigable ? (
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
                {page.description.wholeTotal !== undefined ? <span>{page.description.wholeTotal === null ? `Полный итог ${label} неизвестен` : `Полный итог ${label}: ${page.description.wholeTotal}`}</span> : null}
              </>
            ) : (
              <span>Число {label} неизвестно до подтверждения выполненной проверки.</span>
            )}
            {historyInvalid ? (
              <span>
                Сохранён прежний подтверждённый снимок; актуальность повторного ответа не подтверждена.
              </span>
            ) : null}
            {pending ? <span>Загружаем {label}… Номер и диапазон ещё не изменены.</span> : null}
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
          {navigable ? <p className="scan-a1__muted scan-report-pages__note">
            Только последовательные страницы API. Общего числа страниц и перехода к произвольной странице нет.
          </p> : null}
        </>
      )}
    </div>
  );
}
