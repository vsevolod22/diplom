import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';
import { ScanShell, controlClass } from '@/features/scans/ScanShell';
import { ScanFilterSheet } from '@/features/scans/ScanFilterSheet';
import { ScanStatusAnnouncement } from '@/features/scans/ScanStatusAnnouncement';
import { stateLabels } from '@/features/scans/scanStateLabels';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import type { ScanCoverage, ScanStatus } from '@/shared/api/scans/scanTransport';
import { Alert, Badge, Button, Card } from '@/shared/ui/scan-primitives';

const coverageLabels: Record<ScanCoverage['status'], string> = {
  checked: 'Выполнено (не гарантия безопасности)',
  failed: 'Сбой · не проверено',
  unsupported: 'Не поддерживается',
  not_authorized: 'Нет разрешения',
  skipped: 'Пропущено',
};
const coverageTone: Record<ScanCoverage['status'], 'neutral' | 'info' | 'warning' | 'danger'> = {
  checked: 'info',
  failed: 'danger',
  unsupported: 'warning',
  not_authorized: 'warning',
  skipped: 'neutral',
};
const stateTone: Record<ScanStatus['state'], 'neutral' | 'info' | 'warning' | 'danger'> = {
  queued: 'neutral',
  running: 'info',
  cancelling: 'warning',
  completed: 'neutral',
  partial: 'warning',
  failed: 'danger',
  cancelled: 'neutral',
};

export function ScanDetailPage({ demo = false }: { demo?: boolean }) {
  const { scanId = '' } = useParams();
  const [filter, setFilter] = useState('all');
  const [cursor, setCursor] = useState<string | undefined>();
  const transport = demo ? fixtureScanTransport : unavailableScanTransport;
  const enabled = !!scanId && (demo || transport.capabilities.list);
  const scan = useQuery({
    queryKey: ['scan', transport.kind, scanId],
    queryFn: ({ signal }) => transport.get(scanId, signal),
    enabled,
    retry: false,
    refetchOnWindowFocus: !demo,
  });
  const report = useQuery({
    queryKey: ['scan-results', transport.kind, scanId, filter, cursor],
    queryFn: ({ signal }) => transport.results(scanId, cursor, signal),
    enabled: enabled && scan.isSuccess,
    retry: false,
  });
  const findings =
    report.data?.findings.filter((finding) => filter === 'all' || finding.category === filter) ?? [];
  const changeFilter = (value: string) => {
    setFilter(value);
    setCursor(undefined);
  };
  return (
    <ScanShell demo={demo}>
      <section className="min-w-0 space-y-6" aria-labelledby="scan-detail">
        <div className="min-w-0 space-y-2">
          <p className="text-xs font-bold uppercase tracking-widest text-indigo-800">Обзор / деталь</p>
          <h2 id="scan-detail" className="min-w-0 text-2xl font-semibold tracking-tight sm:text-3xl">
            Деталь скана{' '}
            <span className="block text-base font-normal text-slate-600 [overflow-wrap:anywhere]">
              {scanId}
            </span>
          </h2>
        </div>
        {!enabled ? (
          <Alert tone="neutral" className="border-slate-300 bg-white text-slate-800">
            Деталь недоступна без защищённой авторизованной сессии; scanId в адресе не подтверждает доступ.
          </Alert>
        ) : null}
        {scan.isPending && enabled ? <p className="text-slate-600">Загружаем снимок…</p> : null}
        {scan.isError ? (
          <Alert role="alert" tone="danger" className="border-red-300 bg-red-50 text-red-900">
            Не удалось получить данные скана. Его существование и доступность не подтверждены.
          </Alert>
        ) : null}
        {scan.data ? (
          <div className="grid min-w-0 items-start gap-4 lg:grid-cols-2">
            <Card className="min-w-0 space-y-5 p-5 sm:p-6">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="text-xs font-bold uppercase tracking-widest text-indigo-800">
                    01 / {demo ? 'демонстрационный снимок' : 'снимок GET'}
                  </p>
                  <h3 className="mt-1 text-lg font-semibold">Цель и состояние</h3>
                </div>
                <Badge tone={stateTone[scan.data.state]}>{stateLabels[scan.data.state]}</Badge>
              </div>
              <dl className="min-w-0 space-y-3 text-sm leading-relaxed">
                <div className="border-b border-slate-100 pb-3">
                  <dt className="font-semibold text-slate-600">Указанная цель</dt>
                  <dd className="[overflow-wrap:anywhere]">
                    Указанная цель: {scan.data.imageReference || 'не предоставлена сервером'}
                  </dd>
                </div>
                <div className="border-b border-slate-100 pb-3">
                  <dt className="font-semibold text-slate-600">Подтверждение цели</dt>
                  <dd className="[overflow-wrap:anywhere]">
                    Закреплённая цель:{' '}
                    {scan.data.digest && scan.data.platform
                      ? `${scan.data.digest} · ${scan.data.platform}`
                      : 'ожидаем подтверждения digest/platform от авторизованного GET status'}
                  </dd>
                </div>
              </dl>
              <ScanStatusAnnouncement scan={scan.data} />
              <div className="grid gap-2 rounded-xl bg-slate-50 p-4 text-sm text-slate-800 sm:grid-cols-2">
                <p>Статус: {stateLabels[scan.data.state]}</p>
                <p>Этап: {scan.data.stage || 'не предоставлен'}</p>
                <p>Прогресс: {scan.data.percent == null ? 'неизвестен' : `${scan.data.percent}%`}</p>
              </div>
              <p className="text-sm leading-relaxed text-slate-600">
                {demo
                  ? 'Состояние из локальной фикстуры; это не GET status и не live-поток.'
                  : 'Состояние только из GET snapshot; live SSE/replay не подтверждён.'}
              </p>
              <div className="space-y-2 border-t border-slate-200 pt-4">
                <Button variant="secondary" type="button" disabled title="Серверный API отмены не реализован">
                  Отмена недоступна
                </Button>
                <p className="text-sm text-slate-600">
                  Нет авторизованного cancel API. Неполные результаты не удаляются.
                </p>
              </div>
            </Card>
            <Card className="min-w-0 space-y-4 p-5 sm:p-6">
              <div>
                <p className="text-xs font-bold uppercase tracking-widest text-indigo-800">
                  02 / {demo ? 'демонстрационное покрытие' : 'область проверок'}
                </p>
                <h3 className="mt-1 text-lg font-semibold">Покрытие проверок</h3>
                <p className="mt-1 text-sm text-slate-600">
                  Исход каждой проверки отдельно от статуса скана.
                </p>
              </div>
              {report.data ? (
                <ul className="space-y-3">
                  {report.data.coverage.map((item) => (
                    <li
                      key={item.check}
                      className="min-w-0 space-y-2 rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm [overflow-wrap:anywhere]"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <strong>{item.check}</strong>
                        <Badge tone={coverageTone[item.status]}>{coverageLabels[item.status]}</Badge>
                      </div>
                      {item.reason ? <p className="text-slate-700">{item.reason}</p> : null}
                      {item.scannerVersion || item.dbVersion ? (
                        <p className="text-xs text-slate-600">
                          {item.scannerVersion ? `scanner ${item.scannerVersion}` : ''}
                          {item.scannerVersion && item.dbVersion ? ' · ' : ''}
                          {item.dbVersion ? `DB ${item.dbVersion}` : ''}
                        </p>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-slate-700">
                  Нет подтверждённого coverage; «0 проблем» недопустимо.
                </p>
              )}
            </Card>
          </div>
        ) : null}
        {scan.data ? (
          <Card className="min-w-0 space-y-5 p-5 sm:p-6">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="text-xs font-bold uppercase tracking-widest text-indigo-800">03 / результаты</p>
                <h3 className="mt-1 text-lg font-semibold">Находки</h3>
                <p className="mt-1 text-sm text-slate-600">
                  Фильтр действует только на загруженную страницу, не на весь отчёт.
                </p>
              </div>
              <ScanFilterSheet filter={filter} onFilterChange={changeFilter} />
            </div>
            <div className="hidden sm:block">
              <label htmlFor="finding-filter" className="mr-3 font-medium">
                Категория
              </label>
              <select
                id="finding-filter"
                className={controlClass}
                value={filter}
                onChange={(event) => changeFilter(event.target.value)}
              >
                <option value="all">Все на загруженной странице</option>
                <option value="secret">Secrets</option>
                <option value="vulnerability">CVE</option>
              </select>
            </div>
            <p className="text-sm text-slate-600">
              Категория: {filter === 'all' ? 'Все' : filter === 'secret' ? 'Secrets' : 'CVE'} (на загруженной
              странице)
            </p>
            {report.isPending ? <p>Загружаем результаты…</p> : null}
            {report.isError ? (
              <Alert role="alert" tone="danger" className="border-red-300 bg-red-50 text-red-900">
                Не удалось загрузить результаты; число находок неизвестно.
              </Alert>
            ) : null}
            {report.data && findings.length > 0 ? (
              <ul className="grid min-w-0 gap-3 md:grid-cols-2">
                {findings.map((finding) => (
                  <li
                    key={finding.findingId}
                    className="min-w-0 space-y-2 rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm [overflow-wrap:anywhere]"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="neutral">{finding.severity}</Badge>
                      <strong>
                        {finding.category} · {finding.ruleId}
                      </strong>
                    </div>
                    <p className="text-slate-600">ID: {finding.findingId}</p>
                  </li>
                ))}
              </ul>
            ) : null}
            {report.data && findings.length === 0 && filter !== 'all' ? (
              <Alert tone="neutral" className="border-slate-300 bg-slate-50 text-slate-800">
                Нет совпадений фильтра на загруженной странице. Это не означает отсутствие находок во всём
                отчёте.{' '}
                <button
                  type="button"
                  className="min-h-11 rounded text-indigo-800 underline underline-offset-4"
                  onClick={() => changeFilter('all')}
                >
                  Сбросить фильтр
                </button>
              </Alert>
            ) : null}
            {report.data &&
            findings.length === 0 &&
            filter === 'all' &&
            (report.data.nextCursor || cursor) ? (
              <p>На текущей странице находок нет; общий результат не подтверждён.</p>
            ) : null}
            {report.data &&
            findings.length === 0 &&
            filter === 'all' &&
            !report.data.nextCursor &&
            !cursor ? (
              <p>
                {report.data.coverage.some((item) => item.status === 'checked') &&
                !report.data.coverage.some((item) => item.status === 'failed')
                  ? '0 находок в выполненной проверенной области; другие области не исключены.'
                  : 'Нет подтверждённых находок: область не проверена полностью. Это не «0 CVE».'}
              </p>
            ) : null}
            {report.data?.nextCursor ? (
              <Button
                variant="secondary"
                type="button"
                onClick={() => setCursor(report.data.nextCursor ?? undefined)}
              >
                Следующая страница
              </Button>
            ) : null}
          </Card>
        ) : null}
      </section>
    </ScanShell>
  );
}
