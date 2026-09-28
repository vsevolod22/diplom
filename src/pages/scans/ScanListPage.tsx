import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { ScanShell } from '@/features/scans/ScanShell';
import { stateLabels } from '@/features/scans/scanStateLabels';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';
import { Alert, Badge, Card } from '@/shared/ui/scan-primitives';

const stateTone: Record<ScanStatus['state'], 'neutral' | 'info' | 'warning' | 'danger'> = {
  queued: 'neutral',
  running: 'info',
  cancelling: 'warning',
  completed: 'neutral',
  partial: 'warning',
  failed: 'danger',
  cancelled: 'neutral',
};

export function ScanListPage({ demo = false }: { demo?: boolean }) {
  const transport = demo ? fixtureScanTransport : unavailableScanTransport;
  const list = useQuery({
    queryKey: ['scans', transport.kind, 'list'],
    queryFn: ({ signal }) => transport.list(signal),
    enabled: transport.capabilities.list,
    retry: false,
  });
  return (
    <ScanShell demo={demo}>
      <section aria-labelledby="scan-list" className="min-w-0 space-y-5">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div className="space-y-1">
            <p className="text-xs font-bold uppercase tracking-widest text-indigo-800">Обзор / сканы</p>
            <h2 id="scan-list" className="text-2xl font-semibold tracking-tight sm:text-3xl">
              Список сканов
            </h2>
          </div>
          {demo ? <Badge tone="warning">Только фикстуры</Badge> : null}
        </div>
        {!transport.capabilities.list ? (
          <Alert role="status" tone="neutral" className="border-slate-300 bg-white text-slate-800">
            <strong className="block">
              Список недоступен: GET /api/v1/scans и защищённый браузерный доступ ещё не реализованы.
            </strong>
            <span className="mt-1 block text-sm">Отсутствие списка не означает «сканов нет».</span>
          </Alert>
        ) : null}
        {list.isPending && transport.capabilities.list ? (
          <p className="text-slate-600">Загружаем список…</p>
        ) : null}
        {list.isError ? (
          <Alert role="alert" tone="danger" className="border-red-300 bg-red-50 text-red-900">
            Не удалось загрузить список. Неизвестно, есть ли сканы.
          </Alert>
        ) : null}
        {list.isSuccess && list.data.length === 0 ? (
          <Card className="p-6 text-slate-700">Сканов нет (успешный ответ списка).</Card>
        ) : null}
        {list.isSuccess ? (
          <ul className="grid min-w-0 gap-4 md:grid-cols-2">
            {list.data.map((scan) => (
              <li key={scan.scanId} className="min-w-0">
                <Card className="flex h-full min-w-0 flex-col gap-5 p-5 sm:p-6">
                  <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <p className="mb-2 text-xs font-bold uppercase tracking-widest text-slate-500">
                        Цель сканирования
                      </p>
                      <h3 className="min-w-0 break-words text-lg font-semibold leading-snug">
                        <Link
                          className="text-indigo-900 underline decoration-indigo-300 underline-offset-4 hover:decoration-indigo-800"
                          to={`${demo ? '/demo' : ''}/scans/${encodeURIComponent(scan.scanId)}`}
                        >
                          {scan.targetLabel}
                        </Link>
                      </h3>
                    </div>
                    <Badge tone={stateTone[scan.state]}>{stateLabels[scan.state]}</Badge>
                  </div>
                  <div className="mt-auto grid gap-3 border-t border-slate-200 pt-4 text-sm text-slate-700 sm:grid-cols-2">
                    <div>
                      <p>Статус: {stateLabels[scan.state]}</p>
                      <p>Этап: {scan.stage || 'не предоставлен'}</p>
                    </div>
                    <p>Прогресс: {scan.percent == null ? 'неизвестен' : `${scan.percent}%`}</p>
                  </div>
                  {demo ? (
                    <p className="text-xs font-medium text-amber-900">
                      Вымышленные данные · не результат реальной проверки
                    </p>
                  ) : null}
                </Card>
              </li>
            ))}
          </ul>
        ) : null}
      </section>
    </ScanShell>
  );
}
