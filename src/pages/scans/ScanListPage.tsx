import { useQuery } from '@tanstack/react-query';
import { ArrowUpRight, Layers3, ScanLine, ShieldAlert } from 'lucide-react';
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
      <section aria-labelledby="scan-list" className="min-w-0 space-y-8 pb-8">
        <div className="scan-experience-hero relative min-w-0 overflow-hidden rounded-[1.75rem] bg-[#17142a] px-5 py-7 text-white sm:px-9 sm:py-10 lg:px-12">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -right-14 -top-16 size-56 rounded-full border-[34px] border-[#c9ff54]/20 sm:size-72"
          />
          <div
            aria-hidden="true"
            className="pointer-events-none absolute bottom-0 right-0 h-24 w-1/2 bg-[linear-gradient(120deg,transparent,rgba(145,98,255,0.22))]"
          />
          <div className="relative flex min-w-0 flex-wrap items-start justify-between gap-6">
            <div className="min-w-0 flex-1">
              <p className="flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.22em] text-[#c9ff54]">
                <ScanLine size={16} aria-hidden="true" /> Обзор / сканы
              </p>
              <h2
                id="scan-list"
                className="mt-5 max-w-[12ch] text-[clamp(2.7rem,7vw,5.5rem)] font-black leading-[0.92] tracking-[-0.065em]"
              >
                Список <span className="text-[#c9ff54]">сканов</span>
              </h2>
              <p className="mt-6 max-w-xl text-sm leading-relaxed text-[#e1dff1] sm:text-base">
                Цель, состояние и ход проверки — без догадок о том, что осталось за пределами видимости.
              </p>
            </div>
            <div className="flex flex-col items-start gap-3 sm:items-end">
              <span
                aria-hidden="true"
                className="text-6xl font-black leading-none tracking-[-0.09em] text-[#c9ff54]/60 sm:text-8xl"
              >
                01
              </span>
              {demo ? <Badge tone="warning">Только фикстуры</Badge> : null}
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-end justify-between gap-3 border-b border-[#cbc7dc] pb-4">
          <div>
            <p className="text-[11px] font-black uppercase tracking-[0.2em] text-[#5535a0]">01 / Каталог</p>
            <p className="mt-1 text-sm text-slate-700">
              {demo ? 'Локальные демонстрационные записи' : 'Реальный режим недоступен'}
            </p>
          </div>
          <Layers3 size={27} className="text-[#5535a0]" aria-hidden="true" />
        </div>

        {!transport.capabilities.list ? (
          <Alert role="status" tone="neutral" className="border-slate-300 bg-white text-slate-800">
            <div className="flex min-w-0 items-start gap-4">
              <span
                aria-hidden="true"
                className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-[#eee8ff] text-[#5535a0]"
              >
                <ShieldAlert size={22} />
              </span>
              <div className="min-w-0">
                <p className="mb-2 text-[11px] font-black uppercase tracking-[0.18em] text-[#5535a0]">
                  Нет доступа / не пустой список
                </p>
                <strong className="block [overflow-wrap:anywhere]">
                  Список недоступен: GET /api/v1/scans и защищённый браузерный доступ ещё не реализованы.
                </strong>
                <span className="mt-2 block text-sm">Отсутствие списка не означает «сканов нет».</span>
              </div>
            </div>
          </Alert>
        ) : null}
        {list.isPending && transport.capabilities.list ? (
          <p role="status" className="border-l-4 border-[#5535a0] bg-white p-5 text-slate-700">
            Загружаем список…
          </p>
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
          <ul className="grid min-w-0 gap-5 md:grid-cols-2">
            {list.data.map((scan, index) => (
              <li key={scan.scanId} className="group min-w-0">
                <Card className="scan-demo-reveal flex h-full min-w-0 flex-col overflow-hidden">
                  <div className="flex min-w-0 items-start justify-between gap-3 border-b border-[#e3dff0] bg-[#f0ebff] px-5 py-4 sm:px-7">
                    <span
                      className="text-4xl font-black leading-none tracking-[-0.09em] text-[#5535a0]"
                      aria-hidden="true"
                    >
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    <Badge tone={stateTone[scan.state]}>{stateLabels[scan.state]}</Badge>
                  </div>
                  <div className="flex min-w-0 flex-1 flex-col gap-6 p-5 sm:p-7">
                    <div className="min-w-0">
                      <p className="mb-3 text-[11px] font-black uppercase tracking-[0.2em] text-[#5535a0]">
                        Цель сканирования
                      </p>
                      <h3 className="min-w-0 text-xl font-extrabold leading-tight tracking-tight sm:text-2xl">
                        <Link
                          className="inline-flex min-h-11 min-w-0 items-center gap-2 rounded-sm text-[#21153d] underline decoration-[#a68be8] decoration-2 underline-offset-4 transition-colors hover:text-[#5535a0] hover:decoration-[#5535a0] focus-visible:outline-3 focus-visible:outline-offset-4 focus-visible:outline-[#5535a0]"
                          to={`${demo ? '/demo' : ''}/scans/${encodeURIComponent(scan.scanId)}`}
                        >
                          <span className="min-w-0 [overflow-wrap:anywhere]">{scan.targetLabel}</span>
                          <ArrowUpRight
                            size={20}
                            className="shrink-0 text-[#5535a0] motion-safe:transition-transform motion-safe:group-hover:translate-x-0.5 motion-safe:group-hover:-translate-y-0.5"
                            aria-hidden="true"
                          />
                        </Link>
                      </h3>
                    </div>
                    <div className="mt-auto grid min-w-0 gap-3 border-t border-[#e3dff0] pt-5 text-sm text-slate-700 sm:grid-cols-2">
                      <div className="min-w-0 [overflow-wrap:anywhere]">
                        <p>Статус: {stateLabels[scan.state]}</p>
                        <p>Этап: {scan.stage || 'не предоставлен'}</p>
                      </div>
                      <p>Прогресс: {scan.percent == null ? 'неизвестен' : `${scan.percent}%`}</p>
                    </div>
                    {demo ? (
                      <p className="border-l-[3px] border-[#5535a0] pl-3 text-xs font-semibold leading-relaxed text-[#392368]">
                        Вымышленные данные · не результат реальной проверки
                      </p>
                    ) : null}
                  </div>
                </Card>
              </li>
            ))}
          </ul>
        ) : null}
      </section>
    </ScanShell>
  );
}
