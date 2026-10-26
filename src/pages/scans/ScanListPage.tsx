import { useQuery } from '@tanstack/react-query';
import { ArrowRight, ArrowUpRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { MagicCard } from '@/features/scans/MagicCard';
import { ScanShell } from '@/features/scans/ScanShell';
import { useLiveScanSession } from '@/features/scans/liveScanContext';
import { ScanScene } from '@/features/scans/ScanScene';
import { ScanProgressPanel } from '@/features/scans/ScanProgressPanel';
import { stateLabels } from '@/features/scans/scanStateLabels';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { ScanAccessError } from '@/shared/api/scans/httpScanTransport';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';
import { Alert, Badge } from '@/shared/ui/scan-primitives';

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
  const live = useLiveScanSession();
  const transport = demo ? fixtureScanTransport : live?.transport ?? unavailableScanTransport;
  const list = useQuery({
    queryKey: demo ? ['scans', 'fixture', 'list'] : [...(live?.scope ?? ['live-scans', 'unavailable']), 'list'],
    queryFn: ({ signal }) => transport.list(signal),
    enabled: transport.capabilities.list,
    retry: false,
  });
  return (
    <ScanShell demo={demo}>
      <section aria-labelledby="scan-list" className="min-w-0 space-y-8 pb-8">
        <div className="scan-a1__chapter">
          <span>ГЛАВА 01 / КАТАЛОГ</span>
          <span>{demo ? 'ЗАПИСИ ИЗ ФИКСТУР' : 'АВТОРИЗОВАННЫЙ СПИСОК'}</span>
        </div>
        <div className="scan-a1__intro scan-a1__intro--editorial">
          <div className="scan-a1__intro-copy min-w-0">
            <span className="scan-a1__folio">СИГНАЛ / 01 — АРХИВ ПРОВЕРОК</span>
            <h2 id="scan-list" className="scan-a1__heading">
              Каждая проверка —<br />
              <em>история с границами.</em>
            </h2>
            <p className="mt-5 max-w-2xl">
              Цель, состояние и область проверки — без догадок о том, что осталось за пределами отчёта.
            </p>
          </div>
          <div className="scan-a1__intro-art">
            <ScanScene variant="list" />
            <div className="scan-a1__intro-cta">
              <span>01 / {demo ? 'ФИКСТУРЫ, НЕ LIVE' : 'СНИМОК API'}</span>
              {transport.capabilities.create || demo ? (
                <Link className="scan-a1__action" to={demo ? '/demo/scans/new' : '/scans/new'}>
                  + Новый скан <ArrowRight size={20} aria-hidden="true" />
                </Link>
              ) : null}
            </div>
          </div>
        </div>
        <div className="scan-a1__section-title">
          <span>РЕЕСТР / {demo ? 'ДЕМО' : 'LIVE'}</span>
          <span>ЦЕЛЬ → СОСТОЯНИЕ → ОТЧЁТ</span>
        </div>
        {!transport.capabilities.list ? (
          <Alert role="status" tone="neutral">
            <strong>
              Список недоступен без подтверждённой сессии.
            </strong>
            <span className="mt-2 block">Отсутствие списка не означает «сканов нет».</span>
            <Link to="/demo/scans" className="mt-3 inline-block font-bold underline">
              Посмотреть вымышленные записи
            </Link>
          </Alert>
        ) : null}
        {list.isPending && transport.capabilities.list ? (
          <p role="status" className="scan-a1__muted">
            Загружаем список…
          </p>
        ) : null}
        {list.isError ? (
          <Alert role="alert" tone="danger">
            {list.error instanceof ScanAccessError && list.error.status === 403 ? (
              <>Аккаунту не выдано разрешение на реальные сканы. Вход работает, но список и запуск закрыты. Узнайте ID на <Link to="/account" className="font-bold underline">странице аккаунта</Link>, чтобы разрешить этот аккаунт на стенде.</>
            ) : list.error instanceof ScanAccessError && list.error.status === 401 ? (
              <>Сессия больше не действует. <Link to="/login" className="font-bold underline">Войдите заново</Link>.</>
            ) : 'Не удалось загрузить список. Неизвестно, есть ли сканы.'}
          </Alert>
        ) : null}
        {list.isSuccess && !list.data.length ? (
          <p className="scan-a1__muted">Сканов нет (успешный ответ списка).</p>
        ) : null}
        {list.isSuccess ? (
          <ol className="scan-a1__records min-w-0 list-none p-0">
            {list.data.map((scan, index) => (
              <li
                key={scan.scanId}
                className={`scan-a1__record min-w-0 ${scan.state === 'partial' ? 'scan-a1__record--featured' : ''}`}
              >
                <MagicCard>
                  <div className="scan-a1__record-content">
                    <span className="scan-a1__index">
                      {String(index + 1).padStart(2, '0')} / {stateLabels[scan.state]}
                    </span>
                    <div className="scan-a1__record-facts min-w-0">
                      <h3>{scan.targetLabel}</h3>
                      <ScanProgressPanel scan={scan} compact />
                      {demo ? (
                        <p className="mt-1 text-xs">Вымышленные данные · не результат реальной проверки</p>
                      ) : null}
                    </div>
                    <div className="flex flex-wrap items-center gap-4">
                      <Badge tone={stateTone[scan.state]}>{stateLabels[scan.state]}</Badge>
                      <Link
                        className="scan-a1__link"
                        to={`${demo ? '/demo' : ''}/scans/${encodeURIComponent(scan.scanId)}`}
                      >
                        Открыть деталь <ArrowUpRight size={17} aria-hidden="true" />
                      </Link>
                    </div>
                  </div>
                </MagicCard>
              </li>
            ))}
          </ol>
        ) : null}
        <p className="scan-a1__muted text-sm">
          {demo
            ? 'Сканы в списке — локальные фикстуры. Анимации не отображают реальный ход проверки.'
            : 'Список и запуск доступны разрешённому аккаунту; деталь получает SSE-подсказки и подтверждает состояние через GET. Отмена доступна активным сканам.'}
        </p>
      </section>
    </ScanShell>
  );
}
