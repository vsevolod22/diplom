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
import { ScanListIdentityError, type ScanStatus, type ScanTransport } from '@/shared/api/scans/scanTransport';
import { Alert, Badge, Button } from '@/shared/ui/scan-primitives';
import { useScanListPages } from './useScanListPages';
import './scan-detail-a1.css';

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
  const scope = demo ? ['scans', 'fixture'] : live?.scope ?? ['live-scans', 'unavailable'];
  return <ScanListSession key={JSON.stringify(scope)} transport={transport} scope={scope} demo={demo} />;
}

function ScanListSession({ transport, scope, demo }: { transport: ScanTransport; scope: readonly unknown[]; demo: boolean }) {
  const list = useScanListPages(transport, scope, demo);
  const denied = list.error instanceof ScanAccessError;
  const snapshot = denied || !transport.capabilities.list ? null : list.snapshot;
  return (
    <ScanShell demo={demo}>
      <section aria-labelledby="scan-list" className="scan-a1-list min-w-0 space-y-8 pb-8">
        <div className="scan-a1__chapter">
          <span>МОИ ПРОВЕРКИ</span>
          <span>{demo ? 'ВЫМЫШЛЕННЫЕ ПРИМЕРЫ' : 'ИСТОРИЯ'}</span>
        </div>
        <div className="scan-a1__intro scan-a1__intro--editorial">
          <div className="scan-a1__intro-copy min-w-0">
            <span className="scan-a1__folio">ОБРАЗЫ И РЕЗУЛЬТАТЫ</span>
            <h2 id="scan-list" className="scan-a1__heading">
              Ваши <em>проверки.</em>
            </h2>
            <p className="mt-5 max-w-2xl">
              Откройте отчёт, чтобы разобраться с находками и исправлениями. После обновления образа запустите новую проверку.
            </p>
          </div>
          <div className="scan-a1__intro-art">
            <ScanScene variant="list" />
            <div className="scan-a1__intro-cta">
              <span>{demo ? 'ПРИМЕРЫ, НЕ РЕАЛЬНЫЕ РЕЗУЛЬТАТЫ' : 'ПРОВЕРИТЬ ДРУГОЙ ОБРАЗ'}</span>
              {transport.capabilities.create || demo ? (
                <Link className="scan-a1__action" to={demo ? '/demo/scans/new' : '/scans/new'}>
                  + Новая проверка <ArrowRight size={20} aria-hidden="true" />
                </Link>
              ) : null}
            </div>
          </div>
        </div>
        <div className="scan-a1__section-title">
          <span>{demo ? 'ПРИМЕРЫ ОТЧЁТОВ' : 'ИСТОРИЯ ПРОВЕРОК'}</span>
          <span>ОБРАЗ → РЕЗУЛЬТАТ</span>
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
        {list.pending && !snapshot && transport.capabilities.list && !denied ? (
          <p role="status" className="scan-a1__muted">
            Загружаем список…
          </p>
        ) : null}
        {list.error ? (
          <Alert role="alert" tone="danger">
            {list.error instanceof ScanAccessError && list.error.status === 403 ? (
              <>Аккаунту не выдано разрешение на реальные сканы. Вход работает, но список и запуск закрыты. Узнайте ID на <Link to="/account" className="font-bold underline">странице аккаунта</Link>, чтобы разрешить этот аккаунт на стенде.</>
            ) : list.error instanceof ScanAccessError && list.error.status === 401 ? (
              <>Сессия больше не действует. <Link to="/login" state={{ returnTo: '/scans' }} className="font-bold underline">Войдите заново</Link>.</>
            ) : list.error instanceof ScanListIdentityError ? list.error.message
              : snapshot ? 'Не удалось загрузить страницу. Ранее загруженные проверки сохранены.'
                : 'Не удалось загрузить список. Неизвестно, есть ли сканы.'}
            {transport.capabilities.list && !denied && !snapshot ? (
              <Button type="button" variant="secondary" disabled={list.pending} onClick={list.reload}>
                {list.pending ? 'Загружаем список…' : 'Повторить загрузку списка'}
              </Button>
            ) : null}
          </Alert>
        ) : null}
        {snapshot && !snapshot.scans.length ? (
          <p className="scan-a1__muted">Проверок пока нет. Нажмите «Новая проверка», выберите образ и получите первый отчёт.</p>
        ) : null}
        {snapshot ? (
          <ol className="scan-a1__records min-w-0 list-none p-0">
            {snapshot.scans.map((scan, index) => (
              <li
                key={scan.scanId}
                className={`scan-a1__record min-w-0 ${scan.state === 'partial' ? 'scan-a1__record--featured' : ''}`}
              >
                <MagicCard>
                  <Link
                    className="scan-a1__record-content scan-a1__record-link"
                    to={`${demo ? '/demo' : ''}/scans/${encodeURIComponent(scan.scanId)}`}
                    aria-label={`Открыть отчёт: ${scan.targetLabel}, ID ${scan.scanId}`}
                  >
                    <span className="scan-a1__index">
                      {String(index + 1).padStart(2, '0')} / {stateLabels[scan.state]}
                    </span>
                    <div className="scan-a1__record-facts min-w-0">
                      <h3>{scan.targetLabel.replace(/@sha256:[a-f0-9]{64}/g, ' · точная сборка')}</h3>
                      <p className="mt-2 break-all text-xs">
                        <span title={scan.scanId}>ID {scan.scanId.length > 16 ? `${scan.scanId.slice(0, 8)}…${scan.scanId.slice(-4)}` : scan.scanId}</span>
                        {scan.digest ? <span title={scan.digest}> · {scan.digest.slice(0, 19)}…</span> : null}
                      </p>
                      <ScanProgressPanel scan={scan} compact list />
                      {demo ? (
                        <p className="mt-1 text-xs">Вымышленные данные · не результат реальной проверки</p>
                      ) : null}
                    </div>
                    <div className="flex flex-wrap items-center gap-4">
                      <Badge tone={stateTone[scan.state]}>{stateLabels[scan.state]}</Badge>
                      <span className="scan-a1__link">
                        Открыть отчёт <ArrowUpRight size={17} aria-hidden="true" />
                      </span>
                    </div>
                  </Link>
                </MagicCard>
              </li>
            ))}
          </ol>
        ) : null}
        {snapshot ? (
          <div className="space-y-4">
            {list.refreshError ? (
              <Alert role="alert" tone="warning">
                Не удалось обновить активные проверки. Показаны последние полученные данные; автообновление приостановлено.
                <Button type="button" variant="secondary" disabled={list.pending} onClick={list.retryRefresh}>
                  Повторить обновление активных проверок
                </Button>
              </Alert>
            ) : null}
            <div className="flex flex-wrap items-center gap-4">
              {snapshot.nextCursor !== null && !(list.error instanceof ScanListIdentityError) ? (
                <Button type="button" variant="secondary" disabled={list.pending} onClick={list.next}>
                  {list.pending ? 'Загружаем страницу…' : list.error ? 'Повторить загрузку страницы' : 'Показать ещё'}
                </Button>
              ) : null}
              <Button type="button" variant="secondary" disabled={list.pending} onClick={list.reload}>
                Обновить список сначала
              </Button>
              <span className="scan-a1__muted text-sm" role="status">
                Загружено проверок: {snapshot.scans.length}.
                {list.pending ? ' Загружаем страницу…' : list.refreshPending ? ' Обновляем активные проверки…' : ''}
              </span>
            </div>
          </div>
        ) : null}
        <p className="scan-a1__muted text-sm">
          {demo
            ? 'Это вымышленные примеры, не результаты проверки ваших образов.'
            : 'Текущую проверку можно отменить на странице отчёта. Завершённый отчёт описывает проверенную сборку, а не будущие версии образа.'}
        </p>
      </section>
    </ScanShell>
  );
}
