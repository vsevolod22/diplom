import { useState } from 'react';
import * as Accordion from '@radix-ui/react-accordion';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, ChevronDown, Sparkles } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { MagicCard } from '@/features/scans/MagicCard';
import { ScanFilterSheet } from '@/features/scans/ScanFilterSheet';
import { ScanShell, controlClass } from '@/features/scans/ScanShell';
import { ScanScene } from '@/features/scans/ScanScene';
import { ScanStatusAnnouncement } from '@/features/scans/ScanStatusAnnouncement';
import { stateLabels } from '@/features/scans/scanStateLabels';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import type { ScanCoverage, ScanStatus } from '@/shared/api/scans/scanTransport';
import { Alert, Badge, Button } from '@/shared/ui/scan-primitives';
import './scan-detail-a1.css';

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
      <section className="scan-a1-detail" aria-labelledby="scan-detail">
        <div className="scan-a1__chapter">
          <span>ГЛАВА 03 / ОТЧЁТ</span>
          <Link to={demo ? '/demo/scans' : '/scans'}>
            <ArrowLeft size={17} aria-hidden="true" /> К списку
          </Link>
        </div>
        <div className="scan-a1__lead">
          <div className="scan-a1__lead-copy">
            <p className="scan-a1__eyebrow">
              {demo ? 'ДЕМО / ВЫМЫШЛЕННЫЕ ДАННЫЕ' : 'РЕАЛЬНЫЙ РЕЖИМ / НЕДОСТУПЕН'}
            </p>
            <h2 id="scan-detail">
              Не всё, что видно, <em>проверено.</em>
            </h2>
            <p className="scan-a1__reference">ID / {scanId}</p>
            <p className="scan-a1__muted">
              {demo ? 'Демонстрационная карточка · вымышленные данные' : 'Авторизованный просмотр недоступен'}
            </p>
          </div>

          {scan.data ? (
            <div className="scan-a1__summary">
              <Badge tone={stateTone[scan.data.state]}>{stateLabels[scan.data.state]}</Badge>
              <span>Прогресс: {scan.data.percent == null ? 'неизвестен' : `${scan.data.percent}%`}</span>
            </div>
          ) : null}
        </div>
        {!enabled ? (
          <Alert tone="neutral">
            Деталь недоступна без защищённой авторизованной сессии; scanId в адресе не подтверждает доступ.
          </Alert>
        ) : null}
        {scan.isPending && enabled ? <p>Загружаем снимок…</p> : null}
        {scan.isError ? (
          <Alert role="alert" tone="danger">
            Не удалось получить данные скана. Его существование и доступность не подтверждены.
          </Alert>
        ) : null}
        {scan.data ? (
          <>
            <MagicCard className="scan-a1__reading-card">
              <p className="scan-a1__reading-copy">
                Порядок чтения / цель → состояние → покрытие → находки. Подсветка помогает ориентироваться, но
                не показывает ход проверки.
              </p>
            </MagicCard>
            <nav className="scan-a1__report-nav" aria-label="Разделы отчёта">
              <a href="#scan-a1-state">
                01 <span>Состояние и цель</span>
              </a>
              <a href="#scan-a1-coverage">
                02 <span>Покрытие</span>
              </a>
              <a href="#scan-a1-findings">
                03 <span>Находки</span>
              </a>
              <a href="#scan-a1-ai">
                04 <span>Помощник</span>
              </a>
            </nav>
            <div className="scan-a1__chapter scan-a1__chapter--section" id="scan-a1-state">
              01 / СОСТОЯНИЕ И ЦЕЛЬ
            </div>
            <div className="scan-a1__state">
              <div className="scan-a1__state-main">
                <h3>Цель и состояние</h3>
                <p className="scan-a1__muted">Указанная цель не подтверждает закреплённый образ.</p>
                <dl className="scan-a1__facts">
                  <div>
                    <dt>Указанная цель</dt>
                    <dd>Указанная цель: {scan.data.imageReference || 'не предоставлена сервером'}</dd>
                  </div>
                  <div>
                    <dt>Подтверждение цели</dt>
                    <dd>
                      Закреплённая цель:{' '}
                      {scan.data.digest && scan.data.platform
                        ? `${scan.data.digest} · ${scan.data.platform}`
                        : 'ожидаем подтверждения digest/platform от авторизованного GET status'}
                    </dd>
                  </div>
                  <div>
                    <dt>Статус</dt>
                    <dd>{stateLabels[scan.data.state]}</dd>
                  </div>
                  <div>
                    <dt>Этап</dt>
                    <dd>Этап: {scan.data.stage || 'не предоставлен'}</dd>
                  </div>
                </dl>
                <ScanStatusAnnouncement scan={scan.data} />
              </div>
              <div className="scan-a1__state-aside">
                <p>
                  {demo
                    ? 'Состояние из локальной фикстуры; это не GET status и не live-поток.'
                    : 'Состояние только из GET snapshot; live SSE/replay не подтверждён.'}
                </p>
                <Button variant="secondary" type="button" disabled title="Серверный API отмены не реализован">
                  Отмена недоступна
                </Button>
                <p>Нет авторизованного cancel API. Неполные результаты не удаляются.</p>
              </div>
            </div>
            <div className="scan-a1__detail-divider" aria-hidden="true">
              <ScanScene variant="detail" />
            </div>
            <div className="scan-a1__grid">
              <section className="scan-a1__panel" aria-labelledby="scan-a1-coverage">
                <p className="scan-a1__eyebrow">02 / ПОКРЫТИЕ</p>
                <h3 id="scan-a1-coverage">Покрытие проверок</h3>
                <p className="scan-a1__muted">Исход каждой проверки отдельно от статуса скана.</p>
                {report.data ? (
                  <ul className="scan-a1__coverage">
                    {report.data.coverage.map((item) => (
                      <li key={item.check}>
                        <strong>{item.check}</strong>
                        <div>
                          <Badge tone={coverageTone[item.status]}>{coverageLabels[item.status]}</Badge>
                          {item.reason ? <p>{item.reason}</p> : null}
                          {item.scannerVersion || item.dbVersion ? (
                            <small>
                              {item.scannerVersion ? `scanner ${item.scannerVersion}` : ''}
                              {item.scannerVersion && item.dbVersion ? ' · ' : ''}
                              {item.dbVersion ? `DB ${item.dbVersion}` : ''}
                            </small>
                          ) : null}
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>Нет подтверждённого coverage; «0 проблем» недопустимо.</p>
                )}
                <Accordion.Root type="single" collapsible className="scan-a1__explanation">
                  <Accordion.Item value="notes">
                    <Accordion.Header>
                      <Accordion.Trigger>
                        Что означает неполный отчёт? <ChevronDown size={17} aria-hidden="true" />
                      </Accordion.Trigger>
                    </Accordion.Header>
                    <Accordion.Content>
                      Нельзя считать непроверенные категории безопасными. Причины сбоев видны выше без
                      раскрытия пояснения.
                    </Accordion.Content>
                  </Accordion.Item>
                </Accordion.Root>
              </section>
              <section className="scan-a1__panel" aria-labelledby="scan-a1-findings">
                <p className="scan-a1__eyebrow">03 / РЕЗУЛЬТАТЫ</p>
                <h3 id="scan-a1-findings">Находки</h3>
                <p className="scan-a1__muted">
                  Фильтр действует только на загруженную страницу, не на весь отчёт.
                </p>
                <ScanFilterSheet filter={filter} onFilterChange={changeFilter} />
                <div className="scan-a1__desktop-filter">
                  <label htmlFor="finding-filter">Категория</label>
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
                <p className="scan-a1__muted">
                  Категория: {filter === 'all' ? 'Все' : filter === 'secret' ? 'Secrets' : 'CVE'} (на
                  загруженной странице)
                </p>
                {report.isPending ? <p>Загружаем результаты…</p> : null}
                {report.isError ? (
                  <Alert role="alert" tone="danger">
                    Не удалось загрузить результаты; число находок неизвестно.
                  </Alert>
                ) : null}
                {report.data && findings.length > 0 ? (
                  <ul className="scan-a1__findings">
                    {findings.map((finding) => (
                      <li key={finding.findingId}>
                        <span className="scan-a1__eyebrow">НАХОДКА / {finding.severity}</span>
                        <strong>
                          {finding.category} · {finding.ruleId}
                        </strong>
                        <p>ID: {finding.findingId}</p>
                      </li>
                    ))}
                  </ul>
                ) : null}
                {report.data && findings.length === 0 && filter !== 'all' ? (
                  <Alert tone="neutral" className="scan-a1__empty">
                    Нет совпадений фильтра на загруженной странице. Это не означает отсутствие находок во всём
                    отчёте.{' '}
                    <button type="button" className="scan-a1__link" onClick={() => changeFilter('all')}>
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
              </section>
            </div>
            <section className="scan-a1__ai" aria-labelledby="scan-a1-ai">
              <div>
                <p className="scan-a1__eyebrow">04 / КОНТЕКСТНЫЙ ПОМОЩНИК · КОНЦЕПТ</p>
                <h3 id="scan-a1-ai">
                  <Sparkles size={24} aria-hidden="true" /> Спросить об отчёте
                </h3>
                <p>
                  Будущий чат должен учитывать finding_id и границы coverage. Здесь нет модели, истории или
                  авторизованной отправки.
                </p>
              </div>
              <div className="scan-a1__compose">
                <label htmlFor="scan-a1-prompt">Ваш вопрос</label>
                <textarea id="scan-a1-prompt" disabled placeholder="Почему проверка не выполнена?" />
                <Button type="button" disabled>
                  Чат недоступен
                </Button>
                <small>Сообщения не сохраняются и не отправляются.</small>
              </div>
            </section>
          </>
        ) : null}
      </section>
    </ScanShell>
  );
}
