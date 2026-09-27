import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';
import { ScanShell, controlClass } from '@/features/scans/ScanShell';
import { ScanFilterSheet } from '@/features/scans/ScanFilterSheet';
import { ScanStatusAnnouncement } from '@/features/scans/ScanStatusAnnouncement';
import { stateLabels } from '@/features/scans/scanStateLabels';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import type { ScanCoverage } from '@/shared/api/scans/scanTransport';

const coverageLabels: Record<ScanCoverage['status'], string> = {
  checked: 'Выполнено (не гарантия безопасности)', failed: 'Сбой · не проверено',
  unsupported: 'Не поддерживается', not_authorized: 'Нет разрешения', skipped: 'Пропущено',
};

export function ScanDetailPage({ demo = false }: { demo?: boolean }) {
  const { scanId = '' } = useParams();
  const [filter, setFilter] = useState('all');
  const [cursor, setCursor] = useState<string | undefined>();
  const transport = demo ? fixtureScanTransport : unavailableScanTransport;
  const enabled = !!scanId && (demo || transport.capabilities.list);
  const scan = useQuery({ queryKey: ['scan', transport.kind, scanId], queryFn: ({ signal }) => transport.get(scanId, signal), enabled, retry: false, refetchOnWindowFocus: !demo });
  const report = useQuery({ queryKey: ['scan-results', transport.kind, scanId, filter, cursor], queryFn: ({ signal }) => transport.results(scanId, cursor, signal), enabled: enabled && scan.isSuccess, retry: false });
  const findings = report.data?.findings.filter((finding) => filter === 'all' || finding.category === filter) ?? [];
  const changeFilter = (value: string) => { setFilter(value); setCursor(undefined); };
  return <ScanShell demo={demo}>
    <section className="space-y-6" aria-labelledby="scan-detail">
      <h2 id="scan-detail" className="text-xl font-semibold">Деталь скана <span className="break-all text-base font-normal">{scanId}</span></h2>
      {!enabled ? <p>Деталь недоступна без защищённой авторизованной сессии; scanId в адресе не подтверждает доступ.</p> : null}
      {scan.isPending && enabled ? <p>Загружаем снимок…</p> : null}
      {scan.isError ? <p role="alert">Не удалось получить данные скана. Его существование и доступность не подтверждены.</p> : null}
      {scan.data ? <div className="grid min-w-0 gap-4 sm:grid-cols-2">
        <div className="min-w-0 break-words rounded-xl border border-slate-300 p-5">
          <h3 className="font-semibold">Цель и состояние</h3>
          <p>Указанная цель: {scan.data.imageReference || 'не предоставлена сервером'}</p>
          <p>Закреплённая цель: {scan.data.digest && scan.data.platform ? `${scan.data.digest} · ${scan.data.platform}` : 'ожидаем подтверждения digest/platform от авторизованного GET status'}</p>
          <ScanStatusAnnouncement scan={scan.data} />
          <p>Статус: {stateLabels[scan.data.state]}</p>
          <p>Этап: {scan.data.stage || 'не предоставлен'}</p>
          <p>Прогресс: {scan.data.percent == null ? 'неизвестен' : `${scan.data.percent}%`}</p>
          <p className="text-sm">Состояние только из GET snapshot; live SSE/replay не подтверждён.</p>
          <button type="button" disabled className={`${controlClass} mt-3`} title="Серверный API отмены не реализован">Отмена недоступна</button>
          <p className="text-sm text-slate-600">Нет авторизованного cancel API. Неполные результаты не удаляются.</p>
        </div>
        <div className="min-w-0 break-words rounded-xl border border-slate-300 p-5"><h3 className="font-semibold">Покрытие проверок</h3>
          {report.data ? <ul className="mt-2 space-y-3">{report.data.coverage.map((item) => <li key={item.check} className="border-l-2 border-indigo-300 pl-3"><strong>{item.check}</strong>: {coverageLabels[item.status]}{item.reason ? ` · ${item.reason}` : ''}{item.scannerVersion ? ` · scanner ${item.scannerVersion}` : ''}{item.dbVersion ? ` · DB ${item.dbVersion}` : ''}</li>)}</ul> : <p>Нет подтверждённого coverage; «0 проблем» недопустимо.</p>}
        </div>
      </div> : null}
      {scan.data ? <div className="min-w-0 space-y-3 break-words rounded-xl border border-slate-300 p-5"><h3 className="font-semibold">Находки</h3>
        <ScanFilterSheet filter={filter} onFilterChange={changeFilter} />
        <div className="hidden sm:block"><label htmlFor="finding-filter">Категория</label>{' '}
          <select id="finding-filter" className={controlClass} value={filter} onChange={(event) => changeFilter(event.target.value)}><option value="all">Все на загруженной странице</option><option value="secret">Secrets</option><option value="vulnerability">CVE</option></select></div>
        <p>Категория: {filter === 'all' ? 'Все' : filter === 'secret' ? 'Secrets' : 'CVE'} (на загруженной странице)</p>
        {report.isPending ? <p>Загружаем результаты…</p> : null}
        {report.isError ? <p role="alert">Не удалось загрузить результаты; число находок неизвестно.</p> : null}
        {report.data && findings.length > 0 ? <ul className="space-y-2">{findings.map((finding) => <li key={finding.findingId} className="min-w-0 break-words rounded border border-slate-400 p-3"><strong>{finding.category} · {finding.ruleId}</strong> · {finding.severity}<p>ID: {finding.findingId}</p></li>)}</ul> : null}
        {report.data && findings.length === 0 && filter !== 'all' ? <p>Нет совпадений фильтра на загруженной странице. Это не означает отсутствие находок во всём отчёте. <button type="button" className="rounded text-indigo-800 underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-700" onClick={() => changeFilter('all')}>Сбросить фильтр</button></p> : null}
        {report.data && findings.length === 0 && filter === 'all' && (report.data.nextCursor || cursor) ? <p>На текущей странице находок нет; общий результат не подтверждён.</p> : null}
        {report.data && findings.length === 0 && filter === 'all' && !report.data.nextCursor && !cursor ? <p>{report.data.coverage.some((item) => item.status === 'checked') && !report.data.coverage.some((item) => item.status === 'failed') ? '0 находок в выполненной проверенной области; другие области не исключены.' : 'Нет подтверждённых находок: область не проверена полностью. Это не «0 CVE».'}</p> : null}
        {report.data?.nextCursor ? <button type="button" className={controlClass} onClick={() => setCursor(report.data.nextCursor ?? undefined)}>Следующая страница</button> : null}
      </div> : null}
    </section>
  </ScanShell>;
}
