import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { ScanShell } from '@/features/scans/ScanShell';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';

export function ScanListPage({ demo = false }: { demo?: boolean }) {
  const transport = demo ? fixtureScanTransport : unavailableScanTransport;
  const list = useQuery({ queryKey: ['scans', transport.kind, 'list'], queryFn: ({ signal }) => transport.list(signal), enabled: transport.capabilities.list, retry: false });
  return <ScanShell demo={demo}>
    <section aria-labelledby="scan-list" className="space-y-4">
      <h2 id="scan-list" className="text-xl font-semibold">Список сканов</h2>
      {!transport.capabilities.list ? <p role="status">Список недоступен: GET /api/v1/scans и защищённый браузерный доступ ещё не реализованы. Отсутствие списка не означает «сканов нет».</p> : null}
      {list.isPending && transport.capabilities.list ? <p role="status">Загружаем список…</p> : null}
      {list.isError ? <p role="alert">Не удалось загрузить список. Неизвестно, есть ли сканы.</p> : null}
      {list.isSuccess && list.data.length === 0 ? <p>Сканов нет (успешный ответ списка).</p> : null}
      {list.isSuccess ? <ul className="grid gap-3 sm:grid-cols-2">{list.data.map((scan) => <li key={scan.scanId} className="rounded-xl border border-slate-200 p-4 shadow-sm"><Link className="font-semibold text-indigo-700 underline focus-visible:outline-2" to={`${demo ? '/demo' : ''}/scans/${encodeURIComponent(scan.scanId)}`}>{scan.targetLabel}</Link><p>Статус: {scan.state}</p><p>Прогресс: {scan.percent == null ? 'неизвестен' : `${scan.percent}%`}</p></li>)}</ul> : null}
    </section>
  </ScanShell>;
}
