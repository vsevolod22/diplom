import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

export function ScanShell({ demo, children }: { demo: boolean; children: ReactNode }) {
  return <main className="mx-auto max-w-5xl min-w-0 space-y-6 bg-white p-4 text-slate-900 sm:p-8">
    <header className="space-y-3 border-b border-slate-200 pb-5">
      <p className="text-sm font-semibold uppercase tracking-widest text-indigo-700">Image security · диплом</p>
      <h1 className="text-3xl font-semibold">Сканирование образов</h1>
      <nav aria-label="Разделы сканирования" className="flex flex-wrap gap-4 text-sm font-medium text-indigo-700">
        <Link to="/scans" className="rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-700">Реальный режим</Link>
        <Link to="/demo/scans" className="rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-700">Демо</Link>
        <Link to={demo ? '/demo/scans/new' : '/scans/new'} className="rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-700">Новый скан</Link>
      </nav>
    </header>
    {demo ? <div role="note" className="rounded-lg border-2 border-amber-500 bg-amber-50 p-4 font-semibold text-amber-950">ДЕМО · вымышленные данные. Не результат реального сканирования и не подтверждение безопасности образа.</div> : <div className="rounded-lg border border-slate-300 bg-slate-50 p-4">Реальный режим недоступен: нет безопасного browser ingress и авторизованной сессии. Сервер не предоставляет GET списка и отмену. Демонстрация доступна отдельно.</div>}
    {children}
  </main>;
}

export const controlClass = 'rounded-lg border border-slate-300 bg-white px-3 py-2 text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-700';
