import type { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Alert, Badge } from '@/shared/ui/scan-primitives';

export function ScanShell({ demo, children }: { demo: boolean; children: ReactNode }) {
  const { pathname } = useLocation();
  const newScanPath = demo ? '/demo/scans/new' : '/scans/new';
  return (
    <main className="mx-auto min-w-0 max-w-6xl space-y-6 bg-[#f4f6fa] px-4 py-6 text-slate-950 sm:px-8 sm:py-10 lg:space-y-8">
      <header className="min-w-0 space-y-5 border-b border-slate-200 pb-6 sm:pb-8">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs font-bold uppercase tracking-[0.18em] text-indigo-800">
            Image security{' '}
            <span aria-hidden="true" className="mx-1 text-slate-400">
              /
            </span>{' '}
            диплом
          </p>
          <Badge tone={demo ? 'warning' : 'neutral'}>
            {demo ? 'Режим · демо' : 'Режим · реальный доступ недоступен'}
          </Badge>
        </div>
        <div className="space-y-2">
          <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">Сканирование образов</h1>
          <p className="max-w-2xl text-sm leading-relaxed text-slate-600 sm:text-base">
            Цель, ход проверки и подтверждённая область результатов — отдельно и без догадок.
          </p>
        </div>
        <nav aria-label="Разделы сканирования" className="flex flex-wrap gap-2 text-sm font-semibold">
          <Link
            to="/scans"
            aria-current={pathname === '/scans' ? 'page' : undefined}
            className={`inline-flex min-h-11 items-center rounded-xl border px-4 transition-colors hover:bg-indigo-50 ${!demo ? 'border-indigo-200 bg-indigo-50 text-indigo-900' : 'border-slate-200 bg-white text-slate-700'}`}
          >
            Реальный режим
          </Link>
          <Link
            to="/demo/scans"
            aria-current={pathname === '/demo/scans' ? 'page' : undefined}
            className={`inline-flex min-h-11 items-center rounded-xl border px-4 transition-colors hover:bg-indigo-50 ${demo ? 'border-indigo-200 bg-indigo-50 text-indigo-900' : 'border-slate-200 bg-white text-slate-700'}`}
          >
            Демо
          </Link>
          <Link
            to={newScanPath}
            aria-current={pathname === newScanPath ? 'page' : undefined}
            className="inline-flex min-h-11 items-center rounded-xl border border-slate-200 bg-white px-4 text-indigo-800 transition-colors hover:bg-indigo-50"
          >
            Новый скан{' '}
            <span aria-hidden="true" className="ml-2">
              ↗
            </span>
          </Link>
        </nav>
      </header>
      {demo ? (
        <Alert role="note" className="border-amber-300">
          <strong className="block">ДЕМО · вымышленные данные</strong>
          <span className="mt-1 block text-sm leading-relaxed">
            Не результат реального сканирования и не подтверждение безопасности образа.
          </span>
        </Alert>
      ) : (
        <Alert role="note" tone="neutral" className="border-slate-300 bg-slate-50 text-slate-800">
          <strong className="block">Реальный режим недоступен</strong>
          <span className="mt-1 block text-sm leading-relaxed">
            Нет безопасного browser ingress и авторизованной сессии. Сервер не предоставляет GET списка и
            отмену. Демонстрация доступна отдельно.
          </span>
        </Alert>
      )}
      {children}
    </main>
  );
}

export const controlClass =
  'min-h-11 rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-700';
