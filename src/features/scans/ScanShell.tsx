import type { ReactNode } from 'react';
import { ArrowLeft, ArrowUpRight, ScanLine, Sparkles } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { Alert, Badge } from '@/shared/ui/scan-primitives';

export function ScanShell({ demo, children }: { demo: boolean; children: ReactNode }) {
  const { pathname } = useLocation();
  const newScanPath = demo ? '/demo/scans/new' : '/scans/new';
  const screenTitle =
    pathname === newScanPath
      ? 'Новый скан'
      : pathname === '/scans' || pathname === '/demo/scans'
        ? 'Список сканов'
        : 'Деталь скана';
  return (
    <main className="scan-shell min-w-0 text-slate-950">
      <div className="scan-shell__hero">
        <div className="scan-shell__grid" aria-hidden="true" />
        <div className="scan-shell__glow" aria-hidden="true" />
        <div className="scan-shell__inner">
          <header className="scan-shell__top">
            <Link to="/" className="scan-shell__brand" aria-label="OCI / VISION — на главную">
              <span className="scan-shell__mark" aria-hidden="true">
                <ScanLine size={19} />
              </span>
              OCI <span aria-hidden="true">/</span> VISION
            </Link>
            <Link to="/" className="scan-shell__back">
              <ArrowLeft size={15} aria-hidden="true" /> На главную
            </Link>
          </header>
          <div className="scan-shell__body">
            <div className="scan-shell__copy">
              <p className="scan-shell__eyebrow">
                <Sparkles size={17} aria-hidden="true" /> IMAGE / EXPLORER <span aria-hidden="true">—</span>{' '}
                ДИПЛОМНЫЙ ПРОЕКТ
              </p>
              <h1 className="scan-shell__title">
                <span aria-hidden="true">
                  СМОТРИ <span>ГЛУБЖЕ.</span>
                </span>
                <span className="sr-only">{screenTitle}</span>
              </h1>
              <p className="scan-shell__lead">
                Сканирование образов: цель, статус и подтверждённое покрытие. Без догадок о том, что не было
                проверено.
              </p>
              <Badge tone={demo ? 'warning' : 'neutral'}>
                {demo ? 'Режим · демо' : 'Режим · реальный доступ недоступен'}
              </Badge>
            </div>
            <div className="scan-shell__art" aria-hidden="true">
              <div className="scan-shell__art-ring">
                <ScanLine size={90} strokeWidth={1} />
              </div>
              <span>LOOK / CLOSER</span>
            </div>
          </div>
          <nav aria-label="Разделы сканирования" className="scan-shell__nav">
            <Link to="/scans" aria-current={pathname === '/scans' ? 'page' : undefined}>
              О реальном режиме <ArrowUpRight size={16} aria-hidden="true" />
            </Link>
            <Link to="/demo/scans" aria-current={pathname === '/demo/scans' ? 'page' : undefined}>
              Демо <ArrowUpRight size={16} aria-hidden="true" />
            </Link>
            <Link to={newScanPath} aria-current={pathname === newScanPath ? 'page' : undefined}>
              Новый скан <ArrowUpRight size={16} aria-hidden="true" />
            </Link>
          </nav>
        </div>
      </div>
      <div className="scan-shell__stage">
        <div className="scan-shell__content">
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
        </div>
      </div>
    </main>
  );
}

export const controlClass =
  'min-h-11 rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-700';
