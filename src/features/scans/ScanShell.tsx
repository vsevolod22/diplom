import { useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, ArrowUpRight, ScanLine } from 'lucide-react';
import { NavListCard } from './NavListCard';
import { motion, useReducedMotion, useScroll } from 'motion/react';
import './scan-a1.css';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { logoutDemoUser } from '@/shared/api/auth/demoAuth';
import { transitionScanSession } from '@/shared/api/auth/scanSession';
import { Alert, Badge } from '@/shared/ui/scan-primitives';

export function ScanShell({ demo, children }: { demo: boolean; children: ReactNode }) {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState(false);
  async function logout() {
    if (loggingOut) return;
    setLoggingOut(true);
    setLogoutError(false);
    try {
      await logoutDemoUser();
      transitionScanSession(null, queryClient, true);
      await queryClient.cancelQueries();
      queryClient.clear();
      navigate('/login');
    } catch {
      setLogoutError(true);
    } finally {
      setLoggingOut(false);
    }
  }
  const reducedMotion = useReducedMotion();
  const { scrollYProgress } = useScroll();
  const newScanPath = demo ? '/demo/scans/new' : '/scans/new';
  const screenTitle =
    pathname === newScanPath
      ? 'Новый скан'
      : pathname === '/scans' || pathname === '/demo/scans'
        ? 'Список сканов'
        : 'Деталь скана';
  return (
    <main className="scan-shell scan-a1 min-w-0 text-slate-950">
      <motion.div
        className="scan-a1__progress"
        aria-hidden="true"
        style={reducedMotion ? undefined : { scaleX: scrollYProgress }}
      />
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
            <div className="scan-shell__account-links">
              <Link to="/account">Аккаунт</Link>
              {!demo ? <button className="scan-shell__logout" type="button" disabled={loggingOut} onClick={() => { void logout(); }}>
                {loggingOut ? 'Выходим…' : 'Выйти'}
              </button> : null}
              <Link to="/" className="scan-shell__back">
                <ArrowLeft size={15} aria-hidden="true" /> На главную
              </Link>
            </div>
          </header>
          <div className="scan-shell__body">
            <p className="scan-shell__eyebrow">IMAGE / EXPLORER</p>
            <h1 className="sr-only">{screenTitle}</h1>
            <Badge tone={demo ? 'warning' : 'neutral'}>
              {demo ? 'Режим · демо' : 'Режим · авторизованный API'}
            </Badge>
          </div>
          <NavListCard
            items={[
              {
                label: 'Реальные сканы',
                description: 'По защищённой сессии',
                to: '/scans',
                icon: <ArrowUpRight size={18} />,
                current: pathname === '/scans',
              },
              {
                label: 'Демо',
                description: 'Вымышленные записи',
                to: '/demo/scans',
                icon: <ArrowUpRight size={18} />,
                current: pathname === '/demo/scans',
              },
              {
                label: 'Новый скан',
                description: demo ? 'Форма без запуска' : 'Запуск с разрешения сервера',
                to: newScanPath,
                icon: <ArrowUpRight size={18} />,
                current: pathname === newScanPath,
              },
            ]}
          />
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
              <strong className="block">Авторизованный режим</strong>
              <span className="mt-1 block text-sm leading-relaxed">
                Снимки доступны через защищённую cookie-сессию и разрешение сервера.
                Статус обновляется по серверным событиям или опросу; доступные действия определяет сервер. Демонстрация доступна отдельно.
              </span>
            </Alert>
          )}
          {logoutError ? <Alert role="alert" tone="danger">Не удалось завершить сессию на сервере. Повторите выход.</Alert> : null}
          {children}
        </div>
      </div>
    </main>
  );
}

export const controlClass =
  'min-h-11 rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-700';
