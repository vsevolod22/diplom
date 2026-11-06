import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, ArrowUpRight, ScanLine } from 'lucide-react';
import { NavListCard } from './NavListCard';
import { motion, useReducedMotion, useScroll } from 'motion/react';
import './scan-a1.css';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { logoutDemoUser } from '@/shared/api/auth/demoAuth';
import { transitionScanSession } from '@/shared/api/auth/scanSession';
import { Alert, Badge } from '@/shared/ui/scan-primitives';

export function ScanShell({ demo, children, compact = false }: { demo: boolean; children: ReactNode; compact?: boolean }) {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState(false);
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  async function logout() {
    if (loggingOut) return;
    setLoggingOut(true);
    setLogoutError(false);
    try {
      await logoutDemoUser();
      const redirect = mounted.current;
      transitionScanSession(null, queryClient, true);
      if (redirect) navigate('/login');
      await queryClient.cancelQueries();
      queryClient.clear();
    } catch {
      if (mounted.current) setLogoutError(true);
    } finally {
      if (mounted.current) setLoggingOut(false);
    }
  }
  const reducedMotion = useReducedMotion();
  const { scrollYProgress } = useScroll();
  const newScanPath = demo ? '/demo/scans/new' : '/scans/new';
  const screenTitle =
    pathname === newScanPath
      ? 'Новая проверка'
      : pathname === '/scans' || pathname === '/demo/scans'
        ? 'Мои проверки'
        : 'Отчёт по образу';
  return (
    <main className={`scan-shell scan-a1 min-w-0 text-slate-950${compact ? ' scan-shell--compact' : ''}`}>
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
          <div className={compact ? 'sr-only' : 'scan-shell__body'}>
            <p className="scan-shell__eyebrow">IMAGE / EXPLORER</p>
            <h1 className="sr-only">{screenTitle}</h1>
            <Badge tone={demo ? 'warning' : 'neutral'}>
              {demo ? 'Демонстрация' : 'Личный кабинет'}
            </Badge>
          </div>
          {compact ? <nav className="scan-shell__compact-nav" aria-label="Разделы сканирования">
            <Link to={demo ? '/demo/scans' : '/scans'} aria-current={pathname === (demo ? '/demo/scans' : '/scans') ? 'page' : undefined}>Мои проверки</Link>
            <Link to={newScanPath} aria-current={pathname === newScanPath ? 'page' : undefined}>Новая проверка</Link>
          </nav> : <NavListCard
            items={[
              {
                label: 'Мои проверки',
                description: 'Результаты и история',
                to: demo ? '/demo/scans' : '/scans',
                icon: <ArrowUpRight size={18} />,
                current: pathname === (demo ? '/demo/scans' : '/scans'),
              },
              ...(!demo ? [{
                label: 'Демо',
                description: 'Вымышленные записи',
                to: '/demo/scans',
                icon: <ArrowUpRight size={18} />,
                current: pathname === '/demo/scans',
              }] : []),
              {
                label: 'Новая проверка',
                description: demo ? 'Форма без запуска' : 'Выбрать и проверить образ',
                to: newScanPath,
                icon: <ArrowUpRight size={18} />,
                current: pathname === newScanPath,
              },
            ]}
          />}
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
          ) : null}
          {logoutError ? <Alert role="alert" tone="danger">Не удалось завершить сессию на сервере. Повторите выход.</Alert> : null}
          {children}
        </div>
      </div>
    </main>
  );
}

export const controlClass =
  'min-h-11 rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-700';
