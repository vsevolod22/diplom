import { useMemo, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useLocation } from 'react-router-dom';
import { currentDemoUser } from '@/shared/api/auth/demoAuth';
import { safeAuthReturnTo } from '@/shared/api/auth/authReturnTo';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { useScanSession } from '@/shared/api/auth/useScanSession';
import { useSessionRecovery } from '@/shared/api/auth/useSessionRecovery';
import { createAuthorizedScanTransport } from '@/shared/api/scans/httpScanTransport';
import { RouteLoading } from '@/shared/ui/RouteLoading';
import { LiveScanContext } from './liveScanContext';

export function LiveScanSession({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const location = useLocation();
  const authState = { returnTo: safeAuthReturnTo(location.pathname) };
  const session = useQuery({
    queryKey: ['demo-auth', 'me'],
    queryFn: async ({ signal }) => {
      try {
        const user = await currentDemoUser(signal);
        if (signal.aborted) throw new Error('Проверка сессии отменена');
        transitionScanSession(user?.id ?? null, client);
        return user;
      } catch (error) {
        if (!signal.aborted) transitionScanSession(null, client, false, 'unverified');
        throw error;
      }
    },
    retry: false,
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: 'always',
    refetchInterval: 30_000,
  });
  useSessionRecovery(session.isError);
  const identity = useScanSession();
  const userId = session.data?.id;
  const scope = userId && identity.subject === userId ? (`${identity.generation}:${userId}`) : null;
  const value = useMemo(() => scope && userId ? {
    scope: ['live-scans', identity.generation, userId] as const,
    transport: createAuthorizedScanTransport({ subject: userId, currentSubject: () => {
      const current = scanSession();
      return current.generation === identity.generation ? current.subject : null;
    } }),
  } : null, [scope, userId, identity.generation]);

  if (session.isPending) return (
    <RouteLoading
      label="Проверка сессии"
      title="Проверяем сессию…"
      description="Данные скрыты до успешной проверки."
    />
  );
  if (session.isError) return <div>
    <p role="alert">Не удалось проверить сессию. Данные скрыты до успешной проверки; выход из аккаунта не выполнялся.</p>
    <button type="button" disabled={session.isFetching} onClick={() => void session.refetch({ cancelRefetch: false })}>
      {session.isFetching ? 'Проверяем сессию…' : 'Повторить проверку сессии'}
    </button>
    {' '}<Link to="/login" state={authState}>Перейти ко входу</Link>
  </div>;
  if (userId && identity.subject !== userId) return (
    <RouteLoading
      label="Подтверждение сессии"
      title="Подтверждаем сессию…"
      description="Данные скрыты до успешной проверки."
    />
  );
  if (!value) return <p role="status">Вход не выполнен или сессия истекла. Для доступа к сканам <Link to="/login" state={authState}>войдите</Link>. <Link to="/demo/scans">Демо без входа</Link>.</p>;
  return <LiveScanContext.Provider key={scope} value={value}>{children}</LiveScanContext.Provider>;
}
