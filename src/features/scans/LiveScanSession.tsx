import { useMemo, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { currentDemoUser } from '@/shared/api/auth/demoAuth';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { useSessionRecovery } from '@/shared/api/auth/useSessionRecovery';
import { createAuthorizedScanTransport } from '@/shared/api/scans/httpScanTransport';
import { LiveScanContext } from './liveScanContext';

export function LiveScanSession({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const session = useQuery({
    queryKey: ['demo-auth', 'me'],
    queryFn: async ({ signal }) => {
      try {
        const user = await currentDemoUser(signal);
        if (signal.aborted) throw new Error('Проверка сессии отменена');
        transitionScanSession(user?.id ?? null, client);
        return user;
      } catch (error) {
        if (!signal.aborted) transitionScanSession(null, client);
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
  const identity = scanSession();
  const userId = session.data?.id;
  const scope = userId && identity.subject === userId ? (`${identity.generation}:${userId}`) : null;
  const value = useMemo(() => scope && userId ? {
    scope: ['live-scans', identity.generation, userId] as const,
    transport: createAuthorizedScanTransport({ subject: userId, currentSubject: () => {
      const current = scanSession();
      return current.generation === identity.generation ? current.subject : null;
    } }),
  } : null, [scope, userId, identity.generation]);

  if (session.isPending) return <p role="status">Проверяем сессию…</p>;
  if (session.isError) return <p role="status">Проверка сессии не удалась. Закрываем доступ…</p>;
  if (!value) return <p role="status">Для доступа к сканам <Link to="/login">войдите</Link>. <Link to="/demo/scans">Демо без входа</Link>.</p>;
  return <LiveScanContext.Provider value={value}>{children}</LiveScanContext.Provider>;
}
