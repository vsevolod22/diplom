import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { logoutDemoUser } from './demoAuth';
import { transitionScanSession } from './scanSession';

export function useSessionRecovery(active: boolean) {
  const client = useQueryClient();
  const navigate = useNavigate();

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4_000);
    transitionScanSession(null, client, true);

    void (async () => {
      let revoked = false;
      try {
        await logoutDemoUser(controller.signal);
        revoked = true;
      } catch {
        // Without a server response we cannot claim the cookie was revoked.
      } finally {
        clearTimeout(timeout);
        if (!cancelled) {
          await client.cancelQueries();
          client.clear();
          navigate('/login', {
            replace: true,
            state: { sessionNotice: revoked
              ? 'Не удалось проверить сессию. Доступ закрыт, выполните вход заново.'
              : 'Не удалось проверить сессию. Доступ закрыт, но сервер не подтвердил выход. Проверьте подключение и войдите заново.' },
          });
        }
      }
    })();

    return () => {
      cancelled = true;
      clearTimeout(timeout);
      controller.abort();
    };
  }, [active, client, navigate]);
}
