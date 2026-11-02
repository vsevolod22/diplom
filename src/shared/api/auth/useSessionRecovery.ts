import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { transitionScanSession } from './scanSession';

export function useSessionRecovery(active: boolean) {
  const client = useQueryClient();

  useEffect(() => {
    if (!active) return;
    // Fail closed locally, but an unavailable /me does not prove the cookie is invalid.
    // Keep the auth query in its error state until a fresh check succeeds.
    transitionScanSession(null, client, false, 'unverified');
  }, [active, client]);
}
