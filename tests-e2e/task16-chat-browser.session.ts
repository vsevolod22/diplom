import { QueryClient } from '@tanstack/react-query';
import { transitionScanSession } from '../src/shared/api/auth/scanSession';

// Test-only signal injection into the actual session observable, not a backend authentication claim.
// This independent client has no queries. App consumers remount through their real session subscriptions.
export function switchSubject(subject: string) {
  transitionScanSession(subject, new QueryClient(), true);
}
