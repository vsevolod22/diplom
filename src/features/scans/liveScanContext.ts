import { createContext, useContext } from 'react';
import type { ScanTransport } from '@/shared/api/scans/scanTransport';

export type LiveContext = { transport: ScanTransport; scope: readonly [string, number, string] };
export const LiveScanContext = createContext<LiveContext | null>(null);

export function useLiveScanSession() {
  return useContext(LiveScanContext);
}
