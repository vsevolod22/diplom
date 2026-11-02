import { useSyncExternalStore } from 'react';
import { scanSession, subscribeScanSession } from './scanSession';

// Every subject change (including unverified -> null) advances this stable primitive snapshot.
const sessionGeneration = () => scanSession().generation;

export function useScanSession() {
  useSyncExternalStore(subscribeScanSession, sessionGeneration, sessionGeneration);
  return scanSession();
}
