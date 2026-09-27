import { useEffect, useRef } from 'react';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';
import { stateLabels } from './scanStateLabels';

const terminalStates = new Set<ScanStatus['state']>(['completed', 'partial', 'failed', 'cancelled']);

export function ScanStatusAnnouncement({ scan }: { scan: ScanStatus }) {
  const previous = useRef<{ scanId: string; stage?: string; state: ScanStatus['state'] } | null>(null);
  const region = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    const last = previous.current;
    if (last?.scanId === scan.scanId) {
      const enteredTerminal = terminalStates.has(scan.state) && !terminalStates.has(last.state);
      const changedStage = scan.stage && scan.stage !== last.stage;
      const message = enteredTerminal ? `Итог скана: ${stateLabels[scan.state]}` : changedStage ? `Этап скана: ${scan.stage}` : '';
      if (message && region.current) region.current.textContent = message;
    } else if (region.current) {
      region.current.textContent = '';
    }
    previous.current = { scanId: scan.scanId, state: scan.state, stage: scan.stage };
  }, [scan.scanId, scan.stage, scan.state]);

  return <p ref={region} aria-live="polite" aria-atomic="true" className="sr-only" />;
}

