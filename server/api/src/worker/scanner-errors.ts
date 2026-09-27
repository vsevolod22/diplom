export type ScannerFailure = { errorCode: 'SCAN_UNAVAILABLE' | 'SCAN_TIMEOUT' | 'SCAN_FAILED'; stage: 'worker'; exitCode: number | null };

// Scanner diagnostics can contain bearer tokens and signed blob URLs. Never persist,
// return or log raw stdout/stderr, command-line arguments or the thrown Error object.
export function scannerFailure(exitCode: number | null, timedOut = false): ScannerFailure {
  return { errorCode: timedOut ? 'SCAN_TIMEOUT' : exitCode === null ? 'SCAN_UNAVAILABLE' : 'SCAN_FAILED',
    stage: 'worker', exitCode: Number.isInteger(exitCode) && exitCode! >= 0 && exitCode! <= 255 ? exitCode : null };
}
