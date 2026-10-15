// Proposed CLI supervisor of fixed LEAF children, NOT a process-tree/parent-death guarantee.
// No broad PID/group kills, OS settings, discovery or external authority service.
export const SUPERVISOR_ID = 'native-macos-fixed-leaf-supervisor-v2';
export const INVOCATION_MS = 5500;
export const SHUTDOWN_MS = 150;
const blocked = () => ({ host: 'blocked', reason: 'cleanup_unconfirmed', engineQueried: false });
const denied = () => ({ host: 'not_authorized', engineQueried: false });

export function supervise(work, { processLike = process, timers = { setTimeout, clearTimeout } } = {}) {
  const controller = new AbortController();
  return new Promise((resolve) => {
    let settled = false,
      stopped = false,
      exitCode = 0,
      shutdownTimer;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      timers.clearTimeout(invocationTimer);
      timers.clearTimeout(shutdownTimer);
      processLike.removeListener('SIGINT', interrupt);
      processLike.removeListener('SIGTERM', terminate);
      resolve({ result, exitCode: result?.host === 'blocked' ? 1 : exitCode });
    };
    const stop = (code) => {
      if (settled || stopped) return;
      stopped = true;
      exitCode = code;
      // Register finite fallback before notifying work; no successful late publication allowed.
      shutdownTimer = timers.setTimeout(() => finish(blocked()), SHUTDOWN_MS);
      controller.abort();
    };
    const interrupt = () => stop(130),
      terminate = () => stop(143);
    processLike.on('SIGINT', interrupt);
    processLike.on('SIGTERM', terminate);
    const invocationTimer = timers.setTimeout(() => stop(1), INVOCATION_MS);
    Promise.resolve()
      .then(() => work(controller.signal))
      .then(
        (result) => {
          if (stopped) finish(result?.host === 'blocked' ? blocked() : denied());
          else finish(result);
        },
        () => {
          // A thrown supervisor work callback cannot certify child cleanup.
          stop(1);
          finish(blocked());
        },
      );
  });
}
