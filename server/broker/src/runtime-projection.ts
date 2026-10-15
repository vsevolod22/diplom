import { createHash } from 'node:crypto';
import { SafeFailure } from './contracts.js';
import { project, canonical } from './projection.js';
import type { Capture } from '../../runtime/src/contract.js';
export type RuntimeBinding = Capture['binding'];
export class RuntimeProjectionFailure extends SafeFailure {
  readonly runtimeReason = 'INVALID_RUNTIME_INPUT' as const;
  constructor() {
    super('upstream');
  }
}
// Called only inside the trusted broker after SAME matching-ID response projection.
export function projectRuntime(
  raw: unknown,
  snapshot: ReturnType<typeof project>,
  binding: RuntimeBinding,
  startedAt: number,
  imageConfigSemantics: boolean,
): Capture {
  const top = raw as Record<string, unknown>;
  if (
    !top.State ||
    typeof top.State !== 'object' ||
    Array.isArray(top.State) ||
    typeof (top.State as Record<string, unknown>).Running !== 'boolean'
  )
    throw new RuntimeProjectionFailure();
  const running = (top.State as { Running: boolean }).Running;
  const configDigest =
    imageConfigSemantics && typeof top.Image === 'string' && /^sha256:[a-f0-9]{64}$/.test(top.Image)
      ? top.Image
      : null;
  const body = {
    schemaVersion: 'runtime-capture-v1' as const,
    snapshot,
    startedAt: new Date(startedAt).toISOString(),
    endedAt: snapshot.observedAt,
    running,
    imageConfigDigest: configDigest,
    imageSemantics: configDigest ? ('docker-config-sha256-v1' as const) : ('unknown' as const),
    binding: { ...binding },
  };
  return {
    ...body,
    hash: createHash('sha256')
      .update(`runtime-capture-v1\n${canonical(body)}`)
      .digest('hex'),
  };
}
