// Full immutable citations share the original 32 * 2048-byte aggregate budget.
// A single source may use more of that budget, but must still fit one existing
// NDJSON line. Derive its ceiling from the largest legal fixed frame envelope,
// including the final newline; do not enlarge transport or physical reservations.
const uuid = '00000000-0000-0000-0000-000000000000';
const largestCitationFrame = {
  v: 1, deliveryMode: 'validated-completed-reply', nativeProviderStream: false,
  scanId: uuid, digest: `sha256:${'0'.repeat(64)}`, platform: 'linux/amd64', reportVersion: '0'.repeat(64),
  epoch: uuid, revision: Number.MAX_SAFE_INTEGER, mutationId: uuid, turnId: uuid,
  type: 'citation', seq: 51, index: 31, source: null,
};
export const CHAT_SOURCE_BUDGET = Object.freeze({
  revision: 'immutable-full-citations-aggregate-v2',
  citationBytes: 8192 - (Buffer.byteLength(JSON.stringify(largestCitationFrame)) - 4 + 1),
  sourcesBytes: 32 * 2048,
});

// Sum objects, not the array framing: the unchanged reservation proof separately
// includes up to 31 commas and the reply envelope's brackets.
export function chatSourcesWithinBudget(sources: readonly unknown[]): boolean {
  let total = 0;
  return sources.length <= 32 && sources.every(source => {
    if (!source || typeof source !== 'object' || Array.isArray(source)) return false;
    try {
      const serialized = JSON.stringify(source);
      if (typeof serialized !== 'string') return false;
      const size = Buffer.byteLength(serialized);
      total += size;
      return size <= CHAT_SOURCE_BUDGET.citationBytes && total <= CHAT_SOURCE_BUDGET.sourcesBytes;
    } catch { return false; }
  });
}
