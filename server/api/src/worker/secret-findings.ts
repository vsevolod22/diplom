import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { validateArchiveJson, type ArchiveBinding } from '../oci/archive-identity.js';
import { PUBLIC_IMAGE_LIMITS, isPublicReceipt } from '../oci/public-image-policy.js';

export type SecretFinding = { findingId: string; ruleId: string; line: number | null; evidenceRef: string };
export const MAX_FINDINGS = 1000;
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const digest = (value: unknown): value is string => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);

// Scanner strings are untrusted, and can contain the matched secret itself. Keep only
// bounded rule identifiers and numeric positions; never persist source text or paths.
export function parseSecretFindings(value: unknown, binding?: ArchiveBinding): SecretFinding[] {
  if (binding) validateArchiveJson(value, binding);
  const maxLayers = binding && isPublicReceipt(binding.receipt) ? PUBLIC_IMAGE_LIMITS.maxLayers : 32;
  if (!object(value)) throw new Error('Invalid scanner output');
  const report = value as { Results?: unknown; SchemaVersion?: unknown; ArtifactType?: unknown;
    Metadata?: { ImageID?: unknown; Layers?: unknown; DiffIDs?: unknown; ImageConfig?: unknown } };
  // Trivy can omit Results for a clean image. Empty/meaningless result arrays
  // need the same positive inspection evidence; identity alone is not coverage.
  const layers = report.Metadata?.Layers, diffIds = report.Metadata?.DiffIDs;
  const cleanImage = report.SchemaVersion === 2 && report.ArtifactType === 'container_image' &&
    Array.isArray(layers) && layers.length > 0 && layers.length <= maxLayers && Array.isArray(diffIds) &&
    diffIds.length === layers.length && diffIds.every(digest) && object(report.Metadata?.ImageConfig) &&
    layers.every((layer, index) => object(layer) && layer.DiffID === diffIds[index] &&
      (layer.Size === undefined || Number.isSafeInteger(layer.Size) && (layer.Size as number) >= 0));
  if (report.Results !== undefined && !Array.isArray(report.Results)) throw new Error('Invalid scanner output');
  const findings: SecretFinding[] = [];
  const results = (report.Results ?? []) as unknown[];
  if (results.length > MAX_FINDINGS) throw new Error('Too many scanner results');
  const config = report.Metadata?.ImageConfig;
  const image = binding?.receipt.digest ?? (digest(report.Metadata?.ImageID) ? report.Metadata.ImageID : null);
  const platform = binding?.receipt.platform ?? (object(config) && config.os === 'linux' &&
    typeof config.architecture === 'string' && /^[a-z0-9]{1,32}$/.test(config.architecture) &&
    (config.variant === undefined || typeof config.variant === 'string' && /^[a-z0-9]{1,32}$/.test(config.variant))
    ? ['linux', config.architecture, config.variant].filter(Boolean).join('/') : null);
  // Report-local opaque locations use equality, never a digest of an untrusted
  // path (which can itself contain a secret). No raw location leaves this call.
  const locations: Array<{ target: string; kind: unknown; type: unknown }> = [];
  const seen = new Map<string, Record<string, unknown>[]>();
  let inputCount = 0;
  for (let r = 0; r < results.length; r++) {
    const result = results[r];
    if (!object(result)) throw new Error('Invalid scanner result');
    if (result.Vulnerabilities !== undefined && (!Array.isArray(result.Vulnerabilities) ||
        result.Vulnerabilities.length > 0)) throw new Error('Unexpected scanner coverage');
    const secrets = (result as { Secrets?: unknown }).Secrets;
    if (secrets !== undefined && !Array.isArray(secrets)) throw new Error('Invalid secrets');
    if (!Array.isArray(secrets)) continue;
    // Limit INPUT observations too: duplicate floods cannot evade the old bound.
    if (secrets.length > MAX_FINDINGS) throw new Error('Too many findings');
    let location: number | undefined;
    if (typeof result.Target === 'string' && result.Target.length > 0 && result.Target.length <= 4096) {
      location = locations.findIndex(item => item.target === result.Target &&
        isDeepStrictEqual(item.kind, result.Class) && isDeepStrictEqual(item.type, result.Type));
      if (location < 0) { location = locations.length; locations.push({ target: result.Target, kind: result.Class, type: result.Type }); }
    }
    for (let s = 0; s < secrets.length; s++) {
      if (++inputCount > MAX_FINDINGS) throw new Error('Too many findings');
      const item = secrets[s];
      if (!object(item)) throw new Error('Invalid finding');
      const { RuleID, StartLine } = item as { RuleID?: unknown; StartLine?: unknown };
      if (typeof RuleID !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/.test(RuleID)) throw new Error('Unsafe rule');
      const line = Number.isSafeInteger(StartLine) && (StartLine as number) >= 0 && (StartLine as number) <= 10_000_000 ? StartLine as number : null;
      const ruleId = `rule-${createHash('sha256').update(RuleID).digest('hex').slice(0, 16)}`;
      if (location !== undefined) {
        const key = JSON.stringify([image, platform, ruleId, location, line]);
        const observations = seen.get(key) ?? [];
        // Same semantic position can contain distinct matches/ranges/layer evidence.
        // Compare originals privately; never hash/serialize Match, Code or Target.
        if (observations.some(previous => isDeepStrictEqual(previous, item))) continue;
        observations.push(item); seen.set(key, observations);
      }
      // Keep the FIRST original coordinates, including gaps: persisted legacy IDs
      // and distinct observations must not be renumbered just because a duplicate fell out.
      findings.push({ findingId: `secret-${r}-${s}`, ruleId, line, evidenceRef: `result-${r}-secret-${s}` });
    }
  }
  if (findings.length === 0 && !cleanImage) throw new Error('Missing secret inspection evidence');
  return findings;
}
