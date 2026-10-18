import { createHash } from 'node:crypto';
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
    Metadata?: { Layers?: unknown; DiffIDs?: unknown; ImageConfig?: unknown } };
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
  for (let r = 0; r < results.length; r++) {
    const result = results[r];
    if (!object(result)) throw new Error('Invalid scanner result');
    if (result.Vulnerabilities !== undefined && (!Array.isArray(result.Vulnerabilities) ||
        result.Vulnerabilities.length > 0)) throw new Error('Unexpected scanner coverage');
    const secrets = (result as { Secrets?: unknown }).Secrets;
    if (secrets !== undefined && !Array.isArray(secrets)) throw new Error('Invalid secrets');
    if (!Array.isArray(secrets)) continue;
    for (let s = 0; s < secrets.length; s++) {
      if (findings.length >= MAX_FINDINGS) throw new Error('Too many findings');
      const item = secrets[s];
      if (!item || typeof item !== 'object') throw new Error('Invalid finding');
      const { RuleID, StartLine } = item as { RuleID?: unknown; StartLine?: unknown };
      if (typeof RuleID !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/.test(RuleID)) throw new Error('Unsafe rule');
      const line = Number.isSafeInteger(StartLine) && (StartLine as number) >= 0 && (StartLine as number) <= 10_000_000 ? StartLine as number : null;
      findings.push({ findingId: `secret-${r}-${s}`, ruleId: `rule-${createHash('sha256').update(RuleID).digest('hex').slice(0, 16)}`,
              line, evidenceRef: `result-${r}-secret-${s}` });
    }
  }
  if (findings.length === 0 && !cleanImage) throw new Error('Missing secret inspection evidence');
  return findings;
}
