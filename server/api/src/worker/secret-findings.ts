import { createHash } from 'node:crypto';

export type SecretFinding = { findingId: string; ruleId: string; line: number | null; evidenceRef: string };
export const MAX_FINDINGS = 1000;

// Scanner strings are untrusted, and can contain the matched secret itself. Keep only
// bounded rule identifiers and numeric positions; never persist source text or paths.
export function parseSecretFindings(value: unknown): SecretFinding[] {
  if (!value || typeof value !== 'object') throw new Error('Invalid scanner output');
  const report = value as { Results?: unknown; SchemaVersion?: unknown; ArtifactType?: unknown;
    Metadata?: { Layers?: unknown; DiffIDs?: unknown; ImageConfig?: unknown } };
  // Trivy omits Results for a clean image. Only accept that shape after a successful
  // subprocess and with evidence that an image with layers was actually inspected.
  const cleanImage = report.Results === undefined && report.SchemaVersion === 2 &&
    report.ArtifactType === 'container_image' && Array.isArray(report.Metadata?.Layers) &&
    report.Metadata.Layers.length > 0 && Array.isArray(report.Metadata.DiffIDs) &&
    report.Metadata.DiffIDs.length > 0 && report.Metadata.ImageConfig !== null &&
    typeof report.Metadata.ImageConfig === 'object';
  if (!Array.isArray(report.Results) && !cleanImage) throw new Error('Invalid scanner output');
  const findings: SecretFinding[] = [];
  const results = (report.Results ?? []) as unknown[];
  if (results.length > MAX_FINDINGS) throw new Error('Too many scanner results');
  for (let r = 0; r < results.length; r++) {
    const result = results[r];
    if (!result || typeof result !== 'object') throw new Error('Invalid scanner result');
    if (Array.isArray((result as { Vulnerabilities?: unknown }).Vulnerabilities) &&
        ((result as { Vulnerabilities: unknown[] }).Vulnerabilities.length > 0)) throw new Error('Unexpected scanner coverage');
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
  return findings;
}
