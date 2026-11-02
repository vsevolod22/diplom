// Finite, diagnostic-only metadata. No source strings or validation-view offsets escape.
export const LANGUAGE_REASONS = Object.freeze(['insufficient_russian', 'residual_latin', 'residual_other_script', 'mixed'] as const);
export const LANGUAGE_TOKEN_CLASSES = Object.freeze(['cited_identity', 'cited_ecosystem', 'conventional_report_term', 'unknown', 'indeterminate'] as const);
export type LanguageTokenClass = typeof LANGUAGE_TOKEN_CLASSES[number];
export type LanguageRejection = Readonly<{ reason: typeof LANGUAGE_REASONS[number]; tokenClass: LanguageTokenClass }>;
export const insufficientRussian = (): LanguageRejection => Object.freeze({ reason: 'insufficient_russian', tokenClass: 'indeterminate' });

export function finiteLanguageRejection(value: unknown): LanguageRejection | undefined {
  if (!value || typeof value !== 'object') return undefined;
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.length !== 2 || !keys.includes('reason') || !keys.includes('tokenClass')) return undefined;
    const reason = Object.getOwnPropertyDescriptor(value, 'reason')?.value;
    const tokenClass = Object.getOwnPropertyDescriptor(value, 'tokenClass')?.value;
    if (!LANGUAGE_REASONS.includes(reason) || !LANGUAGE_TOKEN_CLASSES.includes(tokenClass)) return undefined;
    return Object.freeze({ reason, tokenClass });
  } catch { return undefined; }
}

type LanguageSources = Readonly<{
  identities: ReadonlySet<string>;
  ecosystems: ReadonlySet<string>;
  reportTerms: ReadonlySet<string>;
}>;
// Called only for the first residual letter in the evaluator's final masked prose.
// This tokenizer cannot authorize/mask anything. Keep domain/path/compound syntax
// together rather than reporting a known substring as a cited identity.
export function residualTokenClass(prose: string, firstLetter: number, sources: LanguageSources): LanguageTokenClass {
  if (prose.length > 16384 || sources.identities.size + sources.ecosystems.size + sources.reportTerms.size > 256)
    return 'indeterminate';
  for (const match of prose.matchAll(/[\p{L}\p{M}\p{N}_./@:+~!,\-\u2010-\u2015]+/gu)) {
    if (match.index > firstLetter) break;
    if (match.index + match[0].length <= firstLetter) continue;
    const token = match[0];
    if (token.length > 256) return 'indeterminate';
    // Only a terminal sentence-punctuation interpretation is considered, and only
    // at a finite prose boundary. If both interpretations are known, it is ambiguous.
    const terminal = /^(?:$|\s|[;()!?«»“”"'‘’‹›…])/u.test(prose.slice(match.index + token.length));
    const trimmed = terminal ? token.replace(/[.,:!]+$/u, '') : token;
    const candidates = new Set([token, trimmed]);
    let matched: LanguageTokenClass | undefined;
    for (const candidate of candidates) {
      const classes: LanguageTokenClass[] = [];
      if (sources.identities.has(candidate)) classes.push('cited_identity');
      if (sources.ecosystems.has(candidate)) classes.push('cited_ecosystem');
      if (sources.reportTerms.has(candidate)) classes.push('conventional_report_term');
      if (classes.length > 1 || classes.length && matched) return 'indeterminate';
      if (classes.length) matched = classes[0];
    }
    if (matched) return matched;
    // "Unknown" means a complete simple word is absent from these dictionaries,
    // not that it is absent from arbitrary source JSON or is factually incorrect.
    return /^[\p{L}\p{N}_]+$/u.test(trimmed) ? 'unknown' : 'indeterminate';
  }
  return 'indeterminate';
}
