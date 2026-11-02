import { isDebianDlaId } from '../worker/public-image-evidence.js';
import { tokenWitness, type GroundingWitness } from './grounding-witness.js';
import { insufficientRussian, type LanguageRejection, type LanguageTokenClass } from './language-rejection.js';

// This is a bounded script/identifier guard, not a language model or semantic-fidelity proof.
const tokenPattern = /(?<![\p{L}\p{N}_.])(?:C#|C\+\+|Node\.js|(?:CVE|TEMP|DLA)-[A-Za-z0-9-]+|[A-Za-z][A-Za-z0-9_+-]{0,79}|[0-9]+(?:\.[0-9]+)*(?:[-+][A-Za-z0-9.]+)?)(?![\p{L}\p{N}_]|\.(?=[\p{L}\p{N}_./]))/gu;
const names = new Set(['API', 'CPU', 'CVE', 'HTTP', 'HTTPS', 'JSON', 'RCE', 'SQL', 'SSL', 'TEMP', 'TLS', 'UTF', 'XML', 'XSS',
  'C#', 'C++', 'Node.js', 'OpenSSL', 'libxml2', 'Linux', 'Windows', 'Debian', 'Alpine', 'Phala']);
// Spelling is not authority: arbitrary CamelCase, snake_case and letter/digit words remain prose.
// Unknown technical proper names may fail closed rather than exempt untranslated English.
const technical = (token: string) => names.has(token) || /^CVE-\d{4}-\d{4,12}$/i.test(token) ||
  /^TEMP-\d{7}-[A-Fa-f0-9]{6}$/i.test(token) || isDebianDlaId(token) || /^[0-9]+(?:\.[0-9]+)*(?:-r[0-9]+)?$/.test(token);
export function technicalIdentifiers(text: string): string[] {
  return [...new Set((text.match(tokenPattern) ?? []).filter(technical))];
}
export function withoutPreservedIdentifiers(text: string, original: string): string {
  const allowed = new Set(technicalIdentifiers(original));
  return text.replace(tokenPattern, token => allowed.has(token) ? ' ' : token);
}
export function russianHumanText(text: string, reference: string): boolean {
  return russianHumanTextFailure(text, reference) === undefined;
}
// The boolean API and public diagnostics share this exact mask and acceptance
// decision, including the legacy identifier-only special case. Callback inputs
// are ephemeral positions in this local view, never diagnostic output.
export function russianHumanTextFailure(text: string, reference: string,
  classify?: (prose: string, firstLetter: number) => LanguageTokenClass): LanguageRejection | undefined {
  const prose = withoutPreservedIdentifiers(text, reference);
  const russian = prose.match(/[А-Яа-яЁё]/gu)?.length ?? 0;
  const other = prose.replace(/[А-Яа-яЁё]/gu, '').match(/\p{L}/gu) ?? [];
  if (!russian && !other.length) {
    if (reference.includes(text) && (technicalIdentifiers(text).length > 0 || /^[\d\s.,:+-]+$/.test(text))) return undefined;
  } else if (russian >= 3 && other.length === 0) return undefined;
  // Preserve the minimum-Russian predicate's priority. No token is blamed when
  // the text fails that predicate, even if non-Russian letters are also present.
  if (russian < 3) return insufficientRussian();
  const latin = other.some(letter => /\p{Script=Latin}/u.test(letter));
  const otherScript = other.some(letter => !/\p{Script=Latin}/u.test(letter));
  const first = /(?![А-Яа-яЁё])\p{L}/u.exec(prose);
  return Object.freeze({ reason: latin && otherScript ? 'mixed' : latin ? 'residual_latin' : 'residual_other_script',
    tokenClass: first && classify ? classify(prose, first.index) : 'indeterminate' });
}
export const advisoryIdentifiers = (text: string): string[] => [...new Set(text.match(/\b(?:CVE|TEMP|DLA)-[A-Za-z0-9-]+/gi) ?? [])].sort();
export function groundedIdentifiers(text: string, reference: unknown): boolean {
  return advisoryGroundingWitness(text, reference) === undefined;
}
export function advisoryGroundingWitness(text: string, reference: unknown): GroundingWitness | undefined {
  const allowed = new Set(advisoryIdentifiers(JSON.stringify(reference)));
  // Preserve the existing sorted-unique check order, not textual occurrence order.
  // A deduplicated ID may have several occurrences with different boundaries.
  for (const id of advisoryIdentifiers(text)) {
    if (!allowed.has(id)) return tokenWitness(id, 'no_cited_value_match', 'indeterminate');
  }
  return undefined;
}
// Permit the exact standalone runtime brand, not domains, URLs, paths or differently cased hostnames.
export function withoutRuntimeBrand(text: string): string {
  return text.replace(/(?<![\p{L}\p{N}_./@])Node\.js(?=$|[\s,;!()]|\.(?=$|\s))/gu, 'Runtime');
}
