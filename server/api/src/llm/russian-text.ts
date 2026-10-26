// This is a bounded script/identifier guard, not a language model or semantic-fidelity proof.
const tokenPattern = /(?<![\p{L}\p{N}_.])(?:C#|C\+\+|Node\.js|(?:CVE|TEMP)-[A-Za-z0-9-]+|[A-Za-z][A-Za-z0-9_+-]{0,79}|[0-9]+(?:\.[0-9]+)*(?:[-+][A-Za-z0-9.]+)?)(?![\p{L}\p{N}_]|\.(?=[\p{L}\p{N}_./]))/gu;
const names = new Set(['API', 'CPU', 'CVE', 'HTTP', 'HTTPS', 'JSON', 'RCE', 'SQL', 'SSL', 'TEMP', 'TLS', 'UTF', 'XML', 'XSS',
  'C#', 'C++', 'Node.js', 'OpenSSL', 'libxml2', 'Linux', 'Windows', 'Debian', 'Alpine', 'Phala']);
// Spelling is not authority: arbitrary CamelCase, snake_case and letter/digit words remain prose.
// Unknown technical proper names may fail closed rather than exempt untranslated English.
const technical = (token: string) => names.has(token) || /^CVE-\d{4}-\d{4,12}$/i.test(token) ||
  /^TEMP-\d{7}-[A-Fa-f0-9]{6}$/i.test(token) || /^[0-9]+(?:\.[0-9]+)*(?:-r[0-9]+)?$/.test(token);
export function technicalIdentifiers(text: string): string[] {
  return [...new Set((text.match(tokenPattern) ?? []).filter(technical))];
}
export function withoutPreservedIdentifiers(text: string, original: string): string {
  const allowed = new Set(technicalIdentifiers(original));
  return text.replace(tokenPattern, token => allowed.has(token) ? ' ' : token);
}
export function russianHumanText(text: string, reference: string): boolean {
  const prose = withoutPreservedIdentifiers(text, reference);
  const russian = prose.match(/[А-Яа-яЁё]/gu)?.length ?? 0;
  const other = prose.replace(/[А-Яа-яЁё]/gu, '').match(/\p{L}/gu)?.length ?? 0;
  if (!russian && !other) return reference.includes(text) && (technicalIdentifiers(text).length > 0 || /^[\d\s.,:+-]+$/.test(text));
  // A Russian prefix cannot compensate for an untranslated sentence. Only the finite,
  // source-bound identifiers above may contain non-Russian letters.
  return russian >= 3 && other === 0;
}
export const advisoryIdentifiers = (text: string): string[] => [...new Set(text.match(/\b(?:CVE|TEMP)-[A-Za-z0-9-]+/gi) ?? [])].sort();
export function groundedIdentifiers(text: string, reference: unknown): boolean {
  const allowed = new Set(advisoryIdentifiers(JSON.stringify(reference)));
  return advisoryIdentifiers(text).every(id => allowed.has(id));
}
// Permit the exact standalone runtime brand, not domains, URLs, paths or differently cased hostnames.
export function withoutRuntimeBrand(text: string): string {
  return text.replace(/(?<![\p{L}\p{N}_./@])Node\.js(?=$|[\s,;!()]|\.(?=$|\s))/gu, 'Runtime');
}
