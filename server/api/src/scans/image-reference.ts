import { createHash } from 'node:crypto';

export type ImageReference = { registry: string; repository: string; selector: string; canonical: string };

// Deliberately narrower than Docker's permissive reference grammar: no implicit registry,
// scheme, port, IP literal, Unicode, credentials or ambiguous normalization.
export function parseImageReference(input: unknown, allowedRegistries: ReadonlySet<string>): ImageReference {
  if (typeof input !== 'string' || input.length > 512 || !input || input.trim() !== input ||
      /[^\x21-\x7e]/.test(input) || /[?#\\%]/.test(input)) throw new TypeError('Invalid image reference');
  const slash = input.indexOf('/');
  if (slash < 1) throw new TypeError('Explicit registry required');
  const registry = input.slice(0, slash);
  if (!/^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+$/.test(registry) ||
      !allowedRegistries.has(registry)) throw new TypeError('Registry not allowed');
  const rest = input.slice(slash + 1);
  const match = /^([a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)(?::([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})|@(sha256:[a-f0-9]{64}))?$/.exec(rest);
  if (!match || match[1].split('/').some(part => part.length > 128)) throw new TypeError('Invalid repository or selector');
  const repository = match[1];
  const selector = match[3] || match[2] || 'latest';
  return { registry, repository, selector, canonical: `${registry}/${repository}${match[3] ? '@' : ':'}${selector}` };
}

export function requestFingerprint(reference: ImageReference, checks: readonly string[], scope: string): string {
  return createHash('sha256').update(JSON.stringify([reference.canonical, [...checks].sort(), scope])).digest('hex');
}
