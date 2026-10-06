import { fail, POLICY } from './policy.js';

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };
export const isObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
export const has = (object: object, key: string): boolean => Object.hasOwn(object, key);

/** Bounds are enforced while descending/tokenizing, not after unbounded JSON.parse.
 * JSON.parse is used only for a single already-bounded string token.
 */
export function parseBoundedJson(bytes: Uint8Array): Json {
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { return fail('INVALID_CONFIG'); }
  let cursor = 0;
  let nodes = 0;
  const invalid = (): never => fail('INVALID_CONFIG');
  const limit = (): never => fail('CONFIG_LIMIT_EXCEEDED');
  const whitespace = () => { while (/^[\t\n\r ]$/.test(text[cursor] ?? '')) cursor++; };
  const string = (maxBytes: number): string => {
    const start = cursor++;
    while (cursor < text.length) {
      // A decoded UTF-8 byte can use at most six source characters (\uXXXX).
      if (cursor - start > maxBytes * 6 + 1) limit();
      const character = text[cursor++];
      if (character === '"') {
        let decoded: unknown;
        try { decoded = JSON.parse(text.slice(start, cursor)); } catch { return invalid(); }
        if (typeof decoded !== 'string') return invalid();
        if (Buffer.byteLength(decoded, 'utf8') > maxBytes) limit();
        // Reject lone surrogate escapes, which have no exact UTF-8 representation.
        if (/[\uD800-\uDFFF]/u.test(decoded)) return invalid();
        return decoded;
      }
      if (character === '\\') {
        const escape = text[cursor++];
        if (escape === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(cursor, cursor + 4))) return invalid();
          cursor += 4;
        } else if (!escape || !'"\\/bfnrt'.includes(escape)) return invalid();
      } else if (character.charCodeAt(0) < 32) return invalid();
    }
    return invalid();
  };
  const value = (depth: number): Json => {
    if (depth > POLICY.depth || ++nodes > POLICY.nodes) limit();
    whitespace();
    const character = text[cursor];
    if (character === '"') return string(POLICY.stringBytes);
    if (character === '{') {
      cursor++;
      const object: JsonObject = Object.create(null);
      let members = 0;
      whitespace();
      if (text[cursor] === '}') { cursor++; return object; }
      while (true) {
        if (++members > POLICY.collection) limit();
        whitespace();
        if (text[cursor] !== '"') return invalid();
        const key = string(POLICY.keyBytes);
        if (has(object, key)) return invalid();
        whitespace();
        if (text[cursor++] !== ':') return invalid();
        object[key] = value(depth + 1);
        whitespace();
        const separator = text[cursor++];
        if (separator === '}') return object;
        if (separator !== ',') return invalid();
      }
    }
    if (character === '[') {
      cursor++;
      const array: Json[] = [];
      whitespace();
      if (text[cursor] === ']') { cursor++; return array; }
      while (true) {
        if (array.length >= POLICY.collection) limit();
        array.push(value(depth + 1));
        whitespace();
        const separator = text[cursor++];
        if (separator === ']') return array;
        if (separator !== ',') return invalid();
      }
    }
    for (const [token, literal] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(token, cursor)) { cursor += token.length; return literal; }
    }
    // Scan rather than slicing the remaining document for every number.
    const start = cursor;
    if (text[cursor] === '-') cursor++;
    if (text[cursor] === '0') cursor++;
    else {
      if (!/^[1-9]$/.test(text[cursor] ?? '')) return invalid();
      while (/^[0-9]$/.test(text[cursor] ?? '')) cursor++;
    }
    if (text[cursor] === '.') {
      cursor++;
      const fraction = cursor;
      while (/^[0-9]$/.test(text[cursor] ?? '')) cursor++;
      if (cursor === fraction) return invalid();
    }
    if (text[cursor] === 'e' || text[cursor] === 'E') {
      cursor++;
      if (text[cursor] === '+' || text[cursor] === '-') cursor++;
      const exponent = cursor;
      while (/^[0-9]$/.test(text[cursor] ?? '')) cursor++;
      if (cursor === exponent) return invalid();
    }
    const number = Number(text.slice(start, cursor));
    if (!Number.isFinite(number)) return invalid();
    return number;
  };
  const result = value(1);
  whitespace();
  if (cursor !== text.length) invalid();
  return result;
}
