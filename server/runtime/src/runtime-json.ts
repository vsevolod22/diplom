// Dedicated raw-wire parser: integer lexemes are checked before JSON.parse loses them.
export function parseRuntimeJson(bytes: Uint8Array): unknown {
  const fail = (): never => {
    throw new Error('INVALID_RUNTIME_INPUT');
  };
  if (bytes.byteLength > 65536) fail();
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return fail();
  }
  let at = 0;
  let nodes = 0;
  const space = () => {
    while (/\s/.test(text[at] ?? '') && at < text.length) {
      if (!/[ \r\n\t]/.test(text[at])) fail();
      at++;
    }
  };
  const string = (): string => {
    const start = at++;
    while (at < text.length) {
      if (text[at] === '\\') {
        at += 2;
        continue;
      }
      if (text[at++] === '"') {
        let value: unknown;
        try {
          value = JSON.parse(text.slice(start, at));
        } catch {
          return fail();
        }
        if (
          typeof value !== 'string' ||
          new TextEncoder().encode(value).length > 1024 ||
          /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)
        )
          fail();
        return value as string;
      }
    }
    return fail();
  };
  const value = (depth: number): unknown => {
    if (++nodes > 4096 || depth > 32) fail();
    space();
    const c = text[at];
    if (c === '"') return string();
    if (c === '{') {
      at++;
      space();
      const out: Record<string, unknown> = {};
      const keys = new Set<string>();
      if (text[at] === '}') {
        at++;
        return out;
      }
      while (at < text.length) {
        space();
        if (text[at] !== '"') fail();
        const key = string();
        if (
          new TextEncoder().encode(key).length > 128 ||
          keys.has(key) ||
          ['__proto__', 'prototype', 'constructor'].includes(key) ||
          keys.size >= 256
        )
          fail();
        keys.add(key);
        space();
        if (text[at++] !== ':') fail();
        out[key] = value(depth + 1);
        space();
        if (text[at] === '}') {
          at++;
          return out;
        }
        if (text[at++] !== ',') fail();
      }
      return fail();
    }
    if (c === '[') {
      at++;
      space();
      const out: unknown[] = [];
      if (text[at] === ']') {
        at++;
        return out;
      }
      while (at < text.length) {
        if (out.length >= 256) fail();
        out.push(value(depth + 1));
        space();
        if (text[at] === ']') {
          at++;
          return out;
        }
        if (text[at++] !== ',') fail();
      }
      return fail();
    }
    for (const [literal, result] of [
      ['true', true],
      ['false', false],
      ['null', null],
    ] as const) {
      if (text.startsWith(literal, at)) {
        at += literal.length;
        return result;
      }
    }
    const match = /^-?(?:0|[1-9][0-9]*)/.exec(text.slice(at));
    if (!match) return fail();
    at += match[0].length;
    if (/[.eE0-9]/.test(text[at] ?? '') || match[0] === '-0') fail();
    const n = Number(match[0]);
    if (!Number.isSafeInteger(n)) fail();
    return n;
  };
  const result = value(1);
  space();
  if (at !== text.length) fail();
  return result;
}
