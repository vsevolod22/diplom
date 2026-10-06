import { LIMITS, SafeFailure, type Limits } from './contracts.js';

// Preflight before JSON.parse: duplicate decoded keys and structural/string/node budgets.
// All retained input is bounded by upstreamBytes. Timers do not preempt synchronous CPU.
export function strictJson(bytes: Buffer, bound: Limits = LIMITS): unknown {
  const fail = (): never => {
    throw new SafeFailure('upstream');
  };
  if (bytes.length > bound.upstreamBytes) fail();
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return fail();
  }
  let pos = 0;
  let nodes = 0;
  const whitespace = () => {
    while (/^[\x20\t\r\n]$/.test(text[pos] ?? '')) pos++;
  };
  const node = () => {
    if (++nodes > bound.nodes) fail();
  };
  function string(): string {
    if (text[pos++] !== '"') fail();
    const start = pos - 1;
    let closed = false;
    while (pos < text.length) {
      const c = text[pos++];
      if (c === '"') {
        closed = true;
        break;
      }
      if (c.charCodeAt(0) < 32) fail();
      if (c === '\\') {
        const e = text[pos++];
        if (e === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(pos, pos + 4))) fail();
          pos += 4;
        } else if (!e || !'"\\/bfnrt'.includes(e)) fail();
      }
      if (pos - start > bound.stringBytes * 6 + 2) fail();
    }
    if (!closed) fail();
    let value: string;
    try {
      value = JSON.parse(text.slice(start, pos));
    } catch {
      return fail();
    }
    if (Buffer.byteLength(value) > bound.stringBytes) fail();
    // Reject escaped lone surrogates, not valid Unicode scalar strings.
    for (const c of value) {
      const n = c.codePointAt(0)!;
      if (n >= 0xd800 && n <= 0xdfff) fail();
    }
    return value;
  }
  const number = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  function value(depth: number): void {
    whitespace();
    node();
    if (depth > bound.depth) fail();
    const c = text[pos];
    if (c === '"') {
      string();
      return;
    }
    if (c === '{' || c === '[') {
      pos++;
      whitespace();
      const object = c === '{';
      const close = object ? '}' : ']';
      if (text[pos] === close) {
        pos++;
        return;
      }
      const keys = new Set<string>();
      let fields = 0;
      while (true) {
        if (object) {
          node();
          const key = string();
          if (keys.has(key) || ++fields > bound.fields) fail();
          keys.add(key);
          whitespace();
          if (text[pos++] !== ':') fail();
        }
        value(depth + 1);
        whitespace();
        if (text[pos] === close) {
          pos++;
          return;
        }
        if (text[pos++] !== ',') fail();
        whitespace();
      }
    }
    for (const token of ['true', 'false', 'null']) {
      if (text.startsWith(token, pos)) {
        pos += token.length;
        return;
      }
    }
    number.lastIndex = pos;
    const match = number.exec(text);
    if (!match || !Number.isFinite(Number(match[0]))) fail();
    pos = number.lastIndex;
  }
  value(1);
  whitespace();
  if (pos !== text.length) fail();
  try {
    return JSON.parse(text);
  } catch {
    return fail();
  }
}
