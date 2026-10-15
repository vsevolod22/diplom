function fenceContainer(line: string, opening: boolean) {
  let offset = 0;
  let indent = 0;
  let quotes = 0;
  let lists = 0;
  for (;;) {
    while (line[offset] === ' ' || line[offset] === '\t') {
      indent += line[offset] === '\t' ? 4 - (indent % 4) : 1;
      offset++;
    }
    if (line[offset] === '>') {
      quotes++;
      offset++;
      if (line[offset] === ' ') offset++;
      continue;
    }
    // List markers can open a container, but inside fenced code they are literal body text.
    const marker = opening ? /^(?:[-+*]|\d{1,9}[.)])(?=[ \t])/.exec(line.slice(offset)) : null;
    if (!marker) break;
    lists++;
    offset += marker[0].length;
    indent += marker[0].length;
  }
  return { content: line.slice(offset), indent, quotes, lists };
}
export function unfinishedFence(text: string) {
  let fence: { mark: string; length: number; indent: number; quotes: number } | null = null;
  for (const line of text.split('\n')) {
    const container = fenceContainer(line.replace(/\r$/, ''), fence === null);
    if (
      fence &&
      container.content &&
      (container.quotes !== fence.quotes || container.indent < fence.indent)
    ) {
      // An implicit container end is ambiguous without a full Markdown parser: prefer exact fallback.
      return true;
    }
    const match = /^(`{3,}|~{3,})(.*)$/.exec(container.content);
    if (!match) continue;
    if (!fence) {
      if (match[1][0] === '`' && match[2].includes('`')) continue;
      fence = {
        mark: match[1][0],
        length: match[1].length,
        indent: container.lists ? container.indent : 0,
        quotes: container.quotes,
      };
    } else if (
      match[1][0] === fence.mark &&
      match[1].length >= fence.length &&
      container.indent <= fence.indent + 3 &&
      !match[2].trim()
    )
      fence = null;
  }
  return fence !== null;
}
export function safeMarkdownUrl(value: string | undefined) {
  // eslint-disable-next-line no-control-regex
  if (!value || /[\s\\\u0000-\u001f\u007f]/u.test(value) || !value.startsWith('https://')) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.hostname && !url.username && !url.password ? url.href : null;
  } catch {
    return null;
  }
}
