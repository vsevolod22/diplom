import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';

it('all passport variants use the actual inherited A1 dark/lime tokens without light/cyan overrides', () => {
  const css = readFileSync('src/features/scans/scan-a1.css', 'utf8');
  const start = css.indexOf('.scan-a1 .scan-a1__scene {');
  const scene = css.slice(start, css.indexOf('.scan-a1 .scan-a1__create-hero {', start));
  for (const declaration of [
    '--passport-bg: var(--a1-bg, #141324)',
    '--passport-surface: var(--a1-surface, #211f34)',
    '--passport-ink: var(--a1-ink, #faf8ff)',
    '--passport-muted: var(--a1-muted, #c6c0d6)',
    '--passport-accent: var(--a1-accent, #d1ff5e)',
    '--passport-line: var(--a1-line, #605b74)',
    'background: var(--passport-bg)',
    'background: var(--passport-surface)',
    'background: var(--passport-accent)',
    'color: var(--passport-bg)',
    'color: var(--passport-ink)',
    'color: var(--passport-muted)',
  ])
    expect(scene).toContain(declaration);
  expect(scene).not.toMatch(/#e8e5ef|#252139|#f6f4fa|#5c536e|#71d7db|#fca58e|animation:|transition:/);
  expect(scene.match(/--passport-accent:/g)).toHaveLength(1);
});
