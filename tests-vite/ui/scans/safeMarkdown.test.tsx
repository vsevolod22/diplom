import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CopyText, SafeMarkdown } from '@/features/scans/safeMarkdown';
import SafeMarkdownRenderer from '@/features/scans/SafeMarkdownRenderer';
import { safeMarkdownUrl, unfinishedFence } from '@/features/scans/safeMarkdownPolicy';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
it('R4 copy feedback is separated from the button label without changing copied text', async () => {
  const text = '- ```js\n  Exact unfinished text',
    writeText = vi.fn(async () => {});
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  const { container } = render(<CopyText text={text} />);
  fireEvent.click(screen.getByRole('button', { name: 'Скопировать текст' }));
  await act(async () => {});
  expect(screen.getByRole('status').textContent).toBe('Скопировано');
  expect(container.textContent).toBe('Скопировать текст Скопировано');
  expect(writeText).toHaveBeenCalledWith(text);
  writeText.mockRejectedValueOnce(new Error('denied'));
  fireEvent.click(screen.getByRole('button', { name: 'Скопировать текст' }));
  await act(async () => {});
  expect(container.textContent).toBe('Скопировать текст Копирование недоступно; выделите текст вручную.');
  expect(writeText).toHaveBeenNthCalledWith(2, text);
  expect(container.querySelector('script,a,img,pre,code')).toBeNull();
});
it('unfinished fences (length/type/nested markers) stay plain, exactly copyable and inert', async () => {
  const text = '```js\n<script>alert(1)</script>\n[jump](javascript:alert)';
  const writeText = vi.fn(async () => {});
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  const { container, rerender } = render(<SafeMarkdown text={text} />);
  expect(container.querySelector('pre')?.textContent).toBe(text);
  expect(container.querySelector('script,a,img')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Скопировать текст' }));
  await act(async () => {});
  expect(writeText).toHaveBeenCalledWith(text);
  rerender(<SafeMarkdown text={'~~~\nnot closed\n```'} />);
  expect(container.querySelector('pre')?.textContent).toContain('not closed');
  expect(unfinishedFence('````\n```\n')).toBe(true);
  expect(unfinishedFence('````\n````\n')).toBe(false);
  expect(unfinishedFence('~~~\n```\n~~~')).toBe(false);
});
const nestedUnfinished = [
  ['list backticks', '- ```js\n  alert(1)'],
  ['list tildes', '- ~~~js\n  inert text'],
  ['plus list', '+ ```ts\n  **not rich**'],
  ['star list', '* ~~~text\n  inert'],
  ['ordered period', '1. ```js\n   inert'],
  ['ordered parenthesis', '12) ~~~js\n    inert'],
  ['nested unordered list', '- item\n  - ```js\n    inert'],
  ['nested same-line list', '- - ~~~js\n    inert'],
  ['indented ordered list', '  2. ```js\n     inert'],
  ['tab continuation', '- ```js\n\talert(1)'],
  ['blockquote', '> ```js\n> inert'],
  ['nested blockquote list', '> > - ~~~js\n> >   inert'],
  ['list with blockquote', '- > ```js\n  > inert'],
  ['mixed nested containers', '> - > 1. ~~~js\n>   >    inert'],
  ['list-looking code is not a close', '- ```js\n  - ```\n  still code'],
  ['outside list fence is a new incomplete block', '- ```js\n```\nnot a valid list close'],
  ['wrong fence mark', '- ```js\n  ~~~'],
  ['short nested close', '- ````js\n  ```'],
  ['closing info is not a close', '- ~~~js\n  ~~~ extra'],
] as const;
it.each(nestedUnfinished)(
  'R2 nested unfinished %s uses exact inert fallback and exact whole-message copy',
  async (_name, text) => {
    expect(unfinishedFence(text)).toBe(true);
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    const { container } = render(<SafeMarkdown text={text} />);
    await act(async () => {});
    expect(container.querySelector('pre')?.textContent).toBe(text);
    expect(container.querySelector('script,img,svg,iframe,a,ul,ol,strong,[data-streamdown]')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Скопировать текст' }));
    await act(async () => {});
    expect(writeText).toHaveBeenCalledWith(text);
  },
);
it.each([
  ['unordered close', '- ```js\n  inert\n  ```'],
  ['tilde close', '- ~~~js\n  inert\n  ~~~~'],
  ['ordered close', '12) ```js\n    inert\n    ```'],
  ['nested list close', '- item\n  - ```js\n    inert\n    ```'],
  ['same-line nested close', '- - ~~~js\n    inert\n    ~~~'],
  ['blockquote close', '> ```js\n> inert\n> ```'],
  ['quoted nested list close', '> > - ~~~js\n> >   inert\n> >   ~~~'],
  ['list with quote close', '- > ```js\n  > inert\n  > ```'],
  ['mixed nested close', '> - > 1. ~~~js\n>   >    inert\n>   >    ~~~'],
  ['list-looking body and real close', '- ```js\n  - ```\n  ```'],
  ['ordinary prose and inline backticks', '- prose with ``` inline\n1. ordinary text'],
])('R2 completed container control %s does not remain unfinished', (_name, text) => {
  expect(unfinishedFence(text)).toBe(false);
});
it('raw HTML remains text and never yields scripts, event handlers, SVG, iframe or active HTML links', () => {
  const text =
    '<script>alert(1)</script><svg onload="alert(2)"></svg><iframe src="https://example.com"></iframe><a href="javascript:alert">x</a>';
  const { container } = render(<SafeMarkdown text={text} />);
  expect(container.querySelector('script,svg,iframe,a,img')).toBeNull();
  expect(container.querySelector('pre')?.textContent).toBe(text);
});
it('actual Streamdown wrapper has no rawHTML plugin, diagrams, image fetch or executable code path', async () => {
  const fetcher = vi.fn(() => {
    throw new Error('No network');
  });
  vi.stubGlobal('fetch', fetcher);
  const { container } = render(
    <SafeMarkdownRenderer
      text={
        '<script>alert(1)</script>\n\n![image](https://example.com/p.png)\n\n```mermaid\ngraph TD\nA-->B\n```\n\n```javascript\nalert(1)\n```'
      }
    />,
  );
  await act(async () => {});
  expect(container.querySelector('script,img,svg,iframe')).toBeNull();
  expect(
    container.querySelector('[data-streamdown="mermaid-block"],[data-streamdown="code-block"]'),
  ).toBeNull();
  expect(container.textContent).toContain('alert(1)');
  expect(fetcher).not.toHaveBeenCalled();
  const writeText = vi.fn(async () => {});
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  fireEvent.click(screen.getAllByRole('button', { name: 'Скопировать код' })[1]);
  await act(async () => {});
  expect(writeText).toHaveBeenCalledWith('alert(1)\n');
});
it('only explicit HTTPS without credentials/controls is active; unsafe and reference links are inert', () => {
  const text =
    '[safe](https://example.com/path) [bad](javascript:alert) [data](data:text/html,test) [file](file:///etc/passwd) [rel](/path) [protocol](//example.com) [ref][r]\n\n[r]: javascript:evil';
  const { container } = render(<SafeMarkdownRenderer text={text} />);
  const links = container.querySelectorAll('a');
  expect(links).toHaveLength(1);
  expect(links[0].href).toBe('https://example.com/path');
  expect(links[0].rel).toContain('noopener');
  for (const href of [
    'https://u:p@example.com',
    'https://example.com\\@evil.com',
    'https://example.com\n',
    'javascript:evil',
    'data:x',
    '//example.com',
    '#finding',
  ])
    expect(safeMarkdownUrl(href)).toBeNull();
});
it('lazy Markdown still renders completed prose and copy failure remains usable plain text', async () => {
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: {
      writeText: vi.fn(async () => {
        throw new Error('denied');
      }),
    },
  });
  const { container } = render(<SafeMarkdown text="**Hypothesis**, not scanner fact" />);
  await screen.findByText('Hypothesis');
  expect(container.querySelector('strong, [data-streamdown="strong"]')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Скопировать текст' }));
  await screen.findByText(/Копирование недоступно/);
});
