import '@testing-library/jest-dom/vitest';
import { useRef, useState } from 'react';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ChatMarkdownComposer } from '@/features/scans/ChatMarkdownComposer';
import { scanChatInputFeedback } from '@/features/scans/scanChatInputFeedback';
import { validChatText } from '@/shared/api/scans/llmChatContract';

const submit = vi.fn();
afterEach(() => {
  cleanup();
  submit.mockClear();
});
function Editor({
  initial = '',
  disabled = false,
  invalid = false,
}: {
  initial?: string;
  disabled?: boolean;
  invalid?: boolean;
}) {
  const [value, setValue] = useState(initial);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        submit(value);
      }}
    >
      <ChatMarkdownComposer
        value={value}
        onChange={setValue}
        textareaRef={textareaRef}
        disabled={disabled}
        invalid={invalid}
        describedBy="composer-help"
      />
      <p id="composer-help">2048 байт UTF-8</p>
    </form>
  );
}
function input() {
  return screen.getByLabelText('Вопрос чату') as HTMLTextAreaElement;
}

it.each([
  ['Жирный текст', '**находку**', 2, 9],
  ['Курсив', '*находку*', 1, 8],
  ['Код в строке', '`находку`', 1, 8],
  ['Блок кода', '\n```\nнаходку\n```\n', 5, 12],
] as const)(
  'formats the selection with %s, restores selection/focus, and does not submit',
  (label, replacement, start, end) => {
    render(<Editor initial="До находку после" />);
    input().focus();
    input().setSelectionRange(3, 10);
    fireEvent.click(screen.getByRole('button', { name: label }));
    expect(input()).toHaveValue(`До ${replacement} после`);
    expect(input()).toHaveFocus();
    expect([input().selectionStart, input().selectionEnd]).toEqual([3 + start, 3 + end]);
    expect(submit).not.toHaveBeenCalled();
  },
);

it.each([
  ['Список', '- первая\n- вторая'],
  ['Заголовок', '## первая\n## вторая'],
])('applies %s to selected whole lines without changing surrounding lines', (label, formatted) => {
  render(<Editor initial={'до\nпервая\nвторая\nпосле'} />);
  input().setSelectionRange(4, 15);
  fireEvent.click(screen.getByRole('button', { name: label }));
  expect(input()).toHaveValue(`до\n${formatted}\nпосле`);
  expect(input()).toHaveFocus();
  expect(submit).not.toHaveBeenCalled();
});

it.each(['Список', 'Заголовок'])('does not format the unselected next line when %s selection ends after a newline', label => {
  const draft = 'первая\nвторая';
  render(<Editor initial={draft} />);
  input().setSelectionRange(0, draft.indexOf('\n') + 1);
  fireEvent.click(screen.getByRole('button', { name: label }));
  expect(input()).toHaveValue(`${label === 'Список' ? '- ' : '## '}первая\nвторая`);
});

it('reveals the editor and focuses a newly prepared external retry draft from preview', () => {
  function RetryEditor() {
    const [value, setValue] = useState('Старый вопрос');
    const textareaRef = useRef<HTMLTextAreaElement>(null);
    return <form><ChatMarkdownComposer value={value} onChange={setValue} textareaRef={textareaRef} />
      <button type="button" onClick={() => setValue('Повторить проверку')}>Подготовить повтор</button></form>;
  }
  render(<RetryEditor />);
  fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр Markdown' }));
  expect(input()).not.toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Подготовить повтор' }));
  expect(input()).toBeVisible(); expect(input()).toHaveFocus(); expect(input()).toHaveValue('Повторить проверку');
});

it('inserts a selected placeholder at the caret so typing replaces it, not surrounding text', () => {
  render(<Editor initial="До после" />);
  input().setSelectionRange(3, 3);
  fireEvent.click(screen.getByRole('button', { name: 'Жирный текст' }));
  expect(input()).toHaveValue('До **текст**после');
  expect(input().value.slice(input().selectionStart, input().selectionEnd)).toBe('текст');
});

it('previews Markdown, GFM tables and fenced code without submitting, copying or losing the draft', async () => {
  const draft =
    '**важно** и *курсив*\n\n- пункт\n\n| Имя | Итог |\n| --- | --- |\n| образ | проверен |\n\n```text\nпример кода\n```';
  render(<Editor initial={draft} />);
  fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр Markdown' }));
  const preview = screen.getByRole('region', { name: 'Предпросмотр Markdown' });
  await waitFor(() => expect(preview.querySelector('[data-streamdown="strong"]')).toHaveTextContent('важно'));
  expect(preview.querySelector('em')).toHaveTextContent('курсив');
  expect(within(preview).getByRole('listitem')).toHaveTextContent('пункт');
  expect(within(preview).getByRole('table')).toHaveTextContent('проверен');
  expect(preview.querySelector('pre code')).toHaveTextContent('пример кода');
  expect(within(preview).queryByRole('button', { name: /копир|copy/i })).not.toBeInTheDocument();
  expect(input()).not.toBeVisible();
  expect(screen.getByRole('button', { name: 'Жирный текст' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Редактировать Markdown' }));
  expect(input()).toBeVisible();
  expect(input()).toHaveValue(draft);
  expect(submit).not.toHaveBeenCalled();
});

it.each([
  '<img src=x onerror=alert(1)>',
  '[опасно](javascript:alert(1))\n\n![remote](https://example.test/pixel.png)',
])('keeps unsafe content inert in preview without changing the draft: %s', async (draft) => {
  const { container } = render(<Editor initial={draft} />);
  fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр Markdown' }));
  const preview = screen.getByRole('region', { name: 'Предпросмотр Markdown' });
  if (!draft.includes('<')) await within(preview).findByText('опасно');
  expect(preview.querySelector('img, script, iframe, a[href]')).toBeNull();
  expect(container.querySelector('[onerror]')).toBeNull();
  expect(input()).toHaveValue(draft);
  expect(submit).not.toHaveBeenCalled();
});

it('passes disabled and validation accessibility through without enabling toolbar actions', () => {
  render(<Editor initial="Вопрос" disabled invalid />);
  expect(input()).toBeDisabled();
  expect(input()).toHaveAttribute('aria-invalid', 'true');
  expect(input()).toHaveAccessibleDescription('2048 байт UTF-8');
  for (const button of screen.getAllByRole('button')) expect(button).toBeDisabled();
});

it('does not truncate UTF-8 drafts or bypass the existing 2048-byte validator with preview', () => {
  const draft = 'я '.repeat(683);
  render(<Editor initial={draft} />);
  expect(new TextEncoder().encode(draft).length).toBe(2049);
  expect(validChatText(draft)).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр Markdown' }));
  expect(screen.getByRole('region', { name: 'Предпросмотр Markdown' })).toHaveTextContent(
    '2048 байт. Черновик сохранён',
  );
  expect(input()).toHaveValue(draft);
  expect(submit).not.toHaveBeenCalled();
  expect(validChatText('я '.repeat(682) + 'я')).toBe(true);
});

it.each(['<script>пример</script>', 'https://example.test', 'token=synthetic'])(
  'formatting/preview does not make forbidden input valid: %s',
  (draft) => {
    render(<Editor initial={draft} />);
    input().setSelectionRange(0, draft.length);
    fireEvent.click(screen.getByRole('button', { name: 'Жирный текст' }));
    expect(validChatText(input().value)).toBe(false);
    expect(scanChatInputFeedback(input().value)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр Markdown' }));
    expect(input()).toHaveValue(`**${draft}**`);
    expect(submit).not.toHaveBeenCalled();
  },
);
