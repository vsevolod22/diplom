import '@testing-library/jest-dom/vitest';
import { createRef } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ChatMarkdownComposer } from '@/features/scans/ChatMarkdownComposer';
import { scanChatInputFeedback } from '@/features/scans/scanChatInputFeedback';
import { validChatText } from '@/shared/api/scans/llmChatContract';

// Lifecycle/controlled-value tests ONLY. The BlockNote surface below is an explicit
// test adapter, not WYSIWYG proof. Real input rules, DOM rendering, selection and
// browser security are qualified by BlockNoteChatComposer.test.tsx / Chromium.
type AdapterBlock = { type: string; text?: string };
type AdapterEditor = {
  document: AdapterBlock[];
  domElement?: HTMLTextAreaElement;
  isEditable: boolean;
  notify?: () => void;
  replaceBlocks: ReturnType<typeof vi.fn>;
  tryParseMarkdownToBlocks: ReturnType<typeof vi.fn>;
  blocksToMarkdownLossy: ReturnType<typeof vi.fn>;
};
const adapter = vi.hoisted(() => ({
  editors: [] as AdapterEditor[],
  options: [] as Record<string, unknown>[],
  views: [] as Record<string, unknown>[],
}));
vi.mock('@blocknote/react', async () => {
  const React = await import('react');
  return {
    useCreateBlockNote(options: Record<string, unknown>) {
      const [editor] = React.useState(() => {
        const instance: AdapterEditor = {
          document: [{ type: 'paragraph' }],
          isEditable: true,
          tryParseMarkdownToBlocks: vi.fn((text: string) => [{ type: 'paragraph', text }]),
          blocksToMarkdownLossy: vi.fn((blocks: AdapterBlock[]) => blocks.map(block => block.text ?? '').join('\n')),
          replaceBlocks: vi.fn((_old: AdapterBlock[], blocks: AdapterBlock[]) => {
            instance.document = blocks;
            if (instance.domElement) instance.domElement.value = blocks.map(block => block.text ?? '').join('\n');
            // Synchronous replacement notifications must not leak to onChange.
            instance.notify?.();
          }),
          ...{
            getActiveStyles: () => ({}),
            getTextCursorPosition: () => ({ block: { type: 'paragraph' } }),
          },
        };
        adapter.editors.push(instance);
        adapter.options.push(options);
        return instance;
      });
      return editor;
    },
    BlockNoteViewRaw(props: Record<string, unknown> & { editor: AdapterEditor; onChange(): void }) {
      adapter.views.push(props);
      React.useLayoutEffect(() => {
        props.editor.notify = props.onChange;
        return () => { props.editor.notify = undefined; };
      }, [props.editor, props.onChange]);
      return <textarea aria-label="Lifecycle editor adapter" ref={node => { props.editor.domElement = node ?? undefined; }}
        disabled={props.editable === false}
        onChange={event => {
          props.editor.document = [{ type: 'paragraph', text: event.target.value }];
          props.onChange();
        }} />;
    },
  };
});
afterEach(() => {
  cleanup();
  adapter.editors.length = 0;
  adapter.options.length = 0;
  adapter.views.length = 0;
});
function setup(value = '') {
  const onChange = vi.fn();
  const textareaRef = createRef<HTMLElement>();
  const props = { value, onChange, textareaRef };
  return { ...render(<ChatMarkdownComposer {...props} />), props, onChange, textareaRef };
}
function input() { return screen.getByRole('textbox', { name: 'Lifecycle editor adapter' }); }

it('imports an external draft exactly once without publishing parser normalization or replacement events', () => {
  const original = '**Сохранённый** вопрос\n\n- пункт\n';
  const { rerender, props, onChange } = setup(original);
  const editor = adapter.editors[0];
  expect(input()).toHaveValue(original);
  expect(editor.tryParseMarkdownToBlocks).toHaveBeenCalledWith(original);
  expect(onChange).not.toHaveBeenCalled();
  rerender(<ChatMarkdownComposer {...props} />);
  expect(editor.replaceBlocks).toHaveBeenCalledTimes(1);
  rerender(<ChatMarkdownComposer {...props} value="## Повторная проверка" />);
  expect(input()).toHaveValue('## Повторная проверка');
  expect(onChange).not.toHaveBeenCalled();
  rerender(<ChatMarkdownComposer {...props} value="" />);
  expect(input()).toHaveValue('');
  expect(editor.document).toEqual([{ type: 'paragraph' }]);
  expect(onChange).not.toHaveBeenCalled();
});

it('publishes the synchronous document export, accepts its controlled echo and then honors a reset', () => {
  const { rerender, props, onChange } = setup('старый');
  const editor = adapter.editors[0];
  editor.blocksToMarkdownLossy.mockReturnValueOnce('**Экспорт документа**\n');
  fireEvent.change(input(), { target: { value: 'adapter document edit' } });
  expect(editor.blocksToMarkdownLossy).toHaveBeenCalledWith(editor.document);
  expect(onChange).toHaveBeenLastCalledWith('**Экспорт документа**\n');
  const replacements = editor.replaceBlocks.mock.calls.length;
  rerender(<ChatMarkdownComposer {...props} value={'**Экспорт документа**\n'} />);
  expect(editor.replaceBlocks).toHaveBeenCalledTimes(replacements);
  rerender(<ChatMarkdownComposer {...props} value="" />);
  expect(input()).toHaveValue('');
  expect(onChange).toHaveBeenCalledTimes(1);
});

it('assigns and clears the actual editor focus ref and updates disabled/validation attributes', () => {
  const { rerender, props, textareaRef, onChange, unmount } = setup('вопрос');
  expect(textareaRef.current).toBe(input());
  rerender(<ChatMarkdownComposer {...props} disabled invalid describedBy="feedback" />);
  expect(adapter.editors[0].isEditable).toBe(false);
  expect(input()).toHaveAttribute('aria-disabled', 'true');
  expect(input()).toHaveAttribute('aria-invalid', 'true');
  expect(input()).toHaveAttribute('aria-describedby', 'feedback');
  for (const button of screen.getAllByRole('button')) expect(button).toBeDisabled();
  // Even an adapter notification while disabled must not publish a draft.
  fireEvent.change(input(), { target: { value: 'ignored disabled notification' } });
  expect(onChange).not.toHaveBeenCalled();
  rerender(<ChatMarkdownComposer {...props} disabled={false} invalid={false} />);
  expect(adapter.editors[0].isEditable).toBe(true);
  expect(input()).toHaveAttribute('aria-invalid', 'false');
  expect(input()).not.toHaveAttribute('aria-describedby');
  unmount();
  expect(textareaRef.current).toBeNull();
});

it('isolates owner remounts and detaches old adapter subscriptions', () => {
  const { unmount, textareaRef } = setup('старый владелец');
  const previous = adapter.editors[0];
  unmount();
  expect(previous.notify).toBeUndefined();
  expect(textareaRef.current).toBeNull();
  const next = setup('новый владелец');
  expect(adapter.editors[1]).not.toBe(previous);
  expect(input()).toHaveValue('новый владелец');
  expect(next.onChange).not.toHaveBeenCalled();
});

it('retains over-limit external drafts and leaves UTF-8/forbidden-input enforcement to existing validators', () => {
  const draft = 'я '.repeat(683);
  setup(draft);
  expect(input()).toHaveValue(draft);
  expect(new TextEncoder().encode(draft).length).toBe(2049);
  expect(validChatText(draft)).toBe(false);
  expect(scanChatInputFeedback(draft)).toBeTruthy();
  expect(validChatText('я '.repeat(682) + 'я')).toBe(true);
  for (const forbidden of ['<script>пример</script>', 'https://example.test', 'token=synthetic']) {
    expect(validChatText(`**${forbidden}**`)).toBe(false);
    expect(scanChatInputFeedback(`**${forbidden}**`)).toBeTruthy();
  }
});

it('configures a narrow schema, disables links/file drop and omits automatic rich-editor UI', () => {
  setup();
  const options = adapter.options[0];
  const schema = options.schema as { blockSchema: object; styleSchema: object };
  expect(Object.keys(schema.blockSchema).sort()).toEqual(['bulletListItem', 'codeBlock', 'heading', 'numberedListItem', 'paragraph']);
  expect(Object.keys(schema.styleSchema).sort()).toEqual(['bold', 'code', 'italic']);
  expect(options.disableExtensions).toEqual(expect.arrayContaining(['link', 'linkToolbar', 'dropFile']));
  expect(options.domAttributes).toEqual({ editor: { role: 'textbox', 'aria-label': 'Вопрос чату', 'aria-multiline': 'true' } });
  expect(adapter.views.at(-1)).toEqual(expect.objectContaining({
    formattingToolbar: false, linkToolbar: false, slashMenu: false, sideMenu: false,
    filePanel: false, tableHandles: false, emojiPicker: false, comments: false,
  }));
});

it('routes only clipboard plain text to the adapter and ignores it when editing is disabled', () => {
  setup();
  const paste = adapter.options[0].pasteHandler as (context: {
    event: { preventDefault(): void; clipboardData: { getData(type: string): string } };
    editor: { isEditable: boolean; pasteText(text: string): void };
  }) => boolean;
  const event = { preventDefault: vi.fn(), clipboardData: { getData: vi.fn(() => 'literal text') } };
  const target = { isEditable: true, pasteText: vi.fn() };
  expect(paste({ event, editor: target })).toBe(true);
  expect(event.preventDefault).toHaveBeenCalled();
  expect(event.clipboardData.getData).toHaveBeenCalledExactlyOnceWith('text/plain');
  expect(target.pasteText).toHaveBeenCalledExactlyOnceWith('literal text');
  target.isEditable = false;
  paste({ event, editor: target });
  expect(target.pasteText).toHaveBeenCalledTimes(1);
});
