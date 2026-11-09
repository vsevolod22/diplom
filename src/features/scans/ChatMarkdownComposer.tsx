import { useLayoutEffect, useRef, useState, type RefObject } from 'react';
import { BlockNoteSchema, defaultBlockSpecs, defaultStyleSpecs } from '@blocknote/core';
import { useCreateBlockNote, BlockNoteViewRaw } from '@blocknote/react';
import { Bold, Italic, List, ListOrdered, Code, Braces, Heading2 } from 'lucide-react';
import '@blocknote/react/style.css';
import './chat-markdown-composer.css';

type Props = {
  value: string;
  onChange(value: string): void;
  // Legacy prop name retained; the ref now points to the actual contenteditable textbox.
  textareaRef: RefObject<HTMLElement | null>;
  disabled?: boolean;
  invalid?: boolean;
  describedBy?: string;
};

const schema = BlockNoteSchema.create({
  blockSpecs: {
    paragraph: defaultBlockSpecs.paragraph,
    heading: defaultBlockSpecs.heading,
    bulletListItem: defaultBlockSpecs.bulletListItem,
    numberedListItem: {
      ...defaultBlockSpecs.numberedListItem,
      config: {
        ...defaultBlockSpecs.numberedListItem.config,
        propSchema: {
          ...defaultBlockSpecs.numberedListItem.config.propSchema,
          // 0.41's undefined default becomes a required ProseMirror attribute.
          start: { default: 1 },
        },
      },
    },
    codeBlock: defaultBlockSpecs.codeBlock,
  },

  styleSpecs: {
    bold: defaultStyleSpecs.bold,
    italic: defaultStyleSpecs.italic,
    code: defaultStyleSpecs.code,
  },
});
const tools = [
  { format: 'bold', label: 'Жирный текст', icon: Bold },
  { format: 'italic', label: 'Курсив', icon: Italic },
  { format: 'heading', label: 'Заголовок', icon: Heading2 },
  { format: 'bulletListItem', label: 'Список', icon: List },
  { format: 'numberedListItem', label: 'Нумерованный список', icon: ListOrdered },
  { format: 'code', label: 'Код в строке', icon: Code },
  { format: 'codeBlock', label: 'Блок кода', icon: Braces },
] as const;
type Format = (typeof tools)[number]['format'];

export function ChatMarkdownComposer({ value, onChange, textareaRef, disabled, invalid, describedBy }: Props) {
  const editor = useCreateBlockNote({
    schema,
    // BlockNote requires the link spec in its type-level schema, but the actual
    // ProseMirror link mark and its UI are removed, including automatic linking.
    disableExtensions: ['link', 'linkToolbar', 'dropFile'],
    placeholders: { default: 'Спросите о находках или плане исправлений…' },
    domAttributes: { editor: { role: 'textbox', 'aria-label': 'Вопрос чату', 'aria-multiline': 'true' } },
    // Only literal clipboard text is accepted: no HTML, linked images, files or URL fetching.
    pasteHandler: ({ event, editor: target }) => {
      event.preventDefault();
      const text = event.clipboardData?.getData('text/plain');
      if (target.isEditable && text) target.pasteText(text);
      return true;
    },
  });
  const appliedValue = useRef<string | null>(null);
  const replacing = useRef(false);
  const [, refreshSelection] = useState(0);

  useLayoutEffect(() => {
    editor.isEditable = !disabled;
    const input = editor.domElement;
    textareaRef.current = input ?? null;
    if (input) {
      input.setAttribute('aria-disabled', String(!!disabled));
      input.setAttribute('aria-invalid', String(!!invalid));
      if (describedBy) input.setAttribute('aria-describedby', describedBy);
      else input.removeAttribute('aria-describedby');
    }
    return () => { if (textareaRef.current === input) textareaRef.current = null; };
  }, [editor, textareaRef, disabled, invalid, describedBy]);

  useLayoutEffect(() => {
    if (appliedValue.current === value) return;
    replacing.current = true;
    try {
      const blocks = value ? editor.tryParseMarkdownToBlocks(value) : [];
      editor.replaceBlocks(editor.document, blocks.length ? blocks : [{ type: 'paragraph' }]);
      // Keep the exact supplied draft until the user actually edits it. In particular,
      // retry preparation must not rewrite or truncate the server's saved question.
      appliedValue.current = value;
    } finally {
      replacing.current = false;
    }
  }, [editor, value]);

  function publish() {
    if (replacing.current || disabled) return;
    // BlockNote 0.41 exports synchronously: no pending promise can restore an old
    // document after an external reset, retry, or owner-scope unmount.
    const markdown = editor.blocksToMarkdownLossy(editor.document);
    appliedValue.current = markdown;
    onChange(markdown);
    refreshSelection(current => current + 1);
  }
  function active(kind: Format) {
    if (kind === 'bold' || kind === 'italic' || kind === 'code') return !!editor.getActiveStyles()[kind];
    const type = editor.getTextCursorPosition().block.type;
    return type === (kind === 'heading' ? 'heading' : kind);
  }
  function format(kind: Format) {
    if (disabled) return;
    editor.focus();
    if (kind === 'bold' || kind === 'italic' || kind === 'code') {
      editor.toggleStyles({ [kind]: true });
    } else {
      const block = editor.getTextCursorPosition().block;
      if (active(kind)) editor.updateBlock(block, { type: 'paragraph' });
      else if (kind === 'heading') editor.updateBlock(block, { type: 'heading', props: { level: 2 } });
      else editor.updateBlock(block, { type: kind });
    }
    refreshSelection(current => current + 1);
  }

  return (
    <div className="scan-chat-editor" data-disabled={disabled || undefined}
      onDropCapture={event => event.preventDefault()}
      onKeyDown={event => {
        // Enter edits the document; no editor shortcut may implicitly submit the form.
        if (event.key === 'Enter') event.stopPropagation();
      }}>
      <div className="scan-chat-editor__toolbar" role="group" aria-label="Форматирование Markdown">
        <div className="scan-chat-editor__tools">
          {tools.map(({ format: kind, label, icon: Icon }) => (
            <button key={kind} type="button" title={label} aria-label={label} aria-pressed={active(kind)} disabled={disabled}
              onMouseDown={event => event.preventDefault()} onClick={() => format(kind)}>
              <Icon size={16} aria-hidden="true" />
            </button>
          ))}
        </div>
        <span className="scan-chat-editor__hint">Markdown</span>
      </div>
      <BlockNoteViewRaw editor={editor} editable={!disabled} theme="dark" onChange={publish}
        onSelectionChange={() => refreshSelection(current => current + 1)}
        formattingToolbar={false} linkToolbar={false} slashMenu={false} sideMenu={false}
        filePanel={false} tableHandles={false} emojiPicker={false} comments={false} />
    </div>
  );
}
