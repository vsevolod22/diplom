import { useLayoutEffect, useRef, useState, type RefObject } from 'react';
import { Bold, Italic, List, Code, Braces, Heading2, Eye, Pencil } from 'lucide-react';
import { utf8Bytes } from '@/shared/api/scans/vulnAdvisory';
import { SafeMarkdown } from './safeMarkdown';
import './chat-markdown-composer.css';

type Props = {
  value: string;
  onChange(value: string): void;
  textareaRef: RefObject<HTMLTextAreaElement | null>;
  disabled?: boolean;
  invalid?: boolean;
  describedBy?: string;
};
type Format = 'bold' | 'italic' | 'code' | 'block' | 'list' | 'heading';
const tools = [
  { format: 'bold', label: 'Жирный текст', icon: Bold },
  { format: 'italic', label: 'Курсив', icon: Italic },
  { format: 'heading', label: 'Заголовок', icon: Heading2 },
  { format: 'list', label: 'Список', icon: List },
  { format: 'code', label: 'Код в строке', icon: Code },
  { format: 'block', label: 'Блок кода', icon: Braces },
] as const;

export function ChatMarkdownComposer({ value, onChange, textareaRef, disabled, invalid, describedBy }: Props) {
  const [preview, setPreview] = useState(false);
  const selection = useRef<[number, number] | null>(null);
  const previousValue = useRef(value);
  useLayoutEffect(() => {
    if (preview && previousValue.current !== value) {
      setPreview(false);
      // Only explicit retry preparation supplies a new nonempty external draft.
      if (value) selection.current = [0, value.length];
    }
    previousValue.current = value;
  }, [value, preview]);
  useLayoutEffect(() => {
    if (preview) return;
    const range = selection.current;
    if (!range || !textareaRef.current) return;
    selection.current = null;
    textareaRef.current.focus({ preventScroll: true });
    textareaRef.current.setSelectionRange(...range);
  }, [value, textareaRef, preview]);
  function format(kind: Format) {
    const input = textareaRef.current;
    if (!input || disabled) return;
    const start = input.selectionStart, end = input.selectionEnd;
    const chosen = value.slice(start, end) || (kind === 'block' || kind === 'code' ? 'код' : 'текст');
    let from = start, to = end, replacement: string, selectStart: number, selectEnd: number;
    if (kind === 'list' || kind === 'heading') {
      from = start === 0 ? 0 : value.lastIndexOf('\n', start - 1) + 1;
      const lastSelected = end > start && value[end - 1] === '\n' ? end - 1 : end;
      const next = value.indexOf('\n', lastSelected);
      to = next === -1 ? value.length : next;
      const prefix = kind === 'list' ? '- ' : '## ';
      replacement = (value.slice(from, to) || chosen).split('\n').map(line => prefix + line).join('\n');
      selectStart = from + prefix.length; selectEnd = from + replacement.length;
    } else {
      const prefix = kind === 'bold' ? '**' : kind === 'italic' ? '*' : kind === 'block' ? '\n```\n' : '`';
      const suffix = kind === 'block' ? '\n```\n' : prefix;
      replacement = prefix + chosen + suffix;
      selectStart = from + prefix.length; selectEnd = selectStart + chosen.length;
    }
    selection.current = [selectStart, selectEnd];
    setPreview(false);
    onChange(value.slice(0, from) + replacement + value.slice(to));
  }
  return (
    <div className="scan-chat-editor">
      <div className="scan-chat-editor__toolbar" role="group" aria-label="Форматирование Markdown">
        <div className="scan-chat-editor__tools">
          {tools.map(({ format: kind, label, icon: Icon }) => (
            <button key={kind} type="button" title={label} aria-label={label} disabled={disabled || preview}
              onMouseDown={event => event.preventDefault()} onClick={() => format(kind)}>
              <Icon size={16} aria-hidden="true" />
            </button>
          ))}
        </div>
        <button type="button" className="scan-chat-editor__preview-toggle" disabled={disabled}
          aria-label={preview ? 'Редактировать Markdown' : 'Предпросмотр Markdown'} aria-pressed={preview}
          onClick={() => setPreview(current => !current)}>
          {preview ? <Pencil size={15} aria-hidden="true" /> : <Eye size={15} aria-hidden="true" />}
          <span>{preview ? 'Текст' : 'Вид'}</span>
        </button>
      </div>
      <label className="scan-chat-editor__label">
        <span>Вопрос чату</span>
        <textarea ref={textareaRef} value={value} hidden={preview} disabled={disabled} aria-invalid={invalid}
          aria-describedby={describedBy} rows={3} placeholder="Спросите о находках или плане исправлений…"
          onChange={event => onChange(event.target.value)} />
      </label>
      {preview ? (
        <div className="scan-chat-editor__preview" role="region" aria-label="Предпросмотр Markdown">
          {utf8Bytes(value) > 2048 ? <p>Для предпросмотра сократите вопрос до 2048 байт. Черновик сохранён.</p> :
            value.trim() ? <SafeMarkdown text={value} showCopy={false} /> : <p>Здесь появится оформленный вопрос.</p>}
        </div>
      ) : null}
    </div>
  );
}
