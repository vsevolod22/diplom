import { vi } from 'vitest';

// Transport/history tests need controlled string input, not ProseMirror layout.
// Real BlockNote rendering, input rules, paste and focus are tested in Chromium
// by BlockNoteChatComposer.test.tsx and blocknote-chat-layout.mjs.
vi.mock('@/features/scans/ChatMarkdownComposer', () => ({
  ChatMarkdownComposer: (props: {
    value: string;
    onChange(value: string): void;
    textareaRef: import('react').RefObject<HTMLElement | null>;
    disabled?: boolean;
    invalid?: boolean;
    describedBy?: string;
  }) => <textarea aria-label="Вопрос чату" value={props.value}
    ref={node => { props.textareaRef.current = node; }} disabled={props.disabled}
    aria-invalid={props.invalid} aria-describedby={props.describedBy}
    onChange={event => props.onChange(event.target.value)} />,
}));
