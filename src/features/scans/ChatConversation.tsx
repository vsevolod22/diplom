import type { ReactNode } from 'react';
import { Message, TypingIndicator } from '@chatscope/chat-ui-kit-react';
import '@chatscope/chat-ui-kit-styles/dist/default/styles.min.css';
import './chat-conversation.css';

export function ChatBubble({
  direction,
  children,
}: {
  direction: 'incoming' | 'outgoing';
  children: ReactNode;
}) {
  return (
    <Message className="scan-chat-bubble" model={{ direction, position: 'single', type: 'custom' }}>
      <Message.CustomContent>{children}</Message.CustomContent>
    </Message>
  );
}

export function ChatThinking() {
  return (
    <div className="scan-chat-thinking" role="status" aria-live="polite" aria-atomic="true">
      <span aria-hidden="true">
        <TypingIndicator content="" />
      </span>
      <span>
        ИИ готовит ответ
        <span className="scan-chat-thinking__hint">
          Ответ появится после проверки и сохранения. Можно продолжать читать отчёт.
        </span>
      </span>
    </div>
  );
}
