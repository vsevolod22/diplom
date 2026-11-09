import { useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ChatMarkdownComposer } from '@/features/scans/ChatMarkdownComposer';
import { scanChatInputFeedback } from '@/features/scans/scanChatInputFeedback';
import { validChatText } from '@/shared/api/scans/llmChatContract';
import '@/app/styles/index.css';
import '@/features/scans/scan-a1.css';
import '@/pages/scans/scan-detail-a1.css';

// This fixture never sends a question: submission is captured in memory only.
function ControlledComposer() {
  const [value, setValue] = useState('');
  const [disabled, setDisabled] = useState(false);
  const [submitted, setSubmitted] = useState<string[]>([]);
  const textareaRef = useRef<HTMLElement>(null);
  const feedback = scanChatInputFeedback(value);
  return (
    <main className="scan-a1" style={{ width: '100%', maxWidth: 600, padding: 12 }}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setSubmitted((previous) => [...previous, value]);
        }}
      >
        <ChatMarkdownComposer
          value={value}
          onChange={setValue}
          textareaRef={textareaRef}
          disabled={disabled}
          invalid={Boolean(feedback)}
          describedBy="fixture-feedback"
        />
        <p id="fixture-feedback">{feedback ?? 'Допустимый вопрос'}</p>
        <button type="submit" disabled={disabled || !validChatText(value)}>
          Отправить тестовый вопрос
        </button>
      </form>
      <button onClick={() => setValue('## Повторная проверка\n\n**Сохранённый** вопрос\n\n- Первый пункт')}>
        Внешний повтор
      </button>
      <button onClick={() => setValue('')}>Внешний сброс</button>
      <button onClick={() => setValue('Alpha paragraph\n\nBeta paragraph\n\nGamma paragraph')}>
        Три абзаца
      </button>
      <button onClick={() => setValue('# Existing H1')}>Исходный H1</button>
      <button onClick={() => setValue('## Existing H2\n\n## Second H2')}>Исходные H2</button>
      <button onClick={() => setValue('Before selected after')}>Подстрока</button>
      <button
        onClick={() => {
          setValue('## Retry heading\n\nRetry paragraph');
          textareaRef.current?.focus();
        }}
      >
        Повтор с фокусом как в панели
      </button>
      <button onClick={() => setDisabled((previous) => !previous)}>Переключить блокировку</button>
      <button onClick={() => setValue('я '.repeat(682) + 'я')}>Граница UTF-8</button>
      <button onClick={() => setValue('я '.repeat(683))}>Сверх лимита UTF-8</button>
      <pre data-testid="draft">{value}</pre>
      <output data-testid="bytes">{new TextEncoder().encode(value).length}</output>
      <output data-testid="submitted">{JSON.stringify(submitted)}</output>
    </main>
  );
}

if (new URLSearchParams(location.search).has('composer')) {
  createRoot(document.getElementById('root')!).render(<ControlledComposer />);
} else {
  // Reuse only the existing in-memory data fixture; no existing test is modified.
  void import('./chat-widget-layout.renderer');
}
