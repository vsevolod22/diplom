import { Component, lazy, Suspense, useState, type ReactNode } from 'react';
import { unfinishedFence } from './safeMarkdownPolicy';

const Markdown = lazy(() => import('./SafeMarkdownRenderer'));
const plainStyle = { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxWidth: '100%' } as const;

export function CopyText({ text, label = 'Скопировать текст' }: { text: string; label?: string }) {
  const [message, setMessage] = useState('');
  return (
    <>
      <button
        type="button"
        onClick={() => {
          if (!navigator.clipboard?.writeText) {
            setMessage('Копирование недоступно; выделите текст вручную.');
            return;
          }
          void navigator.clipboard.writeText(text).then(
            () => setMessage('Скопировано'),
            () => setMessage('Копирование недоступно; выделите текст вручную.'),
          );
        }}
      >
        {label}
      </button>{' '}
      <span role="status">{message}</span>
    </>
  );
}
function PlainMessage({ text }: { text: string }) {
  return <pre style={plainStyle}>{text}</pre>;
}
class MarkdownBoundary extends Component<{ children: ReactNode; text: string }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? <PlainMessage text={this.props.text} /> : this.props.children;
  }
}
export function SafeMarkdown({ text }: { text: string }) {
  // Unclosed fences and HTML-like input stay inert and exactly copyable, even during future delivery chunks.
  const plain = unfinishedFence(text) || /[<>]/.test(text);
  return (
    <div style={{ minWidth: 0, maxWidth: '100%', overflowWrap: 'anywhere' }}>
      {plain ? (
        <PlainMessage text={text} />
      ) : (
        <MarkdownBoundary key={text} text={text}>
          <Suspense fallback={<PlainMessage text={text} />}>
            <Markdown text={text} />
          </Suspense>
        </MarkdownBoundary>
      )}
      <CopyText key={`copy:${text}`} text={text} />
    </div>
  );
}
