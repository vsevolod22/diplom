import { Component, lazy, Suspense, useEffect, useRef, useState, type ReactNode } from 'react';
import { Check, Copy } from 'lucide-react';
import { unfinishedFence } from './safeMarkdownPolicy';
import './chat-conversation.css';

const Markdown = lazy(() => import('./SafeMarkdownRenderer'));
const plainStyle = { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxWidth: '100%' } as const;

export function CopyText({ text, label = 'Скопировать текст' }: { text: string; label?: string }) {
  // A changed source must discard feedback and any still-pending clipboard result immediately.
  return <CopyAction key={text} text={text} label={label} />;
}

function CopyAction({ text, label }: { text: string; label: string }) {
  const [status, setStatus] = useState<'idle' | 'copied' | 'error'>('idle');
  const request = useRef(0);
  useEffect(
    () => () => {
      request.current += 1;
    },
    [],
  );
  useEffect(() => {
    if (status !== 'copied') return;
    const timer = window.setTimeout(() => setStatus('idle'), 2000);
    return () => window.clearTimeout(timer);
  }, [status]);

  async function copy() {
    const currentRequest = ++request.current;
    setStatus('idle');
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(text);
      if (currentRequest === request.current) setStatus('copied');
    } catch {
      if (currentRequest === request.current) setStatus('error');
    }
  }

  const message =
    status === 'copied'
      ? 'Скопировано'
      : status === 'error'
        ? 'Копирование недоступно; выделите текст вручную.'
        : '';
  return (
    <span className="scan-markdown__copy-action" data-copy-status={status}>
      <button
        type="button"
        className="scan-markdown__copy"
        aria-label={label}
        title={status === 'copied' ? 'Скопировано' : label}
        onClick={() => {
          void copy();
        }}
      >
        {status === 'copied' ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
        <span className="scan-markdown__sr-only">{label}</span>
      </button>{' '}
      <span
        className={status === 'error' ? 'scan-markdown__copy-status' : 'scan-markdown__sr-only'}
        role="status"
        aria-atomic="true"
      >
        {message}
      </span>
    </span>
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
export function SafeMarkdown({ text, showCopy = true }: { text: string; showCopy?: boolean }) {
  // Unclosed fences and HTML-like input stay inert and exactly copyable, even during future delivery chunks.
  const plain = unfinishedFence(text) || /[<>]/.test(text);
  return (
    <div className="scan-markdown" style={{ minWidth: 0, maxWidth: '100%', overflowWrap: 'anywhere' }}>
      {plain ? (
        <PlainMessage text={text} />
      ) : (
        <MarkdownBoundary key={text} text={text}>
          <Suspense fallback={<PlainMessage text={text} />}>
            <Markdown text={text} showCopy={showCopy} />
          </Suspense>
        </MarkdownBoundary>
      )}
      {showCopy ? <CopyText key={`copy:${text}`} text={text} /> : null}
    </div>
  );
}
