import { useEffect, useId, useLayoutEffect, useRef, useState, type ComponentProps } from 'react';
import { createPortal } from 'react-dom';
import { MessageCircle, Minus, Sparkles } from 'lucide-react';
import { ScanChatPanel } from './ScanChatPanel';
import './scan-chat-widget.css';

type Props = ComponentProps<typeof ScanChatPanel>;

export function ScanChatWidget(props: Props) {
  const [open, setOpen] = useState(false);
  const [visited, setVisited] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const windowRef = useRef<HTMLDivElement>(null);
  const restoreFocus = useRef(false);
  const id = useId();
  const changeOpen = (next: boolean) => {
    restoreFocus.current = !next;
    if (next) setVisited(true);
    setOpen(next);
  };
  useLayoutEffect(() => {
    if (open) {
      const target = windowRef.current?.querySelector<HTMLElement>('textarea:not([hidden]):not(:disabled)') ??
        windowRef.current?.querySelector<HTMLElement>('[aria-label="Редактировать Markdown"]:not(:disabled)') ?? windowRef.current;
      target?.focus({ preventScroll: true });
    }
    else if (restoreFocus.current) {
      trigger.current?.focus({ preventScroll: true });
      restoreFocus.current = false;
    }
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const escape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented || !(event.target instanceof Node) || !windowRef.current?.contains(event.target)) return;
      event.preventDefault();
      event.stopPropagation();
      restoreFocus.current = true;
      setOpen(false);
    };
    document.addEventListener('keydown', escape, true);
    return () => document.removeEventListener('keydown', escape, true);
  }, [open]);
  return (
    <>
      <button ref={trigger} type="button" className="scan-chat-launcher" aria-label="Открыть чат по отчёту"
        aria-haspopup="dialog" aria-expanded={open} aria-controls={id} hidden={open} onClick={() => changeOpen(true)}>
        <MessageCircle size={23} aria-hidden="true" /><span>Спросить ИИ</span>
      </button>
      {visited ? createPortal(
        <div ref={windowRef} id={id} role="dialog" tabIndex={-1} aria-modal="false" aria-labelledby={`${id}-title`}
          aria-describedby={`${id}-description`} hidden={!open} className="scan-a1 scan-chat-widget">
          <header className="scan-chat-widget__header">
            <div className="scan-chat-widget__identity">
              <span className="scan-chat-widget__icon"><Sparkles size={19} aria-hidden="true" /></span>
              <div><h2 id={`${id}-title`}>Ассистент отчёта</h2><p id={`${id}-description`}>Находки, приоритеты и исправления</p></div>
            </div>
            <button type="button" className="scan-chat-widget__minimize" aria-label="Свернуть чат" onClick={() => changeOpen(false)}><Minus size={21} aria-hidden="true" /></button>
          </header>
          <div className="scan-chat-widget__body">
            <ScanChatPanel {...props} onNavigateSource={props.onNavigateSource ? category => {
              const navigated = props.onNavigateSource?.(category) ?? false;
              if (navigated) {
                // The report owns focus after successful source navigation.
                restoreFocus.current = false;
                setOpen(false);
              }
              return navigated;
            } : undefined} />
          </div>
        </div>, document.body,
      ) : null}
    </>
  );
}
