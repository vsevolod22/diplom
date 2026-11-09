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
      const widget = windowRef.current;
      if (!widget) return;
      let waiting = true;
      const stopWaiting = () => {
        waiting = false;
        observer.disconnect();
        document.removeEventListener('focusin', onFocus, true);
        document.removeEventListener('pointerdown', stopWaiting, true);
      };
      const onFocus = (event: FocusEvent) => {
        if (event.target !== widget) stopWaiting();
      };
      const focusEditor = () => {
        if (!waiting) return;
        if (!widget.isConnected || widget.hidden || document.activeElement !== widget) {
          stopWaiting();
          return;
        }
        const editor = widget.querySelector<HTMLElement>(
          '[role="textbox"][aria-label="Вопрос чату"][contenteditable="true"]:not([aria-disabled="true"])',
        );
        if (!editor || editor.closest('[hidden], [aria-hidden="true"]')) return;
        stopWaiting();
        editor.focus({ preventScroll: true });
      };
      widget.focus({ preventScroll: true });
      document.addEventListener('focusin', onFocus, true);
      document.addEventListener('pointerdown', stopWaiting, true);
      // The panel/editor may mount after this layout effect. Wait only while the
      // dialog still owns focus; never steal it back after manual navigation.
      const observer = new MutationObserver(focusEditor);
      observer.observe(widget, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['contenteditable', 'aria-disabled', 'aria-label', 'role', 'hidden', 'aria-hidden'],
      });
      focusEditor();
      return stopWaiting;
    }
    else if (restoreFocus.current) {
      trigger.current?.focus({ preventScroll: true });
      restoreFocus.current = false;
    }
  }, [open]);
  useEffect(() => {
    if (!open) return;
    let active = true;
    const handledEscapes = new WeakSet<KeyboardEvent>();
    const editorEscapes = new WeakSet<KeyboardEvent>();
    const focusedEditorEscapes = new WeakSet<KeyboardEvent>();
    const rememberEditorMenu = (event: KeyboardEvent) => {
      const widget = windowRef.current;
      if (event.key !== 'Escape' || !(event.target instanceof Node) || !widget?.contains(event.target)) return;
      if (!event.defaultPrevented && event.target instanceof HTMLElement &&
        event.target.matches('[role="textbox"][contenteditable="true"]') && document.activeElement === event.target) {
        focusedEditorEscapes.add(event);
      }
      // Observe before BlockNote removes its menu, but let the editor consume Escape first.
      const menus = widget.querySelectorAll<HTMLElement>(
        '.bn-suggestion-menu, .bn-grid-suggestion-menu, .bn-formatting-toolbar, .bn-menu-dropdown, .bn-popover-content, [role="menu"], [role="listbox"]',
      );
      const controlledIds = widget.querySelector('[role="textbox"]')?.getAttribute('aria-controls')?.split(/\s+/) ?? [];
      const controlledMenus = controlledIds.flatMap(id => {
        const menu = document.getElementById(id);
        return menu ? [menu] : [];
      });
      if ([...menus, ...controlledMenus].some(menu => !menu.closest('[hidden], [aria-hidden="true"]') &&
        getComputedStyle(menu).display !== 'none' && getComputedStyle(menu).visibility !== 'hidden')) {
        editorEscapes.add(event);
      }
      // ProseMirror can stop propagation before the document bubble listener.
      // Let its handlers finish, then handle only this known focused editor event.
      if (focusedEditorEscapes.has(event)) queueMicrotask(() => escape(event, true));
    };
    const escape = (event: KeyboardEvent, fallback = false) => {
      // BlockNote's base Escape shortcut prevents default solely to blur its textbox.
      // Other prevented events (including menu dismissal) still belong to their owner.
      const editorBlurred = focusedEditorEscapes.has(event) && document.activeElement === document.body;
      const editorStillFocused = focusedEditorEscapes.has(event) && document.activeElement === event.target;
      if (!active || handledEscapes.has(event) || event.key !== 'Escape' ||
        (event.defaultPrevented && !editorBlurred && !(fallback && editorStillFocused)) ||
        event.isComposing || editorEscapes.has(event) ||
        !(event.target instanceof Node) || !windowRef.current?.contains(event.target)) return;
      if (fallback && !editorBlurred && !editorStillFocused) return;
      handledEscapes.add(event);
      if (!fallback) {
        event.preventDefault();
        event.stopPropagation();
      }
      restoreFocus.current = true;
      setOpen(false);
    };
    document.addEventListener('keydown', rememberEditorMenu, true);
    document.addEventListener('keydown', escape);
    return () => {
      active = false;
      document.removeEventListener('keydown', rememberEditorMenu, true);
      document.removeEventListener('keydown', escape);
    };
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
