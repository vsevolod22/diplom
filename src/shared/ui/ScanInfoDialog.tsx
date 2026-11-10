import * as Dialog from '@radix-ui/react-dialog';
import type { ReactNode } from 'react';
import { Info, X } from 'lucide-react';
import './scan-info-dialog.css';

type Props = { title: string; description: string; children: ReactNode };

/** Informational only: opening this dialog never initiates an operation. */
export function ScanInfoDialog({ title, description, children }: Props) {
  return (
    <Dialog.Root>
      <Dialog.Trigger asChild>
        <button type="button" className="scan-info-trigger">
          <Info size={16} aria-hidden="true" /> {title}
        </button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="scan-info-overlay" />
        <Dialog.Content className="scan-info-dialog">
          <header className="scan-info-dialog__header">
            <Dialog.Title className="scan-info-dialog__title">{title}</Dialog.Title>
            <Dialog.Close asChild>
              <button type="button" className="scan-info-dialog__close">
                Закрыть <X size={18} aria-hidden="true" />
              </button>
            </Dialog.Close>
          </header>
          <div className="scan-info-dialog__body">
            <Dialog.Description className="scan-info-dialog__description">{description}</Dialog.Description>
            {children}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
