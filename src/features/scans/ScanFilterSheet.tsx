import * as Dialog from '@radix-ui/react-dialog';
import { useRef } from 'react';
import { Button } from '@/shared/ui/scan-primitives';
import { controlClass } from './ScanShell';

type Props = { filter: string; onFilterChange: (filter: string) => void };

export function ScanFilterSheet({ filter, onFilterChange }: Props) {
  const trigger = useRef<HTMLButtonElement>(null);
  const select = useRef<HTMLSelectElement>(null);
  return (
    <Dialog.Root>
      <Dialog.Trigger ref={trigger} className="scan-button scan-button--secondary scan-filter-trigger">
        Фильтры
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="scan-filter-overlay fixed inset-0 z-40 bg-slate-950/65 sm:hidden" />
        <Dialog.Content
          className="scan-filter-panel fixed inset-y-0 right-0 z-50 flex w-[min(100vw,24rem)] min-w-0 flex-col gap-5 overflow-y-auto border-l border-slate-300 bg-white p-5 text-slate-900 shadow-2xl outline-none sm:hidden"
          onOpenAutoFocus={(event) => {
            event.preventDefault();
            select.current?.focus();
          }}
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            trigger.current?.focus();
          }}
        >
          <div className="space-y-2 border-b border-slate-200 pb-5">
            <p className="text-xs font-bold uppercase tracking-widest text-indigo-800">Просмотр отчёта</p>
            <Dialog.Title className="text-2xl font-semibold tracking-tight">Фильтры находок</Dialog.Title>
            <Dialog.Description className="text-sm leading-relaxed text-slate-600">
              Категория применяется только к загруженной странице результатов.
            </Dialog.Description>
          </div>
          <div className="flex flex-col gap-2">
            <label htmlFor="mobile-finding-filter" className="font-medium">
              Категория
            </label>
            <select
              ref={select}
              id="mobile-finding-filter"
              className={`${controlClass} w-full min-w-0`}
              value={filter}
              onChange={(event) => onFilterChange(event.target.value)}
            >
              <option value="all">Все на загруженной странице</option>
              <option value="secret">Secrets</option>
              <option value="vulnerability">CVE</option>
            </select>
          </div>
          <Button
            type="button"
            variant="secondary"
            onClick={() => onFilterChange('all')}
            disabled={filter === 'all'}
          >
            Сбросить фильтр
          </Button>
          <Dialog.Close className="scan-button scan-button--primary mt-auto">Закрыть фильтры</Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
