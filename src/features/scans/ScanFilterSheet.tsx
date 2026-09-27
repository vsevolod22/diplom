import * as Dialog from '@radix-ui/react-dialog';
import { useRef } from 'react';
import { controlClass } from './ScanShell';

type Props = { filter: string; onFilterChange: (filter: string) => void };

export function ScanFilterSheet({ filter, onFilterChange }: Props) {
  const trigger = useRef<HTMLButtonElement>(null);
  const select = useRef<HTMLSelectElement>(null);
  return <Dialog.Root>
    <Dialog.Trigger ref={trigger} className={`${controlClass} sm:hidden`}>Фильтры</Dialog.Trigger>
    <Dialog.Portal>
      <Dialog.Overlay className="fixed inset-0 z-40 bg-slate-950/70 sm:hidden" />
      <Dialog.Content
        className="fixed inset-y-0 right-0 z-50 flex w-[min(100vw,24rem)] flex-col gap-4 overflow-y-auto border-l border-slate-500 bg-white p-5 text-slate-900 shadow-xl outline-none sm:hidden"
        onOpenAutoFocus={(event) => { event.preventDefault(); select.current?.focus(); }}
        onCloseAutoFocus={(event) => { event.preventDefault(); trigger.current?.focus(); }}
      >
        <Dialog.Title className="text-xl font-semibold">Фильтры находок</Dialog.Title>
        <Dialog.Description>Категория применяется только к загруженной странице результатов.</Dialog.Description>
        <label htmlFor="mobile-finding-filter">Категория</label>
        <select ref={select} id="mobile-finding-filter" className={controlClass} value={filter} onChange={(event) => onFilterChange(event.target.value)}>
          <option value="all">Все на загруженной странице</option><option value="secret">Secrets</option><option value="vulnerability">CVE</option>
        </select>
        <button type="button" className={controlClass} onClick={() => onFilterChange('all')} disabled={filter === 'all'}>Сбросить фильтр</button>
        <Dialog.Close className={controlClass}>Закрыть фильтры</Dialog.Close>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>;
}
