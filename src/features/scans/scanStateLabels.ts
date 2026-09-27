import type { ScanStatus } from '@/shared/api/scans/scanTransport';

export const stateLabels: Record<ScanStatus['state'], string> = {
  queued: 'В очереди', running: 'Выполняется', cancelling: 'Отмена выполняется',
  completed: 'Завершён', partial: 'Частичный результат', failed: 'Ошибка', cancelled: 'Отменён',
};
