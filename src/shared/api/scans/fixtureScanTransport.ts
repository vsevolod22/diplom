import type { ScanResults, ScanStatus, ScanSummary, ScanTransport } from './scanTransport';

export const demoScans: ScanSummary[] = [
  { scanId: 'partial-demo', state: 'partial', percent: null, targetLabel: 'library/alpine:latest (демо)', imageReference: 'library/alpine:latest', checks: ['secret', 'sbom', 'vuln'], perCheck: { secret: { check: 'secret', coverage: 'image', outcome: 'checked' }, sbom: { check: 'sbom', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_FAILED' }, vuln: { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_UNAVAILABLE' } } },
  { scanId: 'empty-demo', state: 'completed', percent: null, targetLabel: 'library/alpine:3.21 (демо)' },
  { scanId: 'unsupported-demo', state: 'partial', percent: null, targetLabel: 'library/alpine:edge (демо)' },
  { scanId: 'running-demo', state: 'running', stage: 'secret', percent: null, targetLabel: 'library/alpine:3 (демо)' },
];
const baseCoverage: ScanResults['coverage'] = [
  { check: 'CVE', status: 'failed', reason: 'База уязвимостей недоступна' },
  { check: 'Secrets', status: 'checked', scannerVersion: 'демо-версия' },
  { check: 'SBOM', status: 'unsupported', reason: 'Проверка не поддерживается текущим API' },
];
const reports: Record<string, ScanResults> = {
  'partial-demo': { findings: [{ findingId: 'demo-1', category: 'secret', ruleId: 'SECRET_DETECTED', severity: 'high', evidenceRef: 'redacted:demo-1' }], nextCursor: null, coverage: baseCoverage },
  'empty-demo': { findings: [], nextCursor: null, coverage: [{ check: 'Secrets', status: 'checked' }, { check: 'CVE', status: 'unsupported', reason: 'Не запускалась' }] },
  'unsupported-demo': { findings: [], nextCursor: null, coverage: [{ check: 'Secrets', status: 'skipped', reason: 'Проверка не запускалась' }, { check: 'CVE', status: 'unsupported', reason: 'Нет данных' }] },
  'running-demo': { findings: [], nextCursor: null, coverage: [{ check: 'Secrets', status: 'skipped', reason: 'Проверка ещё не завершена' }, { check: 'CVE', status: 'unsupported', reason: 'Нет данных' }] },
};
export const fixtureScanTransport: ScanTransport = {
  kind: 'fixture',
  capabilities: { list: true, create: false, cancel: false, events: false },
  async list() { return demoScans; },
  async get(id): Promise<ScanStatus> {
    const item = demoScans.find((scan) => scan.scanId === id);
    if (!item) throw new Error('Скан недоступен');
    return item;
  },
  async results(id, cursor) {
    if (!reports[id] || cursor) throw new Error('Результаты недоступны');
    return reports[id];
  },
  async sbom() { return { outcome: 'failed', coverage: 'image', errorCode: 'SCAN_FAILED', components: [], nextCursor: null }; },
  async vuln() { return { outcome: 'failed', coverage: 'image', errorCode: 'SCAN_UNAVAILABLE', findings: [], nextCursor: null }; },
  async create() { throw new Error('Запуск доступен только после настройки защищённого браузерного доступа'); },
  async cancel() { throw new Error('Отмена недоступна: серверный маршрут не реализован'); },
};

export const unavailableScanTransport: ScanTransport = {
  kind: 'live',
  capabilities: { list: false, create: false, cancel: false, events: false },
  async list() { throw new Error('Список недоступен: нет защищённого браузерного доступа и GET списка'); },
  async get() { throw new Error('Деталь недоступна: нет защищённого браузерного доступа'); },
  async results() { throw new Error('Результаты недоступны: нет защищённого браузерного доступа'); },
  async sbom() { throw new Error('SBOM недоступен: нет защищённого браузерного доступа'); },
  async vuln() { throw new Error('CVE недоступно: нет защищённого браузерного доступа'); },
  async create() { throw new Error('Запуск недоступен: нет защищённого браузерного доступа'); },
  async cancel() { throw new Error('Отмена недоступна: нет серверного маршрута'); },
};
