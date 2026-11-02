import type { ScanResults, ScanStatus, ScanSummary, ScanTransport } from './scanTransport';

export const demoScans: ScanSummary[] = [
  {
    scanId: 'partial-demo', state: 'partial', percent: null,
    targetLabel: 'library/alpine:latest (демо)', imageReference: 'library/alpine:latest',
    checks: ['secret', 'sbom', 'vuln'],
    perCheck: {
      secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 1, scannerVersion: 'демо-версия' },
      sbom: { check: 'sbom', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_FAILED' },
      vuln: { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_UNAVAILABLE' },
    },
  },
  {
    scanId: 'empty-demo', state: 'completed', percent: null, targetLabel: 'library/alpine:3.21 (демо)',
    checks: ['secret'],
    perCheck: { secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 0 } },
  },
  {
    scanId: 'unsupported-demo', state: 'partial', percent: null, targetLabel: 'library/alpine:edge (демо)',
    checks: ['secret', 'vuln'],
    perCheck: {
      secret: { check: 'secret', coverage: 'image', outcome: 'skipped', reason: 'CHECK_DISABLED' },
      vuln: { check: 'vuln', coverage: 'image', outcome: 'unsupported', reason: 'OS_UNKNOWN' },
    },
  },
  { scanId: 'running-demo', state: 'running', stage: 'secret', percent: null, targetLabel: 'library/alpine:3 (демо)', checks: ['secret'] },
];
const baseCoverage: ScanResults['coverage'] = [
  { check: 'CVE', status: 'failed', reason: 'SCAN_UNAVAILABLE' },
  { check: 'Secrets', status: 'checked', findingCount: 1, scannerVersion: 'демо-версия' },
  { check: 'SBOM', status: 'failed', reason: 'SCAN_FAILED' },
];
const reports: Record<string, ScanResults> = {
  'partial-demo': { findings: [{ findingId: 'demo-1', category: 'secret', ruleId: 'SECRET_DETECTED', severity: 'high', evidenceRef: 'redacted:demo-1' }], nextCursor: null, coverage: baseCoverage },
  'empty-demo': { findings: [], nextCursor: null, coverage: [{ check: 'Secrets', status: 'checked', findingCount: 0 }] },
  'unsupported-demo': { findings: [], nextCursor: null, coverage: [{ check: 'Secrets', status: 'skipped', reason: 'CHECK_DISABLED' }, { check: 'CVE', status: 'unsupported', reason: 'OS_UNKNOWN' }] },
  'running-demo': { findings: [], nextCursor: null, coverage: [] },
};
export const fixtureScanTransport: ScanTransport = {
  kind: 'fixture',
  capabilities: { list: true, create: false, cancel: false, events: false },
  async list() { return demoScans; },
  async listPage(cursor) {
    if (cursor !== undefined) throw new Error('Недопустимая страница демо');
    return { scans: demoScans, nextCursor: null };
  },
  async get(id): Promise<ScanStatus> {
    const item = demoScans.find((scan) => scan.scanId === id);
    if (!item) throw new Error('Скан недоступен');
    return item;
  },
  async results(id, cursor, _signal, query) {
    if (query) throw new Error('Глобальные report-v1 controls не поддерживаются в демо');
    if (!reports[id] || cursor) throw new Error('Результаты недоступны');
    return reports[id];
  },
  async sbom(_id, _cursor, _signal, query) { if (query) throw new Error('Глобальные report-v1 controls не поддерживаются в демо'); return { outcome: 'failed', coverage: 'image', errorCode: 'SCAN_FAILED', components: [], nextCursor: null }; },
  async vuln(id, _cursor, _signal, query) {
    if (query) throw new Error('Глобальные report-v1 controls не поддерживаются в демо');
    if (id === 'unsupported-demo') return { outcome: 'unsupported', coverage: 'image', reason: 'OS_UNKNOWN', findings: [], nextCursor: null };
    return { outcome: 'failed', coverage: 'image', errorCode: 'SCAN_UNAVAILABLE', findings: [], nextCursor: null };
  },
  async create() { throw new Error('Запуск доступен только после настройки защищённого браузерного доступа'); },
  async cancel() { throw new Error('Отмена недоступна: серверный маршрут не реализован'); },
};

export const unavailableScanTransport: ScanTransport = {
  kind: 'live',
  capabilities: { list: false, create: false, cancel: false, events: false },
  async list() { throw new Error('Список недоступен: нет защищённого браузерного доступа и GET списка'); },
  async listPage() { throw new Error('Список недоступен: нет защищённого браузерного доступа и GET списка'); },
  async get() { throw new Error('Деталь недоступна: нет защищённого браузерного доступа'); },
  async results() { throw new Error('Результаты недоступны: нет защищённого браузерного доступа'); },
  async sbom() { throw new Error('SBOM недоступен: нет защищённого браузерного доступа'); },
  async vuln() { throw new Error('CVE недоступно: нет защищённого браузерного доступа'); },
  async create() { throw new Error('Запуск недоступен: нет защищённого браузерного доступа'); },
  async cancel() { throw new Error('Отмена недоступна: нет серверного маршрута'); },
};
