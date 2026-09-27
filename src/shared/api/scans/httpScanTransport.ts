import { parseCurrentResults, parseCurrentStatus, parseScanReceipt, sameOriginScanUrl, type ScanTransport } from './scanTransport';

/** Not wired into the app until a same-origin ingress and a session-bound identity provider exist. */
export function createAuthorizedScanTransport(session: { subject: string; currentSubject: () => string | null; token: () => string | null }): ScanTransport {
  if (!session.subject) throw new Error('Неизвестный субъект');
  async function request(path: string, signal?: AbortSignal, body?: object): Promise<unknown> {
    if (session.currentSubject() !== session.subject) throw new Error('Сессия изменилась: кэш и потоки должны быть очищены');
    const token = session.token();
    if (!token) throw new Error('Нет авторизованной сессии');
    const response = await fetch(path, {
      method: body ? 'POST' : 'GET',
      headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal,
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
    });
    if (!response.ok) throw new Error(response.status === 401 || response.status === 403 || response.status === 404 ? 'Скан недоступен' : 'Запрос скана не выполнен');
    return response.json() as Promise<unknown>;
  }
  return {
    kind: 'live', capabilities: { list: false, create: true, cancel: false, events: false },
    async list() { throw new Error('GET списка не реализован'); },
    async get(id, signal) { return parseCurrentStatus(await request(sameOriginScanUrl(`/api/v1/scans/${encodeURIComponent(id)}`, id), signal)); },
    async results(id, cursor, signal) {
      const path = sameOriginScanUrl(`/api/v1/scans/${encodeURIComponent(id)}/results`, id, '/results');
      if (cursor && !/^(0|[1-9]\d{0,5})$/.test(cursor)) throw new Error('Недопустимая страница');
      return parseCurrentResults(await request(`${path}?limit=50${cursor ? `&cursor=${cursor}` : ''}`, signal));
    },
    async create(intent) {
      const value = parseScanReceipt(await request('/api/v1/scans', undefined, intent));
      sameOriginScanUrl(value.statusUrl, value.scanId);
      sameOriginScanUrl(value.eventsUrl, value.scanId, '/events');
      return value;
    },
    async cancel() { throw new Error('Серверная отмена недоступна'); },
  };
}
