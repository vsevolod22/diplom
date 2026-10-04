import { BROWSER_SCANS_PATH, parseCurrentList, parseCurrentResults, parseCurrentSbom, parseCurrentVuln, parseCurrentStatus, parseScanReceipt, parseScanEventHint, sameOriginScanUrl, type ScanTransport } from './scanTransport';

export class ScanAccessError extends Error {
  constructor(readonly status: 401 | 403) {
    super(status === 401 ? 'Сессия недействительна' : 'Аккаунту не выдано разрешение на реальные сканы');
  }
}

export class ScanHttpError extends Error {
  constructor(readonly status: number, readonly code: string | null) {
    super(status === 409 ? 'Отмена невозможна в текущем состоянии' : 'Запрос скана не выполнен');
  }
}

/** Session-bound, same-origin cookie transport. The server enforces authorization for every request. */
export function createAuthorizedScanTransport(session: { subject: string; currentSubject: () => string | null }): ScanTransport {
  if (!session.subject) throw new Error('Неизвестный субъект');
  async function request(path: string, signal?: AbortSignal, body?: object): Promise<unknown> {
    if (session.currentSubject() !== session.subject) throw new Error('Сессия изменилась: кэш и потоки должны быть очищены');

    const response = await fetch(path, {
      method: body ? 'POST' : 'GET',
      headers: body ? { 'Content-Type': 'application/json', ...(path.endsWith('/cancel') ? { Origin: window.location.origin } : {}) } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal,
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
    });
    if (session.currentSubject() !== session.subject) throw new Error('Сессия изменилась: ответ отклонён');
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) throw new ScanAccessError(response.status);
      if (response.status === 404) throw new Error('Скан недоступен');
      if ([400, 409, 429, 503].includes(response.status)) {
        const payload: unknown = typeof response.json === 'function' ? await response.json().catch(() => null) : null;
        const code = payload && typeof payload === 'object' && 'errorCode' in payload && typeof payload.errorCode === 'string'
          ? payload.errorCode : null;
        throw new ScanHttpError(response.status, code);
      }
      if (response.status === 409) throw new Error('Отмена невозможна в текущем состоянии');
      throw new Error('Запрос скана не выполнен');
    }
    const value: unknown = await response.json();
    if (session.currentSubject() !== session.subject) throw new Error('Сессия изменилась: ответ отклонён');
    return value;
  }
  return {
    kind: 'live', capabilities: { list: true, create: true, cancel: true, events: true },
    async list(signal) {
      const scans = [];
      let cursor: string | null = null;
      // The existing list UI expects a complete array, not just the first page.
      // Fail closed rather than label a truncated list as complete.
      for (let pageIndex = 0; pageIndex < 100; pageIndex++) {
        const path = `${BROWSER_SCANS_PATH}?limit=100${cursor === null ? '' : `&cursor=${cursor}`}`;
        const page = parseCurrentList(await request(path, signal));
        scans.push(...page.scans);
        if (page.nextCursor === null) return scans;
        if (!page.scans.length || cursor === page.nextCursor) {
          throw new Error('Недопустимая пагинация списка');
        }
        cursor = page.nextCursor;
      }
      throw new Error('Список слишком велик для текущего интерфейса');
    },
    async get(id, signal) { return parseCurrentStatus(await request(sameOriginScanUrl(`${BROWSER_SCANS_PATH}/${encodeURIComponent(id)}`, id), signal)); },
    async results(id, cursor, signal) {
      const path = sameOriginScanUrl(`${BROWSER_SCANS_PATH}/${encodeURIComponent(id)}/results`, id, '/results');
      if (cursor && !/^(0|[1-9]\d{0,5})$/.test(cursor)) throw new Error('Недопустимая страница');
      return parseCurrentResults(await request(`${path}?limit=50${cursor ? `&cursor=${cursor}` : ''}`, signal));
    },
    async sbom(id, cursor, signal) {
      const path = sameOriginScanUrl(`${BROWSER_SCANS_PATH}/${encodeURIComponent(id)}/sbom`, id, '/sbom');
      if (cursor !== undefined && !/^(0|[1-9]\d{0,5})$/.test(cursor)) throw new Error('Недопустимая страница');
      return parseCurrentSbom(await request(`${path}?limit=50${cursor === undefined ? '' : `&cursor=${cursor}`}`, signal));
    },
    async vuln(id, cursor, signal) {
      const path = sameOriginScanUrl(`${BROWSER_SCANS_PATH}/${encodeURIComponent(id)}/vuln`, id, '/vuln');
      if (cursor !== undefined && !/^(0|[1-9]\d{0,5})$/.test(cursor)) throw new Error('Недопустимая страница');
      return parseCurrentVuln(await request(`${path}?limit=50${cursor === undefined ? '' : `&cursor=${cursor}`}`, signal));
    },
    async create(intent) {
      if (!intent.checks.length || intent.checks.some((check, index) => !['secret', 'sbom', 'vuln'].includes(check) || index > 0 && ['secret', 'sbom', 'vuln'].indexOf(intent.checks[index - 1]) >= ['secret', 'sbom', 'vuln'].indexOf(check))) throw new Error('Недопустимый набор проверок');
      // Ignore receipt URLs: they may point at the internal JWT-only API.
      return parseScanReceipt(await request(BROWSER_SCANS_PATH, undefined, intent));
    },
    subscribeEvents(id, onHint, onError, onOpen) {
      if (session.currentSubject() !== session.subject) throw new Error('Сессия изменилась: поток отклонён');
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
        throw new Error('Недопустимый адрес скана');
      }
      const path = sameOriginScanUrl(`${BROWSER_SCANS_PATH}/${encodeURIComponent(id)}/events`, id, '/events');
      // Native EventSource sends same-origin HttpOnly cookies and reconnects with Last-Event-ID.
      // Never use receipt URLs, tokens, or event data as a cached status.
      const source = new EventSource(path);
      let closed = false;
      let reconnectDeadline: ReturnType<typeof setTimeout> | undefined;
      const close = () => {
        if (closed) return;
        closed = true;
        clearTimeout(reconnectDeadline);
        source.close();
      };
      source.addEventListener('open', () => {
        if (closed) return;
        if (session.currentSubject() !== session.subject) { close(); return; }
        clearTimeout(reconnectDeadline);
        reconnectDeadline = undefined;
        onOpen();
      });
      source.addEventListener('scan', (event) => {
        if (closed) return;
        if (session.currentSubject() !== session.subject) { close(); return; }
        try {
          if (parseScanEventHint(JSON.parse((event as MessageEvent).data), id)) onHint();
        } catch { /* Malformed hints cannot replace the GET snapshot. */ }
      });
      source.addEventListener('error', () => {
        if (closed) return;
        if (session.currentSubject() !== session.subject) { close(); return; }
        onError();
        // Allow native Last-Event-ID reconnect, but do not retry a rejected stream forever.
        reconnectDeadline ??= setTimeout(close, 15_000);
      });
      return close;
    },
    async cancel(id) {
      if (!/^[A-Za-z0-9-]+$/.test(id)) throw new Error('Недопустимый адрес скана');
      const path = `${sameOriginScanUrl(`${BROWSER_SCANS_PATH}/${encodeURIComponent(id)}`, id)}/cancel`;
      const value = await request(path, undefined, {});
      if (value === null || typeof value !== 'object' || Array.isArray(value) ||
          Object.keys(value).length !== 2 || !Object.hasOwn(value, 'scanId') || !Object.hasOwn(value, 'state') ||
          (value as { scanId: unknown }).scanId !== id || (value as { state: unknown }).state !== 'cancelled') {
        throw new Error('Недопустимый ответ отмены');
      }
    },
  };
}
