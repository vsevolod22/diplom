import {
  canonical,
  exact,
  HEX,
  ID,
  integer,
  one,
  report,
  str,
  target,
  type Report,
  type Target,
  type Mode,
  type ImageLink,
  link,
} from '../../../../server/runtime/src/contract.js';
import { parseRuntimeJson } from '../../../../server/runtime/src/runtime-json.js';
export type { Report as RuntimeReport, Target as RuntimeTarget, Mode as RuntimeMode };
export type RuntimeConsent = {
  consentId: string;
  nonce: string;
  expiresAt: number;
  epoch: number;
  target: Target;
  mode: Mode;
};
export type RuntimeCapabilities = {
  schemaVersion: 'runtime-capabilities-v1';
  historicalImport: boolean;
  liveCapture: boolean;
  liveReason: 'READY' | 'QUALIFICATION_MISSING';
  host: 'not_authorized';
  rawIntake: 'parent-bootstrap-required' | 'authenticated-pre-json';
};
export function parseRuntimeReport(value: unknown, subject: string): Report {
  const r = report(value);
  if (r.subject !== subject) throw new Error('RUNTIME_ACCESS_CHANGED');
  return r;
}
export async function verifyRuntimeReport(value: unknown, subject: string): Promise<Report> {
  const r = parseRuntimeReport(value, subject);
  if (r.evidence) {
    const hash = async (text: string) =>
      Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), (b) =>
        b.toString(16).padStart(2, '0'),
      ).join('');
    const { hash: snapshotHash, ...snapshot } = r.evidence.snapshot;
    const { hash: captureHash, ...capture } = r.evidence;
    if (
      (await hash(canonical(snapshot))) !== snapshotHash ||
      (await hash(`runtime-capture-v1\n${canonical(capture)}`)) !== captureHash
    )
      throw new Error('INVALID_RUNTIME_INPUT');
  }
  return r;
}
export function parseCapabilities(v: unknown): RuntimeCapabilities {
  const c = exact(v, ['schemaVersion', 'historicalImport', 'liveCapture', 'liveReason', 'host', 'rawIntake']);
  one(c.schemaVersion, ['runtime-capabilities-v1']);
  one(c.host, ['not_authorized']);
  one(c.rawIntake, ['parent-bootstrap-required', 'authenticated-pre-json']);
  if (
    typeof c.historicalImport !== 'boolean' ||
    typeof c.liveCapture !== 'boolean' ||
    c.liveCapture !== (c.liveReason === 'READY')
  )
    throw new Error('INVALID_RUNTIME_INPUT');
  one(c.liveReason, ['READY', 'QUALIFICATION_MISSING']);
  return c as RuntimeCapabilities;
}
export class RuntimeTransport {
  private readonly prefix = '/api/v1/browser/runtime';
  constructor(
    readonly subject: string,
    private readonly current: () => boolean,
  ) {}
  private async request<T>(
    path: string,
    parse: (v: unknown) => T | Promise<T>,
    body?: unknown,
    signal?: AbortSignal,
    rawBody?: string,
  ): Promise<T> {
    if (!this.current()) throw new Error('RUNTIME_ACCESS_CHANGED');
    const bytes = rawBody ?? (body === undefined ? undefined : canonical(body));
    if (bytes && new TextEncoder().encode(bytes).length > (path === '/imports' ? 65536 : 1024))
      throw new Error('INVALID_RUNTIME_INPUT');
    const response = await fetch(`${this.prefix}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: bytes ? { 'Content-Type': 'application/json' } : undefined,
      body: bytes,
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10000)]) : AbortSignal.timeout(10000),
    });
    if (!this.current()) throw new Error('RUNTIME_ACCESS_CHANGED');
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        response.status === 503
          ? 'RUNTIME_UNAVAILABLE'
          : response.status === 401 || response.status === 403
            ? 'NOT_AUTHORIZED'
            : 'RUNTIME_REQUEST_FAILED',
      );
    }
    if (!response.body) throw new Error('RUNTIME_REQUEST_FAILED');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        size += next.value.length;
        if (size > 65536) throw new Error('INVALID_RUNTIME_INPUT');
        chunks.push(next.value);
      }
    } finally {
      await reader.cancel();
    }
    if (!this.current()) throw new Error('RUNTIME_ACCESS_CHANGED');
    const all = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) {
      all.set(c, at);
      at += c.length;
    }
    const result = await parse(parseRuntimeJson(all));
    if (!this.current() || signal?.aborted) throw new Error('RUNTIME_ACCESS_CHANGED');
    return result;
  }
  capabilities(signal?: AbortSignal) {
    return this.request('/capabilities', parseCapabilities, undefined, signal);
  }
  targets(signal?: AbortSignal) {
    return this.request(
      '/targets',
      (v) => {
        const t = exact(v, ['targets']);
        if (!Array.isArray(t.targets) || t.targets.length > 100) throw new Error('INVALID_RUNTIME_INPUT');
        return t.targets.map(target);
      },
      undefined,
      signal,
    );
  }
  consent(targetId: string, mode: Mode, expectedTarget?: Target) {
    str(targetId, ID);
    return this.request(
      '/consents',
      (v) => {
        const c = exact(v, ['consentId', 'nonce', 'expiresAt', 'epoch', 'target', 'mode']);
        str(c.consentId, ID);
        str(c.nonce, HEX);
        integer(c.expiresAt, 1);
        integer(c.epoch, 1);
        target(c.target);
        one(c.mode, ['imported-historical', 'broker-capture']);
        if (
          (c.target as Target).targetId !== targetId ||
          c.mode !== mode ||
          (expectedTarget && canonical(c.target) !== canonical(expectedTarget)) ||
          (c.expiresAt as number) <= Date.now() ||
          (c.expiresAt as number) - Date.now() > 300000
        )
          throw new Error('INVALID_RUNTIME_INPUT');
        return c as RuntimeConsent;
      },
      { targetId, mode, confirmed: true },
    );
  }
  revoke(consentId: string) {
    str(consentId, ID);
    return this.request(
      `/consents/${consentId}/revoke`,
      (v) => {
        const b = exact(v, ['revoked', 'changed']);
        if (b.revoked !== true || typeof b.changed !== 'boolean') throw new Error('INVALID_RUNTIME_INPUT');
        return true;
      },
      {},
    );
  }
  async submitImport(idempotencyKey: string, signedPackageText: string) {
    str(idempotencyKey, ID);
    // Preserve duplicate keys/integer lexemes for the authoritative raw-intake parser.
    const raw = `{"idempotencyKey":${JSON.stringify(idempotencyKey)},"package":${signedPackageText}}`;
    return this.receipt('/imports', { idempotencyKey }, raw);
  }
  async submitCapture(idempotencyKey: string, consent: RuntimeConsent) {
    return this.receipt('/captures', {
      idempotencyKey,
      consentId: consent.consentId,
      targetId: consent.target.targetId,
    });
  }
  private receipt(path: string, body: unknown, rawBody?: string) {
    return this.request(
      path,
      (v) => {
        const r = exact(v, ['captureId', 'created']);
        str(r.captureId, ID);
        if (typeof r.created !== 'boolean') throw new Error('INVALID_RUNTIME_INPUT');
        return r as { captureId: string; created: boolean };
      },
      body,
      undefined,
      rawBody,
    );
  }
  history(cursor?: string, signal?: AbortSignal) {
    if (cursor) str(cursor, ID);
    return this.request(
      `/captures${cursor ? `?cursor=${cursor}` : ''}`,
      async (v) => {
        const p = exact(v, ['captures', 'nextCursor']);
        if (!Array.isArray(p.captures) || p.captures.length > 20) throw new Error('INVALID_RUNTIME_INPUT');
        if (p.nextCursor !== null) str(p.nextCursor, ID);
        return {
          captures: await Promise.all(p.captures.map((v) => verifyRuntimeReport(v, this.subject))),
          nextCursor: p.nextCursor as string | null,
        };
      },
      undefined,
      signal,
    );
  }
  detail(id: string, signal?: AbortSignal) {
    str(id, ID);
    return this.request(`/captures/${id}`, (v) => verifyRuntimeReport(v, this.subject), undefined, signal);
  }
  cancel(id: string) {
    str(id, ID);
    return this.request(
      `/captures/${id}/cancel`,
      (v) => {
        const b = exact(v, ['cancelled', 'changed', 'state']);
        one(b.state, ['running', 'completed', 'failed', 'cancelled']);
        if (
          typeof b.cancelled !== 'boolean' ||
          typeof b.changed !== 'boolean' ||
          b.cancelled !== (b.state === 'cancelled') ||
          (b.changed && !b.cancelled)
        )
          throw new Error('INVALID_RUNTIME_INPUT');
        return b as { changed: boolean; cancelled: boolean; state: Report['state'] };
      },
      {},
    );
  }
  imageLink(id: string, imageScanId: string): Promise<ImageLink> {
    str(id, ID);
    str(imageScanId, /^[a-f0-9-]{36}$/);
    return this.request(`/captures/${id}/image-links`, link, { imageScanId });
  }
}
