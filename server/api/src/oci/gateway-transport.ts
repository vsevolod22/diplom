import { request as httpRequest } from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { ResolutionRejected, type ManifestFetch, type ManifestResponse } from './registry-resolver.js';

export type HubSearchResponse = { results: Array<{ repo_name?: unknown; name?: unknown }>; next?: string | null; count?: number; bytes?: number };

export function hubSearchUrl(kind: 'tags' | 'repositories', query: string, page: number): URL {
  if (!Number.isInteger(page) || page < 1 || page > 6) throw new ResolutionRejected('Invalid search page');
  const url = new URL(kind === 'tags' ? 'https://hub.docker.com/v2/repositories/library/alpine/tags/' : 'https://hub.docker.com/v2/search/repositories/');
  url.searchParams.set('page_size', '12');
  url.searchParams.set(kind === 'tags' ? 'name' : 'query', query);
  url.searchParams.set('page', String(page));
  return url;
}

export async function dockerHubSearch(kind: 'tags' | 'repositories', query: string, page = 1,
  request = gatewayGet): Promise<HubSearchResponse> {
  const result = await request({ host: 'egress', port: 8080 }, hubSearchUrl(kind, query, page), { accept: 'application/json' }, 128_000, 5000);
  if (result.body.length > 128_000) throw new ResolutionRejected('Image search size limit');
  if (result.status !== 200 || !String(result.headers['content-type'] ?? '').startsWith('application/json'))
    throw new ResolutionRejected('Image search unavailable');
  try {
    const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.body)) as HubSearchResponse;
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid response');
    return { ...data, bytes: result.body.length };
  }
  catch { throw new ResolutionRejected('Invalid image search response'); }
}

export const DOCKER_HUB_HOSTS = Object.freeze({
  registry: 'registry-1.docker.io', token: 'auth.docker.io', blobs: ['production.cloudfront.docker.com'],
});
const MAX_OBJECT = 4_000_000;
const ACCEPT = 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json';

type Gateway = { host: string; port: number };
function safeUrl(raw: string, allowed: ReadonlySet<string>): URL {
  let url: URL;
  try { url = new URL(raw); } catch { throw new ResolutionRejected('Invalid destination'); }
  if (url.protocol !== 'https:' || url.port || url.username || url.password || url.hash ||
      !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(url.hostname) || !allowed.has(url.hostname) ||
      /%(?:2f|5c|00)/i.test(url.pathname) || url.pathname.includes('..'))
    throw new ResolutionRejected('Invalid destination');
  return url;
}

// Never directly resolve or fetch a remote URL in this process. TLS validates the host
// through Node's trust store; the gateway independently validates every connected IP.
export async function gatewayGet(gateway: Gateway, url: URL, headers: Record<string, string>, maxBytes = MAX_OBJECT, deadlineMs?: number,
  sink?: (chunk: Buffer, status: number) => Promise<void>, signal?: AbortSignal): Promise<ManifestResponse> {
  if (!gateway.host || !Number.isInteger(gateway.port) || gateway.port < 1 || gateway.port > 65535)
    throw new ResolutionRejected('Invalid gateway');
  return new Promise((resolve, reject) => {
    let settled = false;
    const resources: Array<{ destroy: () => void }> = [];
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => { clearTimeout(deadline); signal?.removeEventListener('abort', abort); for (const resource of resources) resource.destroy(); };
    const fail = (stage: string) => { if (!settled) { settled = true; cleanup(); reject(new ResolutionRejected(`Registry ${stage} failed`)); } };
    const abort = () => fail('cancelled');
    if (signal?.aborted) { abort(); return; }
    signal?.addEventListener('abort', abort, { once: true });
    if (deadlineMs !== undefined) deadline = setTimeout(() => fail('absolute deadline'), deadlineMs);
    const connect = httpRequest({ hostname: gateway.host, port: gateway.port, method: 'CONNECT', path: `${url.hostname}:443`, headers: { host: `${url.hostname}:443` }, timeout: 5000 });
    resources.push(connect);
    connect.on('connect', (response, socket, head) => {
      resources.push(socket);
      if (settled) { socket.destroy(); return; }
      if (response.statusCode !== 200 || head.length) { socket.destroy(); fail(`CONNECT status ${response.statusCode ?? 0}`); return; }
      const secure = tlsConnect({ socket, servername: url.hostname, rejectUnauthorized: true });
      resources.push(secure);
      secure.setTimeout(10_000, () => { secure.destroy(); fail('TLS timeout'); });
      secure.on('error', () => fail('TLS')); 
      secure.once('secureConnect', () => {
        if (settled) return;
        const agent = new HttpsAgent({ keepAlive: false });
        resources.push(agent);
        agent.createConnection = () => secure;
        const request = httpsRequest({ hostname: url.hostname, method: 'GET', path: url.pathname + url.search,
          headers, agent, timeout: 10000 }, result => {
          resources.push(result);
          const chunks: Buffer[] = [];
          let size = 0;
          void (async () => {
            try {
              for await (const chunk of result) {
                if (settled) return;
                const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                size += bytes.length;
                if (size > maxBytes) { fail('size limit'); return; }
                if (sink) await sink(bytes, result.statusCode || 0);
                else chunks.push(bytes);
              }
              if (!settled) {
                settled = true; clearTimeout(deadline);
                resolve({ status: result.statusCode || 0, headers: result.headers, body: Buffer.concat(chunks) });
                cleanup();
              }
            } catch { fail('response'); }
          })();
          result.on('error', () => fail('response')); 
        });
        resources.push(request);
        request.on('error', () => fail('request'));
        request.on('timeout', () => { request.destroy(); fail('request timeout'); });
        request.end();
      });
    });
    connect.on('timeout', () => { connect.destroy(); fail('CONNECT timeout'); });
    connect.on('error', () => fail('CONNECT socket'));
    connect.end();
  });
}

function bearerChallenge(header: string | string[] | undefined, repo: string, tokenHost: string): URL {
  if (typeof header !== 'string' || header.length > 2048) throw new ResolutionRejected('Unsupported auth challenge');
  const match = /^Bearer realm="([^"\r\n]+)",service="([^"\r\n]+)",scope="([^"\r\n]+)"$/.exec(header);
  if (!match || match[2] !== 'registry.docker.io' || match[3] !== `repository:${repo}:pull`)
    throw new ResolutionRejected('Unsupported auth challenge');
  const realm = safeUrl(match[1], new Set([tokenHost]));
  if (realm.search || realm.pathname !== '/token') throw new ResolutionRejected('Unsupported auth realm');
  realm.searchParams.set('service', match[2]);
  realm.searchParams.set('scope', match[3]);
  return realm;
}

export function dockerHubManifestFetch(gateway: Gateway, repository: string,
  request: (gateway: Gateway, url: URL, headers: Record<string, string>, maxBytes?: number) => Promise<ManifestResponse> = gatewayGet): ManifestFetch {
  if (!/^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/.test(repository))
    throw new ResolutionRejected('Invalid repository');
  let token: string | undefined;
  return async (host, path) => {
    if (host !== DOCKER_HUB_HOSTS.registry || !path.startsWith(`/v2/${repository}/`) ||
        !/^\/v2\/[a-zA-Z0-9/._%:-]+$/.test(path) || path.includes('..') || /%(?:2f|5c|00)/i.test(path))
      throw new ResolutionRejected('Invalid OCI path');
    const registryUrl = safeUrl(`https://${host}${path}`, new Set([host]));
    async function registryRequest() {
      return request(gateway, registryUrl, { accept: ACCEPT, ...(token ? { authorization: `Bearer ${token}` } : {}) });
    }
    let result = await registryRequest();
    if (result.status === 401 && !token) {
      const realm = bearerChallenge(result.headers['www-authenticate'], repository, DOCKER_HUB_HOSTS.token);
      const response = await request(gateway, realm, { accept: 'application/json' }, 32_768);
      if (response.status !== 200) throw new ResolutionRejected('Token unavailable');
      let data: unknown;
      try { data = JSON.parse(response.body.toString('utf8')); } catch { throw new ResolutionRejected('Invalid token response'); }
      const candidate = (data as { token?: unknown } | null)?.token;
      if (typeof candidate !== 'string' || candidate.length > 8192 || !/^[\x21-\x7e]+$/.test(candidate))
        throw new ResolutionRejected('Invalid token response');
      token = candidate;
      result = await registryRequest();
    }
    // Do not follow registry redirects to arbitrary URLs. Only blob GETs may redirect to
    // this explicitly approved CDN; no Authorization/Cookie is forwarded across origins.
    for (let hops = 0; hops < 3 && [301, 302, 303, 307, 308].includes(result.status); hops++) {
      if (!path.includes('/blobs/') || typeof result.headers.location !== 'string')
        throw new ResolutionRejected('Redirect refused');
      const redirect = safeUrl(result.headers.location, new Set(DOCKER_HUB_HOSTS.blobs));
      if (redirect.hostname === host) throw new ResolutionRejected('Redirect refused');
      result = await request(gateway, redirect, { accept: 'application/octet-stream' });
    }
    if (result.status !== 200) throw new ResolutionRejected('OCI object unavailable');
    return result;
  };
}
