import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { BadRequestException, HttpException, ServiceUnavailableException } from '@nestjs/common';
import { dockerHubSearch, hubSearchUrl, type HubSearchResponse } from '../oci/gateway-transport.js';

export type ImageSuggestion = { label: string; reference: string; scannable: boolean; kind: 'tag' | 'repository'; tagConfirmed: boolean; eligibility: 'alpine-only' | 'unsupported'; reason: string; checks: { secret: boolean; sbom: boolean; vuln: 'conditional' | 'unsupported' } };
export const searchPolicy = Object.freeze({ pageSize: 12, maxPages: 5, maxCandidates: 60, maxPageBytes: 128_000, maxBytes: 640_000, idleMs: 300_000, maxFetchMs: 5000, maxTotalMs: 25_000, maxActivePerProcess: 8, maxActivePerSubject: 2, maxRequestsPerSubject: 30, rateWindowMs: 60_000, maxSessions: 1024, maxRateEntries: 1024, scope: 'process-local' as const });
export type ImageSearchPage = { items: ImageSuggestion[]; nextCursor: string | null; state: 'more-available' | 'terminal' | 'quota-exhausted'; loaded: number; pages: number; policy: typeof searchPolicy };
const repoName = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)?$/;
const tagName = /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$/;

export function parseImageSearch(value: unknown): { query: string; alpineTag: string | null } {
  if (typeof value !== 'string' || value.length < 2 || value.length > 64 || !/^[a-zA-Z0-9_./: -]+$/.test(value)) throw new BadRequestException({ errorCode: 'INVALID_IMAGE_SEARCH' });
  const query = value.trim().toLowerCase().replace(/ +/g, ' ');
  if (query.length < 2 || query.includes('://') || query.includes('..') || query.includes('//')) throw new BadRequestException({ errorCode: 'INVALID_IMAGE_SEARCH' });
  const match = /^(?:(?:library\/)?alpine[: ]([a-z0-9][a-z0-9_.-]{0,63})|(\d[\da-z_.-]{1,63}))$/.exec(query);
  const tag = match?.[1] ?? match?.[2];
  return { query, alpineTag: tag && tagName.test(tag) ? tag : null };
}

export function normalizeImageSuggestions(response: HubSearchResponse, tagSearch: boolean): ImageSuggestion[] {
  if (!response || !Array.isArray(response.results) || response.results.length > searchPolicy.pageSize) throw new Error('Invalid search response');
  const found = new Map<string, ImageSuggestion>();
  for (const item of response.results) {
    if (!item || typeof item !== 'object') continue;
    const name = tagSearch ? item.name : item.repo_name;
    if (typeof name !== 'string' || (tagSearch ? !tagName.test(name) : name.length > 120 || !repoName.test(name))) continue;
    const repository = tagSearch ? 'library/alpine' : name.includes('/') ? name : `library/${name}`;
    const scannable = repository === 'library/alpine';
    const reference = `registry-1.docker.io/${repository}:${tagSearch ? name : 'latest'}`;
    found.set(reference, { label: tagSearch ? `Alpine · ${name}` : name, reference, scannable, kind: tagSearch ? 'tag' : 'repository', tagConfirmed: tagSearch, eligibility: scannable ? 'alpine-only' : 'unsupported', reason: scannable ? 'Только Alpine; платформа и допуск проверяются при запуске' : 'найден в Docker Hub, сканирование пока недоступно', checks: { secret: scannable, sbom: scannable, vuln: scannable ? 'conditional' : 'unsupported' } });
  }
  return [...found.values()];
}

type FetchHub = (kind: 'tags' | 'repositories', query: string, page?: number) => Promise<HubSearchResponse>;
type Session = { subject: string; query: string; generation: string; tag: string | null; until: number; page: number; bytes: number; elapsed: number; seen: Set<string>; cursor: string | null; cached?: { cursor: string; response: ImageSearchPage }; busy: boolean };
function reject(code: string, status: number): never { throw new HttpException({ errorCode: code }, status); }

// Ephemeral scoped cursors contain no upstream URLs. Restart requires a new search.
export class ImageSearchSessions {
  private readonly sessions = new Map<string, Session>();
  private readonly rates = new Map<string, { until: number; count: number }>();
  private active = 0;
  constructor(private readonly fetchHub: FetchHub = dockerHubSearch, private readonly now = Date.now) {}
  async search(subject: string, raw: unknown, generation: unknown, cursor?: unknown): Promise<ImageSearchPage> {
    const { query, alpineTag } = parseImageSearch(raw);
    if (typeof generation !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(generation) || (cursor !== undefined && (typeof cursor !== 'string' || !/^[a-f0-9]{48}$/.test(cursor)))) reject('INVALID_IMAGE_SEARCH', 400);
    const now = this.now();
    for (const [key, session] of this.sessions) if (!session.busy && session.until <= now) this.sessions.delete(key);
    for (const [key, rate] of this.rates) if (rate.until <= now) this.rates.delete(key);
    let rate = this.rates.get(subject);
    if (!rate) {
      if (this.rates.size >= searchPolicy.maxRateEntries) reject('IMAGE_SEARCH_CAPACITY', 429);
      rate = { until: now + searchPolicy.rateWindowMs, count: 0 }; this.rates.set(subject, rate);
    }
    if (++rate.count > searchPolicy.maxRequestsPerSubject) reject('IMAGE_SEARCH_RATE_LIMITED', 429);
    let session: Session | undefined;
    if (cursor !== undefined) {
      session = [...this.sessions.values()].find(value => value.cursor === cursor || value.cached?.cursor === cursor);
      if (!session || session.subject !== subject || session.query !== query || session.tag !== alpineTag || session.generation !== generation) reject('IMAGE_SEARCH_EXPIRED', 410);
      if (session.busy) reject('IMAGE_SEARCH_BUSY', 429);
      if (session.cached?.cursor === cursor) { session.until = now + searchPolicy.idleMs; return session.cached.response; }
    } else {
      if (this.sessions.size >= searchPolicy.maxSessions) reject('IMAGE_SEARCH_CAPACITY', 429);
      session = { subject, query, generation: generation as string, tag: alpineTag, until: now + searchPolicy.idleMs, page: 0, bytes: 0, elapsed: 0, seen: new Set(), cursor: null, busy: false };
      this.sessions.set(randomBytes(24).toString('hex'), session);
    }
    const current = session!;
    if (this.active >= searchPolicy.maxActivePerProcess || [...this.sessions.values()].filter(value => value.subject === subject && value.busy).length >= searchPolicy.maxActivePerSubject) {
      if (cursor === undefined) current.until = 0;
      reject('IMAGE_SEARCH_BUSY', 429);
    }
    current.busy = true; this.active++;
    const started = performance.now();
    try {
      if (current.page >= searchPolicy.maxPages || current.elapsed >= searchPolicy.maxTotalMs) reject('IMAGE_SEARCH_EXHAUSTED', 429);
      const page = current.page + 1;
      const kind = alpineTag ? 'tags' : 'repositories';
      const term = alpineTag ?? query;
      const response = await this.fetchHub(kind, term, page);
      const bytes = response.bytes ?? Buffer.byteLength(JSON.stringify(response));
      current.bytes += bytes;
      if (!Number.isInteger(bytes) || bytes < 0 || bytes > searchPolicy.maxPageBytes || current.bytes > searchPolicy.maxBytes || performance.now() - started > searchPolicy.maxFetchMs || current.elapsed + performance.now() - started > searchPolicy.maxTotalMs) throw new Error('Search budget');
      if (!Number.isInteger(response.count) || response.count! < 0 || !(response.next === null || typeof response.next === 'string')) throw new Error('Invalid page');
      if (response.next !== null) {
        const next = new URL(response.next!);
        const expected = hubSearchUrl(kind, term, page + 1);
        if (next.origin !== expected.origin || next.pathname !== expected.pathname || next.username || next.password || next.hash || [...next.searchParams].length !== [...expected.searchParams].length || [...expected.searchParams].some(([key, value]) => next.searchParams.getAll(key).length !== 1 || next.searchParams.get(key) !== value)) throw new Error('Invalid continuation');
      }
      const items = normalizeImageSuggestions(response, alpineTag !== null).filter(item => !current.seen.has(item.reference));
      for (const item of items) current.seen.add(item.reference);
      current.page = page;
      const state = response.next === null ? 'terminal' : page >= searchPolicy.maxPages || current.seen.size >= searchPolicy.maxCandidates ? 'quota-exhausted' : 'more-available';
      const nextCursor = state === 'more-available' ? randomBytes(24).toString('hex') : null;
      const result: ImageSearchPage = { items, nextCursor, state, loaded: current.seen.size, pages: page, policy: searchPolicy };
      current.cached = cursor ? { cursor: cursor as string, response: result } : undefined;
      current.cursor = nextCursor; current.until = this.now() + searchPolicy.idleMs;
      return result;
    } catch (error) {
      // A failed upstream attempt has an unknown cost; retire rather than allow budget bypass.
      current.until = 0;
      if (error instanceof HttpException) throw error;
      throw new ServiceUnavailableException({ errorCode: 'IMAGE_SEARCH_UNAVAILABLE' });
    } finally { current.elapsed += performance.now() - started; current.busy = false; this.active--; }
  }
}

export async function searchImages(raw: unknown, fetchHub: FetchHub = dockerHubSearch): Promise<ImageSuggestion[]> {
  const { query, alpineTag } = parseImageSearch(raw);
  try { return normalizeImageSuggestions(await fetchHub(alpineTag ? 'tags' : 'repositories', alpineTag ?? query, 1), alpineTag !== null); }
  catch { throw new ServiceUnavailableException({ errorCode: 'IMAGE_SEARCH_UNAVAILABLE' }); }
}
