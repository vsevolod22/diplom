import { BadRequestException, ServiceUnavailableException } from '@nestjs/common';
import { dockerHubSearch, type HubSearchResponse } from '../oci/gateway-transport.js';

export type ImageSuggestion = { label: string; reference: string; scannable: boolean };
const repoName = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)?$/;
const tagName = /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$/;

export function parseImageSearch(value: unknown): { query: string; alpineTag: string | null } {
  if (typeof value !== 'string' || value.length < 2 || value.length > 64 ||
      !/^[a-zA-Z0-9_./: -]+$/.test(value)) throw new BadRequestException({ errorCode: 'INVALID_IMAGE_SEARCH' });
  const query = value.trim().toLowerCase();
  if (query.length < 2 || query.includes('://') || query.includes('..') || query.includes('//'))
    throw new BadRequestException({ errorCode: 'INVALID_IMAGE_SEARCH' });
  const match = /^(?:(?:library\/)?alpine[: ]([a-z0-9][a-z0-9_.-]{0,63})|(\d[\da-z_.-]{1,63}))$/.exec(query);
  const tag = match?.[1] ?? match?.[2];
  const alpineTag = tag && tagName.test(tag) ? tag : null;
  return { query, alpineTag };
}

export function normalizeImageSuggestions(response: HubSearchResponse, tagSearch: boolean): ImageSuggestion[] {
  if (!response || !Array.isArray(response.results) || response.results.length > 20) throw new Error('Invalid search response');
  const found: ImageSuggestion[] = [];
  for (const item of response.results) {
    if (!item || typeof item !== 'object') continue;
    const name = tagSearch ? item.name : item.repo_name;
    if (typeof name !== 'string') continue;
    if (tagSearch) {
      if (!tagName.test(name)) continue;
      found.push({ label: `Alpine · ${name}`, reference: `registry-1.docker.io/library/alpine:${name}`, scannable: true });
    } else if (name.length <= 120 && repoName.test(name)) {
      const repository = name.includes('/') ? name : `library/${name}`;
      found.push({ label: name, reference: `registry-1.docker.io/${repository}:latest`, scannable: repository === 'library/alpine' });
    }
  }
  return found;
}

export async function searchImages(raw: unknown, fetchHub = dockerHubSearch): Promise<ImageSuggestion[]> {
  const { query, alpineTag } = parseImageSearch(raw);
  try {
    const result = await fetchHub(alpineTag ? 'tags' : 'repositories', alpineTag ?? query);
    return normalizeImageSuggestions(result, alpineTag !== null);
  } catch {
    throw new ServiceUnavailableException({ errorCode: 'IMAGE_SEARCH_UNAVAILABLE' });
  }
}
