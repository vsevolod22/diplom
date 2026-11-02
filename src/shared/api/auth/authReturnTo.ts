const SCAN_DETAIL_PATH = /^\/scans\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function safeAuthReturnTo(value: unknown): string {
  if (value === '/account' || value === '/scans' || value === '/scans/new') return value;
  // Match the raw path only: no decoding, URL normalization, query or fragment redirects.
  if (typeof value === 'string' && value.length === 43 && SCAN_DETAIL_PATH.test(value)) return value;
  return '/account';
}
