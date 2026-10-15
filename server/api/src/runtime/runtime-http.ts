type RuntimeHeaders = {
  headers: Record<string, string | string[] | undefined>;
  rawHeaders?: readonly string[];
};

// Node may discard duplicate header values from `headers`; presence is authoritative even when empty.
export function hasRuntimeHeader(req: RuntimeHeaders, name: string): boolean {
  const lower = name.toLowerCase();
  if (Object.keys(req.headers).some(key => key.toLowerCase() === lower)) return true;
  const raw = req.rawHeaders ?? [];
  for (let i = 0; i < raw.length; i += 2) {
    if (raw[i].toLowerCase() === lower) return true;
  }
  return false;
}

export const RUNTIME_PREFIX = '/api/v1/browser/runtime';
const namespace = /^\/api\/v1\/browser\/runtime(?:\/|$)/i;

// Classify only: never rewrite URL, decode DTOs or normalize dot segments into an admitted route.
export function runtimeRequestPath(url: string): { pathname: string; protectedNamespace: boolean } {
  const target = url.split('?')[0];
  // Express/parseurl can extract a pathname from an absolute request target. Intercept it,
  // but the intake permits only original origin-form URLs, never a rewritten absolute URL.
  const absolute = /^[a-z][a-z0-9+.-]*:(?:\/\/[^/]*)?(\/.*)$/i.exec(target);
  const pathname = absolute?.[1] ?? target;
  let classified = pathname;
  try {
    classified = decodeURIComponent(pathname);
  } catch {
    // A malformed escape in the literal protected namespace is still intercepted and rejected.
  }
  return { pathname, protectedNamespace: namespace.test(pathname) || namespace.test(classified) };
}
