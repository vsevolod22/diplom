type NormalizedRowValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | readonly NormalizedRowValue[]
  | { readonly [key: string]: NormalizedRowValue };
const MAX_FINGERPRINT_CHARACTERS = 2 * 1024 * 1024;

// Encode complete normalized rows, not raw transport data or an allowlist of headline fields.
export function fingerprintReportRows(rows: readonly NormalizedRowValue[]): string {
  const parts: string[] = [];
  let length = 0;
  const append = (part: string) => {
    length += part.length;
    if (length > MAX_FINGERPRINT_CHARACTERS) throw new Error('Report page fingerprint limit');
    parts.push(part);
  };
  const isArray = (value: NormalizedRowValue): value is readonly NormalizedRowValue[] => Array.isArray(value);
  const encode = (value: NormalizedRowValue, depth: number): void => {
    if (depth > 32) throw new Error('Report page nesting limit');
    if (value == null) {
      append('null');
      return;
    }
    if (typeof value !== 'object') {
      if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('Invalid report number');
      append(JSON.stringify(value));
      return;
    }
    if (isArray(value)) {
      append('[');
      value.forEach((item, index) => {
        if (index) append(',');
        encode(item, depth + 1);
      });
      append(']');
      return;
    }
    append('{');
    // Missing optional fields and explicitly undefined fields render identically; array order matters.
    Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .forEach((key, index) => {
        if (index) append(',');
        append(JSON.stringify(key));
        append(':');
        encode(value[key], depth + 1);
      });
    append('}');
  };
  encode(rows, 0);
  return parts.join('');
}
