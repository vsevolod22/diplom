import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { ServiceUnavailableException } from '@nestjs/common';

export const PUBLIC_OPENROUTER_KEY_FILE = '/run/secrets/public_openrouter_key';
const unavailable = (): never => { throw new ServiceUnavailableException({ errorCode: 'LLM_CONFIGURATION_UNAVAILABLE' }); };

// Called only at the existing authenticated/consented provider-construction boundary.
// No env-file parser, directory search, fallback path or startup/readiness key read.
export function readPublicProviderKey(path: string): string {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size < 17 || stat.size > 513 ||
      ![0o400, 0o600].includes(stat.mode & 0o777) ||
      process.getuid && stat.uid !== 0 && stat.uid !== process.getuid()) return unavailable();
    const buffer = Buffer.alloc(514);
    let length = 0;
    for (;;) {
      const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (!n) break;
      length += n;
      if (length === buffer.length) return unavailable();
    }
    // ASCII, one final LF, no dotenv expansion, whitespace, alternate entries or BOM.
    const text = buffer.subarray(0, length).toString('latin1');
    if (!/^[A-Za-z0-9_-]{16,512}\n$/.test(text)) return unavailable();
    return text.slice(0, -1);
  } catch { return unavailable(); }
  finally { if (fd !== undefined) closeSync(fd); }
}
