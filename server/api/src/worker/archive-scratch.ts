import { lstat, readdir, readlink, statfs } from 'node:fs/promises';
import { ARCHIVE_LIMITS } from '../oci/layer-tar-validator.js';

// Never follow scanner-created links. Only our exact cache/db RO link is exempt.
export async function auditArchiveScratch(directory: string, dbTarget?: string): Promise<number> {
  let entries = 0, bytes = 0;
  const fail = (): never => { throw new Error('Invalid archive scratch'); };
  const walk = async (path: string, depth: number): Promise<void> => {
    if (depth > 64) fail();
    for (const entry of await readdir(path, { withFileTypes: true })) {
      if (++entries > 50_000) fail();
      const child = `${path}/${entry.name}`;
      const info = await lstat(child);
      if (info.isSymbolicLink()) {
        if (!dbTarget || child !== `${directory}/cache/db` || await readlink(child) !== dbTarget) fail();
      } else if (info.isDirectory()) await walk(child, depth + 1);
      else if (info.isFile()) {
        bytes += info.size;
        if (!Number.isSafeInteger(bytes) || bytes > ARCHIVE_LIMITS.scratchBytes) fail();
      } else fail();
    }
  };
  const root = await lstat(directory);
  if (!root.isDirectory() || root.isSymbolicLink()) fail();
  await walk(directory, 0);
  const fs = await statfs(directory);
  if (fs.bavail * fs.bsize < 16 * 1024 ** 2) fail();
  return bytes;
}
