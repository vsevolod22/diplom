import { lstat, readdir, readlink, statfs } from 'node:fs/promises';
import { ARCHIVE_LIMITS } from '../oci/layer-tar-validator.js';

const scratchFilesystem = { lstat, readdir, readlink, statfs };
const disappeared = (error: unknown): boolean => !!error && typeof error === 'object' &&
  'code' in error && error.code === 'ENOENT';

// Never follow scanner-created links. Only our exact cache/db RO link is exempt.
export async function auditArchiveScratch(directory: string, dbTarget?: string,
  filesystem: typeof scratchFilesystem = scratchFilesystem,
    limits: Readonly<{ scratchBytes: number; entries: number }> = ARCHIVE_LIMITS): Promise<number> {
  let entries = 0, bytes = 0;
  const fail = (): never => { throw new Error('Invalid archive scratch'); };
  const walk = async (path: string, depth: number): Promise<void> => {
    if (depth > 64) fail();
    let before, children;
    try {
      before = await filesystem.lstat(path);
      if (!before.isDirectory() || before.isSymbolicLink()) fail();
      children = await filesystem.readdir(path, { withFileTypes: true });
    } catch (error) {
      // Trivy removes its own cache/tmp directories while the periodic audit runs.
      // Only a vanished descendant is benign: the attempt root must still exist.
      if (depth > 0 && disappeared(error)) return;
      throw error;
    }
    for (const entry of children) {
      if (++entries > limits.entries) fail();
      const child = `${path}/${entry.name}`;
      if (entry.isSymbolicLink() && (!dbTarget || child !== `${directory}/cache/db`)) fail();
      let info;
      try { info = await filesystem.lstat(child); }
      catch (error) { if (disappeared(error)) continue; throw error; }
      if (info.isSymbolicLink()) {
        if (!dbTarget || child !== `${directory}/cache/db`) fail();
        try { if (await filesystem.readlink(child) !== dbTarget) fail(); }
        catch (error) { if (!disappeared(error)) throw error; }
      } else if (info.isDirectory()) await walk(child, depth + 1);
      else if (info.isFile()) {
        bytes += info.size;
        if (!Number.isSafeInteger(bytes) || bytes > limits.scratchBytes) fail();
      } else fail();
    }
    try {
      const after = await filesystem.lstat(path);
      if (!after.isDirectory() || after.isSymbolicLink() ||
          depth === 0 && (after.dev !== before.dev || after.ino !== before.ino)) fail();
    } catch (error) { if (depth === 0 || !disappeared(error)) throw error; }
  };
  const root = await filesystem.lstat(directory);
  if (!root.isDirectory() || root.isSymbolicLink()) fail();
  await walk(directory, 0);
  const finalRoot = await filesystem.lstat(directory);
  if (!finalRoot.isDirectory() || finalRoot.isSymbolicLink() || finalRoot.dev !== root.dev || finalRoot.ino !== root.ino) fail();
  // Quiescent runner audits again after all subprocesses close. Traversal remains
  // bounded even under churn; the tmpfs is the independent physical hard quota.
  const fs = await filesystem.statfs(directory);
  if (fs.bavail * fs.bsize < 16 * 1024 ** 2) fail();
  return bytes;
}
