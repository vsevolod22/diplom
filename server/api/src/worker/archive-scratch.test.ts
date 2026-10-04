import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { auditArchiveScratch } from './archive-scratch.js';
import { ARCHIVE_LIMITS } from '../oci/layer-tar-validator.js';

test('scratch counts archive/cache writes and exempts only exact trusted DB link', async () => {
  const root = await mkdtemp(`${tmpdir()}/archive-scratch-`);
  try {
    await mkdir(`${root}/cache`);
    await writeFile(`${root}/image.tar`, 'archive'); await writeFile(`${root}/cache/fanal`, 'cache');
    await symlink('/trusted/read-only/db', `${root}/cache/db`);
    assert.equal(await auditArchiveScratch(root, '/trusted/read-only/db'), 12);
    await assert.rejects(auditArchiveScratch(root));
    await assert.rejects(auditArchiveScratch(root, '/other/db'));
    await symlink('/private/SECRET_CANARY', `${root}/cache/other`);
    await assert.rejects(auditArchiveScratch(root, '/trusted/read-only/db'), { message: 'Invalid archive scratch' });
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('scratch exact N reservation passes and N+1 sparse bytes fail without allocating unbounded memory', async () => {
  const root = await mkdtemp(`${tmpdir()}/archive-scratch-`);
  try {
    await writeFile(`${root}/image.tar`, ''); await truncate(`${root}/image.tar`, ARCHIVE_LIMITS.scratchBytes);
    assert.equal(await auditArchiveScratch(root), ARCHIVE_LIMITS.scratchBytes);
    await truncate(`${root}/image.tar`, ARCHIVE_LIMITS.scratchBytes + 1);
    await assert.rejects(auditArchiveScratch(root), { message: 'Invalid archive scratch' });
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('scratch root symlink and directory depth overflow fail closed', async () => {
  const root = await mkdtemp(`${tmpdir()}/archive-scratch-`);
  try {
    await symlink(root, `${root}/alias`);
    await assert.rejects(auditArchiveScratch(`${root}/alias`));
    await rm(`${root}/alias`);
    await mkdir(`${root}/${Array(66).fill('d').join('/')}`, { recursive: true });
    await assert.rejects(auditArchiveScratch(root), { message: 'Invalid archive scratch' });
  } finally { await rm(root, { recursive: true, force: true }); }
});
