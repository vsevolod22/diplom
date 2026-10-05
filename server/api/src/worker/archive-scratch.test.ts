import test from 'node:test';
import assert from 'node:assert/strict';
import { lstat, mkdtemp, mkdir, readdir, readlink, rm, statfs, symlink, truncate, writeFile } from 'node:fs/promises';
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
test('only enumerated descendants disappearing with ENOENT are tolerated, not root or other I/O errors', async () => {
  const root = await mkdtemp(`${tmpdir()}/archive-scratch-`);
  const filesystem = { lstat, readdir, readlink, statfs };
  try {
    await mkdir(`${root}/cache`); await writeFile(`${root}/cache/temp`, 'temporary');
    await mkdir(`${root}/cache/gone`); await writeFile(`${root}/cache/gone/temp`, 'temporary');
    // Deterministic enumeration -> lstat and lstat -> readdir cleanup races.
    let races = 0;
    const racing = { ...filesystem, lstat: (async (path: string) => {
      if (path === `${root}/cache/temp`) { await rm(path); races++; }
      const info = await lstat(path);
      if (path === `${root}/cache/gone`) { await rm(path, { recursive: true }); races++; }
      return info;
    }) as typeof lstat };
    assert.equal(await auditArchiveScratch(root, undefined, racing), 0);
    assert.equal(races, 2);
    const denied = { ...filesystem, lstat: (async (path: string) => {
      if (path === `${root}/cache`) throw Object.assign(new Error('denied'), { code: 'EACCES' });
      return lstat(path);
    }) as typeof lstat };
    await assert.rejects(auditArchiveScratch(root, undefined, denied), { code: 'EACCES' });
    await rm(root, { recursive: true });
    await assert.rejects(auditArchiveScratch(root), { code: 'ENOENT' });
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('200 concurrent cache-file/directory cleanup audits keep final accounting and reject live links', async () => {
  const root = await mkdtemp(`${tmpdir()}/archive-scratch-`);
  let stop = false;
  await mkdir(`${root}/cache`); await writeFile(`${root}/image.tar`, 'archive');
  const churn = (async () => {
    while (!stop) {
      await mkdir(`${root}/cache/temp`);
      await Promise.all(Array.from({ length: 16 }, (_, index) => writeFile(`${root}/cache/temp/${index}`, 'tmp')));
      await rm(`${root}/cache/temp`, { recursive: true });
    }
  })();
  try {
    for (let index = 0; index < 200; index++) assert.ok(await auditArchiveScratch(root) >= 7);
    stop = true; await churn;
    assert.equal(await auditArchiveScratch(root), 7);
    await symlink('/outside', `${root}/cache/link`);
    await assert.rejects(auditArchiveScratch(root), { message: 'Invalid archive scratch' });
  } finally { stop = true; await churn; await rm(root, { recursive: true, force: true }); }
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
