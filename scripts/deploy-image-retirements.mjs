// Explicit owner waiver of old rollback-image custody. Historical receipts stay
// immutable; only the live image-retention obligation is relinquished.
import * as fs from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual as equal } from 'node:util';
import { PROJECT, STATE } from './public-image-stand.mjs';

export const IMAGE_RETIREMENTS = 'image-retirements-v1';
export const IMAGE_RETIREMENT_ACK = 'owner-authorized-discard-old-rollback-images';
const nonce = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
const fail = () => { throw new Error('IMAGE_RETIREMENT_INVALID'); };
const need = ok => { if (!ok) fail(); };
const exact = (value, names) => value && Object.getPrototypeOf(value) === Object.prototype && equal(Object.keys(value).sort(), [...names].sort());
export const retirementReference = ({ name, tag, image, origin }) => ({ name, tag, image, origin });

export function applyImageRetirements(references, records) {
  need(Array.isArray(references) && Array.isArray(records) && records.length <= 64);
  const byTag = new Map(references.map(row => [row.tag, row]));
  need(byTag.size === references.length);
  const retired = new Set();
  for (const record of records) {
    need(exact(record, ['version', 'project', 'nonce', 'acknowledgement', 'createdAt', 'references']) &&
      record.version === 1 && record.project === PROJECT && nonce(record.nonce) &&
      record.acknowledgement === IMAGE_RETIREMENT_ACK && Number.isSafeInteger(record.createdAt) && record.createdAt > 0 &&
      Array.isArray(record.references) && record.references.length > 0 && record.references.length <= 256);
    for (const reference of record.references) {
      need(exact(reference, ['name', 'tag', 'image', 'origin']));
      const original = byTag.get(reference.tag);
      need(original && equal(retirementReference(original), reference) && !retired.has(reference.tag));
      retired.add(reference.tag);
    }
  }
  return { references: references.filter(row => !retired.has(row.tag)), retiredTags: retired };
}

export function captureImageRetirements(root, references) {
  const parent = join(root, STATE, IMAGE_RETIREMENTS);
  const exists = () => fs.lstatSync(parent, { throwIfNoEntry: false });
  const before = exists();
  if (!before) return { ...applyImageRetirements(references, []), verify() { need(!exists()); } };
  need(before.isDirectory() && !before.isSymbolicLink() && before.uid === process.getuid() && (before.mode & 0o7777) === 0o700);
  const names = fs.readdirSync(parent).sort();
  need(names.length <= 64 && names.every(name => /^[a-f0-9]{32}\.json$/.test(name)));
  const stamp = value => [value.dev, value.ino, value.mode, value.uid, value.nlink, value.size, value.mtimeMs, value.ctimeMs];
  const proofs = names.map(name => {
    const path = join(parent, name), metadata = fs.lstatSync(path);
    need(metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1 && metadata.uid === process.getuid() &&
      (metadata.mode & 0o7777) === 0o600 && metadata.size <= 262144);
    const read = () => {
      const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      try { need(equal(stamp(fs.fstatSync(fd)), stamp(metadata))); return fs.readFileSync(fd); }
      finally { fs.closeSync(fd); }
    };
    const bytes = read(), record = JSON.parse(bytes);
    need(record.nonce + '.json' === name);
    return { record, verify() { need(equal(stamp(fs.lstatSync(path)), stamp(metadata)) && read().equals(bytes)); } };
  });
  const result = applyImageRetirements(references, proofs.map(proof => proof.record));
  const verify = () => {
    const current = exists();
    need(current?.isDirectory() && !current.isSymbolicLink() && current.ino === before.ino && current.dev === before.dev &&
      current.mode === before.mode && current.uid === before.uid && equal(fs.readdirSync(parent).sort(), names));
    proofs.forEach(proof => proof.verify());
  };
  verify(); return { ...result, verify };
}
