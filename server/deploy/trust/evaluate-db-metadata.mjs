#!/usr/bin/env node
// Public metadata-only time check. No signature, signing, DB compatibility or admission proof.
import { CURRENT_DB_POLICY, evaluateDbPolicy, operatorUsableUntil } from '../../api/src/worker/cve-db-policy.mjs';
try {
  if (process.argv.length !== 2) throw new Error();
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > 4096) throw new Error();
    chunks.push(chunk);
  }
  const metadata = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  if (!metadata || Array.isArray(metadata) || metadata.Version !== 2) throw new Error();
  const db = { updatedAt: metadata.UpdatedAt, downloadedAt: metadata.DownloadedAt, nextUpdate: metadata.NextUpdate };
  console.log(JSON.stringify({ dbPolicy: evaluateDbPolicy(db, CURRENT_DB_POLICY), usableUntil: operatorUsableUntil(db) }));
} catch {
  console.error('DB metadata unusable'); process.exitCode = 1;
}
