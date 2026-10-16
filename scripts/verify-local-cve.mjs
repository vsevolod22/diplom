import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HEX = /^[a-f0-9]{64}(?![\s\S])/;
const MANIFEST = /^sha256:[a-f0-9]{64}(?![\s\S])/;
const failure = () => new Error('LOCAL CVE release verification failed');

export function parseVerifyArguments(argv) {
  const names = ['--release-dir', '--public-key', '--public-key-sha256', '--manifest', '--bundle', '--db'];
  const values = {};
  if (argv.length !== names.length * 2 || !argv.every(value => typeof value === 'string')) throw failure();
  for (let i = 0; i < argv.length; i += 2) {
    if (!names.includes(argv[i]) || Object.hasOwn(values, argv[i])) throw failure();
    values[argv[i]] = argv[i + 1];
  }
  if (![values['--release-dir'], values['--public-key']].every(p => typeof p === 'string' && isAbsolute(p)) ||
      !MANIFEST.test(values['--manifest']) ||
      !['--public-key-sha256', '--bundle', '--db'].every(name => HEX.test(values[name]))) throw failure();
  return values;
}

// Run with node --import ABSOLUTE/server/api/node_modules/tsx/dist/loader.mjs.
// Imports are deferred so importing this script alone performs no verification or I/O.
export async function verifyLocalCve(argv) {
  try {
    const args = parseVerifyArguments(argv);
    const [{ readDbTrustPublicKey }, { preflightVulnDbBundle }, policy] = await Promise.all([
      import('../server/api/src/worker/vuln-db-trust.ts'),
      import('../server/api/src/worker/vuln-db-bundle.ts'),
      import('../server/api/src/worker/cve-db-policy.mjs'),
    ]);
    const trustedPublicKeyPem = readDbTrustPublicKey({ publicKeyPath: args['--public-key'],
      expectedSpkiSha256: args['--public-key-sha256'] });
    const { identity } = await preflightVulnDbBundle({ directory: args['--release-dir'], trustedPublicKeyPem,
      expectedSigner: 'local-db-operator-v1', expectedSource: `ghcr.io/aquasecurity/trivy-db@${args['--manifest']}`,
      expectedSchemaVersion: 2, expectedManifestDigest: args['--manifest'], expectedArtifactSha256: args['--bundle'],
      policy: policy.CURRENT_DB_POLICY });
    if (identity.dbSha256 !== args['--db']) throw failure();
    return { kind: 'authenticated-release-usability-only', db: identity,
      dbPolicy: policy.evaluateDbPolicy(identity, policy.CURRENT_DB_POLICY),
      usableUntil: policy.operatorUsableUntil(identity), scannerChecked: false, admissionChecked: false };
  } catch { throw failure(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verifyLocalCve(process.argv.slice(2)).then(result => console.log(JSON.stringify(result))).catch(() => {
    console.error('LOCAL CVE release verification failed');
    process.exitCode = 1;
  });
}
