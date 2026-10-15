// Manual verifier for a locally attested DB release. This is not a CVE admission decision.
import { readFile } from 'node:fs/promises';
import { preflightVulnDbBundle } from './vuln-db-bundle.js';
import { CURRENT_DB_POLICY, evaluateDbPolicy, operatorUsableUntil } from './cve-db-policy.mjs';

const [directory, manifestDigest, artifactSha256] = process.argv.slice(2);
if (!directory || !/^sha256:[a-f0-9]{64}$/.test(manifestDigest ?? '') ||
    !/^[a-f0-9]{64}$/.test(artifactSha256 ?? '') || process.argv.length !== 5) {
  console.error('usage: tsx src/worker/verify-vuln-db-release.ts ABSOLUTE_DIRECTORY PINNED_OCI_DIGEST PINNED_BUNDLE_SHA256');
  process.exitCode = 1;
} else {
  const trustedPublicKeyPem = await readFile(new URL('../../../deploy/trust/db-signing-key.pub.pem', import.meta.url), 'utf8');
  try {
    const verified = await preflightVulnDbBundle({
      directory,
      trustedPublicKeyPem, expectedSigner: 'local-db-operator-v1',
      expectedSource: `ghcr.io/aquasecurity/trivy-db@${manifestDigest}`,
      expectedSchemaVersion: 2, expectedArtifactSha256: artifactSha256,
      expectedManifestDigest: manifestDigest, policy: CURRENT_DB_POLICY,
    });
    const receipt = evaluateDbPolicy(verified.identity, CURRENT_DB_POLICY);
    console.log(JSON.stringify({ kind: 'authenticated-release-usability-only', resultContractVersion: 2,
      db: verified.identity, dbPolicy: receipt, usableUntil: operatorUsableUntil(verified.identity),
      scannerChecked: false, admissionChecked: false }));
  } catch {
    console.error('DB release verification failed');
    process.exitCode = 1;
  }
}
