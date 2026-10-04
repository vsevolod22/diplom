import { spawn } from 'node:child_process';
import { prepareNginxArchive, NGINX_ARCHIVE_TARGET, NGINX_SUPPORTED_CANDIDATE } from './bounded-image-archive.js';
import { validateArchiveSbom } from './archive-identity.js';
import { parseVulnFindings } from '../worker/vuln-findings.js';
import { parseImageSbom } from '../worker/cyclonedx-components.js';

const archive = await prepareNginxArchive(AbortSignal.timeout(180_000),
  process.argv.includes('--supported-candidate') ? NGINX_SUPPORTED_CANDIDATE : NGINX_ARCHIVE_TARGET);
try {
  console.log(JSON.stringify({ receipt: archive.receipt, metrics: archive.metrics }));
  for (const format of ['json', 'cyclonedx']) {
    const child = spawn('/usr/local/bin/trivy', ['image', '--input', archive.archivePath, '--scanners', format === 'json' ? 'vuln' : 'secret',
      '--format', format, '--list-all-pkgs', '--skip-db-update', '--skip-java-db-update', '--offline-scan',
      '--cache-dir', '/tmp/trivy', '--timeout', '120s', '--quiet'],
    { env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', TMPDIR: archive.directory }, stdio: ['ignore', 'pipe', 'ignore'] });
    let bytes = 0; const chunks: Buffer[] = [];
    const timeout = setTimeout(() => child.kill('SIGKILL'), 125_000);
    child.stdout.on('data', (chunk: Buffer) => { bytes += chunk.length; if (bytes > 8_000_000) child.kill('SIGKILL'); else chunks.push(chunk); });
    const code = await new Promise<number | null>((resolve, reject) => { child.on('error', reject); child.on('close', resolve); });
    clearTimeout(timeout);
    if (code !== 0 || bytes > 8_000_000) throw new Error('Archive smoke failed');
    const report = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (format === 'json') {
      const knownSources = ['debian', 'suse-cvrf', 'suse', 'wolfi', 'chainguard', 'govulndb', 'mariner', 'arch-linux', 'openeuler', 'rootio', 'echo', 'aqua', 'redhat-oval', 'glad', 'seal', 'minimos', 'bottlerocket', 'suse-cvrf-suse', 'suse-cvrf-opensuse'];
      const present = new Set(report.Results.flatMap((item: { Vulnerabilities?: Array<{ VendorSeverity?: object }> }) =>
        (item.Vulnerabilities ?? []).flatMap(item => Object.keys(item.VendorSeverity ?? {}))));
      console.log(JSON.stringify({ recognizedAdditionalSources: knownSources.filter(item => present.has(item)) }));
      try {
        const findings = parseVulnFindings(report, `${archive.receipt.registry}/${archive.receipt.repository}@${archive.receipt.digest}`,
          archive.receipt.platform, { receipt: archive.receipt, archivePath: archive.archivePath });
        console.log(JSON.stringify({ normalizedFindings: findings.length }));
      } catch (error) {
        const message = error instanceof Error ? error.message : '';
        const safe = new Set(['Invalid or unbound vulnerability report', 'Invalid vulnerability result', 'Invalid package inventory',
          'No vulnerability coverage', 'Too many vulnerabilities', 'Invalid vulnerability', 'Invalid severity sources',
          'Invalid severity source', 'Conflicting vulnerability assessments', 'No verified OS coverage', 'Image archive rejected']);
        console.log(JSON.stringify({ vulnerabilityNormalizationError: safe.has(message) ? message : 'Normalization rejected' }));
      }
    }
    if (format === 'cyclonedx') {
      const properties = report.metadata?.component?.properties ?? [];
      const ids = properties.filter((item: { name: string }) => item.name === 'aquasecurity:trivy:DiffID').map((item: { value: string }) => item.value);
      console.log(JSON.stringify({ diffIdsOrdered: JSON.stringify(ids) === JSON.stringify(archive.receipt.diffIds),
        diffIdsMultiset: JSON.stringify([...ids].sort()) === JSON.stringify([...archive.receipt.diffIds].sort()) }));
      try {
        validateArchiveSbom(report, { receipt: archive.receipt, archivePath: archive.archivePath });
        const sbom = parseImageSbom(report, `${archive.receipt.registry}/${archive.receipt.repository}@${archive.receipt.digest}`,
          archive.receipt.platform, { receipt: archive.receipt, archivePath: archive.archivePath });
        console.log(JSON.stringify({ normalizedComponents: sbom.components.length }));
      } catch (error) {
        const message = error instanceof Error ? error.message : '';
        console.log(JSON.stringify({ normalizationError: /^(?:Image archive rejected|Invalid SBOM [A-Za-z ]+|Mismatched SBOM package identity|No verified SBOM packages)$/.test(message) ? message : 'Normalization rejected' }));
      }
    }
    // No raw scanner output, package paths, descriptions or credentials are printed.
    console.log(JSON.stringify(format === 'json' ? { format, schema: report.SchemaVersion, artifactType: report.ArtifactType,
      artifactNameIsArchive: report.ArtifactName === archive.archivePath, metadataKeys: Object.keys(report.Metadata ?? {}),
      imageId: report.Metadata?.ImageID, imageConfigKeys: Object.keys(report.Metadata?.ImageConfig ?? {}),
      imageOs: report.Metadata?.ImageConfig?.os, architecture: report.Metadata?.ImageConfig?.architecture,
      diffIds: report.Metadata?.ImageConfig?.rootfs?.diff_ids, repoDigests: report.Metadata?.RepoDigests,
      os: report.Metadata?.OS, classes: report.Results?.map((result: { Class: string; Type: string; Packages?: unknown[]; Vulnerabilities?: unknown[] }) =>
        ({ class: result.Class, type: result.Type, packages: result.Packages?.length, vulnerabilities: result.Vulnerabilities?.length })) }
      : { format, specVersion: report.specVersion, metadataKeys: Object.keys(report.metadata ?? {}),
        componentKeys: Object.keys(report.metadata?.component ?? {}), componentNameIsArchive: report.metadata?.component?.name === archive.archivePath,
                propertyNames: report.metadata?.component?.properties?.map((property: { name: string }) => property.name), count: report.components?.length }));
  }
} finally { await archive.cleanup(); }
