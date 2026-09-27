// Run only from the isolated deployment network. Never print registry responses,
// signed URLs, tokens or raw errors from remote services.
import { dockerHubManifestFetch } from './gateway-transport.js';
import { resolveManifest, ResolutionRejected } from './registry-resolver.js';
import { parseImageReference } from '../scans/image-reference.js';

let stage = 'bootstrap';
try {
  const ref = parseImageReference('registry-1.docker.io/library/alpine:3.20', new Set(['registry-1.docker.io']));
  const transport = dockerHubManifestFetch({ host: 'egress', port: 8080 }, 'library/alpine');
  const pinned = await resolveManifest(ref, 'linux/amd64', async (host, path) => {
    stage = path.includes('/blobs/') ? 'config blob' : path.includes('sha256:') ? 'child manifest' : 'index manifest';
    const result = await transport(host, path);
    if (!result.headers['docker-content-digest']) stage += ' missing digest header';
    return result;
  });
  if (!/^sha256:[a-f0-9]{64}$/.test(pinned.digest) || pinned.platform !== 'linux/amd64') throw new Error();
  process.stdout.write('public OCI digest/config/platform validated via trusted TLS\n');
} catch (error) {
  const reason = error instanceof ResolutionRejected ? error.message : 'Unexpected failure';
  process.stderr.write(`public OCI validation unavailable at ${stage}: ${reason} (no target accepted)\n`);
  process.exitCode = 1;
}
