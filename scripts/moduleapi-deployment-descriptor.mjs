import { pathToFileURL } from 'node:url';
import { validateModuleApiDeployment } from './public-llm-source-build.mjs';
import { API_ENTRYPOINT, API_COMMAND, API_WORKDIR, BOOTSTRAP_SOURCE, BOOTSTRAP_TARGET,
  SECRET_DIRECTORY, SECRET_VOLUME } from '../server/deploy/moduleapi-secret-bootstrap.mjs';

// Current bounded v7 contract. The historical source-only handoff below is not
// a selectable deployment and is retained for callers inspecting that handoff.
export { MODULEAPI_SLOT_DEPLOYMENT, validateModuleApiDeployment, validateModuleApiBuildDeployment,
  selectModuleApiOperations, moduleApiEnvironment, validateModuleApiVolume, assertNoModuleApiDockerSecret,
  discoverModuleApiExecutionClosure, checkModuleApiQuotaSnapshot } from './public-llm-source-build.mjs';

const freeze = value => {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
};

// Source contract ONLY, deliberately not accepted by legacy v6 deployment validators.
// No installed settings, current/private state, pricing defaults or engine are read.
export const MODULEAPI_DEPLOYMENT = freeze({
  descriptor: 'moduleapi-preserving-v1', stage: 'source-only', executable: false,
  provider: { name: 'ModuleAPI', endpoint: 'https://moduleapi.pro/v1/chat/completions',
    model: 'gpt-5.4-mini', retention: 'unknown', tariff: 'unverified' },
  activated: false, generationVerified: false,
  gateway: { service: 'moduleapi-egress', port: 8080, authority: 'moduleapi.pro:443',
    networks: ['moduleapi_internal', 'moduleapi_uplink'], apiNetwork: 'moduleapi_internal',
    internalNetworkIsolated: true, publishedPorts: [], excludedRoles: ['web', 'worker'],
    dockerfile: 'server/deploy/gateway/moduleapi.Dockerfile', command: ['python', '-I', 'moduleapi.py', '--serve'] },
  api: { dockerfile: 'server/deploy/moduleapi-api.Dockerfile', entrypoint: [...API_ENTRYPOINT],
    command: [...API_COMMAND], workdir: API_WORKDIR, bootstrapSource: BOOTSTRAP_SOURCE, bootstrapTarget: BOOTSTRAP_TARGET,
    uid: 65532, gid: 65532, coreLimit: 0 },
  secret: { volume: SECRET_VOLUME, target: SECRET_DIRECTORY, file: 'server.env',
    readOnly: true, noCopy: true, apiOnly: true, dockerEnvironment: false,
    hostSource: 'passwd-home/.diplom-moduleapi/server.env', hostDirectoryMode: '0700', hostFileMode: '0600',
    runtimeDirectoryMode: '0700', runtimeFileMode: '0400', disabledMarker: 'MODULEAPI_ENABLED=false',
    authority: 'MODULE_API_KEY', provisioner: 'scripts/moduleapi-secret-provision.py',
    initializerDockerfile: 'server/deploy/moduleapi-secret-init.Dockerfile',
    initializerSource: 'server/deploy/moduleapi-secret-init.py', packagedImageRequired: true },
  preservation: { stores: ['auth', 'ledger', 'history', 'quota'], jwt: 'unchanged',
    existingProviderResources: 'retain', liabilities: 'all-retained-including-unknown',
    accountLifetimeMicros: 5_000_000, migrations: false, resets: false,
    requiredOrder: ['source-config-daemon-secret-fences', 'retain-images', 'fence-web', 'stop-api',
      'drain-stop-worker', 'fresh-readonly-four-store-baseline', 'qualify-quota-on-disposable-clone',
      'before-api-four-store-equality', 'start-api-readiness', 'after-api-four-store-equality',
      'web-last', 'publish-preservation-receipt'],
    failure: 'hold-with-evidence-no-automatic-retry-unlock-or-rollback' },
  blockers: [
    'MODULEAPI_PRESERVING_EXECUTOR_NOT_IMPLEMENTED',
    'MODULEAPI_SOURCE_CONFIG_CATALOG_CVE_TOPOLOGY_NOT_QUALIFIED',
    'MODULEAPI_PACKAGED_IMAGES_AND_LINUX_SECRET_BRIDGE_NOT_QUALIFIED',
    'MODULEAPI_EFFECTIVE_TARIFF_AND_GENERATION_COMPATIBILITY_UNVERIFIED',
  ],
});

// Only the explicit normalizer consumes bounded NONSECRET stdin. Import and
// default execution are inert; there is no provider, environment or file reader.
export async function normalizeModuleApiConfiguration(input, output) {
  const chunks = []; let bytes = 0;
  for await (const chunk of input) {
    const buffer = Buffer.from(chunk); bytes += buffer.length;
    if (bytes > 16384) throw Error('MODULEAPI_CONFIG_REJECTED');
    chunks.push(buffer);
  }
  const selection = validateModuleApiDeployment(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  output.write(JSON.stringify(selection));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href && process.argv.length !== 2) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== '--normalize') throw Error('MODULEAPI_CONFIG_REJECTED');
    await normalizeModuleApiConfiguration(process.stdin, process.stdout);
  } catch { process.stderr.write('MODULEAPI_CONFIG_REJECTED\n'); process.exitCode = 1; }
}

export function moduleApiDeploymentSupport() {
  return Object.freeze({ descriptor: MODULEAPI_DEPLOYMENT.descriptor, executable: false,
    activated: false, generationVerified: false, blockers: MODULEAPI_DEPLOYMENT.blockers });
}
