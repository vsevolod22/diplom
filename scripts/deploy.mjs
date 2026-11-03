#!/usr/bin/env node
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DeploymentError, deploymentFailure, normalizeOptions, runDeployment } from './deploy-core.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const HELP = `Usage: node scripts/deploy.mjs <web|app|status|recover> [options]

  web                       Build/switch only web; require backend compatibility.
  app --services web,api     Upgrade exactly this set; plan also lists interruptions.
  status                    Read readiness and shared lock status; never mutate.
  recover --audit <32hex>    Classify a prospective schema5 prestart checkpoint.
  --checkpoint <64hex>      Exact checkpoint SHA256; required for recovery --apply.
                            No migration/build replay; unsupported phases HOLD.

  --apply                   Execute. Without this flag, show a read-only plan.
  --plan, --dry-run          Explicit read-only plan (not a build or reservation).
  --services <csv>           Required for app; web permits only web.
  --migrate                 Consent to auth migration at API startup after copy qualification.
  --migrate-history-v4-to-v5 Explicit history-only migration consent; app API target,
                            separate from --migrate and --upgrade-operations.
  --upgrade-operations      Explicit operations-v2 upgrade; app only, requires exactly
                            web,api,worker,egress,llm-egress,openai-egress.
  --verify                  Opt in to focused verification, not a full test suite.
  --drain-timeout-ms <ms>    App idle-wait budget, 1..300000 (default 30000).
  --help                    Show this help without loading the adapter.

Examples:
  node scripts/deploy.mjs web
  node scripts/deploy.mjs web --apply
  node scripts/deploy.mjs app --services web,api,worker --apply
  node scripts/deploy.mjs status

Existing shared locks are never reclaimed automatically. OLD serves during build.
Every app rollout fences admissions, snapshots, and qualifies state on a copy.
Errors after app fencing or any publication attempt HOLD lock/recovery state.
The database is NEVER auto-rolled back; --migrate covers auth only.
History migration runs only after explicit consent, fencing and copy qualification.
After any history migration attempt: HOLD on failure, no old-v4 binary or stale restore.
App/recovery apply requires the inherited OS lease (embedded Python fcntl supervisor).
Recovery is prospective/prestart only: no writer/publication submission or pending dispatch.
Old attempts without immutable version3 authority/checkpoint are never backfilled.
Output is sanitized JSON. Exit: 0 success/plan, 1 failure, 2 shared lock busy.
`;

export function parseArgs(argv) {
  if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) return { help: true };
  const [mode, ...args] = argv;
  const options = { mode, root: ROOT };
  const seen = new Set();
  for (let i = 0; i < args.length; i += 1) {
    const [flag, ...suffix] = args[i].split('=');
    if (seen.has(flag)) throw new DeploymentError('DEPLOY_USAGE');
    seen.add(flag);
    if (['--services', '--drain-timeout-ms', '--audit', '--checkpoint'].includes(flag)) {
      const value = suffix.length ? suffix.join('=') : args[++i];
      if (!value || value.startsWith('--')) throw new DeploymentError('DEPLOY_USAGE');
      if (flag === '--services') options.services = value.split(',');
      else if (flag === '--audit') options.audit = value;
      else if (flag === '--checkpoint') options.checkpoint = value;
      else {
        if (!/^\d+$/.test(value)) throw new DeploymentError('DEPLOY_USAGE');
        options.drainTimeoutMs = Number(value);
      }
    } else {
      if (suffix.length) throw new DeploymentError('DEPLOY_USAGE');
      if (flag === '--apply') options.apply = true;
      else if (flag === '--verify') options.verify = true;
      else if (flag === '--migrate') options.migrate = true;
      else if (flag === '--migrate-history-v4-to-v5') options.migrateHistoryV4ToV5 = true;
      else if (flag === '--upgrade-operations') options.upgradeOperations = true;
      else if (!['--plan', '--dry-run'].includes(flag)) throw new DeploymentError('DEPLOY_USAGE');
    }
  }
  if (seen.has('--apply') && (seen.has('--plan') || seen.has('--dry-run'))) throw new DeploymentError('DEPLOY_USAGE');
  if (mode !== 'app' && seen.has('--drain-timeout-ms')) throw new DeploymentError('DEPLOY_USAGE');
  if (mode === 'recover' && ['--services','--verify','--migrate','--migrate-history-v4-to-v5','--upgrade-operations'].some(flag => seen.has(flag))) throw new DeploymentError('DEPLOY_USAGE');
  if (mode === 'status' && (seen.has('--plan') || seen.has('--dry-run'))) throw new DeploymentError('DEPLOY_USAGE');
  return normalizeOptions(options);
}

// Injectable factory keeps the CLI independently usable with safe test adapters.
// Importing this module does not load Docker/config/secrets or execute deployment.
export async function main(argv = process.argv.slice(2), createAdapter) {
  let options;
  try { options = parseArgs(argv); }
  catch (error) {
    const result = deploymentFailure(error);
    console.log(JSON.stringify(result));
    return 1;
  }
  if (options.help) { console.log(HELP); return 0; }
  let result;
  try {
    if (!createAdapter && options.apply && ['app','recover'].includes(options.mode)) {
      const { hasDeploySupervisor, requireDeploySupervisor, superviseDeployment } = await import('./deploy-supervisor.mjs');
      if (!hasDeploySupervisor()) return await superviseDeployment(ROOT, argv);
      requireDeploySupervisor(ROOT);
    }
    const factory = createAdapter ?? (await import('./deploy-adapter.mjs')).createAdapter;
    if (typeof factory !== 'function') throw new DeploymentError('DEPLOY_ADAPTER');
    result = await runDeployment(await factory(options), options);
  } catch (error) {
    result = deploymentFailure(error, { mode: options.mode, phase: 'adapter', fallback: 'DEPLOY_ADAPTER' });
  }
  console.log(JSON.stringify(result));
  return result.ok ? 0 : result.code === 'DEPLOY_LOCKED' ? 2 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main();
}
