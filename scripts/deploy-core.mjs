/**
 * FINAL adapter contract: deploy-adapter.mjs exports async createAdapter(options).
 * Methods take ctx = { options, mode, services, interruptedServices, lease, plan,
 * candidate, recovery, snapshot, qualification, receipt, expectedMigration?,
 * fenceAttempted, switchAttempted, migrationAttempted, publishAttempted }.
 * Undefined fields are not yet available. Throw finite DEPLOY_* codes below,
 * never raw stderr/env/token. No legacy monolith lifecycle invocation.
 *
 * status(ctx) -> { ready: boolean, locked: boolean }; read-only.
 * acquireLock(ctx) -> opaque non-null lease. Core calls ONCE for apply, before
 *   preflight. Use the shared legacy lock; NEVER reclaim an existing lock.
 * ALL later apply methods verify ctx.lease ownership, NEVER acquire another lock
 *   or reject merely because this owned lock exists. Plan preflight has no lease.
 * releaseLock(ctx) -> { released: true }; release only this lease, preserve history.
 * preflight(ctx) -> { services: string[], interruptedServices: string[],
 *   migration: boolean, rollbackSafe: boolean, old: opaque,
 *   availableCapabilities: string[] }. Read-only config/current-state validation.
 *   services = exact requested UPGRADES; interruptedServices = full explicit
 *   interruption set (includes upgrades), e.g. writers fenced for snapshots even
 *   when not upgraded. Web: both sets MUST be ['web'], migration MUST be false.
 *   rollbackSafe attests known OLD immutable image + exact recorded compose recipe.
 * build(ctx) -> opaque non-null candidate; OLD keeps serving, no live mutation.
 * validateCandidate(ctx) -> { valid: true, requiredCapabilities: string[],
 *   availableCapabilities?: string[] }; isolated config/compilation/health only.
 *   Web requires capabilities from RUNNING backend (plan.availableCapabilities);
 *   app uses candidate/resulting backend capabilities from validation.
 * verify(ctx) -> { valid: true }; --verify focused checks only, never full suite.
 * waitForIdle(ctx) -> { idle: true }; app-only READ-ONLY polling. Adapter owns
 *   the end-to-end options.drainTimeoutMs deadline: cap each probe/sleep by the
 *   remaining budget, settle in-flight work and clear its operation guard BEFORE
 *   resolving/rejecting (DEPLOY_DRAIN on timeout). Core awaits settlement, without
 *   a competing timer/AbortSignal, before any release. Fence rechecks raced-in work.
 * prepareRecovery(ctx) -> { durable: true, ...opaque }; persist exact OLD recipe,
 *   immutable images, upgrade/interruption scopes BEFORE any live mutation.
 * fenceAdmissions(ctx) -> { fenced: true }; app only. Persist dispatch intent,
 *   prevent new admissions, boundedly drain/recheck work and quiesce writers in
 *   interruptedServices. Core sets fenceAttempted BEFORE await: even a throw holds.
 * snapshot(ctx) -> { durable: true, ...opaque }; EVERY app, all relevant stores;
 *   take consistent snapshots under fencing, never mutate/restore live databases.
 * qualifyState(ctx) -> { qualified: true, migration: boolean, ...opaque };
 *   EVERY app, COPY ONLY from ctx.snapshot using candidate constructors, including
 *   idempotence checks without migration. ctx.expectedMigration = plan.migration;
 *   result.migration MUST match. NEVER run migration/constructors on live stores.
 * switchServices(ctx) -> { switched: true }; upgrade ONLY services; resume other
 *   interruptedServices unchanged. No dependency expansion/build/pull. Actual API
 *   startup/migration happens HERE. Core sets migrationAttempted BEFORE await if
 *   plan.migration. There is NO live migrate() method and NEVER database rollback.
 * health(ctx) -> { healthy: true }; check all interrupted services/routing and
 *   qualified state expectations; target='candidate' or 'old'. No paid calls.
 * publishReceipt(ctx) -> { published: true }; durably publish ACTUAL config/pins
 *   plus small receipt based on ctx.receipt and observed deployment identity.
 *   Journal publication intent/completion; only acknowledge after both are durable.
 *   Core sets publishAttempted BEFORE await; ANY failure then HOLDS, never rollback.
 * restoreOld(ctx) -> { restored: true }; WEB ONLY automatic recovery. May recreate
 *   old web using recorded immutable image + EXACT compose recipe, --no-deps,
 *   no build/pull; container ID may change. Revalidate known state, leave backend,
 *   workers, gateways, stores/auth untouched; refuse uncertain dispatch/state.
 *
 * App errors after ANY fencing attempt conservatively HOLD lock + recovery (even
 * snapshot/qualification failure). No automatic app restore without a fresh proof;
 * this core deliberately chooses HOLD. Web restore requires rollbackSafe, durable
 * recovery, and no publication attempt; health must pass before lease release.
 * Every adapter call awaits settlement; adapter owns bounded operation/process
 * deadlines, including drain, and journals BEFORE dispatch. No timeout races.
 * Dry-run: preflight only, no lock/writes. Status: status only. Import is inert.
 * options: mode=web|app|status, apply=false, explicit services for app,
 * verify=false, migrate=false (CONSENT only), drainTimeoutMs=30000 (1..300000), root.
 * upgradeOperations=false: explicit opt-in, app with exactly web/api/worker/egress/
 * llm-egress/openai-egress. Adapter receives ctx.options.upgradeOperations.
 * plan.operations: public non-secret preset label, 1..128 alphanumeric/._- chars;
 * required with upgradeOperations, optional otherwise; exposed in read-only plan.
 */

export const DEPLOY_ERRORS = Object.freeze({
  DEPLOY_USAGE: ['Invalid deployment arguments.', false, 'Use --help; app requires an explicit --services list.'],
  DEPLOY_ADAPTER: ['Deployment adapter is unavailable or violates its contract.', false, 'Check the adapter against the contract in deploy-core.mjs.'],
  DEPLOY_LOCKED: ['The shared deployment lock is already held.', false, 'Inspect deploy status and the existing recovery record; do not delete the lock automatically.'],
  DEPLOY_PREFLIGHT: ['Deployment preflight failed.', false, 'Check the selected services, configuration and current stand state.'],
  DEPLOY_CONFIG: ['Deployment configuration is invalid or incomplete.', false, 'Validate the selected stand configuration without changing auth settings or reading secrets into logs.'],
  DEPLOY_DOCKER: ['The container runtime is unavailable.', true, 'Check Docker availability and access, then retry.'],
  DEPLOY_PROTECTED: ['The requested operation would touch a protected stand.', false, 'Select only the deployment target; the protected 8080 stand must remain untouched.'],
  DEPLOY_IDENTITY: ['Current container identity does not match the known deployment state.', false, 'Reconcile current container identities with the recovery record before applying changes.'],
  DEPLOY_UNSUPPORTED: ['The adapter cannot safely perform this requested operation.', false, 'Use a supported service set or add the required safe adapter implementation before applying.'],
  DEPLOY_SCOPE: ['The adapter plan changes services outside the requested scope.', false, 'Correct the adapter plan; web may change only web.'],
  DEPLOY_OPERATIONS_SCOPE: ['Operations upgrade requires app mode and all six services.', false, 'Use --upgrade-operations with app --services web,api,worker,egress,llm-egress,openai-egress.'],
  DEPLOY_MIGRATION_REQUIRED: ['A database migration requires explicit consent.', false, 'Review snapshot/recovery support, then use app --migrate --apply.'],
  DEPLOY_BUILD: ['Candidate compilation or build failed; OLD was not switched.', true, 'Fix the build/configuration and retry the deployment.'],
  DEPLOY_CANDIDATE: ['Candidate validation failed.', true, 'Fix candidate configuration or its isolated health check, then retry.'],
  DEPLOY_COMPATIBILITY: ['Required backend capabilities are not available.', false, 'Deploy a compatible explicit app service set, or build a UI compatible with the running API.'],
  DEPLOY_VERIFY: ['Focused verification failed.', true, 'Fix the focused checks before retrying with --verify.'],
  DEPLOY_DRAIN: ['Active work did not become idle within the drain budget.', true, 'Wait for active work to finish, then retry or increase --drain-timeout-ms.'],
  DEPLOY_RECOVERY: ['A durable recovery record could not be prepared.', true, 'Check local recovery storage permissions and capacity before retrying.'],
  DEPLOY_FENCE: ['Admission fencing or writer quiescence failed; the site may be interrupted.', false, 'Inspect the fencing journal and interrupted services before resuming admissions.'],
  DEPLOY_SNAPSHOT: ['A durable fenced app snapshot could not be prepared.', false, 'Inspect snapshot storage and the fencing journal; recover interrupted services before retrying.'],
  DEPLOY_QUALIFY: ['Candidate constructors failed copy-only state qualification.', false, 'Inspect the isolated qualification result; do not start the candidate against live stores.'],
  DEPLOY_MIGRATION: ['Database migration failed or its outcome is uncertain.', false, 'Inspect the retained recovery record; never automatically roll back the database.'],
  DEPLOY_SWITCH: ['Targeted service switch failed or was interrupted.', false, 'Inspect the deployment state and retained recovery record.'],
  DEPLOY_HEALTH: ['Deployment health check failed.', false, 'Inspect target-service health and the deployment recovery record.'],
  DEPLOY_RECEIPT: ['Config/receipt publication failed or its durable outcome is uncertain.', false, 'Reconcile actual config/pins and the receipt with the publication journal before releasing the lock.'],
  DEPLOY_RESTORE: ['Restoring OLD web could not be verified.', false, 'Inspect the recorded old-web image/compose recipe and actual routing; do not touch backend or stores.'],
  DEPLOY_UNLOCK: ['The owned deployment lock could not be released safely.', false, 'Inspect ownership and the recovery record; do not remove another deployment lock.'],
  DEPLOY_STATUS: ['Deployment status could not be read.', true, 'Check adapter access to the stand and shared lock metadata.'],
});

export class DeploymentError extends Error {
  constructor(code) {
    const safeCode = Object.hasOwn(DEPLOY_ERRORS, code) ? code : 'DEPLOY_ADAPTER';
    super(DEPLOY_ERRORS[safeCode][0]);
    this.name = 'DeploymentError';
    this.code = safeCode;
  }
}
const fail = code => { throw new DeploymentError(code); };
const requireValue = (condition, code = 'DEPLOY_ADAPTER') => { if (!condition) fail(code); };
const hasMethod = (adapter, name) => requireValue(typeof adapter?.[name] === 'function');
const stringList = value => Array.isArray(value) && value.length <= 256 &&
  value.every(item => typeof item === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$/.test(item));

export function normalizeOptions(input = {}) {
  const { mode, apply = false, verify = false, migrate = false, upgradeOperations = false, drainTimeoutMs = 30000 } = input;
  requireValue(['web', 'app', 'status'].includes(mode), 'DEPLOY_USAGE');
  requireValue([apply, verify, migrate, upgradeOperations].every(value => typeof value === 'boolean'), 'DEPLOY_USAGE');
  requireValue(Number.isInteger(drainTimeoutMs) && drainTimeoutMs > 0 && drainTimeoutMs <= 300000, 'DEPLOY_USAGE');
  const services = input.services ?? (mode === 'web' ? ['web'] : []);
  requireValue(Array.isArray(services) && services.length <= 32 &&
    services.every(name => typeof name === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(name)) &&
    new Set(services).size === services.length, 'DEPLOY_USAGE');
  requireValue(mode !== 'app' || services.length > 0, 'DEPLOY_USAGE');
  requireValue(mode !== 'web' || (services.length === 1 && services[0] === 'web' && !migrate), 'DEPLOY_USAGE');
  requireValue(mode !== 'status' || (!apply && !verify && !migrate && services.length === 0), 'DEPLOY_USAGE');
  requireValue(!upgradeOperations || (mode === 'app' && services.length === 6 &&
    ['web', 'api', 'worker', 'egress', 'llm-egress', 'openai-egress'].every(name => services.includes(name))), 'DEPLOY_OPERATIONS_SCOPE');
  return Object.freeze({ ...input, mode, apply, verify, migrate, upgradeOperations, drainTimeoutMs, services: Object.freeze([...services]) });
}

// Only finite known codes cross the adapter boundary. Never forward error text,
// cause, stack, stderr, arbitrary adapter metadata, environment or container config.
export function deploymentFailure(error, { phase = 'arguments', fallback = 'DEPLOY_USAGE',
  mode = null, state = 'unchanged', lock = 'not-acquired', rollback = 'not-needed' } = {}) {
  const raw = error && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code')?.value : null;
  const code = typeof raw === 'string' && Object.hasOwn(DEPLOY_ERRORS, raw) ? raw : fallback;
  const [message, retryable, action] = DEPLOY_ERRORS[code];
  const needsRecovery = lock === 'retained' || ['recovery-required', 'publication-uncertain'].includes(state);
  const holdAction = state === 'publication-uncertain' ? ' Hold lock; do not roll back after publication was attempted.'
    : state === 'recovery-required' ? ' Hold lock and recovery record; recover interrupted services without database rollback.'
      : lock === 'retained' ? ' Verify lease ownership before releasing the lock.' : '';
  return { ok: false, mode, phase, code, message, retryable: retryable && !needsRecovery,
    state, lock, rollback, keptOldServing: state === 'unchanged' ? null : state === 'old-serving',
    needsRecovery, nextAction: action + holdAction };
}


/** Never throws adapter errors; returns a sanitized success/failure record. */
export async function runDeployment(adapter, input = {}) {
  let ctx, phase = 'arguments', fallback = 'DEPLOY_USAGE';
  let state = 'unchanged', lock = 'not-acquired', rollback = 'not-needed';
  let switchAttempted = false, fenceAttempted = false, migrationAttempted = false, publishAttempted = false;
  const attempts = () => ({ fenceAttempted, switchAttempted, migrationAttempted, publishAttempted });
  const step = async (name, code, extra = {}) => {
    phase = name; fallback = code; hasMethod(adapter, name);
    return adapter[name]({ ...ctx, ...attempts(), ...extra });
  };
  const release = async () => {
    try {
      requireValue((await adapter.releaseLock({ ...ctx, ...attempts(), state }))?.released === true, 'DEPLOY_UNLOCK');
      lock = 'released'; return true;
    } catch { lock = 'retained'; return false; }
  };
  try {
    const options = normalizeOptions(input);
    ctx = { options, mode: options.mode, services: options.services };
    if (ctx.mode === 'status') {
      const status = await step('status', 'DEPLOY_STATUS');
      requireValue(typeof status?.ready === 'boolean' && typeof status.locked === 'boolean');
      return { ok: true, mode: 'status', phase: 'status', ready: status.ready, locked: status.locked };
    }
    if (options.apply) {
      for (const name of ['acquireLock', 'releaseLock', 'preflight', 'build', 'validateCandidate',
        'prepareRecovery', 'switchServices', 'health', 'publishReceipt',
        ...(ctx.mode === 'app' ? ['waitForIdle', 'fenceAdmissions', 'snapshot', 'qualifyState'] : ['restoreOld']),
        ...(options.verify ? ['verify'] : [])]) hasMethod(adapter, name);
      ctx.lease = await step('acquireLock', 'DEPLOY_LOCKED');
      requireValue(ctx.lease != null && ctx.lease !== false);
      lock = 'owned';
    }
    ctx.plan = await step('preflight', 'DEPLOY_PREFLIGHT');
    requireValue(ctx.plan && typeof ctx.plan.migration === 'boolean' && typeof ctx.plan.rollbackSafe === 'boolean' &&
      stringList(ctx.plan.availableCapabilities));
    requireValue(Array.isArray(ctx.plan.services) && ctx.plan.services.length === ctx.services.length &&
      new Set(ctx.plan.services).size === ctx.services.length && ctx.services.every(name => ctx.plan.services.includes(name)), 'DEPLOY_SCOPE');
    const interrupted = ctx.plan.interruptedServices;
    requireValue(Array.isArray(interrupted) && interrupted.length <= 32 &&
      interrupted.every(name => typeof name === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(name)) &&
      new Set(interrupted).size === interrupted.length && ctx.services.every(name => interrupted.includes(name)), 'DEPLOY_SCOPE');
    ctx.interruptedServices = Object.freeze([...interrupted]);
    requireValue(ctx.mode !== 'web' || (!ctx.plan.migration && interrupted.length === 1 && interrupted[0] === 'web'), 'DEPLOY_SCOPE');
    requireValue(!ctx.plan.rollbackSafe || ctx.plan.old != null);
    const operations = ctx.plan.operations;
    requireValue((operations === undefined && !options.upgradeOperations) ||
      (typeof operations === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(operations)));
    if (!options.apply) return { ok: true, mode: ctx.mode, phase: 'plan', state: 'unchanged',
      services: [...ctx.services], interruptedServices: [...interrupted], migration: ctx.plan.migration,
      rollbackSafe: ctx.mode === 'web' && ctx.plan.rollbackSafe, verify: options.verify,
      upgradeOperations: options.upgradeOperations, operations: operations ?? null,
      nextAction: 'Review upgrades AND interrupted services, then use --apply; migration also requires --migrate.' };
    state = 'old-serving';
    if (ctx.plan.migration) requireValue(options.migrate, 'DEPLOY_MIGRATION_REQUIRED');
    ctx.candidate = await step('build', 'DEPLOY_BUILD');
    requireValue(ctx.candidate != null && ctx.candidate !== false, 'DEPLOY_BUILD');
    const validation = await step('validateCandidate', 'DEPLOY_CANDIDATE');
    requireValue(validation?.valid === true, 'DEPLOY_CANDIDATE');
    requireValue(stringList(validation.requiredCapabilities), 'DEPLOY_COMPATIBILITY');
    const available = ctx.mode === 'web' ? ctx.plan.availableCapabilities : validation.availableCapabilities;
    requireValue(stringList(available) && validation.requiredCapabilities.every(capability => available.includes(capability)), 'DEPLOY_COMPATIBILITY');
    if (options.verify) requireValue((await step('verify', 'DEPLOY_VERIFY'))?.valid === true, 'DEPLOY_VERIFY');
    if (ctx.mode === 'app') {
      // Adapter owns the deadline; never release a lease while its probe is active.
      requireValue((await step('waitForIdle', 'DEPLOY_DRAIN'))?.idle === true, 'DEPLOY_DRAIN');
    }
    ctx.recovery = await step('prepareRecovery', 'DEPLOY_RECOVERY');
    requireValue(ctx.recovery?.durable === true, 'DEPLOY_RECOVERY');
    if (ctx.mode === 'app') {
      // A rejected fence can already have stopped writers: never unlock on error.
      fenceAttempted = true; state = 'recovery-required';
      requireValue((await step('fenceAdmissions', 'DEPLOY_FENCE'))?.fenced === true, 'DEPLOY_FENCE');
      ctx.snapshot = await step('snapshot', 'DEPLOY_SNAPSHOT');
      requireValue(ctx.snapshot?.durable === true, 'DEPLOY_SNAPSHOT');
      ctx.qualification = await step('qualifyState', 'DEPLOY_QUALIFY', { expectedMigration: ctx.plan.migration });
      requireValue(ctx.qualification?.qualified === true && ctx.qualification.migration === ctx.plan.migration, 'DEPLOY_QUALIFY');
    }
    // API startup inside switch may migrate live state even if dispatch throws.
    switchAttempted = true; migrationAttempted = ctx.plan.migration; state = 'recovery-required';
    requireValue((await step('switchServices', 'DEPLOY_SWITCH'))?.switched === true, 'DEPLOY_SWITCH');
    requireValue((await step('health', 'DEPLOY_HEALTH', { target: 'candidate' }))?.healthy === true, 'DEPLOY_HEALTH');
    state = 'new-healthy';
    ctx.receipt = Object.freeze({ version: 1, mode: ctx.mode, services: [...ctx.services],
      interruptedServices: [...ctx.interruptedServices], migration: migrationAttempted,
      verified: options.verify, healthy: true, completedAt: new Date().toISOString() });
    // Config may already be published when receipt publication rejects. HOLD.
    publishAttempted = true;
    requireValue((await step('publishReceipt', 'DEPLOY_RECEIPT'))?.published === true, 'DEPLOY_RECEIPT');
    if (!await release()) return { ...deploymentFailure(null, { mode: ctx.mode, phase: 'releaseLock',
      fallback: 'DEPLOY_UNLOCK', state, lock }), ...attempts() };
    return { ok: true, mode: ctx.mode, phase: 'complete', state, lock, receipt: ctx.receipt };
  } catch (error) {
    const failedPhase = phase, failedCode = fallback;
    let failure = error, reportPhase = failedPhase;
    if (publishAttempted) {
      state = 'publication-uncertain'; rollback = 'unsafe';
    } else if (fenceAttempted || switchAttempted) {
      state = 'recovery-required'; rollback = 'unsafe';
      // No fresh app-safe proof exists here: conservatively HOLD all app failures.
      if (ctx.mode === 'web' && !migrationAttempted && ctx.plan.rollbackSafe === true && ctx.recovery?.durable === true) {
        try {
          requireValue((await step('restoreOld', 'DEPLOY_RESTORE'))?.restored === true, 'DEPLOY_RESTORE');
          requireValue((await step('health', 'DEPLOY_RESTORE', { target: 'old' }))?.healthy === true, 'DEPLOY_RESTORE');
          state = 'old-restored'; rollback = 'restored';
        } catch { rollback = 'failed'; failure = new DeploymentError('DEPLOY_RESTORE'); reportPhase = phase; }
      }
    }
    if (lock === 'owned') {
      if (['recovery-required', 'publication-uncertain'].includes(state)) lock = 'retained';
      else if (!await release()) { failure = new DeploymentError('DEPLOY_UNLOCK'); reportPhase = 'releaseLock'; }
    }
    const result = deploymentFailure(failure, { mode: ctx?.mode ?? null, phase: reportPhase,
      fallback: failedCode, state, lock, rollback });
    if (failure !== error) {
      result.causeCode = deploymentFailure(error, { fallback: failedCode }).code;
      result.causePhase = failedPhase;
    }
    return { ...result, ...attempts() };
  }
}
