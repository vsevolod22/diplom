import { ServiceUnavailableException } from '@nestjs/common';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { ScansService } from '../scans/scans.service.js';
import type { ImageReference } from '../scans/image-reference.js';
import type { ImageSuggestion } from '../scans/image-search.js';
import { inspectNginxCandidate } from './nginx-candidate.js';
import { exactLocalTarget, localChecksAllowed, NGINX_LOCAL_BINDING, NGINX_LOCAL_POLICY as policy } from './nginx-local-policy.js';

export const LOCAL_READY_PATH = '/data/nginx-local.ready';
export async function localWorkerReady(path = LOCAL_READY_PATH, now = Date.now()): Promise<boolean> {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > 256) return false;
    const marker = JSON.parse(await file.readFile('utf8')) as Record<string, unknown>;
    return Object.keys(marker).length === 3 && marker.qualificationId === policy.qualificationId && marker.version === policy.version &&
      typeof marker.at === 'number' && Number.isSafeInteger(marker.at) && now >= marker.at && now - marker.at <= 5000;
  } catch { return false; }
  finally { await file?.close(); }
}

// Ordinary accounts/controllers/trust: this class has no proof startup or test key.
export class NginxLocalScansService extends ScansService {
  protected override async readiness() { return await super.readiness() && await localWorkerReady(); }
  protected override acceptsReference(ref: ImageReference) {
    return super.acceptsReference(ref) || ref.registry === policy.registry && ref.repository === policy.repository && ref.selector === policy.digest;
  }
  protected override acceptsChecks(ref: ImageReference, checks: readonly string[]) {
    return ref.repository === policy.repository ? localChecksAllowed(checks) : super.acceptsChecks(ref, checks);
  }
  protected override allowedCheckSets(ref: ImageReference) {
    return ref.repository === policy.repository ? policy.allowedCheckSets : super.allowedCheckSets(ref);
  }
  protected override executionBinding(ref: ImageReference) { return ref.repository === policy.repository ? NGINX_LOCAL_BINDING : undefined; }
  protected override async resolveTarget(ref: ImageReference) {
    if (ref.repository !== policy.repository) return super.resolveTarget(ref);
    const pinned = await inspectNginxCandidate(ref);
    if (!exactLocalTarget(pinned) || pinned.configDigest !== policy.configDigest) throw new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
    return pinned;
  }
  protected override acceptsPinned(pinned: { registry: string; repository: string; platform: string; digest: string }) {
    return super.acceptsPinned(pinned) || exactLocalTarget(pinned);
  }
  override imageSuggestion(item: ImageSuggestion): ImageSuggestion {
    if (item.kind !== 'repository' || item.reference !== `${policy.registry}/${policy.repository}:latest`) return super.imageSuggestion(item);
    return { ...item, reference: `${policy.registry}/${policy.repository}@${policy.digest}`, label: 'nginx · закреплённый локальный профиль',
      eligibility: 'qualified-exact-profile', qualificationId: policy.qualificationId, allowedCheckSets: policy.allowedCheckSets,
      scannable: true, reason: 'Точный локальный профиль. Актуальный допуск и DB проверяются отдельно перед запуском',
      checks: { secret: true, sbom: true, vuln: 'conditional' } };
  }
}
