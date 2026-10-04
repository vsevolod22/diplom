import { ServiceUnavailableException } from '@nestjs/common';
import { ScansService } from '../scans/scans.service.js';
import type { ImageReference } from '../scans/image-reference.js';
import type { ImageSuggestion } from '../scans/image-search.js';
import { NGINX_SUPPORTED_CANDIDATE as target } from './bounded-image-archive.js';
import { inspectNginxCandidate } from './nginx-candidate.js';

// Not imported by AppModule or the production entry point. Disposable proof only:
// the immutable child/config are reverified, not admitted by a tag or enable flag.
export class NginxProofScansService extends ScansService {
  protected override acceptsReference(ref: ImageReference): boolean {
    return ref.registry === target.registry && ref.repository === target.repository && ref.selector === target.digest;
  }
  protected override async resolveTarget(ref: ImageReference) {
    const pinned = await inspectNginxCandidate(ref);
    if (!this.acceptsPinned(pinned) || pinned.configDigest !== target.configDigest)
      throw new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
    return pinned;
  }
  protected override acceptsPinned(pinned: { registry: string; repository: string; platform: string; digest: string }): boolean {
    return pinned.registry === target.registry && pinned.repository === target.repository &&
      pinned.platform === target.platform && pinned.digest === target.digest;
  }
  override imageSuggestion(item: ImageSuggestion): ImageSuggestion {
    if (item.kind !== 'repository' || item.reference !== `${target.registry}/${target.repository}:latest`) return item;
    return { ...item, label: 'nginx · изолированный точный профиль', reference: `${target.registry}/${target.repository}@${target.digest}`,
      eligibility: 'isolated-exact-profile', scannable: true,
      reason: 'Изолированный proof; не производственный допуск. Digest/config проверяются при запуске',
      checks: { secret: true, sbom: true, vuln: 'conditional' } };
  }
}
