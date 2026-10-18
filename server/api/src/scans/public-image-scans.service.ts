import { NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from '../oci/oci-resolver.js';
import { inspectPublicImage } from '../oci/public-image-archive.js';
import { PUBLIC_IMAGE_LIMITS, PUBLIC_IMAGE_PROFILE, isPublicReceipt } from '../oci/public-image-policy.js';
import { NGINX_ARCHIVE_CANDIDATES } from '../oci/bounded-image-archive.js';
export { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_RESOURCE_POLICY } from '../oci/public-image-policy.js';
import { PRODUCTION_DB_TRUST_ANCHOR, type DbTrustAnchor } from '../worker/vuln-db-trust.js';
import type { Identity } from '../security/identity.js';
import { parseImageReference, type ImageReference } from './image-reference.js';
import type { ImageSuggestion } from './image-search.js';
import { ScansService } from './scans.service.js';
import { publicIdentifierCounts } from './public-vulnerability-identifiers.js';


export type PublicImageInspection = Readonly<{ registry: string; repository: string; digest: `sha256:${string}`;
  configDigest: string; platform: string; layers: readonly Readonly<{ digest: string; size: number; mediaType: string }>[] }>;
export type PublicImageInspector = (reference: ImageReference) => Promise<PublicImageInspection>;
export const PUBLIC_IMAGE_INSPECTOR = Symbol('PUBLIC_IMAGE_INSPECTOR');
const hub = new Set(['registry-1.docker.io']);
const digest = /^sha256:[a-f0-9]{64}$/;
const repository = /^[a-z0-9]+(?:[._-][a-z0-9]+)*\/[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

/** Explicit composition only: no user parameter or environment flag broadens AppModule. */
export class PublicImageScansService extends ScansService {
  private readonly anchor: DbTrustAnchor;
  constructor(private readonly publicLedger: LedgerStore, resolver: OciResolver,
    private readonly inspect: PublicImageInspector = inspectPublicImage, anchor: DbTrustAnchor = PRODUCTION_DB_TRUST_ANCHOR) {
    super(publicLedger, resolver);
    this.anchor = Object.freeze({ ...anchor });
  }
  protected override dbTrustAnchor(): DbTrustAnchor { return this.anchor; }
  protected override acceptsReference(ref: ImageReference): boolean {
    return ref.registry === 'registry-1.docker.io' && ref.repository.length <= 255 && repository.test(ref.repository) &&
      ref.repository.split('/').every(part => part.length <= 128) &&
      ref.canonical === `${ref.registry}/${ref.repository}${ref.selector.startsWith('sha256:') ? '@' : ':'}${ref.selector}`;
  }
  protected override acceptsReferenceInput(input: unknown, ref: ImageReference): boolean {
    return input === ref.canonical && this.acceptsReference(ref);
  }
  protected override eligibilityProfile(ref: ImageReference): ImageSuggestion['eligibility'] {
    return this.acceptsReference(ref) ? 'public-hub-profile' : 'unsupported';
  }
  protected override acceptsPinned(target: { registry: string; repository: string; platform: string; digest: string }): boolean {
    return target.registry === 'registry-1.docker.io' && target.repository.length <= 255 && repository.test(target.repository) &&
      target.platform === 'linux/amd64' && digest.test(target.digest);
  }
  protected override async resolveTarget(ref: ImageReference) {
    const target = await this.inspect(ref);
    // Inspection authenticates the config and manifest. Also fence injected adapters
    // before enqueue: neither a different repository nor an unbounded inventory is authority.
    if (!this.acceptsReference(ref) || !this.acceptsPinned(target) || target.registry !== ref.registry || target.repository !== ref.repository ||
      !digest.test(target.configDigest) || !Array.isArray(target.layers) || target.layers.length < 1 || target.layers.length > PUBLIC_IMAGE_LIMITS.maxLayers ||
      target.layers.some(layer => !digest.test(layer.digest) || !Number.isSafeInteger(layer.size) || layer.size <= 0 ||
        layer.size > PUBLIC_IMAGE_LIMITS.compressedLayer || !['application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip'].includes(layer.mediaType)) ||
      target.layers.reduce((total, layer) => total + layer.size, 0) > PUBLIC_IMAGE_LIMITS.compressedTotal) {
      throw new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
    }
    return target;
  }
  override imageSuggestion(item: ImageSuggestion): ImageSuggestion {
    let ref: ImageReference;
    try { ref = parseImageReference(item.reference, hub); } catch { return { ...item, scannable: false, eligibility: 'unsupported' }; }
    if (!this.acceptsReference(ref)) return { ...item, scannable: false, eligibility: 'unsupported' };
    return { ...item, scannable: false, eligibility: 'public-hub-profile', allowedCheckSets: this.allowedCheckSets(ref),
      reason: 'Кандидат Docker Hub: публичность, linux/amd64, config и ресурсы проверяются отдельно; поиск не разрешает запуск',
      checks: { secret: true, sbom: true, vuln: 'conditional' } };
  }
  override report(...args: Parameters<ScansService['report']>) {
    const ledger = this.publicLedger.ledger;
    const read = () => {
      const result = super.report(...args);
      const [identity, scanId, kind] = args;
      if (kind === 'secret' || !('outcome' in result) || result.outcome === 'failed') return result;
      const archive = ledger?.archiveResult(scanId, identity.subject);
      // Serving a legacy result through this module does not change its grammar.
      // Keep the receipt decision in the same snapshot as ordinary/report-v1 data.
      return archive?.[kind]?.outcome === result.outcome && isPublicReceipt(archive.receipt)
        ? { ...result, profile: PUBLIC_IMAGE_PROFILE,
                  ...(kind === 'vuln' && archive.vuln?.outcome === 'checked'
                    ? { identifierCounts: publicIdentifierCounts(archive.vuln.findings) } : {}) } : result;
    };
    return ledger ? ledger.readReportSnapshot(read) : read();
  }
  override status(identity: Identity, scanId: string) {
    const ledger = this.publicLedger.ledger;
    if (!ledger) throw new NotFoundException();
    return ledger.readReportSnapshot(() => {
      const status = super.status(identity, scanId);
      const target = ledger.pinnedTarget(scanId, identity.subject);
      if (!target) throw new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
      const archive = ledger.archiveResult(scanId, identity.subject);
      const legacyTarget = target.repository === 'library/alpine' || NGINX_ARCHIVE_CANDIDATES.some(candidate =>
        candidate.registry === target.registry && candidate.repository === target.repository &&
        candidate.digest === target.digest && candidate.platform === target.platform);
      // An existing archive receipt alone selects the result contract. With no
      // archive, public queued/config-only identity must not relabel legacy targets.
      const publicProfile = archive ? isPublicReceipt(archive.receipt)
        : !legacyTarget && !ledger.executionProfile(scanId) && this.acceptsPinned(target);
      return { ...status, imageReference: `${target.registry}/${target.repository}@${target.digest}`,
        ...(publicProfile ? { profile: PUBLIC_IMAGE_PROFILE } : {}),
                ...(publicProfile && archive?.vuln?.outcome === 'checked'
                  ? { identifierCounts: publicIdentifierCounts(archive.vuln.findings) } : {}) };
    });
  }
}
