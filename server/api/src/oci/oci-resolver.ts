import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { resolveManifest, type ManifestFetch } from './registry-resolver.js';
import type { ImageReference } from '../scans/image-reference.js';

// No production gateway policy has been validated. Never use an implicit direct fetch.
@Injectable()
export class OciResolver {
  async resolve(ref: ImageReference, platform: string, fetchManifest?: ManifestFetch) {
    if (!fetchManifest) throw new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
    return resolveManifest(ref, platform, fetchManifest);
  }
}
