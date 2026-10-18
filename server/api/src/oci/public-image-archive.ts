import type { ImageReference } from '../scans/image-reference.js';
import { prepareBoundedImageArchive } from './bounded-image-archive.js';
import { inspectPublicImage as inspect } from './public-image-inspection.js';
import { PUBLIC_IMAGE_PROFILE, type PublicImageTarget } from './public-image-policy.js';

export { type PublicImageTarget } from './public-image-policy.js';
export function inspectPublicImage(reference: ImageReference) {
  return inspect(reference);
}

// A queued digest is re-inspected, never a mutable tag. Optional config pins are
// checked if supplied; the returned receipt always contains the verified config.
export function preparePublicImageArchive(signal: AbortSignal | undefined, target: PublicImageTarget) {
  return prepareBoundedImageArchive(signal, target, PUBLIC_IMAGE_PROFILE);
}
