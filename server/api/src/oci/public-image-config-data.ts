import { createHash } from 'node:crypto';
import { PUBLIC_IMAGE_LIMITS as L, publicDigest, publicObject } from './public-image-policy.js';
import { ResolutionRejected } from './registry-resolver.js';

const ociConfig = 'application/vnd.oci.image.config.v1+json';
const configTypes = new Set([ociConfig, 'application/vnd.docker.container.image.v1+json']);
const reject = (): never => { throw new ResolutionRejected('Public config descriptor rejected'); };
export type PublicConfigDescriptorEvidence = Readonly<{
  digest: `sha256:${string}`; size: number; mediaType: string;
  embedded?: Readonly<{ digest: `sha256:${string}`; size: number }>;
}>;

// No raw descriptor, base64, decoded config or Env leaves this helper. Embedded
// evidence supplements, and never replaces, the independently verified blob GET.
export function validatePublicConfigDescriptor(value: unknown): PublicConfigDescriptorEvidence {
  if (!publicObject(value) || !publicDigest(value.digest) || typeof value.size !== 'number' ||
      !Number.isSafeInteger(value.size) || value.size <= 0 || value.size > L.maxConfigBytes ||
      typeof value.mediaType !== 'string' || !configTypes.has(value.mediaType) || value.urls !== undefined) return reject();
  const { digest, size, mediaType } = value;
  if (value.data === undefined) return Object.freeze({ digest, size, mediaType });
  const data = value.data;
  // Validate declared size and exact encoded length before allocating decoded bytes.
  if (mediaType !== ociConfig || typeof data !== 'string' || data.length !== 4 * Math.ceil(size / 3)) return reject();
  const padding = (3 - size % 3) % 3;
  for (let index = 0; index < data.length; index++) {
    const byte = data.charCodeAt(index);
    if (index >= data.length - padding) {
      if (byte !== 61) return reject();
    } else if (!(byte >= 65 && byte <= 90 || byte >= 97 && byte <= 122 || byte >= 48 && byte <= 57 || byte === 43 || byte === 47)) return reject();
  }
  const decoded = Buffer.from(data, 'base64');
  // Re-encoding also rejects nonzero unused pad bits (permissive decoders accept them).
  if (decoded.length !== size || decoded.toString('base64') !== data ||
      `sha256:${createHash('sha256').update(decoded).digest('hex')}` !== digest) return reject();
  return Object.freeze({ digest, size, mediaType, embedded: Object.freeze({ digest, size }) });
}
