export type ImageFailureStage = 'inspection' | 'download' | 'decode' | 'archive' | 'scan';
export type ImageFailureResource = 'layers' | 'layer_bytes' | 'download_bytes' | 'expanded_bytes' |
  'file_bytes' | 'entries' | 'scratch_bytes' | 'requests' | 'output_bytes';
export type ImageFailureDetail = Readonly<{ stage: ImageFailureStage } & (
  { reason: 'RESOURCE_LIMIT'; resource?: ImageFailureResource } |
  { reason: 'IMAGE_NOT_ACCESSIBLE' | 'PLATFORM_UNSUPPORTED' | 'FORMAT_UNSUPPORTED' | 'IMAGE_INVALID' |
    'INTEGRITY_FAILED' | 'ARCHIVE_UNSAFE' | 'REGISTRY_RATE_LIMITED' | 'REGISTRY_UNAVAILABLE' |
    'DEADLINE_EXCEEDED' | 'SCANNER_FAILED'; resource?: never }
)>;
const stages: readonly string[] = ['inspection', 'download', 'decode', 'archive', 'scan'];
const resources: readonly string[] = ['layers', 'layer_bytes', 'download_bytes', 'expanded_bytes',
  'file_bytes', 'entries', 'scratch_bytes', 'requests', 'output_bytes'];
const reasons: readonly string[] = ['IMAGE_NOT_ACCESSIBLE', 'PLATFORM_UNSUPPORTED', 'FORMAT_UNSUPPORTED',
  'IMAGE_INVALID', 'INTEGRITY_FAILED', 'ARCHIVE_UNSAFE', 'REGISTRY_RATE_LIMITED', 'REGISTRY_UNAVAILABLE',
  'DEADLINE_EXCEEDED', 'SCANNER_FAILED'];

export function isImageFailureDetail(value: unknown): value is ImageFailureDetail {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.some(key => typeof key !== 'string' || !['reason', 'stage', 'resource'].includes(key)) ||
      Object.values(descriptors).some(item => !('value' in item))) return false;
  const reason: unknown = descriptors.reason?.value, stage: unknown = descriptors.stage?.value;
  return typeof stage === 'string' && stages.includes(stage) && typeof reason === 'string' &&
    (reason === 'RESOURCE_LIMIT' ? keys.length === 2 || keys.length === 3 && typeof descriptors.resource?.value === 'string' &&
      resources.includes(descriptors.resource.value as string) : keys.length === 2 && reasons.includes(reason));
}

// Only fixed, validated enums may cross transport/parser/durable/public boundaries.
export class ImageFailure extends Error {
  readonly failureDetail?: ImageFailureDetail;
  constructor(message: string, detail?: ImageFailureDetail) {
    super(message);
    if (isImageFailureDetail(detail)) this.failureDetail = Object.freeze({ ...detail });
  }
}
export function imageFailureDetail(error: unknown): ImageFailureDetail | undefined {
  return error instanceof ImageFailure && isImageFailureDetail(error.failureDetail) ? error.failureDetail : undefined;
}
export function registryFailureDetail(status: number, stage: ImageFailureStage): ImageFailureDetail {
  return { stage, reason: [401, 403, 404].includes(status) ? 'IMAGE_NOT_ACCESSIBLE' :
    status === 429 ? 'REGISTRY_RATE_LIMITED' : 'REGISTRY_UNAVAILABLE' };
}
// Projection of validated persisted failures only, never a lookup of transient errors.
export function persistedFailureDetail(value: { outcome: string; failureDetail?: ImageFailureDetail }) {
  return value.outcome === 'failed' && isImageFailureDetail(value.failureDetail)
    ? { failureDetail: value.failureDetail } : {};
}
